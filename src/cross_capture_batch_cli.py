#!/usr/bin/env python3
"""
Mode batch (issue #277) : expertise de toutes les captures d'un dossier,
et analyse croisee automatique des captures qui semblent etre plusieurs
points de vue d'un meme evenement.

    python3 src/cross_capture_batch_cli.py --input /data/incident-4412 --output rapports/

Deroulement :

1. inventaire : chaque capture est decodee une fois pour en extraire la
   fenetre temporelle, les IP et les conversations (netcross_core.batch) ;
   une capture illisible n'arrete PAS le lot, elle est listee en echec avec
   son motif ;
2. regroupement conservateur (trois criteres, tous requis -- voir
   netcross_core.batch) avec justification ecrite de chaque decision ;
3. un rapport par capture, un rapport croise par groupe ;
4. un index de lot (index.txt) : groupes + justification, captures isolees
   + motif, echecs + motif, synthese.

Code de sortie : 0 si tout a ete traite, 2 si au moins une capture est en
echec (le lot est quand meme alle au bout), 1 sur erreur d'utilisation.
"""

import argparse
import contextlib
import json
import os
import re
import sys
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor

from netcross_core import analyse, correlate, parse_capture, print_report
from netcross_core.batch import (
    DEFAULT_GROUP_WINDOW,
    DEFAULT_MIN_COMMON_IPS,
    DEFAULT_MIN_OVERLAP,
    BatchPlan,
    CaptureInventory,
    format_batch_index,
    inventory_from_packets,
    plan_batch,
)
from netcross_core.logging_config import add_debug_argument, apply_debug_argument, get_logger
from netcross_core.security import findings as security_findings
from netcross_report.security_report import build_security_report, print_security_report

logger = get_logger(__name__)

CAPTURE_EXTENSIONS = (".pcap", ".pcapng", ".cap", ".erf", ".pcap.gz", ".pcapng.gz")
CACHE_DIR = ".netcross-batch"
SERIOUS_SEVERITIES = ("critique", "elevee")


def list_captures(folder: str, recursive: bool = False) -> tuple[list[str], list[str]]:
    """Renvoie (captures, ignores) tries par chemin. Les fichiers ignores
    (extension non reconnue) sont remontes pour etre cites dans l'index :
    rien ne disparait sans trace."""
    captures: list[str] = []
    ignored: list[str] = []
    walker: Iterator[tuple[str, list[str]]]
    if recursive:
        walker = ((root, files) for root, _dirs, files in os.walk(folder))
    else:
        walker = iter([(folder, [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))])])
    for root, files in walker:
        if CACHE_DIR in root.split(os.sep):
            continue
        for name in files:
            path = os.path.join(root, name)
            if name.lower().endswith(CAPTURE_EXTENSIONS):
                captures.append(path)
            else:
                ignored.append(path)
    return sorted(captures), sorted(ignored)


def make_labels(paths: list[str]) -> dict[str, str]:
    """Etiquette lisible et unique par capture (nom de fichier sans
    extension, suffixe _2, _3... en cas de collision)."""
    labels: dict[str, str] = {}
    used: set[str] = set()
    for path in paths:
        base = os.path.basename(path)
        for ext in sorted(CAPTURE_EXTENSIONS, key=len, reverse=True):
            if base.lower().endswith(ext):
                base = base[: -len(ext)]
                break
        base = re.sub(r"[^A-Za-z0-9_.-]", "_", base) or "capture"
        label, n = base, 2
        while label in used:
            label = f"{base}_{n}"
            n += 1
        used.add(label)
        labels[path] = label
    return labels


def build_inventory(label: str, path: str) -> CaptureInventory:
    """Decode une capture et en extrait l'inventaire. Ne leve jamais : une
    erreur devient CaptureInventory.error (motif cite dans l'index)."""
    try:
        packets = parse_capture(label, path, raise_on_error=True)
    except Exception as exc:  # noqa: BLE001 -- une capture illisible ne doit pas arreter le lot
        logger.exception(f"échec dans build_inventory: {exc}")
        msg = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        return CaptureInventory(label=label, path=path, error=msg[:200])
    return inventory_from_packets(label, path, packets)


def _cache_path(output: str, label: str) -> str:
    return os.path.join(output, CACHE_DIR, "inventaire", f"{label}.json")


def _fingerprint(path: str) -> list:
    st = os.stat(path)
    return [st.st_size, int(st.st_mtime)]


def load_cached_inventory(output: str, label: str, path: str) -> CaptureInventory | None:
    cache = _cache_path(output, label)
    try:
        with open(cache, encoding="utf-8") as fh:
            data = json.load(fh)
        if data.get("fingerprint") != _fingerprint(path) or data["inventory"]["path"] != path:
            return None
        return CaptureInventory.from_dict(data["inventory"])
    except (OSError, ValueError, KeyError, TypeError):
        logger.exception("échec dans load_cached_inventory")
        return None


def save_cached_inventory(output: str, inv: CaptureInventory) -> None:
    cache = _cache_path(output, inv.label)
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    with open(cache, "w", encoding="utf-8") as fh:
        json.dump({"fingerprint": _fingerprint(inv.path), "inventory": inv.to_dict()}, fh)


def collect_inventories(paths, labels, output, jobs=1, skip_existing=False) -> list[CaptureInventory]:
    results: dict[str, CaptureInventory] = {}
    todo = []
    for path in paths:
        cached = load_cached_inventory(output, labels[path], path) if skip_existing else None
        if cached is not None:
            results[path] = cached
        else:
            todo.append(path)
    if jobs > 1 and len(todo) > 1:
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            results.update(zip(todo, pool.map(build_inventory, [labels[p] for p in todo], todo)))
    else:
        for path in todo:
            results[path] = build_inventory(labels[path], path)
    for path in todo:
        inv = results[path]
        print(f"  inventaire {inv.label} : {'ECHEC -- ' + inv.error if inv.error else f'{inv.packet_count} paquet(s)'}")
        if inv.error is None:
            save_cached_inventory(output, inv)
    return [results[p] for p in paths]


def analyse_and_write(members: list[CaptureInventory], out_path: str, security: bool) -> dict:
    """Analyse (croisee si plusieurs membres) et ecrit le rapport texte.
    Renvoie un resume pour la synthese : {"findings": {severite: n}}."""
    all_packets = []
    for m in members:
        all_packets.extend(parse_capture(m.label, m.path, raise_on_error=True))
    points = [m.label for m in members]
    report = analyse(correlate(all_packets), points, all_packets)
    counts: dict[str, int] = {}
    with open(out_path, "w", encoding="utf-8") as fh, contextlib.redirect_stdout(fh):
        print_report(report)
        if security:
            security_findings.apply_security_findings(report, all_packets)
            print_security_report(build_security_report(report))
            for f in report.security_findings:
                sev = str(f.get("severity") or "faible")
                counts[sev] = counts.get(sev, 0) + 1
    return {"findings": counts}


def run_analyses(plan: BatchPlan, output: str, security: bool, skip_existing: bool):
    """Un rapport par capture exploitable, un rapport croise par groupe.
    Une analyse qui echoue n'arrete pas le lot : elle est ajoutee a la
    synthese avec son motif."""
    group_reports: dict[int, str] = {}
    capture_reports: dict[str, str] = {}
    summaries: dict[str, dict] = {}
    errors: list[str] = []

    jobs_list: list[tuple[str, list[CaptureInventory], str]] = []
    for grp in plan.groups:
        jobs_list.extend((m.label, [m], f"rapport-{m.label}.txt") for m in grp.members)
    jobs_list.extend(
        (iso.capture.label, [iso.capture], f"rapport-{iso.capture.label}.txt")
        for iso in plan.isolated
        if iso.capture.packet_count > 0
    )
    for idx, grp in enumerate(plan.groups, start=1):
        jobs_list.append((f"groupe {idx}", grp.members, f"rapport-groupe-{idx}.txt"))

    for key, members, name in jobs_list:
        out_path = os.path.join(output, name)
        if key.startswith("groupe "):
            group_reports[int(key.split()[1])] = name
        else:
            capture_reports[key] = name
        if skip_existing and os.path.exists(out_path):
            print(f"  {name} : deja present, conserve (--skip-existing)")
            continue
        try:
            summaries[key] = analyse_and_write(members, out_path, security)
            print(f"  {name} : ecrit")
        except Exception as exc:  # noqa: BLE001 -- une analyse en echec ne doit pas arreter le lot
            logger.exception("analyse %s en echec", key)
            errors.append(f"analyse {key} en echec : {exc}")
            print(f"  {name} : ECHEC -- {exc}", file=sys.stderr)
    return group_reports, capture_reports, summaries, errors


def build_synthesis(plan, summaries, errors, ignored, security) -> list[str]:
    lines = []
    total_pkts = sum(inv.packet_count for g in plan.groups for inv in g.members) + sum(
        iso.capture.packet_count for iso in plan.isolated
    )
    lines.append(f"{total_pkts} paquet(s) inventorie(s)")
    if security:
        serious = {k: v for k, v in summaries.items() if any(v["findings"].get(s) for s in SERIOUS_SEVERITIES)}
        if serious:
            lines.append(
                f"{len(serious)} rapport(s) avec constats de severite critique/elevee : " + ", ".join(sorted(serious))
            )
        else:
            lines.append("aucun constat de severite critique/elevee dans les rapports produits")
    else:
        lines.append("analyse de securite non demandee (--security-report)")
    lines.extend(errors)
    if ignored:
        shown = ", ".join(os.path.basename(p) for p in ignored[:5])
        more = f", ... (+{len(ignored) - 5})" if len(ignored) > 5 else ""
        lines.append(f"{len(ignored)} fichier(s) ignore(s) (extension non reconnue) : {shown}{more}")
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Expertise toutes les captures d'un dossier et tente l'analyse croisee des captures "
        "qui semblent observer le meme evenement (issue #277)."
    )
    ap.add_argument("--input", required=True, metavar="DOSSIER", help="Dossier contenant les captures.")
    ap.add_argument("--output", required=True, metavar="DOSSIER", help="Dossier des rapports (cree si absent).")
    ap.add_argument("--recursive", action="store_true", help="Parcourt aussi les sous-dossiers.")
    ap.add_argument("--no-group", action="store_true", help="Aucun regroupement : chaque capture est analysee seule.")
    ap.add_argument(
        "--group-window",
        type=float,
        default=DEFAULT_GROUP_WINDOW,
        metavar="SECONDES",
        help=f"Decalage d'horloge maximal tolere entre deux captures (defaut {DEFAULT_GROUP_WINDOW:g} s). "
        "Un decalage estime dans cette fenetre est corrige avant le calcul du recouvrement, et mentionne.",
    )
    ap.add_argument(
        "--min-overlap",
        type=float,
        default=DEFAULT_MIN_OVERLAP,
        metavar="RATIO",
        help=f"Recouvrement temporel minimal, en fraction de la plus courte capture (defaut {DEFAULT_MIN_OVERLAP}).",
    )
    ap.add_argument(
        "--min-common-ips",
        type=int,
        default=DEFAULT_MIN_COMMON_IPS,
        metavar="N",
        help=f"Nombre minimal d'IP communes hors infrastructure (defaut {DEFAULT_MIN_COMMON_IPS}).",
    )
    ap.add_argument(
        "--jobs",
        type=int,
        default=1,
        metavar="N",
        help="Captures inventoriees en parallele (defaut 1 : le decodage est deja parallelise en interne, "
        "empiler les deux niveaux sur un gros lot sature la memoire -- voir #283).",
    )
    ap.add_argument(
        "--skip-existing",
        action="store_true",
        help="Reprise d'un lot interrompu : reutilise les inventaires en cache et les rapports deja ecrits.",
    )
    ap.add_argument("--security-report", action="store_true", help="Ajoute l'analyse de securite a chaque rapport.")
    add_debug_argument(ap)
    args = ap.parse_args(argv)
    apply_debug_argument(args)

    if not os.path.isdir(args.input):
        print(f"--input : dossier introuvable : {args.input}", file=sys.stderr)
        sys.exit(1)
    if args.jobs < 1:
        print("--jobs doit etre >= 1.", file=sys.stderr)
        sys.exit(1)
    if not 0.0 < args.min_overlap <= 1.0:
        print("--min-overlap doit etre dans ]0, 1].", file=sys.stderr)
        sys.exit(1)
    if args.min_common_ips < 1:
        print("--min-common-ips doit etre >= 1.", file=sys.stderr)
        sys.exit(1)
    if args.group_window < 0:
        print("--group-window doit etre >= 0.", file=sys.stderr)
        sys.exit(1)

    captures, ignored = list_captures(args.input, args.recursive)
    if not captures:
        print(f"Aucune capture ({', '.join(CAPTURE_EXTENSIONS)}) dans {args.input}.", file=sys.stderr)
        sys.exit(1)
    os.makedirs(args.output, exist_ok=True)
    labels = make_labels(captures)

    print(f"Inventaire de {len(captures)} capture(s)...")
    inventories = collect_inventories(captures, labels, args.output, args.jobs, args.skip_existing)
    plan = plan_batch(
        inventories,
        group=not args.no_group,
        min_overlap=args.min_overlap,
        min_common_ips=args.min_common_ips,
        group_window=args.group_window,
    )
    print("Analyses...")
    group_reports, capture_reports, summaries, errors = run_analyses(
        plan, args.output, args.security_report, args.skip_existing
    )
    synthesis = build_synthesis(plan, summaries, errors, ignored, args.security_report)
    index = format_batch_index(
        plan, args.input, group_reports=group_reports, capture_reports=capture_reports, synthesis=synthesis
    )
    index_path = os.path.join(args.output, "index.txt")
    with open(index_path, "w", encoding="utf-8") as fh:
        fh.write(index)
    print()
    print(index, end="")
    print(f"\nIndex du lot ecrit dans {index_path}")
    if plan.failures or errors:
        sys.exit(2)


if __name__ == "__main__":
    main()
