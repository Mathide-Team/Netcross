"""Moteur du mode lot (issues #277, #872), commun à la CLI
(``cross_capture_batch_cli.py``), à l'API (``POST /batches``) et à la GUI.

Déroulement :

1. inventaire : chaque capture est décodée une fois pour en extraire la
   fenêtre temporelle, les IP et les conversations (netcross_core.batch) ;
   une capture illisible n'arrête PAS le lot, elle est listée en échec avec
   son motif ;
2. regroupement conservateur (trois critères, tous requis -- voir
   netcross_core.batch) avec justification écrite de chaque décision ;
3. un rapport par capture, un rapport croisé par groupe ;
4. un index de lot (index.txt) : groupes + justification, captures isolées
   + motif, échecs + motif, synthèse.

L'avancement passe par ``progress`` (``print`` par défaut, comme la CLI) :
l'API le conserve dans l'état du lot, la GUI l'affiche.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from collections.abc import Callable, Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field

from netcross_core import analyse, correlate, parse_capture, print_report
from netcross_core.batch import (
    DEFAULT_GROUP_WINDOW,
    DEFAULT_MIN_COMMON_IPS,
    DEFAULT_MIN_OVERLAP,
    BatchPlan,
    CaptureInventory,
    format_batch_index,
    inventory_from_packets,
    justify,
    plan_batch,
)
from netcross_core.logging_config import get_logger, summarize
from netcross_core.security import findings as security_findings
from netcross_report.security_report import build_security_report, print_security_report

logger = get_logger(__name__)

CAPTURE_EXTENSIONS = (".pcap", ".pcapng", ".cap", ".erf", ".pcap.gz", ".pcapng.gz")
CACHE_DIR = ".netcross-batch"
SERIOUS_SEVERITIES = ("critique", "elevee")

Progress = Callable[[str], None]


def list_captures(folder: str, recursive: bool = False) -> tuple[list[str], list[str]]:
    """Renvoie (captures, ignores) tries par chemin. Les fichiers ignores
    (extension non reconnue) sont remontes pour etre cites dans l'index :
    rien ne disparait sans trace."""
    logger.debug(
        "list_captures: folder={} recursive={}",
        summarize(folder, "folder"),
        summarize(recursive, "recursive"),
    )
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
    logger.debug("list_captures: retour tuple de 2")
    return sorted(captures), sorted(ignored)


def make_labels(paths: list[str]) -> dict[str, str]:
    """Etiquette lisible et unique par capture (nom de fichier sans
    extension, suffixe _2, _3... en cas de collision)."""
    logger.debug("make_labels: paths={}", summarize(paths, "paths"))
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
    logger.debug("make_labels: retour labels={}", summarize(labels, "labels"))
    return labels


def build_inventory(label: str, path: str) -> CaptureInventory:
    """Decode une capture et en extrait l'inventaire. Ne leve jamais : une
    erreur devient CaptureInventory.error (motif cite dans l'index)."""
    try:
        packets = parse_capture(label, path, raise_on_error=True)
    except Exception as exc:  # noqa: BLE001 -- une capture illisible ne doit pas arreter le lot
        logger.exception(f"échec dans build_inventory: {exc}")
        msg = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        logger.debug("build_inventory: except Exception -> retour CaptureInventory(…)")
        return CaptureInventory(label=label, path=path, error=msg[:200])
    logger.debug("build_inventory: retour inventory_from_packets(…)")
    return inventory_from_packets(label, path, packets)


def _cache_path(output: str, label: str) -> str:
    logger.debug("_cache_path: retour os.path.join(…)")
    return os.path.join(output, CACHE_DIR, "inventaire", f"{label}.json")


def _fingerprint(path: str) -> list:
    st = os.stat(path)
    logger.debug("_fingerprint: retour liste")
    return [st.st_size, int(st.st_mtime)]


def load_cached_inventory(output: str, label: str, path: str) -> CaptureInventory | None:
    cache = _cache_path(output, label)
    try:
        with open(cache, encoding="utf-8") as fh:
            data = json.load(fh)
        if data.get("fingerprint") != _fingerprint(path) or data["inventory"]["path"] != path:
            logger.debug(
                "load_cached_inventory: si data.get('fingerprint') != _fingerprint(path) or data['inve… -> retour None"
            )
            return None
        logger.debug("load_cached_inventory: retour CaptureInventory.from_dict(…)")
        return CaptureInventory.from_dict(data["inventory"])
    except (OSError, ValueError, KeyError, TypeError):
        logger.exception("échec dans load_cached_inventory")
        logger.debug("load_cached_inventory: except (OSError, ValueError, KeyError, TypeErr… -> retour None")
        return None


def save_cached_inventory(output: str, inv: CaptureInventory) -> None:
    logger.debug("save_cached_inventory: output={} inv={}", summarize(output, "output"), summarize(inv, "inv"))
    cache = _cache_path(output, inv.label)
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    with open(cache, "w", encoding="utf-8") as fh:
        json.dump({"fingerprint": _fingerprint(inv.path), "inventory": inv.to_dict()}, fh)
    logger.debug("save_cached_inventory: fin")


def collect_inventories(
    paths, labels, output, jobs=1, skip_existing=False, progress: Progress = print
) -> list[CaptureInventory]:
    logger.debug(
        "collect_inventories: paths={} labels={} output={} jobs={} skip_existing={}",
        summarize(paths, "paths"),
        summarize(labels, "labels"),
        summarize(output, "output"),
        summarize(jobs, "jobs"),
        summarize(skip_existing, "skip_existing"),
    )
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
        progress(
            f"  inventaire {inv.label} : {'ECHEC -- ' + inv.error if inv.error else f'{inv.packet_count} paquet(s)'}"
        )
        if inv.error is None:
            save_cached_inventory(output, inv)
    logger.debug("collect_inventories: retour liste")
    return [results[p] for p in paths]


def analyse_and_write(members: list[CaptureInventory], out_path: str, security: bool) -> dict:
    """Analyse (croisee si plusieurs membres) et ecrit le rapport texte.
    Renvoie un resume pour la synthese : {"findings": {severite: n}}."""
    logger.debug(
        "analyse_and_write: members={} out_path={} security={}",
        summarize(members, "members"),
        summarize(out_path, "out_path"),
        summarize(security, "security"),
    )
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
    logger.debug("analyse_and_write: retour dictionnaire")
    return {"findings": counts}


def run_analyses(plan: BatchPlan, output: str, security: bool, skip_existing: bool, progress: Progress = print):
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
            progress(f"  {name} : deja present, conserve (--skip-existing)")
            continue
        try:
            summaries[key] = analyse_and_write(members, out_path, security)
            progress(f"  {name} : ecrit")
        except Exception as exc:  # noqa: BLE001 -- une analyse en echec ne doit pas arreter le lot
            logger.exception("analyse %s en echec", key)
            errors.append(f"analyse {key} en echec : {exc}")
            progress(f"  {name} : ECHEC -- {exc}")
    logger.debug("run_analyses: retour tuple de 4")
    return group_reports, capture_reports, summaries, errors


def build_synthesis(plan, summaries, errors, ignored, security) -> list[str]:
    logger.debug(
        "build_synthesis: plan={} summaries={} errors={} ignored={} security={}",
        summarize(plan, "plan"),
        summarize(summaries, "summaries"),
        summarize(errors, "errors"),
        summarize(ignored, "ignored"),
        summarize(security, "security"),
    )
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
    logger.debug("build_synthesis: retour lines={}", summarize(lines, "lines"))
    return lines


@dataclass(frozen=True)
class BatchOptions:
    """Réglages d'un lot, miroir des options de ``cross_capture_batch_cli``."""

    recursive: bool = False
    group: bool = True
    group_window: float = DEFAULT_GROUP_WINDOW
    min_overlap: float = DEFAULT_MIN_OVERLAP
    min_common_ips: int = DEFAULT_MIN_COMMON_IPS
    jobs: int = 1
    skip_existing: bool = False
    security_report: bool = False


def check_options(options: BatchOptions) -> str | None:
    """Motif de refus (même texte que la CLI) ou None si les réglages sont valides."""
    if options.jobs < 1:
        return "--jobs doit etre >= 1."
    if not 0.0 < options.min_overlap <= 1.0:
        return "--min-overlap doit etre dans ]0, 1]."
    if options.min_common_ips < 1:
        return "--min-common-ips doit etre >= 1."
    if options.group_window < 0:
        return "--group-window doit etre >= 0."
    return None


@dataclass
class BatchResult:
    """Résultat d'un lot : index texte et éléments structurés pour l'API."""

    plan: BatchPlan
    index: str
    index_path: str
    group_reports: dict[int, str]
    capture_reports: dict[str, str]
    summaries: dict[str, dict]
    errors: list[str]
    ignored: list[str]
    synthesis: list[str] = field(default_factory=list)

    @property
    def has_failures(self) -> bool:
        return bool(self.plan.failures or self.errors)

    def to_dict(self) -> dict:
        """Vue JSON (API) : groupes, isolées, échecs, rapports et synthèse."""
        groups = []
        for idx, grp in enumerate(self.plan.groups, start=1):
            groups.append(
                {
                    "index": idx,
                    "members": grp.labels,
                    "report": self.group_reports.get(idx),
                    "justification": [justify(ev) for ev in grp.evaluations],
                }
            )
        isolated = [
            {
                "label": iso.capture.label,
                "reason": iso.reason,
                "report": self.capture_reports.get(iso.capture.label),
            }
            for iso in self.plan.isolated
        ]
        failures = [{"label": f.label, "error": f.error} for f in self.plan.failures]
        return {
            "groups": groups,
            "isolated": isolated,
            "failures": failures,
            "capture_reports": dict(self.capture_reports),
            "findings": {k: v["findings"] for k, v in self.summaries.items()},
            "errors": list(self.errors),
            "ignored": [os.path.basename(p) for p in self.ignored],
            "synthesis": list(self.synthesis),
        }


def run_batch(
    captures: list[str],
    ignored: list[str],
    output: str,
    options: BatchOptions,
    source: str,
    progress: Progress = print,
) -> BatchResult:
    """Lot complet sur ``captures`` (chemins déjà listés) : inventaire,
    regroupement, rapports, ``index.txt`` dans ``output``."""
    logger.debug(
        "run_batch: captures={} output={} options={}",
        summarize(captures, "captures"),
        summarize(output, "output"),
        summarize(options, "options"),
    )
    os.makedirs(output, exist_ok=True)
    labels = make_labels(captures)
    progress(f"Inventaire de {len(captures)} capture(s)...")
    inventories = collect_inventories(captures, labels, output, options.jobs, options.skip_existing, progress)
    plan = plan_batch(
        inventories,
        group=options.group,
        min_overlap=options.min_overlap,
        min_common_ips=options.min_common_ips,
        group_window=options.group_window,
    )
    progress("Analyses...")
    group_reports, capture_reports, summaries, errors = run_analyses(
        plan, output, options.security_report, options.skip_existing, progress
    )
    synthesis = build_synthesis(plan, summaries, errors, ignored, options.security_report)
    index = format_batch_index(
        plan, source, group_reports=group_reports, capture_reports=capture_reports, synthesis=synthesis
    )
    index_path = os.path.join(output, "index.txt")
    with open(index_path, "w", encoding="utf-8") as fh:
        fh.write(index)
    logger.debug("run_batch: retour BatchResult")
    return BatchResult(
        plan=plan,
        index=index,
        index_path=index_path,
        group_reports=group_reports,
        capture_reports=capture_reports,
        summaries=summaries,
        errors=errors,
        ignored=ignored,
        synthesis=synthesis,
    )
