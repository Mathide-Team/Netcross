#!/usr/bin/env python3
"""
cross_capture_analyzer_cli.py -- interface en ligne de commande pour
netcross_core. Le moteur d'analyse lui-meme (parsing, correlation,
analyse, mise en forme) vit dans le package netcross_core/ et ne depend
d'aucune interface : ce fichier ne fait que lire les arguments, appeler
le package, et afficher/ecrire le resultat.

Voir netcross_core/__init__.py pour l'utiliser comme bibliotheque
(comme le fait deja l'app GTK4 dans netcross_gtk4/, ou le generateur
de rapport PDF dans netcross_report/) plutot que depuis cette CLI.

Prerequis :
    - tshark installe (paquet systeme tshark / wireshark-cli, voir
      install.sh) -- utilise par pcap_parser pour decoder les captures,
      y compris pour --tls/--quic/--live
    - pour --live : declencher un vrai sniffing reseau demande soit de
      lancer cette CLI en root, soit d'avoir donne au binaire dumpcap
      les capacites CAP_NET_RAW/CAP_NET_ADMIN (setcap), soit d'etre
      dans le groupe systeme dedie si la distribution en fournit un
      (selon exactement le meme prerequis que pour l'app GTK4)
    - pip install cryptography --break-system-packages (necessaire
      uniquement pour --quic, pas pour cette CLI de base)
    - pip install reportlab matplotlib networkx --break-system-packages
      (necessaire uniquement pour --pdf-report)
    - --json-report n'a besoin de rien de plus (json/datetime sont dans
      la bibliotheque standard)
    - --merge n'a besoin que des outils livres avec tshark (mergecap,
      reordercap, et editcap pour --merge-dedup)
    - --replay necessite le paquet systeme 'tcpreplay' (apt install
      tcpreplay / dnf install tcpreplay), DISTINCT de tshark -- non
      installe par install.sh. ATTENTION : --replay EMET du trafic
      reseau REEL sur l'interface indiquee -- voir l'avertissement
      d'usage responsable dans pcap_parser.capture.replay_capture et
      dans l'aide de --replay ci-dessous avant tout usage en dehors
      d'un banc de test isole.

Exemple d'utilisation (fichiers deja captures) :
    python3 cross_capture_analyzer_cli.py \
        --capture LAN=capture_lan.pcapng \
        --capture WAN=capture_wan.pcapng \
        --capture DC=capture_datacenter.pcapng \
        --order LAN,WAN,DC \
        --bucket-ms 500 \
        --triage \
        --detail-csv details.csv

Exemple d'utilisation (capture en direct sur 2 interfaces, 60s max) :
    python3 cross_capture_analyzer_cli.py \
        --live LAN:eth0 \
        --live WAN:eth1:"tcp port 443" \
        --live-duration 60 \
        --order LAN,WAN \
        --triage

Exemple d'utilisation (decouper une capture volumineuse en segments plus
petits, par duree, nombre de paquets ou taille -- puis les analyser comme
un seul point continu ; --split ne lance PAS d'analyse) :
    python3 cross_capture_analyzer_cli.py \
        --capture LAN=capture_lan_10Go.pcapng \
        --split size:100M --split-output-dir segments
    python3 cross_capture_analyzer_cli.py \
        --capture "LAN=$(ls segments/LAN/*.pcapng | paste -sd, -)" \
        --triage

Exemple d'utilisation (comparaison client vs client -- "ce poste
fonctionne, pas l'autre", meme capture, memes points) :
    python3 cross_capture_analyzer_cli.py \
        --capture LAN=capture_lan.pcapng \
        --capture WAN=capture_wan.pcapng \
        --client-group PosteA=10.0.0.5 \
        --client-group PosteB=10.0.0.12,10.0.0.13 \
        --client-reference PosteA \
        --client-diff-csv client_diff.csv

Exemple d'utilisation (rapport anonymise pour partage externe -- voir
netcross_core.redact pour le detail et les limites de --redact) :
    python3 cross_capture_analyzer_cli.py \
        --capture LAN=capture_lan.pcapng \
        --capture WAN=capture_wan.pcapng \
        --redact --redact-map correspondance_privee.csv \
        --pdf-report rapport_a_partager.pdf

Exemple d'utilisation (historique inter-runs -- voir netcross_report.history
pour le detail ; le meme fichier .db peut etre reutilise a chaque controle
periodique du meme lien) :
    python3 cross_capture_analyzer_cli.py \
        --capture LAN=capture_lan.pcapng \
        --capture WAN=capture_wan.pcapng \
        --history-db suivi_site_a.db --history-label Site-A --history-show 10

Exemple d'utilisation (fusion de captures en UN seul fichier, ordonne par
timestamp de paquet, sans lancer d'analyse -- les noms de points de
--capture sont ignores, seuls les chemins comptent) :
    python3 cross_capture_analyzer_cli.py \
        --capture LAN=capture_lan.pcapng \
        --capture WAN=capture_wan.pcapng \
        --merge fusion.pcapng --merge-dedup

Exemple d'utilisation (rejeu d'une capture sur une interface reseau, sans
lancer d'analyse -- voir l'avertissement d'usage responsable ci-dessus et
dans l'aide de --replay ; a n'utiliser que sur un banc de test isole sauf
besoin explicite et maitrise d'un rejeu sur un segment reel) :
    python3 cross_capture_analyzer_cli.py \
        --capture LAB=capture_a_rejouer.pcapng \
        --replay eth0 --replay-speed 0.5 --replay-loop 3
"""

import argparse
import os
import re
import signal
import sys
import threading
import time
from datetime import datetime, timezone

from netcross_core import (
    adjust_timestamps,
    analyse,
    compare_clients,
    convert_capture,
    correlate,
    export_csv,
    export_filtered,
    export_json,
    merge_captures,
    parse_capture,
    parse_captures_parallel,
    parse_live,
    print_client_comparison,
    print_report,
    read_capture_comments,
    read_capture_infos,
    redact_packets,
    replay_capture,
    split_capture,
    write_client_diff_csv,
    write_detail_csv,
    write_redaction_map_csv,
)
from netcross_core.discovery import load_baseline_hosts
from netcross_core.flow_timeline import build_flow_timelines
from netcross_core.forensic import DEFAULT_DUPLICATE_THRESHOLD_MS, detect_cross_capture_duplicates
from netcross_core.logging_config import add_debug_argument, apply_debug_argument, get_logger
from netcross_core.security import close_db, connect_cve_db
from netcross_core.security import findings as security_findings
from netcross_core.security.cve_seed import open_seed_db
from netcross_core.support import (
    SCOPES as SUPPORT_SCOPES,
)
from netcross_core.support import (
    Consent,
    TextScrubber,
    build_ticket,
    install_crash_handler,
    write_support_map_csv,
    write_ticket,
)
from netcross_report.security_report import build_security_report, print_security_report
from pcap_parser.ek_source import TsharkError, TsharkNotFoundError
from pcap_parser.remote import CaptureSourceError, parse_source, split_live_target

logger = get_logger(__name__)


def _parse_live_spec(spec):
    """LABEL:INTERFACE[:FILTRE_BPF] -> (label, interface, bpf_ou_None).
    Un filtre BPF contenant lui-meme des ':' (adresse IPv6, par exemple)
    reste intact, seuls les 2 premiers ':' sont significatifs. INTERFACE
    peut etre une source distante (issue #166) : les ':' de son hote/port
    ne comptent pas -- voir pcap_parser.remote.split_live_target."""
    label, sep, rest = spec.partition(":")
    iface, bpf = split_live_target(rest) if sep else ("", None)
    if not label or not iface:
        print(
            f"Format invalide pour --live: {spec} (attendu LABEL:INTERFACE[:FILTRE_BPF], INTERFACE pouvant "
            "etre une source distante rpcap://, sshdump:// ou pipe://)",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        parse_source(iface)
    except CaptureSourceError as exc:
        logger.exception(f"échec dans _parse_live_spec: {exc}")
        print(f"Source invalide pour --live {label} : {exc}", file=sys.stderr)
        sys.exit(1)
    return label, iface, bpf or None


def _check_single_stdin(points):
    """Une seule source pipe://- (entree standard) par execution : deux
    lecteurs se partageraient les octets du meme flux pcap."""
    stdin_labels = [label for label, iface, _bpf in points if parse_source(iface).uses_stdin]
    if len(stdin_labels) > 1:
        print(
            f"Une seule source peut lire l'entree standard (pipe://-) : {', '.join(stdin_labels)}",
            file=sys.stderr,
        )
        sys.exit(1)


def _parse_client_group_spec(spec):
    """NOM=IP1[,IP2,...] -> (nom, {ip1, ip2, ...}). Une IP peut apparaitre
    dans plusieurs groupes (assume, non verifie ici -- voir
    netcross_core.client_diff.group_packets_by_client pour la consequence)."""
    if "=" not in spec:
        print(
            f"Format invalide pour --client-group: {spec} (attendu NOM=IP1[,IP2,...])",
            file=sys.stderr,
        )
        sys.exit(1)
    name, ips = spec.split("=", 1)
    ip_set = {ip.strip() for ip in ips.split(",") if ip.strip()}
    if not name or not ip_set:
        print(
            f"Format invalide pour --client-group: {spec} (attendu NOM=IP1[,IP2,...], nom et IP requis)",
            file=sys.stderr,
        )
        sys.exit(1)
    return name, ip_set


_SEARCH_FIELDS = ("sni", "uri", "http_status", "call_id", "dns_name", "method", "content_type", "message")


def _advanced_options_error(args) -> str | None:
    """Validation de --flow-timeline/--tshark-stats/--forensic-search et des
    --search-* AVANT l'analyse : une erreur detectee apres des minutes de
    parsing ferait perdre le run."""
    search = {
        "--search-text": args.search_text,
        "--search-address": args.search_address,
        "--search-point": args.search_point,
        "--search-protocol": args.search_protocol,
        "--search-port": args.search_port,
        "--search-field": args.search_field,
        "--search-value": args.search_value,
    }
    orphans = [flag for flag, value in search.items() if value is not None]
    if orphans and not args.forensic_search:
        return f"{', '.join(orphans)} necessite --forensic-search."
    if args.search_field is not None and args.search_field not in _SEARCH_FIELDS:
        return f"--search-field : champ inconnu {args.search_field!r} (attendu : {', '.join(_SEARCH_FIELDS)})."
    if args.search_port is not None and not 0 <= args.search_port <= 65535:
        return "--search-port doit etre compris entre 0 et 65535."
    if args.flow_timeline_window <= 0:
        return "--flow-timeline-window doit etre > 0."
    if args.tshark_stats and not args.capture:
        return "--tshark-stats relit les fichiers --capture avec tshark : sans objet en --live seul."
    return None


def _write_json_output(path, payload, label) -> None:
    import json

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f"{label} ecrite(s) dans {path}")


def _collect_tshark_stats(captures) -> dict:
    """Statistiques tshark -z par fichier (issue #361). Une capture en echec
    porte une cle `error` explicite (et un message stderr) au lieu de faire
    perdre les autres ; tshark absent est une erreur par capture elle aussi."""
    import subprocess
    from dataclasses import asdict

    from netcross_core.tshark_stats import (
        TsharkUnavailableError,
        collect_conversations,
        collect_endpoints,
        collect_io_stat,
        collect_protocol_hierarchy,
    )

    result: dict = {"version": 1, "captures": []}
    for label, path in captures:
        entry: dict = {"label": label, "path": path}
        try:
            entry["conversations"] = {
                proto: [asdict(c) for c in collect_conversations(path, proto)] for proto in ("tcp", "udp")
            }
            entry["endpoints"] = {
                proto: [asdict(e) for e in collect_endpoints(path, proto)] for proto in ("tcp", "udp")
            }
            entry["protocol_hierarchy"] = [asdict(p) for p in collect_protocol_hierarchy(path)]
            entry["io_stat"] = asdict(collect_io_stat(path))
        except (TsharkUnavailableError, subprocess.SubprocessError, OSError) as exc:
            entry = {"label": label, "path": path, "error": str(exc)}
            logger.warning("--tshark-stats {} ({}) : {}", label, path, exc)
            print(f"--tshark-stats {label} ({path}) : {exc}", file=sys.stderr)
        result["captures"].append(entry)
    return result


def _run_forensic_search(args, all_packets, flows) -> None:
    """Recherche forensique (issue #360) : la requete est rappelee dans le
    JSON pour qu'un resultat vide reste interpretable."""
    from dataclasses import asdict

    from netcross_core.forensic_search import ForensicSearchIndex, ForensicSearchQuery

    query = ForensicSearchQuery(
        text=args.search_text,
        point=args.search_point,
        protocol=args.search_protocol,
        address=args.search_address,
        port=args.search_port,
        field=args.search_field,
        field_value=args.search_value,
    )
    results = ForensicSearchIndex(all_packets, flows=flows).search(query)
    payload = {
        "version": 1,
        "query": {k: v for k, v in asdict(query).items() if v is not None},
        "count": len(results),
        "results": [asdict(r) for r in results],
    }
    _write_json_output(args.forensic_search, payload, f"Recherche forensique ({len(results)} resultat(s))")


def _run_netflow(args) -> int:
    """Mode --netflow (issue #362) : resume d'exports NetFlow v5, sans analyse
    multi-points. Code de retour : 0, ou 1 (options incompatibles, fichier
    illisible ou tronque)."""
    import json

    from netcross_core.netflow import (
        FlowRecord,
        NetflowV5Error,
        format_flow_summary,
        iter_netflow_v5_file,
        summarize_flow_records,
    )

    incompatible = [
        flag
        for flag, given in (
            ("--capture", args.capture),
            ("--live", args.live),
            ("--merge", args.merge),
            ("--pdf-report", args.pdf_report),
            ("--security-report", args.security_report),
            ("--triage", args.triage),
            ("--flow-timeline", args.flow_timeline),
            ("--tshark-stats", args.tshark_stats),
            ("--forensic-search", args.forensic_search),
        )
        if given
    ]
    if incompatible:
        print(
            f"--netflow resume des flux agreges, sans analyse de captures : incompatible avec "
            f"{', '.join(incompatible)}.",
            file=sys.stderr,
        )
        return 1
    if args.netflow_top < 1:
        print("--netflow-top doit etre >= 1.", file=sys.stderr)
        return 1
    records: list[FlowRecord] = []
    for spec in args.netflow:
        exporter, sep, path = spec.partition("=")
        if not sep:
            exporter, path = None, spec
        elif not exporter or not path:
            print(f"Format invalide pour --netflow: {spec} (attendu [EXPORTATEUR=]FICHIER)", file=sys.stderr)
            return 1
        try:
            records.extend(iter_netflow_v5_file(path, exporter=exporter))
        except (OSError, NetflowV5Error) as exc:
            logger.warning("--netflow {} : lecture impossible ({})", path, exc)
            print(f"--netflow {path} : {exc}", file=sys.stderr)
            return 1
    summary = summarize_flow_records(records, top=args.netflow_top)
    print("\n".join(format_flow_summary(summary)))
    if args.json_report:
        with open(args.json_report, "w", encoding="utf-8") as fh:
            json.dump({"netflow": summary}, fh, ensure_ascii=False, indent=2)
        print(f"\nRapport JSON ecrit : {args.json_report}")
    return 0


def _parse_capture_spec(spec, flag_name):
    """NOM=chemin1[,chemin2,...] -> (label, [chemin1, chemin2, ...]).

    Le cas courant (un seul chemin) reste NOM=chemin, inchange. La forme
    a plusieurs chemins sert a rejouer une capture segmentee (rotation
    tcpdump/tshark -b, ex: -C 100 -> capture_00000_x.pcap,
    capture_00001_x.pcap...) comme un seul point de capture continu,
    sans avoir a les fusionner au prealable (mergecap ou autre) : chaque
    chemin devient une entree (label, chemin) distincte dans la liste
    `captures` de main(), lue separement par tshark puis simplement
    concatenee -- exactement le mecanisme deja existant qui permettrait
    par ailleurs (non teste comme un vrai cas d'usage jusqu'ici) de
    fournir plusieurs fois le meme label avec des --capture separes.
    Aucun tri par timestamp n'est fait ici : les segments doivent etre
    listes par l'appelant dans l'ordre chronologique (ordre naturel
    d'une rotation tcpdump), les quelques analyses qui ont besoin d'un
    ordre strict par point (STP, timeout d'inactivite) trient deja
    explicitement en interne plutot que de faire confiance a l'ordre de
    all_packets -- voir netcross_core.analysis."""
    if "=" not in spec:
        print(
            f"Format invalide pour {flag_name}: {spec} (attendu NOM=chemin[,chemin2,...])",
            file=sys.stderr,
        )
        sys.exit(1)
    label, paths_str = spec.split("=", 1)
    paths = [p.strip() for p in paths_str.split(",")]
    if not label or not paths or any(not p for p in paths):
        print(
            f"Format invalide pour {flag_name}: {spec} (attendu NOM=chemin[,chemin2,...], "
            "nom et chemin(s) requis -- pas de segment vide, ex: virgule en trop)",
            file=sys.stderr,
        )
        sys.exit(1)
    return label, paths


def _run_merge(capture_specs, output_path, dedup):
    """--merge : fusionne tous les chemins des --capture en un seul fichier
    (voir pcap_parser.capture.merge_captures pour l'ordre, le format de
    sortie et la deduplication). Les NOM= des specs ne servent a rien ici
    -- une capture fusionnee perd la notion de point de capture, c'est
    pourquoi aucune analyse n'est lancee ensuite (l'appelant retourne)."""
    paths = []
    for spec in capture_specs:
        _label, spec_paths = _parse_capture_spec(spec, "--capture")
        paths.extend(spec_paths)
    try:
        merge_captures(paths, output_path, dedup=dedup)
    except (OSError, ValueError, RuntimeError) as e:
        # OSError : entree absente/illisible ; ValueError : entree == sortie ;
        # RuntimeError : parent de TsharkNotFoundError/TsharkError (outil
        # absent du PATH ou en echec) -- meme sortie propre que les autres
        # erreurs d'arguments de cette CLI plutot qu'une trace Python.
        logger.exception(f"échec dans _run_merge: {e}")
        print(f"--merge : {e}", file=sys.stderr)
        sys.exit(1)
    print(
        f"{len(paths)} fichier(s) fusionne(s) dans {output_path}"
        + (" (paquets identiques dedupliques)" if dedup else "")
        + "."
    )


def _run_convert(capture_specs, output_path, fmt):
    """--convert : convertit UN fichier de capture vers un autre format
    (pcap, pcapng, erf) ou exporte en CSV/JSON structure, puis s'arrete
    sans lancer d'analyse. Comme --merge/--split, ne lance aucune analyse."""
    if not capture_specs:
        print("--convert necessite --capture (fichier source).", file=sys.stderr)
        sys.exit(1)
    paths = []
    for spec in capture_specs:
        _label, spec_paths = _parse_capture_spec(spec, "--capture")
        paths.extend(spec_paths)
    if len(paths) != 1:
        print(
            f"--convert convertit UN fichier a la fois (recu {len(paths)} fichier(s) via --capture) -- "
            "fusionnez d'abord avec --merge si besoin.",
            file=sys.stderr,
        )
        sys.exit(1)
    path_in = paths[0]
    try:
        if fmt in ("csv", "json"):
            if fmt == "csv":
                export_csv(path_in, output_path)
            else:
                export_json(path_in, output_path)
        else:
            convert_capture(path_in, output_path, fmt=fmt)
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception(f"échec dans _run_convert: {e}")
        print(f"--convert : {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Converti {path_in} -> {output_path} (format: {fmt}).")


def _run_export(capture_specs, output_path, bpf_filter, time_start, time_end, endpoints):
    """--export-pcap : exporte un sous-ensemble filtre de la premiere
    capture vers un nouveau fichier. Comme --merge/--split, ne lance aucune
    analyse ensuite."""
    if not capture_specs:
        print("--export-pcap necessite --capture (fichier source).", file=sys.stderr)
        sys.exit(1)
    # Un seul fichier source : pour exporter plusieurs captures, les fusionner
    # d'abord avec --merge.
    if len(capture_specs) > 1:
        print(
            f"--export-pcap exporte UN fichier a la fois (recu {len(capture_specs)} spec(s) --capture) -- "
            "fusionnez d'abord avec --merge si besoin.",
            file=sys.stderr,
        )
        sys.exit(1)
    label, paths = _parse_capture_spec(capture_specs[0], "--capture")
    if len(paths) > 1:
        print(
            f"--export-pcap exporte UN fichier a la fois (recu {len(paths)} segments dans {label}) -- "
            "fusionnez d'abord avec --merge si besoin.",
            file=sys.stderr,
        )
        sys.exit(1)
    path = paths[0]
    try:
        export_filtered(
            path,
            output_path,
            bpf_filter=bpf_filter,
            time_start=time_start,
            time_end=time_end,
            endpoints=endpoints,
        )
    except (TsharkNotFoundError, TsharkError, FileNotFoundError, ValueError) as e:
        logger.exception(f"échec dans _run_export: {e}")
        print(f"--export-pcap : {e}", file=sys.stderr)
        sys.exit(1)
    print(f"{output_path} cree ({label}).")
    return 0


_SPLIT_DEFAULT_DIR = "captures_split"
_SIZE_RE = re.compile(r"(\d+(?:[.,]\d+)?)\s*([kmg])?[ob]?", re.IGNORECASE)
_SIZE_FACTORS = {None: 1, "k": 10**3, "m": 10**6, "g": 10**9}


def _parse_size(text):
    """ "100M" -> 100_000_000. Unites DECIMALES (k=10^3, M=10^6, G=10^9),
    comme `tcpdump -C` : `--split size:100M` correspond donc a `tcpdump -C
    100`. Suffixe optionnel o/b apres l'unite (100Mo, 100MB). None si le
    format n'est pas reconnu -- les unites binaires (MiB, Mio) sont
    volontairement refusees plutot que lues comme des unites decimales."""
    m = _SIZE_RE.fullmatch(text.strip())
    if not m:
        return None
    number, unit = m.groups()
    return int(float(number.replace(",", ".")) * _SIZE_FACTORS[unit.lower() if unit else None])


def _parse_split_spec(spec):
    """MODE:VALEUR -> (mode, valeur) pour pcap_parser.split_capture.
    time:60 (secondes, decimales admises) | count:10000 (paquets) |
    size:100M (octets, voir _parse_size)."""
    mode, sep, raw = spec.partition(":")
    mode = mode.strip().lower()
    raw = raw.strip()
    err = f"Format invalide pour --split: {spec} (attendu time:SECONDES, count:PAQUETS ou size:TAILLE, ex: size:100M)"
    if not sep or mode not in ("time", "count", "size") or not raw:
        print(err, file=sys.stderr)
        sys.exit(1)
    try:
        if mode == "time":
            value = float(raw.replace(",", "."))
        elif mode == "count":
            value = int(raw)
        else:
            value = _parse_size(raw)
    except ValueError:
        logger.exception("échec dans _parse_split_spec")
        value = None
    if value is None or value <= 0:
        hint = " (unites decimales k/M/G, ex: 100M ; MiB/Mio non supportes)" if mode == "size" else ""
        print(f"{err} -- la valeur doit etre un nombre > 0{hint}", file=sys.stderr)
        sys.exit(1)
    return mode, value


def _run_split(capture_specs, split_spec, output_dir):
    """Decoupe chaque fichier des --capture dans <output_dir>/<LABEL>/ et
    renvoie le code de sortie (0 si tout a reussi, 1 sinon). Un fichier en
    echec est rapporte explicitement puis les suivants sont traites quand
    meme (meme choix que --parallel : rien ne passe sous silence, mais un
    fichier illisible n'empeche pas de decouper les autres)."""
    mode, value = _parse_split_spec(split_spec)
    status = 0
    for spec in capture_specs:
        label, paths = _parse_capture_spec(spec, "--capture")
        # le label sert de nom de sous-repertoire : on neutralise les
        # separateurs de chemin et les points de tete (jamais de "..")
        label_dir = os.path.join(output_dir, re.sub(r"[^\w.-]+", "_", label).lstrip(".") or "capture")
        segments = []
        # OSError : capture absente / sortie deja occupee ; ValueError : mode ou format
        # invalide ; RuntimeError : parent de TsharkNotFoundError/TsharkError (editcap
        # absent ou en echec) -- meme convention que --merge.
        try:
            for path in paths:
                segments.extend(split_capture(path, label_dir, mode, value))
        except (ValueError, OSError, RuntimeError) as e:
            logger.exception(f"échec dans _run_split: {e}")
            print(f"[{label}] ECHEC du decoupage : {e}", file=sys.stderr)
            status = 1
            continue
        if not segments:
            print(f"[{label}] aucun paquet a decouper dans {', '.join(paths)} -- aucun segment cree.")
            continue
        print(f"[{label}] {len(segments)} segment(s) dans {label_dir} :")
        for seg in segments[:3]:
            print(f"  {seg}")
        if len(segments) > 3:
            print(f"  ... ({len(segments) - 3} autre(s))")
        ext = os.path.splitext(segments[0])[1]
        print(f'  Pour les analyser comme un seul point : --capture "{label}=$(ls {label_dir}/*{ext} | paste -sd, -)"')
    return status


def _run_adjust_time(capture_specs, output_path, offset, normalize, align_to):
    """--adjust-time : ajuste les timestamps d'une capture (decalage fixe,
    normalisation ou alignement sur une autre capture). Comme --merge/--split,
    ne lance aucune analyse ensuite."""
    if not capture_specs:
        print("--adjust-time necessite --capture (fichier source).", file=sys.stderr)
        sys.exit(1)
    if len(capture_specs) > 1:
        print(
            f"--adjust-time ajuste UN fichier a la fois (recu {len(capture_specs)} spec(s) --capture).",
            file=sys.stderr,
        )
        sys.exit(1)
    label, paths = _parse_capture_spec(capture_specs[0], "--capture")
    if len(paths) > 1:
        print(
            f"--adjust-time ajuste UN fichier a la fois (recu {len(paths)} segments dans {label}).",
            file=sys.stderr,
        )
        sys.exit(1)
    path = paths[0]
    try:
        adjust_timestamps(
            path,
            output_path,
            offset_seconds=offset,
            normalize=normalize,
            align_to=align_to,
        )
    except (TsharkNotFoundError, TsharkError, FileNotFoundError, ValueError) as e:
        logger.exception(f"échec dans _run_adjust_time: {e}")
        print(f"--adjust-time : {e}", file=sys.stderr)
        sys.exit(1)
    print(f"{output_path} cree ({label}).")
    return 0


def _run_replay(capture_specs, interface, speed, loop):
    """--replay : rejoue UNE capture sur une interface reseau via tcpreplay
    (voir pcap_parser.capture.replay_capture pour l'avertissement d'usage
    responsable, la semantique de speed/loop et les exceptions levees).
    Comme --merge/--split, ne lance aucune analyse ensuite. Contrairement
    a --merge/--split, un seul fichier est accepte : rejouer plusieurs
    fichiers a la fois n'a pas de sens pour tcpreplay (un seul flux emis,
    un seul ordre de paquets possible) -- fusionner d'abord avec --merge
    si plusieurs segments doivent etre rejoues comme un seul flux continu."""
    paths = []
    for spec in capture_specs:
        _label, spec_paths = _parse_capture_spec(spec, "--capture")
        paths.extend(spec_paths)
    if len(paths) != 1:
        print(
            f"--replay necessite exactement un fichier de capture (recu {len(paths)} via --capture) -- "
            "fusionnez d'abord plusieurs segments avec --merge si besoin.",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        replay_capture(paths[0], interface, speed=speed, loop=loop)
    except (OSError, ValueError, RuntimeError) as e:
        # OSError : fichier introuvable ; ValueError : speed/loop invalides ;
        # RuntimeError : parent de TcpreplayNotFoundError/TcpreplayError
        # (tcpreplay absent du PATH ou en echec) -- meme sortie propre que
        # --merge/--split plutot qu'une trace Python.
        logger.exception(f"échec dans _run_replay: {e}")
        print(f"--replay : {e}", file=sys.stderr)
        sys.exit(1)
    print(f"{paths[0]} rejoue sur {interface} (speed={speed}, loop={loop}).")


def _run_live_captures(live_specs, duration, reporter=None):
    """Capture en direct sur un ou plusieurs points simultanement (un thread
    par point, comme l'interface graphique -- voir netcross_gtk4.app
    _begin_live_capture/_live_capture_worker) jusqu'a Ctrl+C ou
    --live-duration. Renvoie la liste de tous les paquets accumules.

    Un point en erreur (tshark absent, interface invalide, permission...)
    n'arrete pas les autres points : meme choix assume que sur la GUI,
    ou seul l'utilisateur (ou la duree max) met fin a la session complete.

    ``reporter`` (issue #274, --live-report) : LiveReporter alimente paquet
    par paquet et publie a intervalle regulier pendant la capture."""
    points = [_parse_live_spec(s) for s in live_specs]
    _check_single_stdin(points)
    stop_event = threading.Event()
    packets_by_point = {label: [] for label, _iface, _bpf in points}
    lock = threading.Lock()

    def _worker(label, iface, bpf):
        count = 0
        last_log = time.monotonic()
        try:
            for pkt in parse_live(label, iface, bpf_filter=bpf, stop_event=stop_event):
                with lock:
                    packets_by_point[label].append(pkt)
                if reporter is not None:
                    reporter.add(pkt)
                count += 1
                now = time.monotonic()
                if now - last_log >= 2.0:
                    print(f"[{label}] {count} paquets...")
                    last_log = now
        except Exception as e:  # noqa: BLE001 -- thread de fond : une erreur sur
            # ce point doit etre rapportee sans arreter les autres points en cours.
            logger.exception(f"échec dans _worker: {e}")
            print(f"[{label}] ERREUR : {e}", file=sys.stderr)
            if reporter is not None:
                reporter.aggregator.set_status(label, "erreur", str(e))
        else:
            if reporter is not None:
                reporter.aggregator.set_status(label, "arrete")
        print(f"[{label}] capture arretee -- {count} paquet(s) au total.")

    def _on_sigint(_signum, _frame):
        print(
            "\nArret demande (Ctrl+C) -- fin de la capture en cours sur tous les points...",
            file=sys.stderr,
        )
        stop_event.set()

    def _on_duration_elapsed():
        print(
            f"\nDuree maximale ({duration}s) atteinte -- arret de la capture.",
            file=sys.stderr,
        )
        stop_event.set()

    old_handler = signal.signal(signal.SIGINT, _on_sigint)
    for label, iface, bpf in points:
        print(
            f"[{label}] capture demarree sur {iface}"
            + (f" (filtre BPF: {bpf})" if bpf else "")
            + "... (Ctrl+C pour arreter)"
        )
    threads = [threading.Thread(target=_worker, args=(label, iface, bpf), daemon=True) for label, iface, bpf in points]
    if reporter is not None:
        for label, _iface, _bpf in points:
            reporter.aggregator.register(label)
        reporter.start()
    for t in threads:
        t.start()

    timer = None
    if duration:
        timer = threading.Timer(duration, _on_duration_elapsed)
        timer.daemon = True
        timer.start()

    try:
        for t in threads:
            t.join()
    finally:
        if timer:
            timer.cancel()
        signal.signal(signal.SIGINT, old_handler)
        if reporter is not None:
            reporter.stop()

    all_packets = []
    for label, _iface, _bpf in points:
        all_packets.extend(packets_by_point[label])
    return all_packets


def _build_support_consent(args) -> Consent:
    """Traduit les drapeaux --support-* en un objet Consent (issue #269).

    Sort en erreur si --support-ticket est demande sans --support-consent :
    mieux vaut un refus bruyant en debut de run qu'un ticket silencieusement
    non ecrit a la fin, apres une analyse de plusieurs minutes.
    """
    if not args.support_ticket:
        if args.support_consent or args.support_scope or args.support_map or args.support_marker:
            print(
                "--support-consent/--support-scope/--support-map/--support-marker necessitent --support-ticket.",
                file=sys.stderr,
            )
            sys.exit(1)
        return Consent(granted=False)

    if not args.support_consent:
        print(
            "--support-ticket necessite --support-consent : la remontee d'un ticket "
            "exige une autorisation explicite (issue #269). Le ticket est anonymise "
            "(voir netcross_core.support.scrubber) mais reste votre decision.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.support_map and not args.support_ticket:
        print("--support-map necessite --support-ticket.", file=sys.stderr)
        sys.exit(1)

    scopes = SUPPORT_SCOPES
    if args.support_scope:
        demandees = tuple(s.strip() for s in args.support_scope.split(",") if s.strip())
        inconnues = [s for s in demandees if s not in SUPPORT_SCOPES]
        if inconnues:
            print(
                f"--support-scope : portee(s) inconnue(s) {', '.join(inconnues)} "
                f"(attendu parmi : {', '.join(SUPPORT_SCOPES)}).",
                file=sys.stderr,
            )
            sys.exit(1)
        scopes = demandees

    return Consent(
        granted=True,
        scopes=scopes,
        granted_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        source="cli",
    )


def _parse_support_markers(specs) -> dict[str, str]:
    """``["trace_id=T-042"]`` -> ``{"trace_id": "T-042"}``."""
    markers: dict[str, str] = {}
    for spec in specs or []:
        if "=" not in spec:
            print(
                f"--support-marker : format attendu CLE=VALEUR, recu {spec!r}.",
                file=sys.stderr,
            )
            sys.exit(1)
        cle, valeur = spec.split("=", 1)
        markers[cle.strip()] = valeur.strip()
    return markers


# -- estimation memoire / avertissement avant analyse (issue #283, Etape 2) -
#
# Ordre de grandeur retenu pour l'octet-par-paquet en memoire de travail,
# base sur scripts/bench_memory.py (voir la courbe consignee dans l'issue
# #283) : un Pkt (dataclass a slots, ~25 champs scalaires) plus les
# structures accumulees par correlate()/analyse() (flux, historiques de
# latence/hop_delta, index de correlation...) qui, elles, croissent avec le
# nombre de paquets et pas seulement avec leur taille sur le fil -- d'ou une
# estimation basee sur le NOMBRE de paquets (capinfos "Number of packets"),
# pas sur la taille du fichier (un fichier de 4 Go avec des trames courtes
# comporte largement plus de paquets, donc plus de memoire de travail,
# qu'un fichier de 4 Go avec des trames pleines). Volontairement
# conservateur (arrondi au superieur) : une estimation trop basse laisserait
# l'OOM-killer faire le travail que cette fonction doit eviter.
_ESTIMATED_BYTES_PER_PACKET = 350


def _format_go(n_bytes: float) -> str:
    """``4_200_000_000`` -> ``"4.2 Go"`` (Go decimal = 10**9, comme le
    reste de ce fichier pour les tailles de fichier -- voir _parse_size)."""
    return f"{n_bytes / 1_000_000_000:.1f} Go"


def _format_paquets(n: int) -> str:
    """``18300000`` -> ``"18,3 M paquets"`` (arrondi au dixieme de
    million, lisible dans un avertissement -- pas une valeur exacte)."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} M paquets".replace(".", ",")
    return f"{n} paquets"


def _available_memory_bytes() -> int | None:
    """Memoire disponible en octets, ou None si indeterminable.

    Lit /proc/meminfo ("MemAvailable", present depuis Linux 3.14 -- estime
    par le noyau lui-meme la memoire reellement recuperable pour une
    nouvelle allocation, cache/buffers inclus, contrairement a "MemFree"
    qui sous-estime largement sur une machine dont le cache disque est
    charge) plutot qu'un paquet tiers (psutil, absent des dependances de ce
    projet -- voir pyproject.toml) : suffisant sur Linux, seule plateforme
    visee par install.sh. Aucune exception ne remonte : une plateforme sans
    /proc/meminfo (autre qu'Linux) degrade simplement vers "indeterminable",
    l'avertissement est alors omis plutot que de bloquer l'analyse."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    # Format : "MemAvailable:    3145728 kB"
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1]) * 1024
    except (OSError, ValueError):
        logger.exception("échec dans _available_memory_bytes")
        return None
    return None


def _estimate_memory_bytes(packet_count: int) -> int:
    """Memoire de travail estimee pour analyser ``packet_count`` paquets --
    voir _ESTIMATED_BYTES_PER_PACKET pour la justification de la constante.
    Multiplie par 4 : all_packets, flows/conversations (correlate()) et les
    accumulateurs de Report (analyse()) coexistent tous en memoire en meme
    temps sur le chemin actuel (pas de flux, voir Etape 4 de l'issue #283
    -- non traitee par cette PR), plus une marge pour le tas Python
    lui-meme (fragmentation, objets intermediaires de tshark -T ek)."""
    return packet_count * _ESTIMATED_BYTES_PER_PACKET * 4


def _memory_warning(label: str, file_size: int, packet_count: int) -> str | None:
    """Avertissement memoire pour UN point de capture (POINT_A dans
    l'exemple de l'issue #283), ou None si la memoire disponible n'a pas pu
    etre determinee ou si l'estimation ne depasse pas le disponible --
    aucune raison d'avertir dans ce cas, meme discipline que
    read_capture_comment (silence plutot que faux positif)."""
    available = _available_memory_bytes()
    if available is None:
        return None
    estimated = _estimate_memory_bytes(packet_count)
    if estimated <= available:
        return None
    return (
        f"{label} : {_format_go(file_size)}, {_format_paquets(packet_count)} -> environ "
        f"{_format_go(estimated)} de memoire estimes, {_format_go(available)} disponibles. "
        "Analyse complete probablement impossible. Utiliser --max-packets, --sample ou --stream."
    )


def _check_memory_before_analysis(captures) -> None:
    """Imprime sur stderr un avertissement memoire (voir _memory_warning)
    pour chaque fichier de ``captures`` (paires (label, path)) dont la
    metadonnee capinfos est lisible et dont l'estimation depasse la
    memoire disponible. N'interrompt jamais l'analyse (comme le reste des
    metadonnees capinfos dans ce fichier) : avertir, pas bloquer -- a
    l'analyste de decider (--max-packets/--sample/Ctrl+C), voir issue
    #283 Etape 2 : "un outil qui annonce sa limite est utilisable"."""
    from pcap_parser.capinfos_source import read_capture_info

    for label, path in captures:
        info = read_capture_info(path)
        if info is None or info.packet_count is None:
            # capinfos absent, fichier illisible, ou format sans compteur
            # fiable (pcap classique tronque...) : pas d'estimation possible,
            # meme tolerance silencieuse que read_capture_comment/
            # read_capture_info eux-memes.
            continue
        if info.file_size is not None:
            file_size = info.file_size
        elif os.path.isfile(path):
            file_size = os.path.getsize(path)
        else:
            file_size = 0
        warning = _memory_warning(label, file_size, info.packet_count)
        if warning:
            print(f"\nATTENTION memoire -- {warning}", file=sys.stderr)


def _parse_sample_spec(spec: str) -> int:
    """``"1/50"`` -> ``50`` (garder 1 paquet sur 50). Rejette toute autre
    forme (0, negatif, denominateur manquant) : une valeur invalide ici
    tronquerait silencieusement l'analyse sans que l'utilisateur s'en
    rende compte, inacceptable pour la meme raison que la troncature
    elle-meme doit toujours etre annoncee (voir Report.truncation_note)."""
    m = re.fullmatch(r"1\s*/\s*(\d+)", spec.strip())
    if not m or int(m.group(1)) <= 0:
        print(
            f"--sample : format attendu 1/N avec N entier > 0, recu {spec!r} (ex: --sample 1/50).",
            file=sys.stderr,
        )
        sys.exit(1)
    return int(m.group(1))


def _apply_packet_limits(all_packets, max_packets, sample_n):
    """Applique --max-packets/--sample (issue #283, Etape 3) a la liste de
    paquets DEJA CHARGEE (tous les fichiers de --capture sont toujours lus
    integralement par parse_capture -- limiter la LECTURE elle-meme est le
    travail de l'Etape 4/traitement en flux, hors perimetre de cette PR) et
    renvoie ``(paquets_retenus, note_ou_None)``. --sample est applique
    AVANT --max-packets quand les deux sont fournis ensemble (echantillonner
    puis plafonner le resultat) : l'ordre inverse laisserait --sample sans
    effet visible si --max-packets est plus restrictif. ``note`` vaut None
    si aucune limite n'a reellement tronque quoi que ce soit (fichier plus
    petit que la limite demandee) -- Report.truncated ne doit jamais
    devenir True sans raison, meme discipline que duplicates_excluded."""
    total = len(all_packets)
    kept = all_packets
    notes = []
    if sample_n and sample_n > 1:
        kept = kept[::sample_n]
        notes.append(f"echantillonnage 1 paquet sur {sample_n} ({len(kept)} retenus sur {total})")
    if max_packets is not None and len(kept) > max_packets:
        before = len(kept)
        kept = kept[:max_packets]
        notes.append(f"analyse limitee aux {max_packets:,} premiers paquets sur {before:,}".replace(",", " "))
    if not notes:
        return kept, None
    return kept, "analyse tronquee -- " + " ; ".join(notes) + " -- les constats ne couvrent pas la capture entiere."


def _send_notifications(args, report, security_report_obj) -> list[dict]:
    """Notifications sortantes (issue #280). Ne leve jamais : un canal en
    echec est une ligne de tracabilite du rapport, pas un echec d'analyse."""
    from pathlib import Path

    from netcross_core.config import load_config
    from netcross_core.notify import build_summary, run_notifications

    dash = security_report_obj.dashboard
    report_path = args.security_html or args.json_report or args.pdf_report
    results = run_notifications(
        lambda threshold: build_summary(
            report.security_findings or [],
            score=dash.score,
            level=dash.level,
            threshold=threshold,
            report_path=os.path.abspath(report_path) if report_path else None,
            detail=args.notify_detail,
        ),
        threshold=args.notify_on,
        cfg=load_config().notify,
        webhook=args.notify_webhook,
        slack=args.notify_slack,
        email_to=args.notify_email,
        state_path=Path(args.notify_state) if args.notify_state else None,
        silence_hours=args.notify_silence,
    )
    return [res.to_dict() for res in results]


def _list_plugins(authorized: list[str], plugin_paths: list[str]) -> int:
    """--list-plugins : installes ET locaux, en disant lesquels sont
    autorises -- un plugin installe n'est pas un plugin autorise."""
    from netcross_core.plugins import list_plugins

    rows = list_plugins(authorized, plugin_paths)
    if not rows:
        print("Aucun plugin installe (entry points netcross.detectors / netcross.exporters) ni --plugin-path.")
        return 0
    print(f"{'NOM':<24} {'TYPE':<10} {'AUTORISE':<9} ORIGINE")
    for row in rows:
        allowed = "oui" if row["authorized"] else "non"
        print(f"{row['name']:<24} {row['kind']:<10} {allowed:<9} {row['origin']}")
        if row["error"]:
            print(f"  !! {row['error']}")
    unknown = [n for n in authorized if n not in {r["name"] for r in rows}]
    if unknown:
        print(f"Demande(s) dans --plugins mais introuvable(s) : {', '.join(unknown)}")
    return 0


def _parse_plugin_exports(specs: list[str], authorized: list[str]) -> list[tuple[str, str]]:
    targets = []
    for spec in specs:
        name, sep, path = spec.partition("=")
        if not sep or not name.strip() or not path.strip():
            print(f"--plugin-export : format attendu NOM=FICHIER, recu {spec!r}.", file=sys.stderr)
            sys.exit(1)
        if name.strip() not in authorized:
            print(f"--plugin-export {name.strip()} : exporteur absent de --plugins.", file=sys.stderr)
            sys.exit(1)
        targets.append((name.strip(), path.strip()))
    return targets


def _check_extraction_args(args) -> tuple[str, ...]:
    """Validations de l'issue #278 ; renvoie les types a extraire."""
    from netcross_core.extract.contents import parse_kinds

    if args.extract_kinds and not args.extract_contents:
        print("--extract-kinds necessite --extract-contents.", file=sys.stderr)
        sys.exit(1)
    if not (args.media_quality or args.extract_contents):
        return ()
    if args.live:
        print(
            "--media-quality/--extract-contents relisent les fichiers passes a --capture : indisponibles avec --live.",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.redact and args.extract_contents:
        print(
            "--extract-contents est incompatible avec --redact : une voix, une video ou un document "
            "extrait ne peut pas etre anonymise, le combiner a un rapport anonymise serait trompeur.",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        kinds = parse_kinds(args.extract_kinds)
    except ValueError as exc:
        logger.exception(f"échec dans _check_extraction_args: {exc}")
        print(f"--extract-kinds : {exc}", file=sys.stderr)
        sys.exit(1)
    if args.extract_contents:
        out = args.extract_contents
        if os.path.exists(out) and (not os.path.isdir(out) or os.listdir(out)):
            print(
                f"--extract-contents : {out} existe deja et n'est pas un repertoire vide "
                "(une extraction par repertoire, pour un manifeste fidele).",
                file=sys.stderr,
            )
            sys.exit(1)
    return kinds


def _run_content_extraction(captures, out_dir, kinds) -> None:
    """Analyse qualitative / extraction des contenus (issue #278)."""
    from netcross_core.extract.contents import USAGE_REMINDER, format_extraction, run_extraction

    print("\n" + "=" * 70)
    print("CONTENUS AUDIO/VIDEO/DOCUMENTS (relit les memes fichiers)")
    print("=" * 70)
    if out_dir:
        print(USAGE_REMINDER, file=sys.stderr)
        logger.warning("extraction de contenus vers {} (types : {})", out_dir, ", ".join(kinds))
    result = run_extraction(captures, out_dir=out_dir, kinds=kinds if out_dir else ())
    for line in format_extraction(result):
        print(line)


def _check_live_report_args(args) -> None:
    """Validations de l'issue #274."""
    if (args.live_report_serve is not None or args.live_report_interval != 5.0) and not args.live_report:
        print("--live-report-interval/--live-report-serve necessitent --live-report.", file=sys.stderr)
        sys.exit(1)
    if not args.live_report:
        return
    if not args.live:
        print("--live-report necessite --live (pour une capture existante, --json-report suffit).", file=sys.stderr)
        sys.exit(1)
    if args.live_report_interval < 1:
        print("--live-report-interval : 1 seconde minimum.", file=sys.stderr)
        sys.exit(1)
    if args.live_report_serve is not None and not 1 <= args.live_report_serve <= 65535:
        print("--live-report-serve : port entre 1 et 65535.", file=sys.stderr)
        sys.exit(1)
    if os.path.exists(args.live_report) and not os.path.isdir(args.live_report):
        print(f"--live-report : {args.live_report} n'est pas un repertoire.", file=sys.stderr)
        sys.exit(1)


def _start_live_report(args):
    """(LiveReporter | None, serveur HTTP | None) pour --live-report."""
    if not args.live_report:
        return None, None
    from netcross_core.live_report import LiveReporter, LiveReportWriter
    from netcross_report.live_html import render_live_html

    writer = LiveReportWriter(args.live_report, render_live_html, args.live_report_interval)
    print(f"Rapport temps reel : {writer.html_path} (releve toutes les {args.live_report_interval:g} s)")
    server = None
    if args.live_report_serve is not None:
        import functools
        from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

        class _Quiet(SimpleHTTPRequestHandler):
            def log_message(self, format, *args):  # noqa: A002 -- signature imposee par http.server
                pass

        handler = functools.partial(_Quiet, directory=str(writer.out_dir))
        try:
            server = ThreadingHTTPServer(("127.0.0.1", args.live_report_serve), handler)
        except OSError as exc:
            logger.exception(f"échec dans log_message: {exc}")
            print(
                f"--live-report-serve : impossible d'ecouter sur le port {args.live_report_serve} ({exc}).",
                file=sys.stderr,
            )
            sys.exit(1)
        threading.Thread(target=server.serve_forever, name="netcross-live-http", daemon=True).start()
        print(f"Page servie sur http://127.0.0.1:{server.server_address[1]}/ (?mode=completive pour le journal)")
    return LiveReporter(writer), server


def _check_ai_args(args):
    """Validations de l'issue #146, AVANT l'analyse (echec immediat plutot
    qu'apres de longues minutes de lecture de capture)."""
    requested = (
        args.ai_baseline_save or args.ai_anomalies or args.ai_training_export or args.ai_classify or args.ai_summary
    )
    if not requested:
        if args.ai_report or args.ai_endpoint or args.ai_baseline_label:
            print(
                "--ai-report/--ai-endpoint/--ai-baseline-label necessitent une option --ai-* d'analyse.",
                file=sys.stderr,
            )
            sys.exit(1)
        return None
    from netcross_ai.optional import AIUnavailableError, require_ml
    from netcross_ai.pipeline import AIOptions
    from netcross_ai.report_writer import WriterConfigError, parse_engine

    if args.ai_baseline_label and not args.ai_baseline_save:
        print("--ai-baseline-label necessite --ai-baseline-save.", file=sys.stderr)
        sys.exit(1)
    if args.ai_endpoint and not args.ai_summary:
        print("--ai-endpoint necessite --ai-summary.", file=sys.stderr)
        sys.exit(1)
    for flag, path in (("--ai-anomalies", args.ai_anomalies), ("--ai-classify", args.ai_classify)):
        if path and not os.path.isfile(path):
            print(f"{flag} : fichier introuvable : {path}", file=sys.stderr)
            sys.exit(1)
    try:
        if args.ai_anomalies:
            require_ml("--ai-anomalies")
        if args.ai_classify:
            require_ml("--ai-classify")
        if args.ai_summary:
            parse_engine(args.ai_summary, args.ai_endpoint)
    except (AIUnavailableError, WriterConfigError) as exc:
        logger.exception(f"échec dans _check_ai_args: {exc}")
        print(f"Module IA : {exc}", file=sys.stderr)
        sys.exit(1)
    return AIOptions(
        baseline_path=args.ai_anomalies,
        baseline_save=args.ai_baseline_save,
        baseline_label=args.ai_baseline_label,
        training_path=args.ai_classify,
        training_export=args.ai_training_export,
        summary_engine=args.ai_summary,
        endpoint=args.ai_endpoint,
    )


def _run_ai(args, ai_options, report, all_packets) -> None:
    import json

    from netcross_ai.pipeline import format_ai, run_ai

    flows = report.flow_anomalies
    if not flows:
        from netcross_core.security.flow_stats import analyze_flow_stats

        flows = [f.to_dict() for f in analyze_flow_stats(all_packets).flows]
    try:
        result = run_ai(report, flows, ai_options)
    except (RuntimeError, ValueError, OSError) as exc:
        logger.exception(f"échec dans _run_ai: {exc}")
        print(f"Module IA : {exc}", file=sys.stderr)
        sys.exit(1)
    print(format_ai(result))
    if args.ai_report:
        with open(args.ai_report, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
        print(f"\nResultats du module IA ecrits dans {args.ai_report}")


def main():
    # `netcross lua-doc ...` : documentation hors ligne de l'API Lua Wireshark (issue #388)
    if sys.argv[1:2] == ["lua-doc"]:
        from netcross_lua_doc_cli import main as lua_doc_main

        sys.exit(lua_doc_main(sys.argv[2:]))
    ap = argparse.ArgumentParser(
        description="Analyse croisee de captures Wireshark multi-points",
        epilog="Documentation de l'API Lua Wireshark : netcross lua-doc --help (ou netcross-lua-doc).",
    )
    ap.add_argument(
        "--capture",
        action="append",
        help="NOM=chemin.pcap(ng)[,chemin2.pcap(ng),...], repetable pour chaque "
        "point de capture. Plusieurs chemins separes par des virgules pour un "
        "meme NOM permettent de rejouer une capture segmentee (rotation "
        "tcpdump/tshark, ex: -C 100) comme un seul point continu -- a lister "
        "dans l'ordre chronologique, aucun tri automatique n'est effectue. "
        "Mutuellement exclusif avec --live.",
    )
    ap.add_argument(
        "--live",
        action="append",
        metavar="LABEL:INTERFACE[:FILTRE_BPF]",
        help="Capture en direct sur une interface reseau au lieu de fichiers "
        "pcap existants (repetable pour plusieurs points simultanes, un "
        "thread par point comme sur l'interface graphique). S'arrete sur "
        "Ctrl+C ou --live-duration. Mutuellement exclusif avec --capture/"
        "--parallel/--tls/--quic (memes limitations assumees que sur la GUI). "
        "INTERFACE peut etre une source distante : rpcap://hote[:port]/eth0, "
        "sshdump://utilisateur@hote/eth0, pipe:///fifo ou pipe://- (voir docs/capture-distante.md).",
    )
    ap.add_argument(
        "--live-duration",
        type=int,
        default=None,
        help="Duree maximale en secondes pour --live (defaut: illimitee, s'arrete uniquement sur Ctrl+C)",
    )
    ap.add_argument(
        "--live-report",
        metavar="REPERTOIRE",
        help="Avec --live : rapport temps reel (issue #274) publie pendant la capture dans REPERTOIRE : "
        "live.json (instantane complet, remplace atomiquement), live.jsonl (journal en ajout seul, une "
        "ligne par releve) et index.html (relecture successive ou completive). Voir docs/live-report.md.",
    )
    ap.add_argument(
        "--live-report-interval",
        type=float,
        default=5.0,
        metavar="SECONDES",
        help="Avec --live-report : intervalle entre deux releves (defaut 5, minimum 1).",
    )
    ap.add_argument(
        "--live-report-serve",
        type=int,
        metavar="PORT",
        help="Avec --live-report : sert REPERTOIRE en HTTP sur 127.0.0.1:PORT (localhost seulement) pour que "
        "la page se mette a jour sans rechargement.",
    )
    ap.add_argument(
        "--split",
        metavar="MODE:VALEUR",
        help="Decoupe chaque fichier de --capture en segments plus petits puis "
        "s'arrete SANS lancer d'analyse : time:60 (secondes par segment), "
        "count:10000 (paquets par segment) ou size:100M (taille maximale par "
        "segment, unites decimales comme tcpdump -C). Format d'origine conserve. "
        "time/count s'appuient sur editcap (livre avec tshark) ; size ne "
        "necessite aucun outil externe. Segments ecrits dans "
        "<--split-output-dir>/<NOM>/, a rejouer ensuite via --capture "
        "NOM=seg1,seg2,... Incompatible avec --live et avec toute option "
        "d'analyse ou de rapport (refusees plutot qu'ignorees en silence).",
    )
    ap.add_argument(
        "--split-output-dir",
        metavar="REPERTOIRE",
        help=f"Avec --split : repertoire de sortie (defaut: ./{_SPLIT_DEFAULT_DIR}, "
        "cree si absent). Refuse d'ecraser ou de melanger des segments deja presents.",
    )
    ap.add_argument(
        "--export-pcap",
        metavar="PATH",
        help="Exporte un sous-ensemble de la premiere capture de --capture "
        "vers un nouveau fichier PCAP/pcapng, filtre par --export-bpf, "
        "--export-time-start/end et/ou --export-endpoints. Comme --merge/--split, "
        "ne lance aucune analyse. Un seul fichier source a la fois.",
    )
    ap.add_argument(
        "--export-bpf",
        metavar="FILTRE",
        help='Avec --export-pcap : filtre BPF (capture filter) a appliquer, ex: "tcp port 80" ou "host 192.168.1.1".',
    )
    ap.add_argument(
        "--export-time-start",
        type=float,
        default=None,
        metavar="SECONDES",
        help="Avec --export-pcap : debut de la plage temporelle a exporter (secondes relatives au premier paquet).",
    )
    ap.add_argument(
        "--export-time-end",
        type=float,
        default=None,
        metavar="SECONDES",
        help="Avec --export-pcap : fin de la plage temporelle a exporter (secondes relatives au premier paquet).",
    )
    ap.add_argument(
        "--export-endpoints",
        metavar="IP1,IP2,...",
        help="Avec --export-pcap : liste d'adresses IP a inclure (src OU dst), "
        "separees par des virgules. Un paquet est conserve si l'une de ses "
        "adresses IP correspond.",
    )
    ap.add_argument(
        "--adjust-time-output",
        metavar="PATH",
        help="Ajuste les timestamps de la premiere capture de --capture et "
        "ecrit le resultat dans ce fichier. Mode utilitaire (comme "
        "--merge/--split/--export-pcap) : ne lance aucune analyse. "
        "Choix du mode : --time-offset (decalage fixe), --normalize-time "
        "(premier paquet a t=0) ou --align-to (alignement sur une autre capture). "
        "Un seul mode a la fois.",
    )
    ap.add_argument(
        "--time-offset",
        type=float,
        default=None,
        metavar="SECONDES",
        help="Avec --adjust-time-output : decale tous les timestamps d'un "
        "montant fixe en secondes (positif ou negatif). Ex: 10.5, -3600.",
    )
    ap.add_argument(
        "--normalize-time",
        action="store_true",
        help="Avec --adjust-time-output : aligne le premier paquet sur t=0.0 "
        "(calcule l'offset = -timestamp du premier paquet).",
    )
    ap.add_argument(
        "--align-to",
        metavar="PATH",
        help="Avec --adjust-time-output : aligne le premier paquet de la "
        "capture source sur le premier paquet de PATH (reference). Utile "
        "pour comparer deux captures dont les horloges etaient "
        "desynchronisees.",
    )
    ap.add_argument("--order", help="Ordre physique des points sur le chemin reseau, ex: LAN,WAN,DC")
    ap.add_argument("--detail-csv", help="Chemin de sortie pour le detail par flux (CSV)")
    ap.add_argument(
        "--names",
        metavar="PATH",
        help="Table des noms (JSON/YAML, section 6.15) : remplace les adresses "
        "IP brutes par des noms logiques (ex: PC-COMPTA-31 -> APP-SQL-01) "
        "dans le CSV detail et le rapport JSON.",
    )
    ap.add_argument(
        "--nat-tolerant",
        action="store_true",
        help="Correle par hash de payload + fenetre temporelle au lieu de "
        "IP/port (necessaire si un NAT/PAT est traverse entre 2 points). "
        "Desactive les modules handshake SYN/SYN-ACK et decalage d'horloge.",
    )
    ap.add_argument(
        "--nat-window-ms",
        type=int,
        default=200,
        help="Largeur de la fenetre temporelle (ms) pour le mode --nat-tolerant "
        "(defaut: 200ms, a elargir si la latence WAN est plus grande)",
    )
    ap.add_argument(
        "--detect-duplicates",
        action="store_true",
        help="Detecte les paquets dupliques entre points de capture (meme payload "
        "vu a deux points a moins de --duplicate-threshold-ms, ex: port miroir "
        "qui renvoie le trafic) et les rapporte par paire de points. Sans "
        "--exclude-duplicates, les doublons restent comptes dans les statistiques.",
    )
    ap.add_argument(
        "--exclude-duplicates",
        action="store_true",
        help="Exclut les doublons inter-captures du comptage (flux, pertes, debits, "
        "paquets/octets) ; implique --detect-duplicates. Un doublon exclu n'est "
        "plus compte comme presence de son flux a son point : un flux vu a ce "
        "point uniquement via ce doublon y apparait comme absent.",
    )
    ap.add_argument(
        "--duplicate-threshold-ms",
        type=float,
        default=DEFAULT_DUPLICATE_THRESHOLD_MS,
        help="Ecart de temps maximal (ms) entre deux observations du meme payload "
        "a deux points pour les considerer comme un doublon (defaut: "
        f"{DEFAULT_DUPLICATE_THRESHOLD_MS:g}ms). A regler SOUS la plus petite latence "
        "attendue entre deux points : au-dela, le trafic normal du segment est "
        "marque doublon.",
    )
    ap.add_argument(
        "--max-packets",
        type=int,
        default=None,
        metavar="N",
        help="Limite l'analyse aux N premiers paquets (tous points confondus, "
        "apres --sample si les deux sont fournis) -- utile sur une capture trop "
        "volumineuse pour la memoire disponible (voir l'avertissement memoire "
        "affiche avant l'analyse). La troncature est ecrite dans le rapport "
        "(Report.truncated/truncation_note) : jamais silencieuse, issue #283.",
    )
    ap.add_argument(
        "--sample",
        metavar="1/N",
        default=None,
        help="Echantillonne 1 paquet sur N (tous points confondus) avant "
        "analyse, ex: --sample 1/50 pour garder 2%% des paquets -- reduit la "
        "memoire necessaire au prix d'une vue partielle (utile pour un premier "
        "apercu d'une capture trop volumineuse). Applique AVANT --max-packets "
        "si les deux sont fournis. Meme obligation de tracabilite que "
        "--max-packets (issue #283).",
    )
    ap.add_argument(
        "--bucket-ms",
        type=int,
        default=1000,
        help="Largeur des fenetres temporelles (ms) pour le debit, la "
        "correlation pertes/debit et le bufferbloat (defaut: 1000ms, "
        "reduire a 50-200ms pour detecter des microbursts)",
    )
    ap.add_argument(
        "--rtp-clock-rate",
        type=int,
        default=8000,
        help="Cadence d'horloge RTP en Hz pour le calcul de gigue (defaut: "
        "8000Hz pour la voix G.711/G.729 ; utiliser 90000 pour de la video)",
    )
    ap.add_argument(
        "--idle-timeout-seconds",
        type=float,
        default=None,
        help="Silence minimal (secondes) entre deux paquets consecutifs au "
        "point amont pour detecter une coupure NAT/pare-feu silencieuse "
        "(defaut: 60s, voir netcross_core.analysis._IDLE_TIMEOUT_SECONDS). "
        "Reduire sur un lien connu pour un timeout d'etat plus agressif, "
        "augmenter pour eviter les faux positifs sur des sessions peu actives.",
    )
    ap.add_argument(
        "--triage",
        action="store_true",
        help="Affiche en plus un classement des segments par ou commencer a "
        "regarder (convergence de plusieurs categories de constats sur un "
        "meme segment). Purement informatif, n'affecte pas les autres sorties.",
    )
    ap.add_argument(
        "--triage-top-n",
        type=int,
        default=5,
        help="Nombre de segments affiches par --triage (defaut: 5)",
    )
    ap.add_argument(
        "--topn-charts",
        type=int,
        default=5,
        metavar="N",
        help="Nombre de categories affichees par graphique temporel top-N "
        "dans --pdf-report (protocole/port/IP/DSCP, un seul point de "
        "capture -- le premier de --order ou de --capture -- pour eviter "
        "de compter certains paquets en double sur un meme graphique). Le "
        "reste est regroupe sous 'autres'. Sans effet si --pdf-report "
        "n'est pas fourni (defaut: 5).",
    )
    ap.add_argument(
        "--tls",
        action="store_true",
        help="Diagnostic TLS en plus de l'analyse principale (ClientHello/SNI, "
        "ServerHello, alertes, segment ou un handshake qui aboutissait "
        "commence a echouer). Relit les memes fichiers passes a --capture "
        "avec un pipeline de decodage independant (mais toujours via tshark).",
    )
    ap.add_argument(
        "--quic",
        action="store_true",
        help="Diagnostic QUIC/HTTP3 en plus de l'analyse principale (SNI extrait "
        "en dechiffrant les paquets Initial QUICv1). Necessite cryptography. "
        "Relit les memes fichiers passes a --capture.",
    )
    ap.add_argument(
        "--security-report",
        action="store_true",
        help="Rapport de securite consolide en plus de l'analyse principale "
        "(services/vulnerabilites, tentatives d'exploitation, anomalies "
        "Expert Info, CVE confirmees -- voir docs/security-report.md). Relit "
        "les memes fichiers passes a --capture pour chercher les signatures "
        "d'exploits dans la charge utile brute (comme --tls). Incompatible "
        "avec --live/--redact et les modes utilitaires --merge/--split/--replay.",
    )
    ap.add_argument(
        "--cve-db",
        help="Avec --security-report : base CVE SQLite locale (construite par "
        "scripts/import_nvd.py) pour la correlation version -> CVE. Doit "
        "designer un fichier existant (aucune base vide n'est creee). Sans cette "
        "option, une base minimale embarquee (quelques CVE critiques) est utilisee.",
    )
    notify = ap.add_argument_group(
        "notifications (issue #280)",
        "Un resume par analyse (jamais un message par constat) quand le pire constat atteint le seuil. "
        "Secrets SMTP et URL de webhook de preference dans .netcross.toml ([notify]) ou en variables "
        "d'environnement (NETCROSS_SLACK_WEBHOOK, NETCROSS_SMTP_*). Voir docs/notifications.md.",
    )
    notify.add_argument(
        "--notify-on",
        choices=("critique", "elevee", "moyenne", "faible"),
        help="Avec --security-report : notifie si le niveau atteint ce seuil. Sans cette option, "
        "AUCUNE notification (aucun appel reseau), meme si des canaux sont configures.",
    )
    notify.add_argument("--notify-webhook", metavar="URL", help="POST JSON du resume vers cette URL.")
    notify.add_argument("--notify-slack", metavar="URL", help="Webhook entrant Slack (Block Kit).")
    notify.add_argument(
        "--notify-email",
        metavar="DEST[,DEST...]",
        help="Destinataires du courriel (serveur et identifiants SMTP : .netcross.toml ou NETCROSS_SMTP_*).",
    )
    notify.add_argument(
        "--notify-detail",
        choices=("resume", "complet"),
        default="resume",
        help="`resume` (defaut) : adresses, noms d'hote et chemins anonymises ; `complet` : texte brut "
        "des constats -- a n'utiliser que vers un canal de confiance.",
    )
    notify.add_argument(
        "--notify-silence",
        type=float,
        metavar="HEURES",
        help="Fenetre anti-repetition : le meme lot de constats n'est pas re-notifie pendant cette "
        "duree (defaut 24, 0 = desactive).",
    )
    notify.add_argument(
        "--notify-state",
        metavar="FICHIER",
        help="Fichier d'etat anti-repetition (defaut ~/.cache/netcross/notify-state.json).",
    )
    ap.add_argument(
        "--known-destinations",
        metavar="FICHIER.json",
        help="Avec --security-report : baseline des destinations connues pour la detection "
        "d'exfiltration (issue #148) -- liste JSON d'IP, ou objet avec une cle `hosts`. "
        "Un transfert suspect vers une IP absente de la liste est aggrave (signal "
        "`new_destination`) ; sans baseline, ce signal n'est jamais emis.",
    )
    ap.add_argument(
        "--known-hosts",
        metavar="FICHIER.json",
        help="Avec --security-report : baseline des hotes connus pour l'inventaire d'actifs "
        "(issue #350) -- liste JSON d'IP, ou objet avec une cle `hosts`. Chaque hote vu dans "
        "la capture et absent de la liste est marque NOUVEAU et devient un constat (rapport, "
        "JSON, export SIEM) ; sans baseline, aucun hote n'est signale nouveau.",
    )
    ap.add_argument(
        "--test-net-external",
        action="store_true",
        help="Avec --security-report : traiter les plages de documentation TEST-NET (RFC 5737 : "
        "192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) comme EXTERNES pour le beaconing et "
        "l'exfiltration (issue #365). Par defaut elles sont internes (comme pour ipaddress) : "
        "une capture de demonstration qui les utilise ne leve alors aucune alerte.",
    )
    ap.add_argument(
        "--siem-export",
        choices=("cef", "leef", "stix"),
        help="Avec --security-report et --siem-output : exporte les constats pour un SIEM -- "
        "`cef` (ArcSight/Splunk/ELK), `leef` (QRadar, LEEF 2.0) ou `stix` (bundle STIX 2.1 "
        "pour MISP/OpenCTI, deterministe). Voir docs/siem-export.md.",
    )
    ap.add_argument(
        "--siem-output",
        metavar="FICHIER",
        help="Fichier de sortie de --siem-export.",
    )
    plug = ap.add_argument_group(
        "plugins (issue #284)",
        "Detecteurs et sorties tierces. Chargement EXPLICITE : un plugin installe n'est execute que "
        "s'il est nomme dans --plugins. Code tiers execute dans le processus : voir docs/plugins.md.",
    )
    plug.add_argument(
        "--plugins",
        metavar="NOM[,NOM...]",
        help="Plugins autorises a s'executer (entry points netcross.detectors / netcross.exporters "
        "ou definis dans un --plugin-path). Les detecteurs necessitent --security-report.",
    )
    plug.add_argument(
        "--plugin-path",
        action="append",
        default=[],
        metavar="FICHIER.py",
        help="Fichier plugin local (DETECTORS = [...] / EXPORTERS = [...]). Repetable. Le fichier est "
        "importe, mais ses plugins ne s'executent que s'ils sont nommes dans --plugins.",
    )
    plug.add_argument(
        "--plugin-export",
        action="append",
        default=[],
        metavar="NOM=FICHIER",
        help="Execute l'exporteur NOM (autorise par --plugins) vers FICHIER. Repetable.",
    )
    plug.add_argument(
        "--list-plugins",
        action="store_true",
        help="Liste les plugins installes et locaux, autorises ou NON par --plugins, puis quitte.",
    )
    ap.add_argument(
        "--security-html",
        help="Avec --security-report : chemin de sortie pour un rendu HTML "
        "autonome du rapport de securite (tableau de bord, services avec "
        "leurs empreintes JA4/HASSH, exploits, anomalies, CVE). Fichier "
        "unique, sans ressource externe ni dependance supplementaire : "
        "consultable hors ligne et archivable dans un ticket.",
    )
    ap.add_argument(
        "--pdf-report",
        help="Chemin de sortie pour un rapport PDF (triage, synthese, graphiques, "
        "detail par module). Necessite reportlab, matplotlib et networkx.",
    )
    ap.add_argument(
        "--json-report",
        help="Chemin de sortie pour un rapport JSON structure (points, constats, "
        "triage, diagnostics TLS/QUIC si --tls/--quic sont fournis) -- pour "
        "l'integration externe (dashboard, ticketing, CI). Aucune dependance "
        "supplementaire (contrairement a --pdf-report).",
    )
    ap.add_argument(
        "--rule-engine",
        action="store_true",
        help="Active le moteur d'execution de regles declaratives "
        "(netcross_report.rule_engine) : evalue chaque regle du catalogue "
        "(expert_rules) contre le Report et affiche les Finding produits. "
        "Integre egalement les resultats au --json-report si fourni. "
        "Independant du chemin procedural (build_findings) -- les deux "
        "chemins coexistent, le moteur declaratif ne le remplace pas encore.",
    )
    ai = ap.add_argument_group(
        'module IA local (issue #146, optionnel : pip install "netcross[ai]")',
        "Tout tourne sur cette machine ; voir docs/module-ia.md.",
    )
    ai.add_argument(
        "--ai-baseline-save",
        metavar="FICHIER.json",
        help="Ajoute les flux de cette capture (supposee NORMALE) a la baseline FICHIER (creee si absente).",
    )
    ai.add_argument("--ai-baseline-label", metavar="ETIQUETTE", default="", help="Avec --ai-baseline-save : nom libre.")
    ai.add_argument(
        "--ai-anomalies",
        metavar="BASELINE.json",
        help="Detection d'anomalies de flux (Isolation Forest) par rapport a la baseline. Necessite scikit-learn.",
    )
    ai.add_argument(
        "--ai-training-export",
        metavar="FICHIER.json",
        help="Exporte les flux pre-etiquetes par les regles FLOW-4, a corriger pour --ai-classify.",
    )
    ai.add_argument(
        "--ai-classify",
        metavar="ENTRAINEMENT.json",
        help="Classe les flux (foret aleatoire entrainee sur ce jeu etiquete) avec un score de confiance. "
        "Necessite scikit-learn.",
    )
    ai.add_argument(
        "--ai-summary",
        metavar="MOTEUR",
        nargs="?",
        const="template",
        help="Resume executif, correlations et recommandations en francais : template (defaut, sans modele), "
        "ollama:MODELE ou llamacpp (modele local).",
    )
    ai.add_argument(
        "--ai-endpoint",
        metavar="URL",
        help="Avec --ai-summary ollama/llamacpp : point d'acces local (defaut http://127.0.0.1:11434 ou :8080). "
        "Toute adresse hors boucle locale est refusee.",
    )
    ai.add_argument("--ai-report", metavar="FICHIER.json", help="Ecrit les resultats du module IA en JSON.")
    ap.add_argument(
        "--expert-section",
        action="store_true",
        help="Affiche en console les objets enrichis (evenements d'expertise "
        "avec cause/impact probables, diagnostics par segment, conformite aux "
        "referentiels, flux correles, signaux tshark bruts). Ces objets "
        "n'etaient jusqu'ici exposes que par --json-report. Egalement ajoutes "
        "en section dediee du --pdf-report si celui-ci est demande, que cette "
        "option soit active ou non.",
    )
    ap.add_argument(
        "--sequence-diagram",
        type=int,
        nargs="?",
        const=1,
        default=0,
        metavar="N",
        help="Ajoute au --pdf-report un diagramme de sequence des echanges "
        "pour les N flux les plus volumineux (N=1 si l'option est passee sans "
        "valeur). Une ligne par paquet ET par point de capture : le meme "
        "paquet vu a deux points apparait deux fois, l'ecart entre les deux "
        "lignes etant son temps de transit. Sans effet sans --pdf-report "
        "(les vues exigent les paquets bruts, que le rapport ne conserve pas).",
    )
    ap.add_argument(
        "--client-group",
        action="append",
        metavar="NOM=IP1[,IP2,...]",
        help="Regroupe les paquets par client (poste) plutot que par point de "
        "capture, pour une comparaison 'ce client fonctionne, pas l'autre' -- "
        "meme capture, memes points, seule la source change. Repetable (au "
        "moins 2 pour produire une comparaison) ; plusieurs IP separees par "
        "des virgules pour un meme client couvrent le cas multi-IP/DHCP. "
        "Additif : n'affecte pas l'analyse principale ci-dessus.",
    )
    ap.add_argument(
        "--client-reference",
        metavar="NOM",
        help="Nom du client de reference pour --client-group (celui qui "
        "fonctionne, ou le comportement majoritaire) -- chaque autre client "
        "est compare a lui. Par defaut : le premier --client-group fourni.",
    )
    ap.add_argument(
        "--client-diff-csv",
        help="Chemin de sortie CSV pour le detail de la comparaison "
        "--client-group (une ligne par ecart, tous clients confondus).",
    )
    ap.add_argument(
        "--parallel",
        action="store_true",
        help="Lit les fichiers de capture en parallele (un processus tshark par "
        "fichier au lieu d'un seul flux sequentiel). Le gain depend du "
        "nombre de coeurs disponibles sur la machine (aucun gain sur "
        "une machine a 1 seul coeur).",
    )
    ap.add_argument(
        "--parallel-workers",
        type=int,
        default=None,
        help="Nombre de processus pour --parallel (defaut: nombre de coeurs CPU disponibles)",
    )
    ap.add_argument(
        "--merge",
        metavar="SORTIE",
        help="Fusionne tous les fichiers passes a --capture en UN seul fichier "
        "SORTIE ordonne par timestamp de paquet (mergecap + reordercap, "
        "livres avec tshark), puis s'arrete SANS lancer d'analyse : les noms de "
        "points (NOM=) sont ignores, seuls les chemins comptent. Format de "
        "sortie pcap si SORTIE se termine par .pcap, pcapng sinon. "
        "Incompatible avec --live et avec les options d'analyse/de rapport.",
    )
    ap.add_argument(
        "--netflow",
        action="append",
        metavar="[EXPORTATEUR=]FICHIER",
        help="Resume d'un export NetFlow v5 (datagrammes concatenes, issue #362) : volumes, "
        "protocoles, principaux emetteurs, conversations et ports -- texte, et JSON avec "
        "--json-report. Repetable (un fichier par exportateur ; EXPORTATEUR= etiquette la "
        "source, defaut : le chemin). Mode autonome : incompatible avec --capture/--live, "
        "les flux agreges ne se correlent pas entre points de capture.",
    )
    ap.add_argument(
        "--netflow-top",
        type=int,
        default=10,
        metavar="N",
        help="Avec --netflow : taille des classements (defaut 10).",
    )
    ap.add_argument(
        "--merge-dedup",
        action="store_true",
        help="Avec --merge : supprime les paquets de contenu ET de timestamp "
        "identiques (editcap). Une retransmission (meme contenu, autre "
        "instant) et une meme trame vue par deux horloges differentes sont "
        "conservees.",
    )
    ap.add_argument(
        "--replay",
        metavar="INTERFACE",
        help="Rejoue le fichier passe a --capture (un seul, exactement) sur "
        "l'interface reseau INTERFACE via tcpreplay, puis s'arrete SANS "
        "lancer d'analyse. ATTENTION -- usage responsable : cette option "
        "EMET du trafic reseau REEL sur INTERFACE ; ne jamais l'utiliser sur "
        "une interface connectee a un reseau de production sans "
        "autorisation explicite (saturation de lien, alarmes IDS/IPS, "
        "paquets a adresse source usurpee). Reserver a un banc de test "
        "isole sauf besoin explicite et maitrise d'un rejeu sur un segment "
        "reel. Necessite le paquet systeme tcpreplay (distinct de tshark). "
        "Incompatible avec --live/--merge/--split et avec les options "
        "d'analyse/de rapport.",
    )
    ap.add_argument(
        "--replay-speed",
        default="1.0",
        metavar="MULTIPLICATEUR|topspeed",
        help="Avec --replay : vitesse de rejeu par rapport a la vitesse "
        "d'origine mesuree par les timestamps du fichier (1.0 = vitesse "
        "d'origine, valeur par defaut ; 0.5 = deux fois plus lent ; 2.0 = "
        "deux fois plus rapide), ou la chaine 'topspeed' pour rejouer aussi "
        "vite que l'interface/le noyau le permettent sans respecter les "
        "timestamps d'origine.",
    )
    ap.add_argument(
        "--replay-loop",
        type=int,
        default=1,
        metavar="N",
        help="Avec --replay : nombre de fois que le fichier est rejoue "
        "integralement (defaut: 1, une seule passe). Doit etre >= 1.",
    )
    ap.add_argument(
        "--convert",
        metavar="SORTIE",
        help="Convertit le fichier passe a --capture (un seul) vers un autre "
        "format, puis s'arrete SANS lancer d'analyse. Le format de sortie "
        "depend de --convert-format (defaut: pcapng). Pour un export "
        "structure (CSV/JSON), utiliser --convert-format csv ou json. "
        "Incompatible avec --live/--merge/--split/--replay et avec les "
        "options d'analyse/de rapport.",
    )
    ap.add_argument(
        "--convert-format",
        default="pcapng",
        choices=["pcap", "pcapng", "erf", "csv", "json"],
        metavar="FORMAT",
        help="Avec --convert : format de sortie (defaut: pcapng). Formats de "
        "capture : pcap, pcapng, erf (via tshark -F). Exports structures : "
        "csv (un paquet par ligne, colonnes timestamp/src/dst/proto/length), "
        "json (un objet par paquet avec tous les champs EK).",
    )
    ap.add_argument(
        "--redact",
        action="store_true",
        help="Anonymise les adresses IP (RFC 5737/3849, plages de documentation) "
        "et MAC (OUI localement administre) avant l'analyse -- mapping "
        "coherent sur tout le run, pour partager un rapport ou une capture "
        "sans exposer l'adressage reel (support vendeur, ticket externe). "
        "Ne couvre que les adresses (pas les noms DNS/HTTP/SAN TLS/SIP, voir "
        "netcross_core.redact). Mutuellement exclusif avec --tls/--quic/"
        "--client-group, qui relisent des fichiers ou des IP fournies "
        "independamment de cette redaction.",
    )
    ap.add_argument(
        "--redact-map",
        metavar="CHEMIN",
        help="Avec --redact : ecrit la correspondance adresse reelle <-> "
        "pseudonyme dans un CSV local (a conserver en prive -- ne JAMAIS le "
        "transmettre avec le rapport/la capture redigee -- utile pour "
        "retrouver plus tard a quelle machine correspond un pseudonyme cite "
        "par un tiers).",
    )
    ap.add_argument(
        "--support-ticket",
        metavar="CHEMIN",
        help="Ecrit un ticket de support ANONYMISE (JSON) : contexte technique, "
        "erreurs de traitement, et trace d'appels en cas de crash. Tout le "
        "texte libre passe par netcross_core.support.scrubber (IP, MAC, "
        "emails, URL, FQDN, noms de capture, repertoires personnels, "
        "secrets). NECESSITE --support-consent : sans accord explicite, rien "
        "n'est ecrit. Un ticket est produit meme quand tout s'est bien passe "
        "(nature 'diagnostic') -- voir docs/quality/traceability-rule.md.",
    )
    ap.add_argument(
        "--support-consent",
        action="store_true",
        help="Autorisation explicite de produire le ticket demande par "
        "--support-ticket (issue #269). Sans ce drapeau, --support-ticket "
        "refuse d'ecrire.",
    )
    ap.add_argument(
        "--support-scope",
        metavar="PORTEES",
        help="Restreint le contenu du ticket a une liste de portees separees "
        "par des virgules parmi : environnement, journal, trace_appels, "
        "marqueurs (defaut : toutes). Ce qui n'est pas autorise est absent "
        "du ticket, et son absence y est tracee explicitement.",
    )
    ap.add_argument(
        "--support-map",
        metavar="CHEMIN",
        help="Avec --support-ticket : ecrit la correspondance valeur reelle "
        "<-> pseudonyme du ticket dans un CSV local. Meme discipline que "
        "--redact-map : a conserver en prive, ne JAMAIS le transmettre avec "
        "le ticket, sinon l'anonymisation est annulee.",
    )
    ap.add_argument(
        "--support-marker",
        metavar="CLE=VALEUR",
        action="append",
        help="Marqueur de correlation a joindre au ticket, repetable "
        "(ex: --support-marker trace_id=T-042 --support-marker "
        "capture_id=C-7). Sert a relier un ticket a une trace precise de la "
        "campagne de tests sans exposer son nom reel (voir "
        "docs/quality/anonymization-plan.md). Un run_id est genere "
        "automatiquement s'il n'est pas fourni.",
    )
    ap.add_argument(
        "--history-db",
        metavar="CHEMIN",
        help="Enregistre un resume de ce run (score de sante, nombre de "
        "constats par severite) dans une base SQLite locale, creee si "
        "absente -- pour observer une tendance dans le temps sur des runs "
        "successifs (ex: controle hebdomadaire du meme lien). Ne remplace "
        "pas --json-report/--pdf-report/--detail-csv (detail complet d'un "
        "run donne) : l'historique ne conserve qu'un resume compact par run.",
    )
    ap.add_argument(
        "--history-label",
        metavar="ETIQUETTE",
        help="Avec --history-db : etiquette libre associee a ce run (ex: nom "
        "de site/scenario), pour distinguer plusieurs historiques qui "
        "partagent le meme fichier .db. Reutilisee automatiquement comme "
        "filtre par --history-show si elle est fournie.",
    )
    ap.add_argument(
        "--history-show",
        nargs="?",
        type=int,
        const=10,
        default=None,
        metavar="N",
        help="Avec --history-db : affiche apres l'analyse les N derniers "
        "runs enregistres (y compris celui-ci), du plus recent au plus "
        "ancien -- defaut 10 si l'option est fournie sans valeur. Filtre "
        "sur --history-label si elle est fournie, sinon montre tous les "
        "runs de la base.",
    )
    ext = ap.add_argument_group(
        "extraction des contenus (issue #278)",
        "Analyse qualitative des flux audio/video (note de degradation due au transport) et, sur demande "
        "explicite, extraction du son, de la video et des documents. Rappel d'usage raisonne : "
        "voir docs/extraction-contenus.md.",
    )
    ext.add_argument(
        "--media-quality",
        action="store_true",
        help="Analyse qualitative des flux RTP (pertes, rafales, gigue, MOS, images endommagees, note de "
        "degradation 0-100). N'ecrit AUCUN contenu : a privilegier quand elle suffit.",
    )
    ext.add_argument(
        "--extract-contents",
        metavar="REPERTOIRE",
        help="Extrait les contenus dans REPERTOIRE (cree en 0700, doit etre absent ou vide) : audio G.711 "
        "-> WAV, video H.264 -> .h264, documents via tshark --export-objects (HTTP, SMB, courriel, TFTP, "
        "FTP-DATA), plus manifest.json (SHA-256, flux d'origine, degradation). Inclut --media-quality.",
    )
    ext.add_argument(
        "--extract-kinds",
        metavar="TYPE[,TYPE]",
        help="Avec --extract-contents : restreint l'extraction a audio, video et/ou documents (defaut : tous).",
    )
    # Issues #359, #360, #361 : modules d'analyse avancee exposes au CLI
    adv = ap.add_argument_group(
        "analyse avancee",
        "Chronologie des flux (#359), recherche forensique (#360) et statistiques tshark (#361), "
        "chacune ecrite en JSON. S'ajoutent a l'analyse --capture/--live habituelle.",
    )
    adv.add_argument(
        "--flow-timeline",
        metavar="FICHIER.json",
        help="Chronologie de chaque conversation, point par point : inter-arrivees, debit par "
        "fenetre, phases (slow-start, rafale, inactivite...), RTT estime.",
    )
    adv.add_argument(
        "--flow-timeline-window",
        type=float,
        default=1.0,
        metavar="SECONDES",
        help="Avec --flow-timeline : duree des fenetres de debit (defaut 1.0).",
    )
    adv.add_argument(
        "--tshark-stats",
        metavar="FICHIER.json",
        help="Statistiques tshark -z de chaque fichier --capture : conversations et endpoints TCP/UDP, "
        "hierarchie de protocoles, io_stat. Necessite tshark ; refuse avec --live.",
    )
    adv.add_argument(
        "--forensic-search",
        metavar="FICHIER.json",
        help="Recherche forensique dans les paquets et flux decodes ; criteres --search-* combines "
        "par ET (aucun critere : tout est liste).",
    )
    adv.add_argument("--search-text", metavar="TEXTE", help="Texte libre (insensible a la casse).")
    adv.add_argument("--search-address", metavar="IP", help="Adresse source ou destination.")
    adv.add_argument("--search-point", metavar="POINT", help="Point de capture.")
    adv.add_argument("--search-protocol", metavar="PROTO", help="Protocole (TCP, UDP, DNS, HTTP...).")
    adv.add_argument("--search-port", type=int, metavar="PORT", help="Port source ou destination.")
    adv.add_argument(
        "--search-field",
        metavar="CHAMP",
        help="Champ decode : sni, uri, http_status, call_id, dns_name, method, content_type, message.",
    )
    adv.add_argument(
        "--search-value",
        metavar="VALEUR",
        help="Valeur cherchee dans --search-field (sans --search-field : dans tous les champs).",
    )
    add_debug_argument(ap)
    args = ap.parse_args()
    apply_debug_argument(args)

    plugin_names = [n.strip() for n in (args.plugins or "").split(",") if n.strip()]
    if args.list_plugins:
        sys.exit(_list_plugins(plugin_names, args.plugin_path))

    if args.netflow:
        sys.exit(_run_netflow(args))

    if not args.capture and not args.live:
        print("Il faut fournir au moins un --capture ou un --live.", file=sys.stderr)
        sys.exit(1)
    advanced_error = _advanced_options_error(args)
    if advanced_error:
        print(advanced_error, file=sys.stderr)
        sys.exit(1)
    if args.capture and args.live:
        print(
            "--capture et --live sont mutuellement exclusifs (meme limitation "
            "assumee que sur l'interface graphique : cases a cocher fichier/live).",
            file=sys.stderr,
        )
        sys.exit(1)

    # --security-report (issue #139) : les signatures d'exploits cherchent la
    # charge utile BRUTE, relue depuis les fichiers --capture (meme discipline
    # que --tls) -- jamais depuis un sniffing live, jamais depuis des paquets
    # anonymises par --redact.
    if args.cve_db and not args.security_report:
        print("--cve-db necessite --security-report.", file=sys.stderr)
        sys.exit(1)
    known_destinations = None
    if args.known_destinations:
        if not args.security_report:
            print("--known-destinations necessite --security-report.", file=sys.stderr)
            sys.exit(1)
        if not os.path.isfile(args.known_destinations):
            print(f"--known-destinations : fichier introuvable : {args.known_destinations}", file=sys.stderr)
            sys.exit(1)
        hosts = load_baseline_hosts(args.known_destinations)
        if not hosts:
            # load_baseline_hosts avale les erreurs de lecture : une baseline
            # vide ferait passer TOUTE destination pour nouvelle. On refuse.
            print(
                f"--known-destinations : aucune IP lue dans {args.known_destinations} (JSON invalide ou liste vide).",
                file=sys.stderr,
            )
            sys.exit(1)
        known_destinations = frozenset(hosts)
    known_hosts = None
    if args.known_hosts:
        if not args.security_report:
            print("--known-hosts necessite --security-report.", file=sys.stderr)
            sys.exit(1)
        if not os.path.isfile(args.known_hosts):
            print(f"--known-hosts : fichier introuvable : {args.known_hosts}", file=sys.stderr)
            sys.exit(1)
        baseline = load_baseline_hosts(args.known_hosts)
        if not baseline:
            # Meme regle que --known-destinations : une baseline vide ferait
            # passer TOUS les hotes pour nouveaux.
            print(
                f"--known-hosts : aucune IP lue dans {args.known_hosts} (JSON invalide ou liste vide).",
                file=sys.stderr,
            )
            sys.exit(1)
        known_hosts = frozenset(baseline)
    # Meme discipline que --cve-db : echouer tot et clairement plutot que
    # de produire un fichier HTML vide, ou de ne rien ecrire en silence --
    # l'utilisateur croirait avoir un rapport (issue #218).
    if bool(args.siem_export) != bool(args.siem_output):
        print("--siem-export et --siem-output vont ensemble (format + fichier).", file=sys.stderr)
        sys.exit(1)
    if args.siem_export and not args.security_report:
        print("--siem-export necessite --security-report.", file=sys.stderr)
        sys.exit(1)
    notify_extras = [
        opt
        for opt, given in (
            ("--notify-webhook", args.notify_webhook),
            ("--notify-slack", args.notify_slack),
            ("--notify-email", args.notify_email),
            ("--notify-detail", args.notify_detail != "resume"),
            ("--notify-silence", args.notify_silence is not None),
            ("--notify-state", args.notify_state),
        )
        if given
    ]
    if notify_extras and not args.notify_on:
        # jamais un canal sortant active a l'insu de l'utilisateur, et jamais
        # une option ignoree en silence : on le dit
        print(
            f"{', '.join(notify_extras)} sans --notify-on : aucun seuil, aucune notification. "
            "Ajoutez --notify-on critique|elevee|moyenne|faible.",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.notify_on and not args.security_report:
        print("--notify-on necessite --security-report.", file=sys.stderr)
        sys.exit(1)
    if args.notify_silence is not None and args.notify_silence < 0:
        print("--notify-silence doit etre >= 0.", file=sys.stderr)
        sys.exit(1)
    plugin_targets = _parse_plugin_exports(args.plugin_export, plugin_names)
    if args.plugin_path and not plugin_names:
        print("--plugin-path sans --plugins : aucun plugin autorise, rien ne s'executerait.", file=sys.stderr)
        sys.exit(1)
    loaded_plugins = None
    if plugin_names:
        from netcross_core.plugins import load_plugins

        loaded_plugins = load_plugins(plugin_names, args.plugin_path)
        if loaded_plugins.detectors and not args.security_report:
            names = ", ".join(d.name for d in loaded_plugins.detectors)
            print(f"detecteur(s) de plugin {names} : --security-report requis.", file=sys.stderr)
            sys.exit(1)
    if args.security_html and not args.security_report:
        print("--security-html necessite --security-report.", file=sys.stderr)
        sys.exit(1)
    if args.security_report:
        if args.live:
            print(
                "--security-report n'est pas disponible avec --live : les "
                "signatures d'exploits cherchent la charge utile brute, relue "
                "depuis les fichiers --capture (comme --tls).",
                file=sys.stderr,
            )
            sys.exit(1)
        if args.redact:
            print(
                "--security-report n'est pas disponible avec --redact : les "
                "signatures d'exploits cherchent la charge utile brute, jamais "
                "des paquets anonymises.",
                file=sys.stderr,
            )
            sys.exit(1)
        if args.cve_db and not os.path.isfile(args.cve_db):
            # refuser plutot que laisser connect_cve_db creer une base vide,
            # qui correlerait... rien (voir scripts/import_nvd.py).
            print(
                f"base CVE introuvable : {args.cve_db} (aucune base vide n'est "
                "creee -- construire la base avec scripts/import_nvd.py).",
                file=sys.stderr,
            )
            sys.exit(1)

    # --export-pcap est exclusif avec --merge/--split/--replay
    if args.export_pcap and (args.merge or args.split or args.replay):
        print(
            "--export-pcap est exclusif avec --merge/--split/--replay : une seule operation a la fois.",
            file=sys.stderr,
        )
        sys.exit(1)
    if (
        args.export_bpf
        or args.export_time_start is not None
        or args.export_time_end is not None
        or args.export_endpoints
    ) and not args.export_pcap:
        print(
            "--export-bpf/--export-time-start/--export-time-end/--export-endpoints necessitent --export-pcap.",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.merge and args.split:
        print("--merge et --split sont exclusifs : fusionner OU decouper, pas les deux.", file=sys.stderr)
        sys.exit(1)
    if args.replay and (args.merge or args.split):
        print(
            "--replay est exclusif avec --merge/--split : rejouer une seule "
            "operation a la fois (fusionner/decouper d'abord si besoin, dans "
            "une commande separee, puis rejouer le resultat).",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.convert and (args.merge or args.split or args.replay or args.export_pcap or args.adjust_time_output):
        print(
            "--convert est exclusif avec --merge/--split/--replay/--export-pcap/--adjust-time : "
            "une seule operation a la fois.",
            file=sys.stderr,
        )
        sys.exit(1)
    if (args.replay_loop != 1 or args.replay_speed != "1.0") and not args.replay:
        print("--replay-speed/--replay-loop necessitent --replay.", file=sys.stderr)
        sys.exit(1)
    # --adjust-time est exclusif avec les autres modes utilitaires
    if args.adjust_time_output and (args.merge or args.split or args.replay):
        print(
            "--adjust-time est exclusif avec --merge/--split/--replay : une seule operation a la fois.",
            file=sys.stderr,
        )
        sys.exit(1)
    if (args.time_offset is not None or args.normalize_time or args.align_to) and not args.adjust_time_output:
        print(
            "--time-offset/--normalize-time/--align-to necessitent --adjust-time-output.",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.merge_dedup and not args.merge:
        print("--merge-dedup necessite --merge.", file=sys.stderr)
        sys.exit(1)
    if args.merge:
        if not args.capture:
            print("--merge necessite --capture (fichiers a fusionner), pas --live.", file=sys.stderr)
            sys.exit(1)
        # --merge n'analyse rien : une option d'analyse/de rapport passee en
        # meme temps serait ignoree en silence, on la refuse plutot.
        ignored = [
            flag
            for flag, given in (
                ("--pdf-report", args.pdf_report),
                ("--json-report", args.json_report),
                ("--flow-timeline", args.flow_timeline),
                ("--tshark-stats", args.tshark_stats),
                ("--forensic-search", args.forensic_search),
                ("--detail-csv", args.detail_csv),
                ("--history-db", args.history_db),
                ("--client-group", args.client_group),
                ("--redact", args.redact),
                ("--triage", args.triage),
                ("--tls", args.tls),
                ("--quic", args.quic),
                ("--security-report", args.security_report),
                ("--cve-db", args.cve_db),
                ("--media-quality", args.media_quality),
                ("--extract-contents", args.extract_contents),
                ("--parallel", args.parallel),
                ("--max-packets", args.max_packets),
                ("--sample", args.sample),
            )
            if given
        ]
        if ignored:
            print(
                f"--merge fusionne les fichiers sans lancer d'analyse : incompatible avec {', '.join(ignored)}.",
                file=sys.stderr,
            )
            sys.exit(1)
        _run_merge(args.capture, args.merge, args.merge_dedup)
        return

    if args.convert:
        if not args.capture:
            print("--convert necessite --capture (fichier source).", file=sys.stderr)
            sys.exit(1)
        if args.live:
            print("--convert convertit un fichier (--capture) : incompatible avec --live.", file=sys.stderr)
            sys.exit(1)
        # --convert est un mode utilitaire qui s'arrete apres la conversion :
        # toute autre option (analyse, rapport...) serait silencieusement ignoree.
        ignored = sorted(
            flag
            for flag, given in (
                ("--pdf-report", args.pdf_report),
                ("--json-report", args.json_report),
                ("--flow-timeline", args.flow_timeline),
                ("--tshark-stats", args.tshark_stats),
                ("--forensic-search", args.forensic_search),
                ("--detail-csv", args.detail_csv),
                ("--history-db", args.history_db),
                ("--client-group", args.client_group),
                ("--redact", args.redact),
                ("--triage", args.triage),
                ("--tls", args.tls),
                ("--quic", args.quic),
                ("--security-report", args.security_report),
                ("--cve-db", args.cve_db),
                ("--media-quality", args.media_quality),
                ("--extract-contents", args.extract_contents),
                ("--parallel", args.parallel),
                ("--max-packets", args.max_packets),
                ("--sample", args.sample),
            )
            if given
        )
        if ignored:
            print(
                f"--convert convertit le fichier sans lancer d'analyse : incompatible avec {', '.join(ignored)}.",
                file=sys.stderr,
            )
            sys.exit(1)
        _run_convert(args.capture, args.convert, args.convert_format)
        return

    if args.split_output_dir and not args.split:
        print("--split-output-dir necessite --split.", file=sys.stderr)
        sys.exit(1)
    if args.split:
        if args.live:
            print("--split decoupe des fichiers (--capture) : incompatible avec --live.", file=sys.stderr)
            sys.exit(1)
        # --split est un mode utilitaire qui s'arrete apres le decoupage : toute
        # autre option (analyse, rapport...) serait silencieusement ignoree, on
        # la refuse plutot que de laisser croire qu'elle a agi.
        ignored = sorted(
            "--" + dest.replace("_", "-")
            for dest, value in vars(args).items()
            if dest not in ("capture", "split", "split_output_dir") and value != ap.get_default(dest)
        )
        if ignored:
            print(
                f"--split ne lance aucune analyse : option(s) incompatible(s) {', '.join(ignored)}. "
                "Decouper d'abord, puis analyser les segments dans une seconde commande.",
                file=sys.stderr,
            )
            sys.exit(1)
        sys.exit(_run_split(args.capture, args.split, args.split_output_dir or _SPLIT_DEFAULT_DIR))

    if args.export_pcap:
        if not args.capture:
            print("--export-pcap necessite --capture (fichier source), pas --live.", file=sys.stderr)
            sys.exit(1)
        # --export-pcap est un mode utilitaire comme --merge/--split : toute
        # option d'analyse serait silencieusement ignoree, on la refuse.
        ignored = sorted(
            "--" + dest.replace("_", "-")
            for dest, value in vars(args).items()
            if dest
            not in (
                "capture",
                "export_pcap",
                "export_bpf",
                "export_time_start",
                "export_time_end",
                "export_endpoints",
            )
            and value != ap.get_default(dest)
        )
        if ignored:
            print(
                f"--export-pcap ne lance aucune analyse : option(s) incompatible(s) {', '.join(ignored)}. "
                "Exporter d'abord, puis analyser le resultat dans une seconde commande.",
                file=sys.stderr,
            )
            sys.exit(1)
        endpoints = None
        if args.export_endpoints:
            endpoints = [ip.strip() for ip in args.export_endpoints.split(",") if ip.strip()]
        sys.exit(
            _run_export(
                args.capture,
                args.export_pcap,
                args.export_bpf,
                args.export_time_start,
                args.export_time_end,
                endpoints,
            )
        )

    if args.replay:
        if not args.capture:
            print("--replay necessite --capture (fichier a rejouer), pas --live.", file=sys.stderr)
            sys.exit(1)
        # --replay n'analyse rien : une option d'analyse/de rapport passee en
        # meme temps serait ignoree en silence, on la refuse plutot (meme
        # discipline que --merge/--split ci-dessus).
        ignored = [
            flag
            for flag, given in (
                ("--pdf-report", args.pdf_report),
                ("--json-report", args.json_report),
                ("--flow-timeline", args.flow_timeline),
                ("--tshark-stats", args.tshark_stats),
                ("--forensic-search", args.forensic_search),
                ("--detail-csv", args.detail_csv),
                ("--history-db", args.history_db),
                ("--client-group", args.client_group),
                ("--redact", args.redact),
                ("--triage", args.triage),
                ("--tls", args.tls),
                ("--quic", args.quic),
                ("--security-report", args.security_report),
                ("--cve-db", args.cve_db),
                ("--media-quality", args.media_quality),
                ("--extract-contents", args.extract_contents),
                ("--parallel", args.parallel),
                ("--max-packets", args.max_packets),
                ("--sample", args.sample),
            )
            if given
        ]
        if ignored:
            print(
                f"--replay rejoue un fichier sans lancer d'analyse : incompatible avec {', '.join(ignored)}.",
                file=sys.stderr,
            )
            sys.exit(1)
        _run_replay(args.capture, args.replay, args.replay_speed, args.replay_loop)
        return

    if args.adjust_time_output:
        if not args.capture:
            print("--adjust-time necessite --capture (fichier source), pas --live.", file=sys.stderr)
            sys.exit(1)
        # --adjust-time est un mode utilitaire : toute option d'analyse
        # serait silencieusement ignoree, on la refuse.
        ignored = sorted(
            "--" + dest.replace("_", "-")
            for dest, value in vars(args).items()
            if dest
            not in (
                "capture",
                "adjust_time_output",
                "time_offset",
                "normalize_time",
                "align_to",
            )
            and value != ap.get_default(dest)
        )
        if ignored:
            print(
                f"--adjust-time ne lance aucune analyse : option(s) incompatible(s) {', '.join(ignored)}. "
                "Ajuster d'abord, puis analyser le resultat dans une seconde commande.",
                file=sys.stderr,
            )
            sys.exit(1)
        # Verifier qu'un seul mode est fourni
        modes = [
            args.time_offset is not None,
            args.normalize_time,
            args.align_to is not None,
        ]
        if sum(modes) > 1:
            print(
                "--time-offset, --normalize-time et --align-to sont mutuellement exclusifs.",
                file=sys.stderr,
            )
            sys.exit(1)
        sys.exit(
            _run_adjust_time(
                args.capture,
                args.adjust_time_output,
                args.time_offset or 0.0,
                args.normalize_time,
                args.align_to,
            )
        )

    # Table des noms (section 6.15) : optionnelle, chargee une fois pour
    # toutes les sorties (CSV detail + JSON). None si --names absent.
    names = None
    if args.names:
        from netcross_core.naming import NameTable

        names = NameTable.load(args.names)
        print(f"Table des noms chargee : {len(names)} entree(s) depuis {args.names}")
    if args.live:
        if args.parallel:
            print(
                "--parallel n'a pas de sens avec --live (deja un thread par point, en parallele).",
                file=sys.stderr,
            )
            sys.exit(1)
        if args.tls or args.quic:
            print(
                "--tls/--quic ne sont pas disponibles avec --live : ils relisent "
                "les fichiers passes a --capture avec un pipeline de decodage "
                "independant, ce qui n'existe pas (encore) pour une capture en "
                "direct. Meme limitation assumee que sur l'interface graphique.",
                file=sys.stderr,
            )
            sys.exit(1)

    ai_options = _check_ai_args(args)
    if args.redact_map and not args.redact:
        print("--redact-map necessite --redact.", file=sys.stderr)
        sys.exit(1)
    extract_kinds = _check_extraction_args(args)
    _check_live_report_args(args)
    if args.redact and (args.tls or args.quic or args.client_group):
        print(
            "--redact n'est pas disponible avec --tls/--quic/--client-group : ces "
            "trois options relisent les fichiers passes a --capture avec leur "
            "propre pipeline (--tls/--quic), ou recoivent des adresses IP reelles "
            "directement en argument (--client-group), independamment des "
            "paquets anonymises par --redact -- les combiner laisserait filtrer "
            "des adresses reelles dans une partie du rapport sans le signaler. "
            "Voir netcross_core.redact pour le detail.",
            file=sys.stderr,
        )
        sys.exit(1)

    if (args.history_label or args.history_show is not None) and not args.history_db:
        print("--history-label/--history-show necessitent --history-db.", file=sys.stderr)
        sys.exit(1)

    # --support-ticket (issue #269) : le consentement est une PRECONDITION,
    # pas un avertissement -- sans --support-consent, on ne construit meme
    # pas le ticket, donc rien ne peut fuiter par accident.
    support_consent = _build_support_consent(args)
    support_markers = _parse_support_markers(args.support_marker)
    if args.support_ticket:
        install_crash_handler(args.support_ticket, support_consent, markers=support_markers)

    client_group = None
    if args.client_group:
        client_group = {}
        for spec in args.client_group:
            name, ips = _parse_client_group_spec(spec)
            client_group.setdefault(name, set()).update(ips)
        if len(client_group) < 2:
            print(
                "--client-group necessite au moins 2 clients distincts pour produire une comparaison "
                f"(un seul fourni : {', '.join(client_group)}).",
                file=sys.stderr,
            )
            sys.exit(1)
        if args.client_reference and args.client_reference not in client_group:
            print(
                f"--client-reference {args.client_reference!r} ne correspond a aucun --client-group fourni "
                f"(clients disponibles : {', '.join(sorted(client_group))}).",
                file=sys.stderr,
            )
            sys.exit(1)
    elif args.client_reference or args.client_diff_csv:
        print(
            "--client-reference/--client-diff-csv necessitent au moins deux --client-group.",
            file=sys.stderr,
        )
        sys.exit(1)

    captures = []
    for c in args.capture or []:
        label, paths = _parse_capture_spec(c, "--capture")
        captures.extend((label, path) for path in paths)

    # Avertissement memoire (issue #283, Etape 2) : AVANT toute lecture de
    # paquets -- une fois parse_capture() lance sur une capture trop
    # volumineuse, il est deja trop tard (c'est precisement le moment ou
    # l'OOM-killer intervient). Sans effet avec --live (rien a lire dans un
    # fichier existant, capinfos n'a pas de sens sur une interface).
    if captures and not args.live:
        _check_memory_before_analysis(captures)

    sample_n = _parse_sample_spec(args.sample) if args.sample else None

    all_packets = []
    if args.live:
        reporter, server = _start_live_report(args)
        try:
            all_packets = _run_live_captures(args.live, args.live_duration, reporter)
        finally:
            if server is not None:
                server.shutdown()
        print(f"\n{len(all_packets)} paquet(s) captures au total, analyse en cours...")
    elif args.parallel:
        _cpu_count = os.cpu_count() or 1
        _effective_workers = args.parallel_workers or _cpu_count
        print(
            f"--parallel : {_effective_workers} worker(s) effectif(s) (os.cpu_count()={_cpu_count} sur cette machine)."
        )
        if _effective_workers <= 1:
            print(
                "  Avec un seul worker effectif, aucun gain de temps reel n'est a "
                "attendre par rapport a une lecture sequentielle -- seulement le "
                "cout de mise en place du pool de processus. Le parallelisme "
                "n'aide que sur un hote disposant de plusieurs coeurs CPU "
                "disponibles."
            )
        elif args.parallel_workers and args.parallel_workers > _cpu_count:
            print(
                f"  ATTENTION : {args.parallel_workers} workers demandes pour "
                f"{_cpu_count} coeur(s) CPU disponible(s) -- au-dela du nombre "
                "de coeurs, les processus tshark se disputent le CPU au lieu "
                "de s'executer reellement en parallele, ce qui peut ralentir "
                "la lecture de chaque fichier individuellement plutot que "
                "l'accelerer."
            )
        all_packets, per_file_stats = parse_captures_parallel(captures, args.parallel_workers)
        # chaque fichier est rapporte explicitement, succes ou echec -- rien
        # ne doit pouvoir passer sous silence derriere un total agrege
        any_error = False
        for s in per_file_stats:
            if s["error"]:
                any_error = True
                print(
                    f"[{s['label']}] ECHEC sur {s['path']} : {s['error']}",
                    file=sys.stderr,
                )
            else:
                print(f"[{s['label']}] {s['count']} paquets charges depuis {s['path']} ({s['seconds']:.2f}s)")
        total_seconds = sum(s["seconds"] for s in per_file_stats if s["seconds"] is not None)
        print(
            f"Temps de lecture cumule (somme des fichiers) : {total_seconds:.2f}s "
            f"-- temps reel ecoule inferieur si le parallelisme a effectivement joue "
            f"(depend du nombre de coeurs disponibles)"
        )
        if any_error:
            print(
                "\nATTENTION : au moins un fichier n'a pas pu etre lu (voir ECHEC "
                "ci-dessus) -- l'analyse continue sur les fichiers restants, mais le "
                "resultat est incomplet.",
                file=sys.stderr,
            )
    else:
        # Meme exigence de tracabilite que la branche --parallel ci-dessus :
        # chaque fichier est rapporte, succes ou echec. Avant l'issue #287,
        # cette branche -- qui est la branche PAR DEFAUT -- se contentait de
        # `parse_capture(label, path)`, qui avale l'erreur et renvoie une liste
        # vide : la sortie affichait alors "[A] 0 paquets charges", strictement
        # indistinguable d'une capture legitimement sans trafic IP, et le
        # resume ATTENTION n'existait que pour --parallel. Un fichier
        # introuvable passait donc pour une capture vide sur le chemin le plus
        # emprunte. raise_on_error=True rend l'echec visible ici.
        any_error = False
        for label, path in captures:
            try:
                pkts = parse_capture(label, path, raise_on_error=True)
            except (TsharkNotFoundError, TsharkError) as exc:
                logger.exception(f"échec dans main: {exc}")
                any_error = True
                print(f"[{label}] ECHEC sur {path} : {exc}", file=sys.stderr)
                continue
            print(f"[{label}] {len(pkts)} paquets IP/TCP/UDP/ICMP charges depuis {path}")
            all_packets.extend(pkts)
        if any_error:
            print(
                "\nATTENTION : au moins un fichier n'a pas pu etre lu (voir ECHEC "
                "ci-dessus) -- l'analyse continue sur les fichiers restants, mais le "
                "resultat est incomplet.",
                file=sys.stderr,
            )

    # CVE-2 (issue #136, pour --security-report) : les signatures d'exploits
    # cherchent la charge utile BRUTE, que Pkt ne garde pas -- relecture de
    # chaque fichier passe a --capture, independante du mode de chargement
    # ci-dessus (sequentiel ou --parallel, comme --tls).
    security_detections = []
    if args.security_report:
        for label, path in captures:
            detections = security_findings.scan_capture_exploits(label, path)
            print(f"[{label}] {len(detections)} signature(s) d'exploit detectee(s) dans {path}")
            security_detections.extend(detections)

    if args.redact:
        redactor = redact_packets(all_packets)
        print(f"\n{len(redactor)} adresse(s) anonymisee(s) (IP/MAC) avant analyse.")
        if args.redact_map:
            write_redaction_map_csv(redactor, args.redact_map)
            print(
                f"Correspondance adresse reelle <-> pseudonyme ecrite dans {args.redact_map} "
                "(a conserver en prive, ne pas transmettre avec le rapport)."
            )

    # --max-packets/--sample (issue #283, Etape 3) : appliques ici, sur
    # all_packets DEJA CHARGE en entier (voir _apply_packet_limits pour la
    # justification -- limiter la LECTURE elle-meme est hors perimetre de
    # cette PR), AVANT la detection de doublons et la correlation, pour que
    # tout l'aval (flows, Report, --detail-csv, --json-report...) voie la
    # meme population reduite -- une troncature appliquee seulement au
    # rendu final laisserait les compteurs intermediaires incoherents avec
    # le rapport affiche.
    truncation_note = None
    if args.max_packets is not None or sample_n:
        all_packets, truncation_note = _apply_packet_limits(all_packets, args.max_packets, sample_n)
        if truncation_note:
            print(f"\nATTENTION : {truncation_note}", file=sys.stderr)

    points_order = args.order.split(",") if args.order else None
    duplicate_counts = None
    if args.detect_duplicates or args.exclude_duplicates:
        if args.duplicate_threshold_ms < 0:
            print("--duplicate-threshold-ms doit etre >= 0.", file=sys.stderr)
            sys.exit(1)
        duplicate_counts = detect_cross_capture_duplicates(all_packets, args.duplicate_threshold_ms)
        print(
            f"\nDoublons inter-captures : {sum(duplicate_counts.values())} paquet(s) "
            f"detecte(s) (seuil {args.duplicate_threshold_ms:g}ms)."
        )
    if args.exclude_duplicates:
        # Depouille la liste UNE fois ici pour que TOUT l'aval (comparaison
        # client, session objects, signaux d'expertise tshark...) voie la
        # meme population que correlate()/analyse() -- pas seulement le
        # rapport principal. exclude_duplicates est quand meme transmis
        # plus bas : c'est lui qui renseigne Report.duplicates_excluded.
        all_packets = [pk for pk in all_packets if not pk.is_duplicate]
    flows = correlate(all_packets, args.nat_tolerant, args.nat_window_ms, args.exclude_duplicates)
    r = analyse(
        flows,
        points_order,
        all_packets,
        args.bucket_ms / 1000.0,
        args.nat_tolerant,
        args.rtp_clock_rate,
        args.topn_charts,
        idle_timeout_seconds=args.idle_timeout_seconds,
        exclude_duplicates=args.exclude_duplicates,
        duplicate_counts=duplicate_counts,
    )
    # Commentaires de SECTION pcapng (Job 39/issue #159) -- lus ici, au
    # dernier moment avant le rendu : metadonnee de fichier, pas de paquet,
    # donc remplie par l'appelant (voir Report.capture_comments) et pas par
    # analyse(). Ne leve jamais et ne produit rien sur un pcap classique ou
    # un pcapng sans commentaire de section.
    if captures:
        r.capture_comments = read_capture_comments(captures)
        r.capture_infos = read_capture_infos(captures)
    # Report.truncated/truncation_note (issue #283, Etape 3) : ecrit ici, pas
    # dans analyse() -- meme discipline que capture_comments/capture_infos
    # ci-dessus, la troncature est une decision de l'appelant (CLI), pas un
    # resultat de l'analyse elle-meme. Une troncature silencieuse produirait
    # un rapport FAUX (l'analyste croirait couvrir toute la capture) : le
    # critere d'acceptation de l'issue #283 l'exige explicitement.
    if truncation_note:
        r.truncated = True
        r.truncation_note = truncation_note
    print_report(r)
    if r.truncated:
        print(f"\nATTENTION : {r.truncation_note}")

    # --security-report (issue #139) : consolidation des quatre detecteurs
    # (CVE-1 a CVE-4) sur le rapport deja rempli par analyse(), puis rendu
    # dedie -- voir docs/security-report.md. Sans --cve-db, base minimale
    # embarquee (issue #353) ; cve_conn ne reste None que si elle est illisible :
    # les services sont listes sans correlation CVE, et l'absence de base est
    # signalee pour ne pas laisser croire a une absence de vulnerabilite.
    # Reste None si --security-report n'est pas demande, ou si l'analyse de
    # securite echoue : les sorties PDF/JSON/HTML s'appuient dessus pour
    # distinguer "pas d'analyse de securite" de "analyse faite, rien trouve"
    # (issue #218).
    security_report_obj = None
    if args.security_report:
        cve_conn = connect_cve_db(args.cve_db) if args.cve_db else None
        if cve_conn is None:
            # issue #353 : filet de securite sans configuration -- quelques CVE
            # critiques (NVD) sur les produits catalogues, chargees en memoire.
            try:
                cve_conn, cve_seed = open_seed_db()
            except (OSError, ValueError) as exc:
                logger.warning("base CVE embarquée illisible, corrélation CVE désactivée : {}", exc)
                print(
                    f"Aucune base CVE fournie (--cve-db) et base embarquee illisible ({exc}) : "
                    "services listes sans correlation CVE."
                )
            else:
                print(
                    f"Aucune base CVE fournie (--cve-db) : base minimale embarquee utilisee "
                    f"({len(cve_seed.entries)} CVE critiques, NVD {cve_seed.generated}). "
                    "Une version absente de cette selection n'est PAS pour autant non vulnerable : "
                    "construire une base complete avec scripts/import_nvd.py."
                )
        try:
            security_findings.apply_security_findings(
                r,
                all_packets,
                detections=security_detections,
                cve_conn=cve_conn,
                known_destinations=known_destinations,
                known_hosts=known_hosts,
                treat_test_net_as_external=args.test_net_external,
            )
            # Conserve pour les sorties PDF/JSON/HTML (issue #218) :
            # jusqu'ici l'objet etait construit, imprime, puis perdu -- les
            # constats de securite n'atteignaient donc aucune sortie
            # machine, meme quand --json-report etait demande.
            if loaded_plugins is not None:
                from netcross_core.plugins import load_error_runs, run_detectors

                r.plugin_runs += load_error_runs(loaded_plugins.errors)
                r.plugin_runs += run_detectors(loaded_plugins.detectors, all_packets, r)
            security_report_obj = build_security_report(r)
            if args.notify_on:
                security_report_obj.notifications = _send_notifications(args, r, security_report_obj)
            print_security_report(security_report_obj)
            if args.security_html:
                from netcross_report.security_html import generate_security_html

                generate_security_html(
                    security_report_obj,
                    args.security_html,
                    meta={"Anonymisation": "adresses IP/MAC anonymisees (--redact)"} if args.redact else None,
                )
                print(f"Rapport de securite HTML ecrit dans {args.security_html}")
            if args.siem_export:
                from netcross_report.siem_export import write_siem

                # bornes de la capture : datent les objets STIX (jamais
                # l'heure de l'export -- determinisme, issue #279)
                timestamps = [p.ts for p in all_packets if p.ts]
                bounds = (
                    (
                        datetime.fromtimestamp(min(timestamps), tz=timezone.utc),
                        datetime.fromtimestamp(max(timestamps), tz=timezone.utc),
                    )
                    if timestamps
                    else (None, None)
                )
                written = write_siem(
                    r, args.siem_output, args.siem_export, observed_from=bounds[0], observed_until=bounds[1]
                )
                print(f"Export SIEM ({args.siem_export}) ecrit dans {written}")
        finally:
            # issue #217 (suite PR #212) : close_db() dans un finally pour
            # garantir la fermeture de la connexion SQLite meme si
            # apply_security_findings()/le rendu du rapport levent une
            # exception -- sans consequence fonctionnelle immediate (le
            # process se termine de toute facon) mais nuit a la robustesse
            # sinon (ressource SQLite laissee ouverte).
            if cve_conn is not None:
                close_db(cve_conn)

    if ai_options is not None:
        _run_ai(args, ai_options, r, all_packets)

    if client_group:
        comparison = compare_clients(
            all_packets,
            client_group,
            reference=args.client_reference,
            points_order=points_order,
            bucket_seconds=args.bucket_ms / 1000.0,
            nat_tolerant=args.nat_tolerant,
            nat_window_ms=args.nat_window_ms,
            rtp_clock_rate=args.rtp_clock_rate,
        )
        print_client_comparison(comparison)
        if args.client_diff_csv:
            write_client_diff_csv(comparison, args.client_diff_csv)
            print(f"\nDetail de la comparaison client vs client ecrit dans {args.client_diff_csv}")

    findings = None
    tls_findings = None
    quic_findings = None
    if args.triage or args.pdf_report or args.json_report or args.history_db or args.expert_section:
        # calcule dans tous les cas si --pdf-report/--json-report/--history-db :
        # les trois integrent desormais le meme classement en tete (voir
        # netcross_report.pdf / netcross_report.json_report / netcross_report.history)
        from netcross_report import build_findings, format_health_line, health_score, print_triage, rank_segments

        findings = build_findings(r)
        if args.triage:
            ranked = rank_segments(findings)
            print_triage(ranked, args.triage_top_n)
            print(format_health_line(health_score(ranked)))

    rule_engine_findings = None
    if args.rule_engine:
        from netcross_report import available_rule_ids, evaluate

        rule_engine_findings = {}
        total = 0
        print("\n" + "=" * 70)
        print("MOTEUR DE REGLES DECLARATIF (rule_engine)")
        print("=" * 70)
        for rule_id in available_rule_ids():
            rule_findings = evaluate(rule_id, r)
            rule_engine_findings[rule_id] = rule_findings
            if rule_findings:
                total += len(rule_findings)
                for f in rule_findings:
                    print(f"  [{f.severity}] {f.category} / {f.segment} -- {f.message}")
        print(f"\n{len(available_rule_ids())} regles evaluees, {total} Finding produits.")
        if not args.json_report:
            print("(utilisez --json-report pour obtenir la sortie JSON structuree)")

    if args.tls or args.quic:
        print("\n" + "=" * 70)
        print("DIAGNOSTICS TLS/QUIC (pipeline de decodage independant, relit les memes fichiers)")
        print("=" * 70)

    if args.tls:
        from netcross_core.tls_diagnostics import (
            build_handshake_status,
            diagnose_tls,
            parse_tls_capture,
            print_tls_diagnostics,
        )

        tls_events = []
        for label, path in captures:
            events = parse_tls_capture(label, path)
            print(f"[{label}] {len(events)} evenements TLS trouves dans {path}")
            tls_events.extend(events)
        status_by_point = build_handshake_status(tls_events)
        tls_findings = diagnose_tls(status_by_point, r.points)
        print_tls_diagnostics(tls_findings)

    if args.quic:
        try:
            from netcross_core.quic_diagnostics import (
                diagnose_quic,
                parse_quic_capture,
                print_quic_diagnostics,
            )
        except ImportError:
            logger.debug("dépendance optionnelle absente: ImportError")
            print(
                "\n--quic necessite cryptography : pip install cryptography --break-system-packages",
                file=sys.stderr,
            )
            sys.exit(1)
        quic_events = []
        for label, path in captures:
            events = parse_quic_capture(label, path)
            print(f"[{label}] {len(events)} paquets QUIC Initial trouves dans {path}")
            quic_events.extend(events)
        quic_findings = diagnose_quic(quic_events, r.points)
        print_quic_diagnostics(quic_findings)

    if args.media_quality or args.extract_contents:
        _run_content_extraction(captures, args.extract_contents, extract_kinds)

    if args.detail_csv:
        write_detail_csv(args.detail_csv, flows, r.points, names=names)
        print(f"\nDetail par flux ecrit dans {args.detail_csv}")

    # Objets de contrat de la Session 0 (FEATURES.md section 13.3) --
    # construits UNE fois ici, puis partages par la console
    # (--expert-section), le PDF et le JSON. Avant l'issue #13, ce bloc
    # vivait sous `if args.json_report:` et n'etait donc visible que la :
    # voir netcross_report.session_objects pour l'extraction (meme
    # sequence d'appels, aucun calcul nouveau).
    session_objects = None
    if args.expert_section or args.pdf_report or args.json_report:
        from netcross_report.session_objects import build_session_objects, print_session_objects

        session_objects = build_session_objects(r, findings, flows, all_packets)
        if args.expert_section:
            print()
            print_session_objects(session_objects)

    # Vues de sequence (Job 14/issue #11) : construites seulement si un PDF
    # est demande ET l'option passee -- elles repartent des Pkt bruts deja
    # groupes par correlate(), donc aucun reparse, mais aucune raison de les
    # calculer pour rien.
    sequence_views = None
    if args.sequence_diagram and args.pdf_report:
        from netcross_report.sequence_view import top_flow_views

        sequence_views = top_flow_views(
            flows,
            flow_objects=session_objects.flows if session_objects else None,
            max_flows=args.sequence_diagram,
        )

    if args.pdf_report:
        try:
            from netcross_report import generate_pdf
        except ImportError:
            logger.debug("dépendance optionnelle absente: ImportError")
            generate_pdf = None
        if generate_pdf is None:
            print(
                "\n--pdf-report necessite reportlab, matplotlib et networkx : "
                "pip install reportlab matplotlib networkx --break-system-packages",
                file=sys.stderr,
            )
            sys.exit(1)
        generate_pdf(
            r,
            args.pdf_report,
            findings=findings,
            security_report=security_report_obj,
            tls_findings=tls_findings,
            quic_findings=quic_findings,
            session_objects=session_objects,
            sequence_views=sequence_views,
            meta={"Anonymisation": "adresses IP/MAC anonymisees (--redact)"} if args.redact else None,
        )
        print(f"Rapport PDF ecrit dans {args.pdf_report}")

    if loaded_plugins is not None:
        from netcross_core.plugins import load_error_runs, run_exporters

        if not args.security_report:
            # sinon deja traces dans le rapport de securite
            r.plugin_runs += load_error_runs(loaded_plugins.errors)
            for run in r.plugin_runs:
                print(f"Plugins : {run['line']}")
        for run in run_exporters(loaded_plugins.exporters, plugin_targets, r):
            r.plugin_runs.append(run)
            print(f"Plugins : {run['line']}")

    if args.json_report:
        from netcross_report import generate_json_report

        # Memes objets que ci-dessus (construits une seule fois) : les
        # cles JSON produites sont inchangees par rapport aux sessions
        # precedentes -- voir netcross_report.session_objects.json_kwargs().
        generate_json_report(
            r,
            args.json_report,
            findings=findings,
            security_report=security_report_obj,
            tls_findings=tls_findings,
            quic_findings=quic_findings,
            rule_engine_findings=rule_engine_findings,
            meta={"Anonymisation": "adresses IP/MAC anonymisees (--redact)"} if args.redact else None,
            names=names,
            **session_objects.json_kwargs(),
        )
        print(f"Rapport JSON ecrit dans {args.json_report}")

    # Issues #359/#360/#361 : sorties JSON d'analyse avancee
    if args.flow_timeline:
        _write_json_output(
            args.flow_timeline,
            build_flow_timelines(all_packets, window_s=args.flow_timeline_window),
            "Chronologie des flux",
        )
    if args.tshark_stats:
        _write_json_output(args.tshark_stats, _collect_tshark_stats(captures), "Statistiques tshark")
    if args.forensic_search:
        _run_forensic_search(args, all_packets, flows)

    if args.history_db:
        from netcross_report import HistoryDatabaseError, list_history, print_history, record_run

        # L'historique est ecrit a la FIN du run : un --history-db pointant sur
        # un fichier qui n'est pas une base netcross faisait perdre toute
        # l'analyse sur une trace sqlite3 brute (issue #287). Le message nomme
        # le chemin, et le run reste un echec explicite -- ecrire "analyse
        # terminee" alors que la trace demandee n'a pas ete conservee serait
        # pire que l'erreur.
        try:
            record_run(
                r,
                args.history_db,
                findings=findings,
                tls_findings=tls_findings,
                quic_findings=quic_findings,
                meta={"Anonymisation": "adresses IP/MAC anonymisees (--redact)"} if args.redact else None,
                label=args.history_label,
            )
            label_txt = f" (etiquette: {args.history_label})" if args.history_label else ""
            print(f"\nResume de ce run enregistre dans l'historique {args.history_db}{label_txt}.")
            if args.history_show is not None:
                entries = list_history(args.history_db, limit=args.history_show, label=args.history_label)
                print_history(entries)
        except HistoryDatabaseError as exc:
            logger.exception(f"échec dans main: {exc}")
            print(exc, file=sys.stderr)
            sys.exit(1)

    # --support-ticket (issue #269) : le run s'est termine SANS crash (le
    # gestionnaire installe plus haut aurait pris la main sinon), donc le
    # ticket produit ici est de nature "diagnostic". Il est ecrit meme
    # lorsque tout va bien : c'est precisement la regle de tracabilite du
    # projet -- attester explicitement du bon fonctionnement plutot que de
    # n'ecrire que lorsque ca casse (docs/quality/traceability-rule.md).
    if args.support_ticket:
        scrubber = TextScrubber()
        ticket = build_ticket(
            consent=support_consent,
            kind="diagnostic",
            markers=support_markers,
            log_lines=[
                f"captures analysees : {len(args.capture or [])}",
                f"interfaces live : {len(args.live or [])}",
                f"anonymisation des adresses (--redact) : {'oui' if args.redact else 'non'}",
            ],
            scrubber=scrubber,
        )
        write_ticket(ticket, args.support_ticket)
        print(f"\nTicket de support anonymise ecrit : {args.support_ticket}")
        print(
            "  nature : diagnostic (aucun incident) -- "
            f"{ticket.anonymization['total_occurrences']} occurrence(s) redigee(s)"
        )
        if args.support_map:
            write_support_map_csv(scrubber, args.support_map)
            print(f"  correspondance privee : {args.support_map} (a NE PAS transmettre avec le ticket)")


if __name__ == "__main__":
    main()
