"""
netcross_gtk4.analysis_pipeline -- pipeline d'analyse extrait de MainWindow
(issue #246, #285 -- lot supplémentaire).

Le thread d'analyse (MainWindow._run_analysis_thread) mélangeait logique
métier (chargement des paquets, corrélation, analyse, diagnostics) et
appels GLib.idle_add pour la mise à jour de l'interface. Ce module porte
toute la logique vérifiable, sans aucune dépendance GTK : le thread de
la fenêtre ne fait que l'appeler avec un callback de progression.

Le pipeline est une fonction pure : mêmes entrées -> mêmes sorties, aucun
effet de bord sur l'interface. Le callback `on_progress` remplace les
GLib.idle_add(self._log, ...) du code original.
"""

from __future__ import annotations

import atexit
import contextlib
import io
import os
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Callable

from netcross_core.correlate import correlate
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Report
from netcross_core.parsing import parse_capture
from netcross_core.report_text import print_report
from netcross_core.wireshark_expert import build_wireshark_expert_events
from netcross_gtk4 import capture_list
from netcross_gtk4.advanced_options import AdvancedSettings, load_host_set, workers_note
from netcross_gtk4.advanced_options import validate as validate_advanced
from netcross_gtk4.expertise_view import (
    ExpertiseExports,
    ExpertiseSettings,
    timeline_summary,
    tshark_stats_summary,
    validate_settings,
)
from netcross_gtk4.notifications import NotifySettings, send_notifications
from netcross_gtk4.report_exports import HistorySettings, ReportContext, record_history
from netcross_report.security_report import build_security_report, print_security_report
from netcross_report.siem_export import observed_bounds

logger = get_logger(__name__)


@dataclass
class AnalysisOptions:
    """Options du pipeline d'analyse, miroir des checkboxes de la GUI."""

    bucket_ms: float = 1000.0
    rtp_rate: int = 8000
    nat_tolerant: bool = False
    # Issue #330 (écart 3) : réglages fins, même sens que --nat-window-ms et
    # --idle-timeout-seconds (None = défaut du cœur, 60 s)
    nat_window_ms: float = 200.0
    idle_timeout_seconds: float | None = None
    parallel: bool = True
    auto_topology: bool = True
    triage: bool = False
    triage_topn: int = 10
    tls: bool = False
    quic: bool = False
    # Issue #357 : analyse de securite (detecteurs, signatures d'exploit, CVE)
    security: bool = False
    redact: bool = False
    topn: int = 25
    detect_duplicates: bool = False
    exclude_duplicates: bool = False
    duplicate_threshold_ms: float = 2.0
    # Issue #474 lot 2 : un point par interface d'un pcapng (--split-interfaces)
    split_interfaces: bool = False
    # Issue #675 : index de recherche forensic (--forensic-search), construit
    # ici pendant que les paquets sont encore en memoire
    forensic_index: bool = False
    # Issue #675 : comparaison de postes (--client-group, --client-reference)
    client_groups: dict | None = None
    client_reference: str | None = None
    # Issue #676 : notifications (webhook, Slack, courriel) sur le rapport de
    # securite, comme --notify-on de la CLI. None ou sans seuil : aucune.
    notify: NotifySettings | None = None
    # Issue #673 : sections d'expertise (--rule-engine, --expert-section,
    # --media-quality, --tshark-stats, --flow-timeline)
    expertise: ExpertiseSettings | None = None
    # Issue #672 : options avancees (--max-packets, --sample,
    # --parallel-workers, --test-net-external, --known-*, --cve-db)
    advanced: AdvancedSettings | None = None
    # Issue #674 : historique SQLite (--history-db, --history-label)
    history: HistorySettings | None = None


@dataclass
class AnalysisResult:
    """Résultat du pipeline d'analyse, transmis à MainWindow._on_analysis_done."""

    mode: str = "single"
    report: Report | None = None
    flows: list = field(default_factory=list)
    findings: list | None = None
    text: str = ""
    tls_findings: list | None = None
    quic_findings: list | None = None
    wireshark_expert_events: list = field(default_factory=list)
    # Issue #357 : rapport de securite structure (SecurityReport), None si
    # l'analyse de securite n'a pas ete demandee -- meme objet que celui de
    # --security-report, pour les exports JSON/PDF/HTML de la GUI
    security_report: Any = None
    # Issue #675 : ForensicSearchIndex, None sans « Index de recherche forensic »
    search_index: Any = None
    # Issue #675 : ClientComparisonResult, None sans groupes de postes
    client_comparison: Any = None
    # Issue #673 : chronologie des flux et statistiques tshark (JSON)
    expertise: ExpertiseExports | None = None
    # Issue #674 : bornes STIX, historique, contexte du ticket de support
    report_context: ReportContext | None = None


def load_packets(
    captures: Sequence[tuple[str, str]],
    parallel: bool,
    on_progress: Callable[[str], None] | None = None,
    max_workers: int | None = None,
) -> list:
    """Charge les paquets depuis une liste de (label, chemin).

    Remplace MainWindow._load_packets : même logique, sans dépendance GTK.
    Supporte le mode parallèle via parse_captures_parallel.
    """
    logger.debug("load_packets: {} capture(s), parallel={}", len(captures), parallel)
    if parallel:
        from pcap_parser.capture import parse_captures_parallel

        all_packets, per_file_stats = parse_captures_parallel(captures, max_workers=max_workers)
        if on_progress:
            for s in per_file_stats:
                if s["error"]:
                    on_progress(f"  [{s['label']}] ECHEC sur {s['path']} : {s['error']}")
                else:
                    on_progress(
                        f"  [{s['label']}] {s['count']} paquets chargés depuis {s['path']} ({s['seconds']:.2f}s)"
                    )
        logger.debug("load_packets: {} paquet(s) chargé(s) en parallèle", len(all_packets))
        return all_packets

    sequential: list = []
    for label, path in captures:
        if on_progress:
            on_progress(f"Lecture de {os.path.basename(path)} ({label})...")
        packets = parse_capture(label, path)
        sequential.extend(packets)
        if on_progress:
            on_progress(f"  -> {len(packets)} paquets chargés")
    logger.debug("load_packets: {} paquet(s) chargé(s) en séquentiel", len(sequential))
    return sequential


def run_analysis_pipeline(
    captures: Sequence[tuple[str, str]],
    options: AnalysisOptions,
    on_progress: Callable[[str], None] | None = None,
) -> AnalysisResult:
    """Pipeline d'analyse complet, extrait de MainWindow._run_analysis_thread.

    Étapes :
    1. Chargement des paquets
    2. Détection des doublons inter-captures (optionnel)
    3. Anonymisation des adresses (optionnel)
    4. Corrélation des flux
    5. Analyse (pertes, latence, TTL, QoS, etc.)
    6. Signaux d'expertise tshark
    7. Métadonnées de capture (commentaires, infos)
    8. Mise en forme du rapport texte
    9. Triage des segments (optionnel)
    10. Diagnostic TLS (optionnel)
    11. Diagnostic QUIC (optionnel)

    Parameters
    ----------
    captures : liste de (label, chemin)
    options : AnalysisOptions
    on_progress : callback appelé à chaque étape (remplace GLib.idle_add)

    Returns
    -------
    AnalysisResult
    """
    if options.security and options.redact:
        # meme refus que --security-report --redact (CLI) : les signatures
        # d'exploits lisent la charge utile brute des fichiers, jamais les
        # paquets anonymises -- le rapport melangerait adresses reelles et
        # pseudonymes
        logger.debug("run_analysis_pipeline: si options.security and options.redact -> levée ValueError")
        raise ValueError("le rapport de securite n'est pas disponible avec l'anonymisation des adresses")

    if options.client_groups and options.redact:
        # meme refus que --client-group --redact (CLI) : les groupes portent
        # des IP reelles, introuvables dans des paquets anonymises
        logger.debug("run_analysis_pipeline: client_groups and redact -> levée ValueError")
        raise ValueError("la comparaison de postes n'est pas disponible avec l'anonymisation des adresses")

    def _log(msg: str) -> None:
        # Avec la GUI, on_progress aboutit a MainWindow._log qui trace deja
        # chaque ligne ("journal: ...") : on ne trace ici que sans callback,
        # pour ne pas doubler les lignes en mode debug.
        if on_progress:
            on_progress(msg)
        else:
            logger.debug("étape: {}", msg)
        logger.debug("run_analysis_pipeline._log: fin")

    if options.split_interfaces:
        # Fichiers extraits gardes jusqu'a la fin du processus, comme la CLI
        # (atexit) : les vues et exports de la GUI peuvent relire les chemins.
        workdir = tempfile.mkdtemp(prefix="netcross-gui-split-")
        atexit.register(shutil.rmtree, workdir, True)
        captures = expand_split_interfaces(captures, workdir, _log)
    result = _run_pipeline(captures, options, on_progress, _log)
    logger.debug("run_analysis_pipeline: retour result={}", summarize(result, "result"))
    return result


def expand_split_interfaces(
    captures: Sequence[tuple[str, str]],
    workdir: str,
    log: Callable[[str], None],
) -> list[tuple[str, str]]:
    """Comme --split-interfaces de la CLI (issue #474 lot 2) : chaque fichier
    qui contient plusieurs captures devient un point NOM:INTERFACE par
    capture, extraite dans `workdir`. Un fichier a une seule capture, ou
    illisible, est garde tel quel (la lecture normale signalera l'erreur)."""
    from pcap_parser.capture import split_by_interface
    from pcap_parser.ek_source import TsharkError, TsharkNotFoundError

    expanded: list[tuple[str, str]] = []
    for index, (label, path) in enumerate(captures):
        try:
            slices = split_by_interface(path, os.path.join(workdir, str(index)))
        except (OSError, TsharkNotFoundError, TsharkError) as exc:
            logger.warning("separation des interfaces : {} non separe ({})", path, exc)
            log(f"[{label}] separation des interfaces impossible ({exc}) : fichier lu tel quel")
            expanded.append((label, path))
            continue
        if len(slices) <= 1:
            log(f"[{label}] une seule capture dans {path} : lu tel quel")
            expanded.append((label, path))
            continue
        log(f"[{label}] {len(slices)} captures dans {path}")
        expanded.extend((f"{label}:{s.name}", str(s.path)) for s in slices)
    logger.debug("expand_split_interfaces: retour expanded={}", summarize(expanded, "expanded"))
    return expanded


def _run_pipeline(
    captures: Sequence[tuple[str, str]],
    options: AnalysisOptions,
    on_progress: Callable[[str], None] | None,
    _log: Callable[[str], None],
) -> AnalysisResult:
    """Etapes 1 a 11 de run_analysis_pipeline, sur des captures deja separees."""
    # Issue #671 : deux lignes de meme nom = segments d'un meme point.
    points_order = None if options.auto_topology else capture_list.ordre_des_points(captures)
    for label, segments in capture_list.segments_par_point(captures).items():
        _log(f"[{label}] {segments} segments lus a la suite (capture en rotation)")

    # Issue #672 : refus et fichiers de securite lus AVANT la lecture des
    # captures, comme la CLI (une erreur ne coute pas une analyse)
    advanced = options.advanced or AdvancedSettings()
    advanced_errors = validate_advanced(advanced, security=options.security)
    if advanced_errors:
        raise ValueError("; ".join(advanced_errors))
    known_destinations = load_host_set(advanced.known_destinations, "--known-destinations")
    known_hosts = load_host_set(advanced.known_hosts, "--known-hosts")

    # 1. Chargement
    if options.parallel and advanced.parallel_workers:
        _log(f"Lecture parallele : {advanced.parallel_workers} lecteur(s) (--parallel-workers)")
        note = workers_note(advanced.parallel_workers, os.cpu_count())
        if note:
            _log(f"  ATTENTION : {note}")
    all_packets = load_packets(captures, options.parallel, on_progress, max_workers=advanced.parallel_workers)
    truncation_note = None
    if advanced.max_packets is not None or advanced.sample_n:
        from netcross_core.packet_limits import apply_packet_limits

        all_packets, truncation_note = apply_packet_limits(all_packets, advanced.max_packets, advanced.sample_n)
        if truncation_note:
            _log(f"ATTENTION : {truncation_note}")

    # 2. Doublons
    duplicate_counts = None
    if options.detect_duplicates:
        _log(f"Détection des doublons inter-captures (seuil {options.duplicate_threshold_ms:.1f} ms)...")
        from netcross_core.forensic import detect_cross_capture_duplicates

        duplicate_counts = detect_cross_capture_duplicates(all_packets, options.duplicate_threshold_ms)
        duplicate_total = sum(duplicate_counts.values())
        _log(f"  -> {duplicate_total} paquet(s) dupliqué(s) détecté(s)")

    # 3. Anonymisation
    if options.redact:
        _log("Anonymisation des adresses IP/MAC (--redact)...")
        from netcross_core.redact import redact_packets

        redactor = redact_packets(all_packets)
        _log(f"  -> {len(redactor)} adresse(s) anonymisée(s)")

    # 4. Corrélation
    _log("Correlation des flux entre points de capture...")
    flows = correlate(all_packets, options.nat_tolerant, options.nat_window_ms, options.exclude_duplicates)
    _log(f"  -> {len(flows)} flux identifiés")

    # 5. Analyse
    _log("Analyse (pertes, latence, TTL, QoS, fragmentation, débit, TCP, VLAN, RTP, DHCP, SIP...)...")
    from netcross_core.analysis import analyse

    report = analyse(
        flows,
        points_order,
        all_packets,
        options.bucket_ms / 1000.0,
        options.nat_tolerant,
        options.rtp_rate,
        options.topn,
        idle_timeout_seconds=options.idle_timeout_seconds,
        exclude_duplicates=options.exclude_duplicates,
        duplicate_counts=duplicate_counts,
    )
    if truncation_note:  # issue #283 : jamais silencieuse, comme la CLI
        report.truncated = True
        report.truncation_note = truncation_note

    # 6. Expertise tshark
    _log("Expertise tshark (signaux bruts)...")
    wireshark_expert_events = build_wireshark_expert_events(all_packets)
    _log(f"  -> {len(wireshark_expert_events)} signal(aux) d'expertise")

    search_index = None
    if options.forensic_index:
        # Meme index que --forensic-search (paquets + flux). Les paquets ne
        # sont pas conserves par la fenetre ; l'index, lui, l'est jusqu'a
        # l'analyse suivante -- d'ou l'option explicite.
        from netcross_core.forensic_search import ForensicSearchIndex

        _log("Index de recherche forensic...")
        search_index = ForensicSearchIndex(all_packets, flows=flows)
        _log(f"  -> {len(search_index)} element(s) indexe(s)")

    # 7. Métadonnées de capture
    if captures:
        from netcross_core.parsing import read_capture_comments, read_capture_infos

        report.capture_comments = read_capture_comments(captures)
        report.capture_infos = read_capture_infos(captures)

    # 8. Rapport texte
    _log("Mise en forme du rapport...")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_report(report)
        if report.truncated:
            print(f"\nATTENTION : {report.truncation_note}")

    # 9. Triage
    findings = None
    if options.triage:
        _log("Triage des segments...")
        from netcross_report import (
            build_findings,
            format_health_line,
            health_score,
            print_triage,
            rank_segments,
        )

        findings = build_findings(report)
        ranked = rank_segments(findings)
        with contextlib.redirect_stdout(buf):
            print("\n" + "=" * 70)
            print("TRIAGE -- PAR OU COMMENCER")
            print("=" * 70)
            print_triage(ranked, options.triage_topn)
            print(format_health_line(health_score(ranked)))

    # 9 bis. Comparaison de postes (issue #675) -- meme appel que la CLI
    client_comparison = None
    if options.client_groups:
        _log("Comparaison de postes...")
        from netcross_core.client_diff import compare_clients, print_client_comparison

        client_comparison = compare_clients(
            all_packets,
            options.client_groups,
            reference=options.client_reference,
            points_order=points_order,
            bucket_seconds=options.bucket_ms / 1000.0,
            nat_tolerant=options.nat_tolerant,
            nat_window_ms=options.nat_window_ms,
            rtp_clock_rate=options.rtp_rate,
        )
        with contextlib.redirect_stdout(buf):
            print_client_comparison(client_comparison)

    # 9 ter. Sections d'expertise (issue #673) -- memes fonctions que la CLI
    expertise_exports = None
    if options.expertise is not None and options.expertise.active:
        expertise_exports = _run_expertise(options.expertise, report, findings, flows, all_packets, captures, buf, _log)

    # 10. TLS
    tls_findings = None
    if options.tls:
        _log("Diagnostic TLS (relecture des captures via tshark)...")
        from netcross_core.tls_diagnostics import (
            build_handshake_status,
            diagnose_tls,
            parse_tls_capture,
            print_tls_diagnostics,
        )

        tls_events = []
        for label, path in captures:
            tls_events.extend(parse_tls_capture(label, path))
        status_by_point = build_handshake_status(tls_events)
        tls_findings = diagnose_tls(status_by_point, report.points)
        with contextlib.redirect_stdout(buf):
            print("\n" + "=" * 70)
            print("DIAGNOSTIC TLS")
            print("=" * 70)
            print_tls_diagnostics(tls_findings)

    # 11. QUIC
    quic_findings = None
    if options.quic:
        _log("Diagnostic QUIC (relecture des captures via tshark)...")
        try:
            from netcross_core.quic_diagnostics import (
                diagnose_quic,
                parse_quic_capture,
                print_quic_diagnostics,
            )
        except ImportError:
            logger.debug("dépendance optionnelle absente: ImportError")
            with contextlib.redirect_stdout(buf):
                print("\n--quic nécessite cryptography : pip install cryptography")
        else:
            quic_events = []
            for label, path in captures:
                quic_events.extend(parse_quic_capture(label, path))
            quic_findings = diagnose_quic(quic_events, report.points)
            with contextlib.redirect_stdout(buf):
                print("\n" + "=" * 70)
                print("DIAGNOSTIC QUIC/HTTP3")
                print("=" * 70)
                print_quic_diagnostics(quic_findings)

    security_report = None
    if options.notify is not None and options.notify.active and not options.security:
        _log("Notifications ignorees : elles portent sur le rapport de securite, non demande.")
    if options.security:
        security_report = run_security_analysis(
            report,
            all_packets,
            captures,
            _log,
            known_destinations=known_destinations,
            known_hosts=known_hosts,
            test_net_external=advanced.test_net_external,
            cve_db=advanced.cve_db,
        )
        if options.notify is not None and options.notify.active:
            # Avant l'impression : la section « Notifications » du rapport
            # de securite trace chaque canal, comme dans la CLI.
            _log("Notifications...")
            security_report.notifications = send_notifications(report, security_report, options.notify)
            for entry in security_report.notifications:
                _log(f"  -> {entry['line']}")
        with contextlib.redirect_stdout(buf):
            print()
            print_security_report(security_report)

    history = options.history or HistorySettings()
    history_message = ""
    if history.db_path:
        from netcross_report import HistoryDatabaseError

        try:
            history_message = record_history(
                report, history, findings=findings, tls=tls_findings, quic=quic_findings, redact=options.redact
            )
        except HistoryDatabaseError as exc:
            # L'analyse reste valable : on la garde et on dit clairement que
            # la trace demandee n'a pas ete conservee (issue #287).
            logger.exception("historique non enregistre : {}", exc)
            history_message = f"ERREUR historique non enregistre : {exc}"
        _log(history_message)
    observed_from, observed_until = observed_bounds(all_packets)
    report_context = ReportContext(
        observed_from=observed_from,
        observed_until=observed_until,
        captures=len(captures),
        redact=options.redact,
        history=history,
        history_message=history_message,
    )

    text = buf.getvalue()
    _log("Analyse terminée.")

    logger.debug("_run_pipeline: retour AnalysisResult(…)")
    return AnalysisResult(
        mode="single",
        report=report,
        flows=flows,
        findings=findings,
        text=text,
        tls_findings=tls_findings,
        quic_findings=quic_findings,
        wireshark_expert_events=wireshark_expert_events,
        search_index=search_index,
        client_comparison=client_comparison,
        security_report=security_report,
        expertise=expertise_exports,
        report_context=report_context,
    )


def _run_expertise(settings, report, findings, flows, all_packets, captures, buf, log):
    """Sections d'expertise de l'issue #673, dans l'ordre de la CLI. Renvoie
    les documents JSON a exporter ; les constats calcules pour la section
    expertise sans triage restent locaux (le resultat garde ceux du triage)."""
    validate_settings(settings)
    if settings.rule_engine:
        log("Moteur de regles...")
        from netcross_report import print_rule_engine

        with contextlib.redirect_stdout(buf):
            print_rule_engine(report)
    if settings.media_quality:
        log("Qualite media (relecture des captures)...")
        from netcross_core.extract.contents import format_extraction, run_extraction

        with contextlib.redirect_stdout(buf):
            print("\n" + "=" * 70)
            print("CONTENUS AUDIO/VIDEO/DOCUMENTS (relit les memes fichiers)")
            print("=" * 70)
            for line in format_extraction(run_extraction(captures, out_dir=None, kinds=())):
                print(line)
    if settings.expert_section:
        log("Section expertise...")
        from netcross_report import build_findings
        from netcross_report.session_objects import build_session_objects, print_session_objects

        if findings is None:
            findings = build_findings(report)
        session_objects = build_session_objects(report, findings, flows, all_packets)
        with contextlib.redirect_stdout(buf):
            print()
            print_session_objects(session_objects)
    flow_timelines = None
    if settings.flow_timeline:
        log("Chronologie des flux...")
        from netcross_core.flow_timeline import build_flow_timelines

        flow_timelines = build_flow_timelines(all_packets, window_s=settings.flow_timeline_window)
        log(f"  -> {timeline_summary(flow_timelines)}")
    tshark_stats = None
    if settings.tshark_stats:
        log("Statistiques tshark (relecture des captures)...")
        from netcross_core.tshark_stats import collect_capture_stats

        tshark_stats = collect_capture_stats(
            captures, on_error=lambda label, path, exc: log(f"  -> {label} ({path}) : {exc}")
        )
        log(f"  -> {tshark_stats_summary(tshark_stats)}")
    logger.debug("_run_expertise: fin")
    return ExpertiseExports(flow_timelines=flow_timelines, tshark_stats=tshark_stats)


def run_security_analysis(
    report,
    all_packets,
    captures,
    log: Callable[[str], None],
    *,
    known_destinations=None,
    known_hosts=None,
    test_net_external: bool = False,
    cve_db: str | None = None,
):
    """Analyse de securite de la GUI (issue #357), alignee sur
    --security-report : signatures d'exploits relues sur les fichiers,
    correlation CVE sur la base choisie (--cve-db, issue #672) ou, a
    defaut, sur la base minimale embarquee, puis `build_security_report`.
    Retourne le SecurityReport."""
    from netcross_core.security import connect_cve_db
    from netcross_core.security.cve_db import close_db
    from netcross_core.security.cve_seed import open_seed_db
    from netcross_core.security.findings import apply_security_findings, scan_capture_exploits

    log(
        "Analyse de securite (beaconing, exfiltration, DGA, fast flux, mouvements lateraux, "
        "flow_stats, DNS tunnel, TLS audit, CVE)..."
    )
    logger.debug("run_security_analysis: {} capture(s), {} paquet(s)", len(captures), len(all_packets))
    detections = []
    for label, path in captures:
        found = scan_capture_exploits(label, path)
        log(f"  [{label}] {len(found)} signature(s) d'exploit")
        detections.extend(found)
    cve_conn = None
    if cve_db:
        cve_conn = connect_cve_db(cve_db)
        log(f"  Base CVE : {cve_db} (--cve-db)")
    try:
        if cve_conn is None:
            cve_conn, seed = open_seed_db()
            log(
                f"  Base CVE minimale embarquee ({len(seed.entries)} CVE critiques, NVD {seed.generated}) : "
                "une version absente de cette selection n'est pas pour autant non vulnerable."
            )
    except (OSError, ValueError) as exc:
        logger.warning("run_security_analysis: base CVE embarquée illisible ({})", exc)
        log(f"  Base CVE embarquee illisible ({exc}) : services listes sans correlation CVE.")
    try:
        apply_security_findings(
            report,
            all_packets,
            detections=detections,
            cve_conn=cve_conn,
            known_destinations=known_destinations,
            known_hosts=known_hosts,
            treat_test_net_as_external=test_net_external,
        )
    finally:
        if cve_conn is not None:
            close_db(cve_conn)
    log(f"  -> {len(report.security_findings)} constat(s) de securite")
    logger.debug("run_security_analysis: {} constat(s) de sécurité", len(report.security_findings))
    return build_security_report(report)
