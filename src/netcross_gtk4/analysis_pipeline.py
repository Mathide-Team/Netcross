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

import contextlib
import io
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Callable

from netcross_core.correlate import correlate
from netcross_core.logging_config import get_logger
from netcross_core.models import Report
from netcross_core.parsing import parse_capture
from netcross_core.report_text import print_report
from netcross_core.wireshark_expert import build_wireshark_expert_events
from netcross_report.security_report import build_security_report, print_security_report

logger = get_logger(__name__)


@dataclass
class AnalysisOptions:
    """Options du pipeline d'analyse, miroir des checkboxes de la GUI."""

    bucket_ms: float = 1000.0
    rtp_rate: int = 8000
    nat_tolerant: bool = False
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


def load_packets(
    captures: Sequence[tuple[str, str]],
    parallel: bool,
    on_progress: Callable[[str], None] | None = None,
) -> list:
    """Charge les paquets depuis une liste de (label, chemin).

    Remplace MainWindow._load_packets : même logique, sans dépendance GTK.
    Supporte le mode parallèle via parse_captures_parallel.
    """
    logger.debug("load_packets: {} capture(s), parallel={}", len(captures), parallel)
    if parallel:
        from pcap_parser.capture import parse_captures_parallel

        all_packets, per_file_stats = parse_captures_parallel(captures)
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
        raise ValueError("le rapport de securite n'est pas disponible avec l'anonymisation des adresses")

    def _log(msg: str) -> None:
        # Avec la GUI, on_progress aboutit a MainWindow._log qui trace deja
        # chaque ligne ("journal: ...") : on ne trace ici que sans callback,
        # pour ne pas doubler les lignes en mode debug.
        if on_progress:
            on_progress(msg)
        else:
            logger.debug("étape: {}", msg)

    points_order = None if options.auto_topology else [label for label, _ in captures]

    # 1. Chargement
    all_packets = load_packets(captures, options.parallel, on_progress)

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
    flows = correlate(all_packets, options.nat_tolerant, 200, options.exclude_duplicates)
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
        exclude_duplicates=options.exclude_duplicates,
        duplicate_counts=duplicate_counts,
    )

    # 6. Expertise tshark
    _log("Expertise tshark (signaux bruts)...")
    wireshark_expert_events = build_wireshark_expert_events(all_packets)
    _log(f"  -> {len(wireshark_expert_events)} signal(aux) d'expertise")

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
    if options.security:
        security_report = run_security_analysis(report, all_packets, captures, _log)
        with contextlib.redirect_stdout(buf):
            print()
            print_security_report(security_report)

    text = buf.getvalue()
    _log("Analyse terminée.")

    return AnalysisResult(
        mode="single",
        report=report,
        flows=flows,
        findings=findings,
        text=text,
        tls_findings=tls_findings,
        quic_findings=quic_findings,
        wireshark_expert_events=wireshark_expert_events,
        security_report=security_report,
    )


def run_security_analysis(report, all_packets, captures, log: Callable[[str], None]):
    """Analyse de securite de la GUI (issue #357), alignee sur
    --security-report : signatures d'exploits relues sur les fichiers,
    correlation CVE sur la base minimale embarquee (la GUI n'a pas de
    --cve-db), puis `build_security_report`. Retourne le SecurityReport."""
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
    try:
        cve_conn, seed = open_seed_db()
        log(
            f"  Base CVE minimale embarquee ({len(seed.entries)} CVE critiques, NVD {seed.generated}) : "
            "une version absente de cette selection n'est pas pour autant non vulnerable."
        )
    except (OSError, ValueError) as exc:
        logger.warning("run_security_analysis: base CVE embarquée illisible ({})", exc)
        log(f"  Base CVE embarquee illisible ({exc}) : services listes sans correlation CVE.")
    try:
        apply_security_findings(report, all_packets, detections=detections, cve_conn=cve_conn)
    finally:
        if cve_conn is not None:
            close_db(cve_conn)
    log(f"  -> {len(report.security_findings)} constat(s) de securite")
    logger.debug("run_security_analysis: {} constat(s) de sécurité", len(report.security_findings))
    return build_security_report(report)
