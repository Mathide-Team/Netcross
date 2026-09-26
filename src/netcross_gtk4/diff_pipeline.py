"""
netcross_gtk4.diff_pipeline -- pipeline de comparaison baseline/courant
extrait de MainWindow._run_diff_thread (issue #246, #285 -- lot supplémentaire).

Même principe qu'analysis_pipeline.py : la logique de comparaison est
extraite dans une fonction pure, sans dépendance GTK. Le thread de la
fenêtre ne fait que l'appeler avec un callback de progression.
"""

from __future__ import annotations

import contextlib
import io
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Callable

from netcross_core.baseline_diff import diff_reports
from netcross_core.correlate import correlate
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class DiffOptions:
    """Options du pipeline de comparaison, miroir des checkboxes de la GUI."""

    bucket_ms: float = 1000.0
    rtp_rate: int = 8000
    nat_tolerant: bool = False
    parallel: bool = True
    auto_topology: bool = True
    loss_min_pp: float = 5.0
    latency_min_ms: float = 2.0
    redact: bool = False
    tls: bool = False
    quic: bool = False


@dataclass
class DiffResult:
    """Résultat du pipeline de comparaison."""

    mode: str = "diff"
    findings: list = field(default_factory=list)
    baseline_report: Any = None
    current_report: Any = None
    text: str = ""
    tls_findings_baseline: list | None = None
    tls_findings_current: list | None = None
    quic_findings_baseline: list | None = None
    quic_findings_current: list | None = None


def run_diff_pipeline(
    baseline_captures: Sequence[tuple[str, str]],
    current_captures: Sequence[tuple[str, str]],
    options: DiffOptions,
    on_progress: Callable[[str], None] | None = None,
) -> DiffResult:
    """Pipeline de comparaison baseline/courant, extrait de _run_diff_thread.

    Étapes :
    1. Chargement + analyse du baseline
    2. Chargement + analyse du courant
    3. Comparaison (diff_reports)
    4. Rapport texte
    5. Diagnostics TLS (optionnel)
    6. Diagnostics QUIC (optionnel)
    """

    def _log(msg: str) -> None:
        # Avec la GUI, on_progress aboutit a MainWindow._log qui trace deja
        # chaque ligne ("journal: ...") : on ne trace ici que sans callback,
        # pour ne pas doubler les lignes en mode debug.
        if on_progress:
            on_progress(msg)
        else:
            logger.debug("étape: {}", msg)

    from netcross_core.analysis import analyse
    from netcross_core.redact import AddressRedactor
    from netcross_gtk4.analysis_pipeline import load_packets

    redactor = AddressRedactor() if options.redact else None
    points_order = None if options.auto_topology else [label for label, _ in baseline_captures]

    # 1. Baseline
    _log("=== CHARGEMENT DU BASELINE ===")
    baseline_packets = load_packets(baseline_captures, options.parallel, on_progress)
    if redactor is not None:
        redactor.redact(baseline_packets)
    baseline_flows = correlate(baseline_packets, options.nat_tolerant, 200)
    baseline_report = analyse(
        baseline_flows,
        points_order,
        baseline_packets,
        options.bucket_ms / 1000.0,
        options.nat_tolerant,
        options.rtp_rate,
    )

    # 2. Courant
    points_order_current = None if options.auto_topology else [label for label, _ in current_captures]
    _log("=== CHARGEMENT DU RUN COURANT ===")
    current_packets = load_packets(current_captures, options.parallel, on_progress)
    if redactor is not None:
        redactor.redact(current_packets)
        _log(f"{len(redactor)} adresse(s) anonymisée(s) (IP/MAC) -- baseline et courant.")
    current_flows = correlate(current_packets, options.nat_tolerant, 200)
    current_report = analyse(
        current_flows,
        points_order_current,
        current_packets,
        options.bucket_ms / 1000.0,
        options.nat_tolerant,
        options.rtp_rate,
    )

    # 3. Comparaison
    _log("Comparaison baseline / courant...")
    findings = diff_reports(
        baseline_report,
        current_report,
        loss_min_pp=options.loss_min_pp,
        latency_min_ms=options.latency_min_ms,
    )

    # 4. Rapport texte
    from netcross_core.baseline_diff import print_diff_report

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_diff_report(findings)

    # 5. TLS
    tls_findings_baseline = tls_findings_current = None
    if options.tls:
        _log("Diagnostic TLS (relecture des captures via tshark)...")
        from netcross_core.tls_diagnostics import (
            build_handshake_status,
            diagnose_tls,
            parse_tls_capture,
            print_tls_diagnostics,
        )

        def _tls_findings(captures, topo):
            events = []
            for label, path in captures:
                events.extend(parse_tls_capture(label, path))
            logger.debug("_tls_findings: {} capture(s), {} événement(s) TLS", len(captures), len(events))
            return diagnose_tls(build_handshake_status(events), topo)

        tls_findings_baseline = _tls_findings(baseline_captures, points_order)
        tls_findings_current = _tls_findings(current_captures, points_order)
        with contextlib.redirect_stdout(buf):
            print("\n" + "=" * 70)
            print("DIAGNOSTIC TLS -- BASELINE")
            print("=" * 70)
            print_tls_diagnostics(tls_findings_baseline)
            print("\n" + "=" * 70)
            print("DIAGNOSTIC TLS -- COURANT")
            print("=" * 70)
            print_tls_diagnostics(tls_findings_current)

    # 6. QUIC
    quic_findings_baseline = quic_findings_current = None
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

            def _quic_findings(captures, topo):
                events = []
                for label, path in captures:
                    events.extend(parse_quic_capture(label, path))
                logger.debug("_quic_findings: {} capture(s), {} événement(s) QUIC", len(captures), len(events))
                return diagnose_quic(events, topo)

            quic_findings_baseline = _quic_findings(baseline_captures, points_order)
            quic_findings_current = _quic_findings(current_captures, points_order)
            with contextlib.redirect_stdout(buf):
                print("\n" + "=" * 70)
                print("DIAGNOSTIC QUIC/HTTP3 -- BASELINE")
                print("=" * 70)
                print_quic_diagnostics(quic_findings_baseline)
                print("\n" + "=" * 70)
                print("DIAGNOSTIC QUIC/HTTP3 -- COURANT")
                print("=" * 70)
                print_quic_diagnostics(quic_findings_current)

    text = buf.getvalue()
    _log("Comparaison terminée.")

    return DiffResult(
        mode="diff",
        findings=findings,
        baseline_report=baseline_report,
        current_report=current_report,
        text=text,
        tls_findings_baseline=tls_findings_baseline,
        tls_findings_current=tls_findings_current,
        quic_findings_baseline=quic_findings_baseline,
        quic_findings_current=quic_findings_current,
    )
