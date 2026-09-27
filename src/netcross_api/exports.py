"""Exports texte, CSV du détail et PDF de l'API REST (issue #670).

Ils sont produits à la fin de l'analyse, pendant que le ``Report`` et les
flux sont encore en mémoire : le store ne garde ensuite que des documents
(JSON, texte, CSV, octets du PDF), relus tels quels après un redémarrage.
Même contenu que la CLI : sortie standard (rapport, triage, sécurité, TLS,
QUIC), ``--detail-csv`` et ``--pdf-report --topn-charts``.
"""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
from typing import Any

from netcross_core.logging_config import get_logger, summarize
from netcross_core.report_text import print_report, write_detail_csv
from netcross_report import format_health_line, health_score, print_triage, rank_segments

logger = get_logger(__name__)

TRIAGE_TOP_N = 5


class PdfUnavailableError(RuntimeError):
    """Dépendances du PDF absentes (reportlab, matplotlib, networkx)."""


def text_report(
    report: Any,
    findings: list,
    security_report: Any = None,
    tls_findings: list | None = None,
    quic_findings: list | None = None,
) -> str:
    """Rapport texte, comme la sortie standard de ``netcross --triage``."""
    logger.debug(
        "text_report: report={} findings={} security_report={}",
        summarize(report, "report"),
        summarize(findings, "findings"),
        summarize(security_report, "security_report"),
    )
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_report(report)
        ranked = rank_segments(list(findings) + list(tls_findings or []) + list(quic_findings or []))
        print("\n" + "=" * 70)
        print("TRIAGE -- PAR OU COMMENCER")
        print("=" * 70)
        print_triage(ranked, TRIAGE_TOP_N)
        print(format_health_line(health_score(ranked)))
        if tls_findings is not None:
            from netcross_core.tls_diagnostics import print_tls_diagnostics

            print("\n" + "=" * 70)
            print("DIAGNOSTIC TLS")
            print("=" * 70)
            print_tls_diagnostics(tls_findings)
        if quic_findings is not None:
            from netcross_core.quic_diagnostics import print_quic_diagnostics

            print("\n" + "=" * 70)
            print("DIAGNOSTIC QUIC")
            print("=" * 70)
            print_quic_diagnostics(quic_findings)
        if security_report is not None:
            from netcross_report.security_report import print_security_report

            print_security_report(security_report)
    text = buf.getvalue()
    logger.debug("text_report: retour {} caractère(s)", len(text))
    return text


def detail_csv(flows: Any, points: list[str]) -> str:
    """Détail par flux, comme ``--detail-csv``."""
    logger.debug("detail_csv: flows={} points={}", summarize(flows, "flows"), summarize(points, "points"))
    fd, path = tempfile.mkstemp(prefix="netcross-api-detail-", suffix=".csv")
    os.close(fd)
    try:
        write_detail_csv(path, flows, points)
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
    finally:
        os.unlink(path)
    logger.debug("detail_csv: retour {} caractère(s)", len(content))
    return content


def pdf_report(
    report: Any,
    findings: list,
    security_report: Any = None,
    tls_findings: list | None = None,
    quic_findings: list | None = None,
    meta: dict | None = None,
) -> bytes:
    """Rapport PDF, comme ``--pdf-report`` ; lève ``PdfUnavailableError`` si
    reportlab, matplotlib ou networkx manquent."""
    logger.debug("pdf_report: report={} meta={}", summarize(report, "report"), summarize(meta, "meta"))
    try:
        from netcross_report.pdf import generate_pdf
    except ImportError as exc:
        logger.warning("pdf indisponible : {}", exc)
        raise PdfUnavailableError(
            "pdf nécessite reportlab, matplotlib et networkx (pip install reportlab matplotlib networkx)"
        ) from exc
    fd, path = tempfile.mkstemp(prefix="netcross-api-", suffix=".pdf")
    os.close(fd)
    try:
        generate_pdf(
            report,
            path,
            findings=findings,
            security_report=security_report,
            tls_findings=tls_findings,
            quic_findings=quic_findings,
            meta=meta,
        )
        with open(path, "rb") as fh:
            content = fh.read()
    finally:
        os.unlink(path)
    logger.debug("pdf_report: retour {} octet(s)", len(content))
    return content
