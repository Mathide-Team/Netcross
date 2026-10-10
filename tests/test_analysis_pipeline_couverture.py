"""Tests de couverture de netcross_gtk4/analysis_pipeline.py (issue #711, suite #665).

Chemins rares, sans GTK ni tshark (tout est doublé) :

- ``load_packets`` en mode parallèle : messages de progression (succès et
  échec d'un fichier) et absence de callback ;
- ``run_analysis_pipeline`` avec ``quic=True`` quand ``cryptography`` est
  absente (ImportError) ;
- ``run_security_analysis`` quand la base CVE embarquée est illisible
  (OSError / ValueError) : pas de ``close_db``, services listés sans CVE.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from netcross_gtk4 import analysis_pipeline as ap
from netcross_gtk4.analysis_pipeline import AnalysisOptions, load_packets, run_analysis_pipeline, run_security_analysis


def _stat(label, path, count=0, seconds=0.0, error=None):
    return {"label": label, "path": path, "count": count, "seconds": seconds, "error": error}


class TestLoadPacketsParallele:
    def _patch(self, monkeypatch, stats, packets=None):
        monkeypatch.setattr(
            "pcap_parser.capture.parse_captures_parallel", lambda captures, max_workers=None: (packets or [], stats)
        )

    def test_progression_succes_et_echec(self, monkeypatch):
        stats = [_stat("A", "/tmp/a.pcap", count=12, seconds=0.5), _stat("B", "/tmp/b.pcap", error="illisible")]
        self._patch(monkeypatch, stats, packets=["p1", "p2"])
        messages: list[str] = []
        result = load_packets([("A", "/tmp/a.pcap"), ("B", "/tmp/b.pcap")], parallel=True, on_progress=messages.append)
        assert result == ["p1", "p2"]
        assert messages == [
            "  [A] 12 paquets chargés depuis /tmp/a.pcap (0.50s)",
            "  [B] ECHEC sur /tmp/b.pcap : illisible",
        ]

    def test_sans_callback_ne_leve_pas(self, monkeypatch):
        self._patch(monkeypatch, [_stat("A", "/tmp/a.pcap", error="boom")], packets=["p"])
        assert load_packets([("A", "/tmp/a.pcap")], parallel=True) == ["p"]


def test_quic_sans_cryptography_signale_la_dependance(monkeypatch):
    monkeypatch.setattr("netcross_gtk4.analysis_pipeline.load_packets", lambda *a, **k: [])
    report = MagicMock(name="report")
    report.points = ["A"]
    report.capture_comments = []
    report.capture_infos = []
    monkeypatch.setattr("netcross_core.analysis.analyse", lambda *a, **k: report)
    monkeypatch.setattr("netcross_gtk4.analysis_pipeline.print_report", lambda r: None)
    # Une entrée None dans sys.modules fait lever ImportError à l'import.
    monkeypatch.setitem(sys.modules, "netcross_core.quic_diagnostics", None)

    result = run_analysis_pipeline([("A", "/tmp/a.pcap")], AnalysisOptions(quic=True))

    assert result.quic_findings is None
    assert "cryptography" in result.text


class TestRunSecurityAnalysisBaseCveIllisible:
    @pytest.mark.parametrize("exc", [OSError("disque"), ValueError("format")])
    def test_base_illisible_continue_sans_correlation_cve(self, monkeypatch, exc):
        def _broken():
            raise exc

        applied: dict = {}
        closed: list = []
        monkeypatch.setattr("netcross_core.security.cve_seed.open_seed_db", _broken)
        monkeypatch.setattr("netcross_core.security.findings.scan_capture_exploits", lambda label, path: [])
        monkeypatch.setattr(
            "netcross_core.security.findings.apply_security_findings",
            lambda report, pkts, detections, cve_conn, **_k: applied.update(cve_conn=cve_conn),
        )
        monkeypatch.setattr("netcross_core.security.cve_db.close_db", closed.append)
        monkeypatch.setattr(ap, "build_security_report", lambda report: "SECURITY_REPORT")
        report = MagicMock(name="report")
        report.security_findings = []
        logs: list[str] = []

        result = run_security_analysis(report, [], [("A", "/tmp/a.pcap")], logs.append)

        assert result == "SECURITY_REPORT"
        assert applied == {"cve_conn": None}
        assert closed == []  # aucune connexion ouverte : rien à fermer
        assert any("illisible" in m and str(exc) in m for m in logs)
