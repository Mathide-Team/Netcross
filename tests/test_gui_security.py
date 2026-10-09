"""Securite dans la GUI (issue #357) : parite avec --security-report.

Le pipeline de la GUI construit le MEME `SecurityReport` que la CLI
(correlation CVE sur la base embarquee comprise), la section Securite en
affiche le rendu texte, l'export HTML/JSON le reprend, et le JSON general
de la GUI porte la cle `security_report` comme --json-report. Verifiable
sans GTK ; le rendu de la fenetre elle-meme est teste dans
test_gui_security_window.py (pygobject, ignore sans affichage).
"""

from __future__ import annotations

import json
import pathlib

import pytest
from conftest import make_pkt

import netcross_core.security.findings as findings_mod
import netcross_gtk4.analysis_pipeline as pipeline_mod
from netcross_core.models import Banner
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline
from netcross_gtk4.run_outcome import analysis_outcome, diff_outcome
from netcross_gtk4.security_view import export_security_report, security_view_text
from netcross_report import generate_json_report
from netcross_report.security_report import (
    build_security_report,
    format_security_report,
    security_report_to_dict,
)

APP = pathlib.Path(__file__).resolve().parents[1] / "src" / "netcross_gtk4" / "app.py"


def _pkts():
    banner = Banner("http", "Apache", "2.4.49", "Apache/2.4.49")
    return [
        make_pkt(point="A", src="10.0.0.5", dst="10.0.0.9", sport=80, dport=51000, service_banners=(banner,)),
        make_pkt(point="A", src="10.0.0.9", dst="10.0.0.5", sport=51000, dport=80, ts=0.01),
    ]


@pytest.fixture
def run(monkeypatch):
    monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: _pkts())
    monkeypatch.setattr(findings_mod, "scan_capture_exploits", lambda label, path: [])

    def _run(**opts):
        progress: list[str] = []
        result = run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(auto_topology=False, parallel=False, **opts),
            on_progress=progress.append,
        )
        return result, progress

    return _run


def test_sans_case_securite_pas_de_rapport(run):
    result, _ = run()
    assert result.security_report is None


def test_rapport_de_securite_correle_les_cve_de_la_base_embarquee(run):
    """Avant #357 la GUI appelait apply_security_findings SANS base CVE :
    une banniere Apache 2.4.49 ne remontait aucune CVE, contrairement a la
    CLI qui utilise la base minimale embarquee par defaut."""
    result, progress = run(security=True)
    sr = result.security_report
    assert sr is not None
    assert {"CVE-2021-41773", "CVE-2021-42013"} <= {c.cve_id for c in sr.cves}
    assert any("Base CVE minimale embarquee" in p for p in progress)
    # le texte de l'onglet Travail/Resultats est le rendu de --security-report
    assert "\n".join(format_security_report(sr)) in result.text
    # meme objet que celui que la CLI construirait depuis ce Report
    assert security_report_to_dict(sr) == security_report_to_dict(build_security_report(result.report))


def test_securite_refusee_avec_anonymisation(run):
    with pytest.raises(ValueError, match="anonymisation"):
        run(security=True, redact=True)


def test_run_outcome_transporte_puis_efface_le_rapport():
    o = analysis_outcome("single", None, [], None, "", security_report="sr")
    assert o.etat()["last_security_report"] == "sr"
    assert diff_outcome([], None, None, "").etat()["last_security_report"] is None


def test_vue_et_exports(run, tmp_path):
    result, _ = run(security=True)
    sr = result.security_report
    assert "CVE-2021-41773" in security_view_text(sr)
    assert "Rapport de securite" in security_view_text(None)

    html = export_security_report(sr, str(tmp_path / "s.html"))
    assert "CVE-2021-41773" in pathlib.Path(html).read_text(encoding="utf-8")

    js = json.loads(pathlib.Path(export_security_report(sr, str(tmp_path / "s.json"))).read_text(encoding="utf-8"))
    assert js == json.loads(json.dumps(security_report_to_dict(sr)))

    with pytest.raises(ValueError, match="format"):
        export_security_report(sr, str(tmp_path / "s.txt"))


def test_parite_json_gui_cli(run, tmp_path):
    """Le JSON general de la GUI porte `security_report` exactement comme
    --json-report (meme fonction, meme objet)."""
    result, _ = run(security=True)
    path = tmp_path / "gui.json"
    generate_json_report(result.report, str(path), security_report=result.security_report)
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["security_report"] == json.loads(json.dumps(security_report_to_dict(result.security_report)))


def test_app_raccorde_la_securite_aux_exports():
    src = APP.read_text(encoding="utf-8")
    assert src.count("security_report=self.last_security_report") == 3  # JSON + PDF + Markdown (#864)
    assert "result.security_report" in src
    assert "self.security_check)" in src  # desactivee avec --redact
    assert "export_security_report(self.last_security_report, path)" in src
