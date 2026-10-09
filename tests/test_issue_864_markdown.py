"""Issue #864 : export Markdown (--md-report) en GUI et en API."""

from __future__ import annotations

import importlib
from unittest.mock import patch

import pytest
from conftest import make_pkt

import netcross_gtk4.analysis_pipeline as pipeline_mod
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline
from netcross_gtk4.expertise_view import ExpertiseSettings
from netcross_report.markdown_report import build_markdown_report_document

CAPTURES = [("A", "a.pcap"), ("B", "b.pcap")]


def _pkts(label, _path):
    return [make_pkt(point=label, src="10.0.0.5", dst="10.0.0.9", sport=1, ts=1000.0 + i * 0.1) for i in range(4)]


def test_pipeline_garde_les_constats_du_moteur_de_regles(monkeypatch):
    monkeypatch.setattr(pipeline_mod, "parse_capture", _pkts)
    result = run_analysis_pipeline(
        CAPTURES, AnalysisOptions(parallel=False, expertise=ExpertiseSettings(rule_engine=True))
    )
    assert isinstance(result.expertise.rule_engine, dict) and result.expertise.rule_engine


def test_api_markdown():
    pytest.importorskip("fastapi", reason="extra [api] non installé")
    pytest.importorskip("multipart", reason="python-multipart non installé")
    from fastapi.testclient import TestClient

    api = importlib.import_module("netcross_api.app")
    client = TestClient(api.app)
    pcap = b"\xd4\xc3\xb2\xa1" + b"\x00" * 64
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post(
            "/captures?wait=true",
            files={"file": ("a.pcap", pcap, "application/octet-stream")},
            data={"label": "LAN", "rule_engine": "true"},
        )
    assert rep.status_code == 201, rep.text
    analysis_id = rep.json()["analysis_id"]
    md = client.get(f"/analyses/{analysis_id}/markdown")
    assert md.status_code == 200
    assert md.headers["content-type"].startswith("text/markdown")
    assert f'filename="netcross-{analysis_id}.md"' in md.headers["content-disposition"]
    assert md.text.startswith("# ")
    assert "API REST" in md.text
    assert client.get("/analyses/inconnue/markdown").status_code == 404


def test_fenetre_export_markdown(monkeypatch, tmp_path):
    from gtk4_display import exiger_gtk4_avec_affichage

    gtk = exiger_gtk4_avec_affichage()
    from netcross_gtk4.app import MainWindow

    monkeypatch.setattr(pipeline_mod, "parse_capture", _pkts)
    result = run_analysis_pipeline(
        CAPTURES, AnalysisOptions(parallel=False, expertise=ExpertiseSettings(rule_engine=True))
    )
    app = gtk.Application(application_id="org.netcross.test864")
    app.register(None)
    window = MainWindow(app)
    assert not window.md_btn.get_sensitive()
    window._on_analysis_done(
        "single",
        result.report,
        result.flows,
        result.findings,
        result.text,
        None,
        None,
        [],
        None,
        None,
        None,
        result.expertise,
        result.report_context,
    )
    assert window.md_btn.get_sensitive()
    chemin = window.export_markdown_to(str(tmp_path / "r.md"))
    texte = (tmp_path / "r.md").read_text(encoding="utf-8")
    attendu = build_markdown_report_document(
        result.report,
        findings=window.last_findings,
        session_objects=window._session_objects(),
        rule_engine_findings=result.expertise.rule_engine,
    )
    # meme document que --md-report, a l'horodatage pres
    assert [ligne for ligne in texte.splitlines() if "Généré" not in ligne] == [
        ligne for ligne in attendu.splitlines() if "Généré" not in ligne
    ]
    assert window.status_label.get_text() == f"Rapport Markdown ecrit dans {chemin}"
    assert window.export_markdown_to(str(tmp_path / "absent" / "r.md")) is None
    assert window.status_label.get_text().startswith("Erreur Markdown")
    window.close()
