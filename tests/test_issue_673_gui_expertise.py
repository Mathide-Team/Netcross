"""Issue #673 : sections d'expertise dans la GUI (--rule-engine,
--expert-section, --media-quality, --tshark-stats, --flow-timeline).
Partie sans GTK : reglages, pipeline, documents JSON ; puis panneau GTK."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest
from conftest import make_pkt

import netcross_gtk4.analysis_pipeline as pipeline_mod
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline
from netcross_gtk4.expertise_view import (
    ExpertiseExports,
    ExpertiseSettings,
    ExpertiseSettingsError,
    timeline_summary,
    tshark_stats_summary,
    validate_settings,
    write_json,
)

CAPTURES = [("A", "a.pcap"), ("B", "b.pcap")]


def test_reglages_actifs_et_refus():
    assert not ExpertiseSettings().active
    assert ExpertiseSettings(flow_timeline=True).active
    validate_settings(ExpertiseSettings(flow_timeline=True, flow_timeline_window=0.5))
    with pytest.raises(ExpertiseSettingsError, match="positive"):
        validate_settings(ExpertiseSettings(flow_timeline=True, flow_timeline_window=0))
    with pytest.raises(ExpertiseSettingsError, match="qualite media"):
        validate_settings(ExpertiseSettings(media_quality=True), live=True)
    with pytest.raises(ExpertiseSettingsError, match="tshark"):
        validate_settings(ExpertiseSettings(tshark_stats=True), live=True)
    validate_settings(ExpertiseSettings(rule_engine=True, expert_section=True), live=True)


def test_resumes():
    assert "non calculee" in timeline_summary(None)
    doc = {"window_s": 2.0, "flows": [{"point": "A"}, {"point": "B"}, {"point": "A"}]}
    assert timeline_summary(doc) == "Chronologie des flux : 3 conversation(s), 2 point(s), fenetre 2.0 s."
    assert "non calculees" in tshark_stats_summary(None)
    stats = {"captures": [{"label": "A"}, {"label": "B", "error": "tshark absent"}]}
    assert tshark_stats_summary(stats) == "Statistiques tshark : 2 capture(s), 1 en echec (B : tshark absent)."
    assert tshark_stats_summary({"captures": [{"label": "A"}]}) == "Statistiques tshark : 1 capture(s)."


def test_json_identique_a_la_cli(tmp_path):
    chemin = tmp_path / "x.json"
    assert write_json(chemin, {"é": [1]}) == str(chemin)
    assert chemin.read_text(encoding="utf-8") == json.dumps({"é": [1]}, ensure_ascii=False, indent=2)


@pytest.fixture
def _paquets(monkeypatch):
    pkts = [
        make_pkt(point="A", src="10.0.0.5", dst="10.0.0.9", sport=1, ts=1000.0),
        make_pkt(point="A", src="10.0.0.5", dst="10.0.0.9", sport=1, ts=1000.5),
        make_pkt(point="B", src="10.0.0.5", dst="10.0.0.9", sport=1, ts=1000.001),
        make_pkt(point="B", src="10.0.0.5", dst="10.0.0.9", sport=1, ts=1000.501),
    ]
    monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: [p for p in pkts if p.point == label])


def test_pipeline_sans_expertise(_paquets):
    result = run_analysis_pipeline(CAPTURES, AnalysisOptions(parallel=False))
    assert result.expertise is None
    assert "MOTEUR DE REGLES" not in result.text


def test_pipeline_sections_du_rapport(_paquets, monkeypatch):
    from netcross_core.extract import contents

    vus = []
    monkeypatch.setattr(contents, "run_extraction", lambda caps, out_dir, kinds: vus.append((caps, out_dir, kinds)))
    monkeypatch.setattr(contents, "format_extraction", lambda result: ["QUALITE=ok"])
    journal = []
    result = run_analysis_pipeline(
        CAPTURES,
        AnalysisOptions(
            parallel=False,
            expertise=ExpertiseSettings(rule_engine=True, expert_section=True, media_quality=True),
        ),
        on_progress=journal.append,
    )
    assert "MOTEUR DE REGLES DECLARATIF (rule_engine)" in result.text
    assert "regles evaluees" in result.text
    assert "CONTENUS AUDIO/VIDEO/DOCUMENTS" in result.text and "QUALITE=ok" in result.text
    assert vus == [(CAPTURES, None, ())]  # analyse sans ecriture, comme --media-quality
    assert result.findings is None  # les constats de la section expertise restent locaux
    assert result.expertise.flow_timelines is None and result.expertise.tshark_stats is None
    assert result.expertise.rule_engine  # constats du moteur de regles, pour le Markdown (#864)
    assert "Section expertise..." in journal


def test_pipeline_chronologie_et_statistiques(_paquets, monkeypatch):
    import netcross_core.tshark_stats as ts

    def conv(path, proto):
        if path == "b.pcap":
            raise subprocess.SubprocessError("tshark absent")
        return []

    monkeypatch.setattr(ts, "collect_conversations", conv)
    monkeypatch.setattr(ts, "collect_endpoints", lambda path, proto: [])
    monkeypatch.setattr(ts, "collect_protocol_hierarchy", lambda path: [])
    monkeypatch.setattr(ts, "collect_io_stat", lambda path: SimpleNamespace())
    monkeypatch.setattr("dataclasses.asdict", lambda obj: {})
    journal = []
    result = run_analysis_pipeline(
        CAPTURES,
        AnalysisOptions(
            parallel=False,
            expertise=ExpertiseSettings(tshark_stats=True, flow_timeline=True, flow_timeline_window=0.25),
        ),
        on_progress=journal.append,
    )
    timelines = result.expertise.flow_timelines
    assert timelines["window_s"] == 0.25
    assert {f["point"] for f in timelines["flows"]} == {"A", "B"}
    stats = result.expertise.tshark_stats
    assert [c["label"] for c in stats["captures"]] == ["A", "B"]
    assert stats["captures"][1] == {"label": "B", "path": "b.pcap", "error": "tshark absent"}
    assert any("B (b.pcap) : tshark absent" in line for line in journal)


def test_pipeline_refuse_une_fenetre_nulle(_paquets):
    with pytest.raises(ExpertiseSettingsError):
        run_analysis_pipeline(
            CAPTURES,
            AnalysisOptions(parallel=False, expertise=ExpertiseSettings(flow_timeline=True, flow_timeline_window=0)),
        )


# -- GTK (ignore sans GTK4 ni affichage) --


def _gtk():
    from gtk4_display import exiger_gtk4_avec_affichage

    return exiger_gtk4_avec_affichage()


def test_panneau_exports(tmp_path):
    _gtk()
    from netcross_gtk4.expertise_panel import ExpertisePanel

    panel = ExpertisePanel()
    assert not panel.timeline_btn.get_sensitive() and not panel.stats_btn.get_sensitive()
    with pytest.raises(ValueError, match="rien a exporter"):
        panel.export_to("flow_timelines", tmp_path / "x.json")
    doc = {"version": 1, "window_s": 1.0, "flows": [{"point": "A"}]}
    panel.set_exports(ExpertiseExports(flow_timelines=doc))
    assert panel.timeline_btn.get_sensitive() and not panel.stats_btn.get_sensitive()
    assert "1 conversation(s)" in panel.timeline_label.get_text()
    chemin = panel.export_to("flow_timelines", tmp_path / "chrono.json")
    assert json.loads((tmp_path / "chrono.json").read_text(encoding="utf-8")) == doc
    assert panel.status_label.get_text() == f"Ecrit dans {chemin}"
    panel.set_exports(None)
    assert not panel.timeline_btn.get_sensitive()
    assert panel.status_label.get_text() == ""


def test_fenetre_transmet_les_reglages(monkeypatch):
    gtk = _gtk()
    from netcross_gtk4.app import MainWindow

    app = gtk.Application(application_id="org.netcross.test673")
    app.register(None)
    window = MainWindow(app)
    window.rule_engine_check.set_active(True)
    window.flow_timeline_check.set_active(True)
    window.flow_timeline_window_spin.set_value(2.5)
    assert window.expertise_settings() == ExpertiseSettings(
        rule_engine=True, flow_timeline=True, flow_timeline_window=2.5
    )
    recus = []
    monkeypatch.setattr(
        pipeline_mod, "run_analysis_pipeline", lambda caps, options, on_progress=None: recus.append(options) or _fin()
    )
    exports = ExpertiseExports(flow_timelines={"window_s": 2.5, "flows": []})

    def _fin():
        return pipeline_mod.AnalysisResult(expertise=exports)

    vus = []
    monkeypatch.setattr(window, "_on_analysis_done", lambda *args: vus.append(args))
    window._run_analysis_thread(
        CAPTURES,
        1000.0,
        8000,
        False,
        False,
        True,
        False,
        10,
        False,
        False,
        False,
        False,
        25,
        False,
        False,
        2.0,
        expertise=window.expertise_settings(),
    )
    from gi.repository import GLib

    ctx = GLib.MainContext.default()
    while ctx.iteration(False):
        pass
    assert recus[0].expertise.flow_timeline_window == 2.5
    assert vus[0][11] is exports  # avant report_context (#674)
    window.expertise_panel.set_exports(exports)
    window._on_diff_done([], None, None, "")
    assert window.expertise_panel.exports is None
