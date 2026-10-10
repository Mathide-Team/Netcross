"""Issue #866 (GUI) : module IA local, équivalent des options --ai-*.
Partie sans GTK : module et pipeline."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from conftest import make_pkt

import netcross_gtk4.analysis_pipeline as pipeline_mod
from netcross_ai.optional import ml_available
from netcross_gtk4.ai_settings import AISettings, run_ai_section, settings_from_widgets, to_options, validate_settings
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline

needs_ml = pytest.mark.skipif(not ml_available(), reason="scikit-learn absent (extra [ai])")


def _paquets():
    # Assez de flux distincts pour les minimums du module IA.
    return [
        make_pkt(
            point=point,
            src=f"10.0.0.{1 + i}",
            dst=f"10.0.1.{1 + i % 7}",
            sport=40000 + i,
            dport=443 if i % 3 else 53,
            ts=1000.0 + i * 0.5 + j * 0.01,
        )
        for i in range(30)
        for j in range(3)
        for point in ("A", "B")
    ]


@pytest.fixture
def paquets(monkeypatch):
    pkts = _paquets()
    monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: [p for p in pkts if p.point == label])


def _pipeline(ai, journal=None):
    return run_analysis_pipeline(
        [("A", "a.pcap"), ("B", "b.pcap")],
        AnalysisOptions(parallel=False, ai=ai),
        on_progress=(journal.append if journal is not None else None),
    )


def test_reglages_depuis_les_champs(tmp_path):
    s = settings_from_widgets(" ~/base.json ", " bureau ", None, "", f"{tmp_path}/t.json", " template ", "", "")
    assert not s.baseline_save.startswith("~")
    assert s.baseline_label == "bureau"
    assert s.classify == f"{tmp_path}/t.json"
    assert s.summary == "template"
    assert s.endpoint is None and s.report is None and s.training_export is None
    assert s.requested
    assert not settings_from_widgets("", "", None, "", None, "", "", "").requested


@pytest.mark.parametrize(
    ("settings", "attendu"),
    [
        (AISettings(report="x.json"), "necessitent une option --ai-* d'analyse"),
        (AISettings(summary="template", baseline_label="x"), "--ai-baseline-label necessite --ai-baseline-save."),
        (AISettings(training_export="t.json", endpoint="http://127.0.0.1:1"), "--ai-endpoint necessite --ai-summary."),
        (AISettings(anomalies="/inexistant.json"), "--ai-anomalies : fichier introuvable"),
        (AISettings(classify="/inexistant.json"), "--ai-classify : fichier introuvable"),
        (AISettings(summary="inconnu"), "moteur inconnu"),
        (AISettings(summary="ollama:m", endpoint="http://203.0.113.5:11434"), "Module IA"),
    ],
)
def test_validations_comme_la_cli(settings, attendu):
    errors = validate_settings(settings)
    assert errors and any(attendu in e for e in errors), errors


def test_sans_usage_aucune_erreur():
    assert validate_settings(AISettings()) == []


def test_sans_scikit_learn(tmp_path):
    base = tmp_path / "b.json"
    base.write_text("{}", encoding="utf-8")
    with patch("netcross_ai.optional.ml_available", return_value=False):
        errors = validate_settings(AISettings(anomalies=str(base)))
    assert any("scikit-learn" in e for e in errors)


def test_options_identiques_a_la_cli():
    o = to_options(AISettings("s.json", "l", "a.json", "e.json", "c.json", "template", "http://127.0.0.1:1"))
    assert (o.baseline_save, o.baseline_label, o.baseline_path, o.training_export, o.training_path) == (
        "s.json",
        "l",
        "a.json",
        "e.json",
        "c.json",
    )
    assert (o.summary_engine, o.endpoint) == ("template", "http://127.0.0.1:1")


def test_pipeline_baseline_export_resume_et_rapport(paquets, tmp_path):
    base, export, rapport = tmp_path / "base.json", tmp_path / "train.json", tmp_path / "ia.json"
    journal: list[str] = []
    result = _pipeline(
        AISettings(
            baseline_save=str(base),
            baseline_label="ref",
            training_export=str(export),
            summary="template",
            report=str(rapport),
        ),
        journal,
    )
    assert result.ai["baseline_saved"]["path"] == str(base)
    assert json.loads(base.read_text(encoding="utf-8"))["label"] == "ref"
    assert export.exists()
    assert result.ai["summary"]["engine"] == "template"
    assert json.loads(rapport.read_text(encoding="utf-8")) == result.ai
    assert "MODULE IA LOCAL" in result.text
    assert any("Resultats du module IA ecrits" in ligne for ligne in journal)


@needs_ml
def test_pipeline_anomalies_et_classification(paquets, tmp_path):
    base, export = tmp_path / "base.json", tmp_path / "train.json"
    _pipeline(AISettings(baseline_save=str(base), training_export=str(export)))
    doc = json.loads(export.read_text(encoding="utf-8"))
    for i, sample in enumerate(doc["samples"]):
        sample["label"] = "normal" if i % 2 else "scan"
    export.write_text(json.dumps(doc), encoding="utf-8")
    result = _pipeline(AISettings(anomalies=str(base), classify=str(export)))
    assert len(result.ai["anomalies"]) == result.ai["flows"]
    assert len(result.ai["classification"]) == result.ai["flows"]


def test_pipeline_erreur_du_module_ia_n_arrete_pas_l_analyse(paquets, tmp_path):
    base = tmp_path / "petite.json"
    base.write_text(json.dumps({"schema": "x", "vectors": []}), encoding="utf-8")
    journal: list[str] = []
    result = _pipeline(AISettings(anomalies=str(base)), journal)
    assert result.ai is None
    assert result.report is not None
    assert any(ligne.startswith("Module IA : ") and "flux" not in ligne[:20] for ligne in journal)


def test_rapport_json_non_ecrit_journalise(paquets, tmp_path):
    journal: list[str] = []
    result = _pipeline(AISettings(summary="template", report=str(tmp_path / "absent" / "ia.json")), journal)
    assert result.ai is not None
    assert any("rapport JSON non ecrit" in ligne for ligne in journal)


def test_pipeline_sans_module_ia(paquets):
    assert _pipeline(None).ai is None
    assert _pipeline(AISettings()).ai is None


def test_section_utilise_les_flux_du_rapport_si_presents():
    from types import SimpleNamespace

    report = SimpleNamespace(flow_anomalies=[{"flow": "x"}], security_findings=[])
    with patch("netcross_ai.pipeline.run_ai", return_value={"schema": "netcross.ai/1", "flows": 1}) as run_ai:
        result, _text, logs = run_ai_section(AISettings(summary="template"), report, [])
    assert run_ai.call_args.args[1] == [{"flow": "x"}]
    assert result["flows"] == 1
    assert logs == ["Module IA : 1 flux analyse(s)."]
