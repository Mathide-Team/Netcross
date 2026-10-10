"""Issue #867 (GUI) : plugins tiers, équivalent de --plugins / --plugin-path /
--plugin-export / --list-plugins. Partie sans GTK : module et pipeline."""

from __future__ import annotations

import textwrap

import pytest
from conftest import make_pkt

import netcross_gtk4.analysis_pipeline as pipeline_mod
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline
from netcross_gtk4.plugin_settings import (
    PluginSettings,
    PluginSettingsError,
    format_plugin_list,
    prepare_plugins,
    settings_from_widgets,
)

PLUGIN_SOURCE = textwrap.dedent("""
    class Maison:
        name = "maison"
        def analyse(self, contexte):
            return [{"category": "anomalie", "severity": "elevee",
                     "detail": "protocole maison vu", "point": "A"}]

    class Csv:
        name = "csv"
        def export(self, report, chemin):
            chemin.write_text(f"{len(report.security_findings)} constat(s)")

    DETECTORS = [Maison]
    EXPORTERS = [Csv]
    """)


@pytest.fixture
def plugin_file(tmp_path, monkeypatch):
    path = tmp_path / "maison.py"
    path.write_text(PLUGIN_SOURCE, encoding="utf-8")
    monkeypatch.setattr("netcross_core.plugins.loader._entry_points", lambda group: [])
    return str(path)


def test_reglages_depuis_les_champs(tmp_path):
    s = settings_from_widgets(" maison, csv ,maison", f"{tmp_path}/a.py ; ~/b.py", f"csv={tmp_path}/out.csv")
    assert s.names == ("maison", "csv")
    assert s.paths[0] == f"{tmp_path}/a.py"
    assert not s.paths[1].startswith("~")
    assert s.exports == (("csv", f"{tmp_path}/out.csv"),)
    assert s.active
    assert not settings_from_widgets("", "", "").active


@pytest.mark.parametrize("spec", ["csv", "=x", "csv="])
def test_export_mal_forme(spec):
    with pytest.raises(PluginSettingsError, match="NOM=FICHIER"):
        settings_from_widgets("csv", "", spec)


def test_validations_comme_la_cli(plugin_file):
    assert prepare_plugins(PluginSettings(paths=(plugin_file,)), security=True)[1] == [
        "--plugin-path sans --plugins : aucun plugin autorise, rien ne s'executerait."
    ]
    _, errors = prepare_plugins(PluginSettings(names=("csv",), exports=(("autre", "x"),)), security=True)
    assert errors == ["--plugin-export autre : exporteur absent de --plugins."]
    _, errors = prepare_plugins(PluginSettings(names=("maison",), paths=(plugin_file,)), security=False)
    assert "Rapport de securite" in errors[0] and "maison" in errors[0]


def test_sans_plugin_rien_n_est_charge():
    assert prepare_plugins(PluginSettings(), security=False) == (None, [])


def test_exporteur_seul_sans_rapport_de_securite(plugin_file):
    prepared, errors = prepare_plugins(PluginSettings(names=("csv",), paths=(plugin_file,)), security=False)
    assert errors == []
    assert list(prepared.loaded.exporters) == ["csv"]
    assert prepared.loaded.detectors == []


def test_liste_identique_a_list_plugins(plugin_file):
    texte = format_plugin_list(PluginSettings(names=("maison", "fantome"), paths=(plugin_file,)))
    lignes = texte.splitlines()
    assert lignes[0].split() == ["NOM", "TYPE", "AUTORISE", "ORIGINE"]
    assert any(ligne.split()[:3] == ["maison", "detector", "oui"] for ligne in lignes)
    assert any(ligne.split()[:3] == ["csv", "exporter", "non"] for ligne in lignes)
    assert lignes[-1] == "Demande(s) dans --plugins mais introuvable(s) : fantome"


def test_liste_vide(monkeypatch):
    monkeypatch.setattr("netcross_core.plugins.loader._entry_points", lambda group: [])
    assert format_plugin_list(PluginSettings()).startswith("Aucun plugin installe")


@pytest.fixture
def paquets(monkeypatch):
    pkts = [make_pkt(point="A", sport=1), make_pkt(point="B", sport=1, ts=1000.001)]
    monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: [p for p in pkts if p.point == label])
    monkeypatch.setattr("netcross_core.security.findings.scan_capture_exploits", lambda label, path: [])


def test_pipeline_detecteur_et_exporteur(plugin_file, paquets, tmp_path):
    sortie = tmp_path / "out.csv"
    prepared, errors = prepare_plugins(
        PluginSettings(names=("maison", "csv", "fantome"), paths=(plugin_file,), exports=(("csv", str(sortie)),)),
        security=True,
    )
    assert errors == []
    journal: list[str] = []
    result = run_analysis_pipeline(
        [("A", "a.pcap"), ("B", "b.pcap")],
        AnalysisOptions(parallel=False, security=True, plugins=prepared),
        on_progress=journal.append,
    )
    runs = {run["plugin"]: run for run in result.report.plugin_runs}
    assert runs["maison"]["status"] == "ok"
    assert runs["fantome"]["status"] == "refuse"
    assert runs["csv"]["status"] == "ok"
    assert any(f.get("plugin") == "maison" for f in result.report.security_findings)
    assert [p["plugin"] for p in result.security_report.plugins] == ["fantome", "maison"]
    assert sortie.read_text(encoding="utf-8").endswith("constat(s)")
    assert any("Plugins : detecteur maison" in ligne for ligne in journal)
    assert "PLUGINS" in result.text.upper()


def test_pipeline_exporteur_sans_securite_trace_les_introuvables(plugin_file, paquets, tmp_path):
    sortie = tmp_path / "out.csv"
    prepared, _ = prepare_plugins(
        PluginSettings(names=("csv", "fantome"), paths=(plugin_file,), exports=(("csv", str(sortie)),)),
        security=False,
    )
    journal: list[str] = []
    result = run_analysis_pipeline(
        [("A", "a.pcap"), ("B", "b.pcap")],
        AnalysisOptions(parallel=False, security=False, plugins=prepared),
        on_progress=journal.append,
    )
    assert [(r["plugin"], r["status"]) for r in result.report.plugin_runs] == [("fantome", "refuse"), ("csv", "ok")]
    assert sortie.exists()
    assert any(ligne.startswith("Plugins : ") and "fantome" in ligne for ligne in journal)


def test_pipeline_sans_plugins_aucune_trace(paquets):
    result = run_analysis_pipeline([("A", "a.pcap"), ("B", "b.pcap")], AnalysisOptions(parallel=False, security=True))
    assert result.report.plugin_runs == []
