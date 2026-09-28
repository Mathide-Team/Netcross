"""
Issue #330 (écart 3 de docs/parite-surfaces.md) : réglages fins de la CLI
dans la GUI -- fenêtre NAT (--nat-window-ms), coupure silencieuse
(--idle-timeout-seconds) et table des noms (--names).

Partie 1 : pipelines (pur Python, sans GTK). Partie 2 : widgets de
MainWindow, ignorée sans GTK4 ou sans affichage (même garde que lot6).
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import netcross_core.analysis as analysis_mod
import netcross_gtk4.analysis_pipeline as pipeline_mod
import netcross_gtk4.diff_pipeline as diff_mod
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline
from netcross_gtk4.diff_pipeline import DiffOptions, run_diff_pipeline
from tests.conftest import make_pkt


def _espions(monkeypatch, module):
    appels = {"correlate": [], "analyse": []}
    vrai_correlate, vraie_analyse = module.correlate, analysis_mod.analyse

    def correlate(*args, **kwargs):
        appels["correlate"].append(args)
        return vrai_correlate(*args, **kwargs)

    def analyse(*args, **kwargs):
        appels["analyse"].append(kwargs)
        return vraie_analyse(*args, **kwargs)

    monkeypatch.setattr(module, "correlate", correlate)
    monkeypatch.setattr(analysis_mod, "analyse", analyse)
    monkeypatch.setattr(
        pipeline_mod, "parse_capture", lambda label, _path: [make_pkt(point=label, src="10.0.0.1", dst="10.0.0.2")]
    )
    return appels


def test_options_par_defaut_identiques_a_la_cli():
    for opts in (AnalysisOptions(), DiffOptions()):
        assert opts.nat_window_ms == 200.0
        assert opts.idle_timeout_seconds is None


def test_pipeline_analyse_transmet_les_reglages(monkeypatch):
    appels = _espions(monkeypatch, pipeline_mod)
    opts = AnalysisOptions(parallel=False, nat_tolerant=True, nat_window_ms=750.0, idle_timeout_seconds=12.0)
    run_analysis_pipeline([("A", "/x/a.pcap"), ("B", "/x/b.pcap")], opts)
    assert appels["correlate"][0][1:3] == (True, 750.0)
    assert appels["analyse"][0]["idle_timeout_seconds"] == 12.0


def test_pipeline_diff_transmet_les_reglages(monkeypatch):
    appels = _espions(monkeypatch, diff_mod)
    opts = DiffOptions(parallel=False, nat_tolerant=True, nat_window_ms=300.0, idle_timeout_seconds=5.0)
    run_diff_pipeline([("A", "/x/a.pcap")], [("A", "/x/a2.pcap")], opts)
    assert [c[1:3] for c in appels["correlate"]] == [(True, 300.0), (True, 300.0)]
    assert [k["idle_timeout_seconds"] for k in appels["analyse"]] == [5.0, 5.0]


# ---------------------------------------------------------------- widgets GTK


@pytest.fixture(scope="module")
def window():
    from gtk4_display import exiger_gtk4_avec_affichage

    gtk = exiger_gtk4_avec_affichage()
    from netcross_gtk4.app import MainWindow

    app = gtk.Application(application_id="org.netcross.test330reglages")
    app.register(None)
    return MainWindow(app)


def test_fenetre_nat_reglable_seulement_avec_la_tolerance_nat(window):
    window.nat_check.set_active(False)
    assert window.nat_window_spin.get_sensitive() is False
    window.nat_check.set_active(True)
    assert window.nat_window_spin.get_sensitive() is True
    window.nat_check.set_active(False)
    assert window.nat_window_spin.get_sensitive() is False


def test_reglages_fins_valeurs_par_defaut_et_zero(window):
    window.nat_window_spin.set_value(200)
    window.idle_timeout_spin.set_value(0)
    assert window._fine_settings() == (200.0, None)
    window.nat_window_spin.set_value(450)
    window.idle_timeout_spin.set_value(30)
    assert window._fine_settings() == (450.0, 30.0)
    window.idle_timeout_spin.set_value(0)


def test_thread_analyse_transmet_les_reglages(window, monkeypatch):
    recu = {}

    def faux_pipeline(_captures, options, on_progress=None):
        recu["options"] = options
        raise RuntimeError("arrêt volontaire")

    monkeypatch.setattr(pipeline_mod, "run_analysis_pipeline", faux_pipeline)
    window._run_analysis_thread(
        [("A", "/tmp/a.pcap")], 1000.0, 8000, True, False, True, False, 5, False, False, False, False, 25,
        False, False, 2.0, nat_window_ms=900.0, idle_timeout_seconds=15.0,
    )  # fmt: skip
    assert recu["options"].nat_window_ms == 900.0
    assert recu["options"].idle_timeout_seconds == 15.0


def test_thread_diff_transmet_les_reglages(window, monkeypatch):
    recu = {}

    def faux_pipeline(_b, _c, options, on_progress=None):
        recu["options"] = options
        raise RuntimeError("arrêt volontaire")

    monkeypatch.setattr(diff_mod, "run_diff_pipeline", faux_pipeline)
    window._run_diff_thread(
        [("A", "/tmp/a.pcap")], [("A", "/tmp/b.pcap")], 1000.0, 8000, True, False, True, 5.0, 2.0, False,
        False, False, nat_window_ms=333.0, idle_timeout_seconds=7.0,
    )  # fmt: skip
    assert (recu["options"].nat_window_ms, recu["options"].idle_timeout_seconds) == (333.0, 7.0)


def test_table_des_noms_chargement_puis_retrait(window, tmp_path):
    fichier = tmp_path / "noms.json"
    fichier.write_text(json.dumps([{"name": "routeur", "address": "10.0.0.1"}]), encoding="utf-8")
    assert window.load_names_table(str(fichier)) is True
    assert window.names_table is not None and len(window.names_table) == 1
    assert window.names_label.get_text() == "noms.json (1 entrée(s))"
    assert window.names_clear_btn.get_sensitive() is True

    window._on_names_clear_clicked(None)
    assert window.names_table is None
    assert window.names_label.get_text() == "Aucune table des noms"
    assert window.names_clear_btn.get_sensitive() is False


def test_table_des_noms_invalide_garde_l_ancienne(window, tmp_path):
    window.names_table = "ancienne"
    assert window.load_names_table(str(tmp_path / "absent.json")) is False
    assert window.names_table == "ancienne"
    assert "Erreur table des noms" in window.status_label.get_text()
    window.names_table = None


def test_export_csv_utilise_la_table_des_noms(window, monkeypatch, tmp_path):
    import netcross_gtk4.app as app_module

    recu = {}
    monkeypatch.setattr(app_module, "write_detail_csv", lambda *a, names=None: recu.setdefault("names", names))

    class _Dialogue:
        def save_finish(self, _r):
            return SimpleNamespace(get_path=lambda: str(tmp_path / "d.csv"))

    window.names_table = "table"
    window.last_mode = "single"
    window.last_flows, window.last_report = [], SimpleNamespace(points=[])
    window._on_csv_path_chosen(_Dialogue(), None)
    assert recu["names"] == "table"
    window.names_table = None


# --- Issue #330, écart 4 : triage des écarts en mode comparaison -----------


def test_diff_options_triage_defauts_cli():
    from netcross_gtk4.diff_pipeline import DiffOptions

    options = DiffOptions()
    assert options.triage is False
    assert options.triage_topn == 5


def test_diff_pipeline_triage_ajoute_le_classement(monkeypatch):
    import netcross_report

    _espions(monkeypatch, diff_mod)
    appels = {}

    def faux_print_triage(ranked, top_n):
        appels["top_n"] = top_n
        print("TRIAGE-FAUX")

    monkeypatch.setattr(netcross_report, "print_triage", faux_print_triage)
    opts = DiffOptions(parallel=False, triage=True, triage_topn=3)
    result = run_diff_pipeline([("A", "/x/a.pcap")], [("A", "/x/a2.pcap")], opts)
    assert appels["top_n"] == 3
    assert "TRIAGE-FAUX" in result.text
    assert "Score de sante" in result.text


def test_diff_pipeline_sans_triage_par_defaut(monkeypatch):
    _espions(monkeypatch, diff_mod)
    result = run_diff_pipeline([("A", "/x/a.pcap")], [("A", "/x/a2.pcap")], DiffOptions(parallel=False))
    assert "Score de sante" not in result.text


def test_thread_diff_transmet_le_triage(window, monkeypatch):
    import netcross_gtk4.diff_pipeline as dp

    vu = {}

    def faux_pipeline(_b, _c, options, on_progress=None):
        vu["options"] = options
        raise RuntimeError("arret du test")

    monkeypatch.setattr(dp, "run_diff_pipeline", faux_pipeline)
    window._run_diff_thread(
        [], [], 1000.0, 8000, False, False, True, 5.0, 2.0, False, False, False, triage=True, triage_topn=7
    )
    assert vu["options"].triage is True
    assert vu["options"].triage_topn == 7


def test_widgets_triage_diff(window):
    assert window.diff_triage_check.get_active() is False
    assert int(window.diff_triage_topn_spin.get_value()) == 5
