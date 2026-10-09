"""Issue #675 : comparaison de postes -- champs de la configuration,
validation avant lancement, panneau « Comparaison de postes » (Resultats).

Ignore sans GTK4 ou sans affichage, meme garde que test_app_gtk4_lot4.py.
"""

import csv

import pytest
from conftest import make_pkt
from gtk4_display import exiger_gtk4_avec_affichage

Gtk = exiger_gtk4_avec_affichage()

import netcross_gtk4.app as app_module  # noqa: E402
from netcross_core.client_diff import compare_clients  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402
from netcross_gtk4.client_compare_panel import ClientComparisonPanel  # noqa: E402

_N = 0


def _comparaison():
    pkts = [
        make_pkt(point="A", src="10.0.0.5", dst="10.0.0.9", sport=1, ts=1.0),
        make_pkt(point="B", src="10.0.0.5", dst="10.0.0.9", sport=1, ts=1.001),
        make_pkt(point="A", src="10.0.0.12", dst="10.0.0.9", sport=2, ts=1.0),
    ]
    return compare_clients(pkts, {"OK": {"10.0.0.5"}, "KO": {"10.0.0.12"}}, reference="OK")


def test_panneau_sans_comparaison():
    panel = ClientComparisonPanel()
    assert "renseignez au moins deux groupes" in panel.summary_label.get_text()
    assert not panel.csv_btn.get_sensitive()


def test_panneau_avec_comparaison_et_export(tmp_path):
    panel = ClientComparisonPanel()
    panel.set_comparison(_comparaison())
    assert panel.summary_label.get_text().startswith("Reference : OK ; compare(s) : KO")
    assert panel.csv_btn.get_sensitive()
    cible = tmp_path / "postes.csv"
    panel.export_to(cible)
    with open(cible, encoding="utf-8") as fh:
        entete = next(csv.reader(fh))
    assert entete[:2] == ["client", "reference"]
    assert str(cible) in panel.status_label.get_text()


@pytest.fixture()
def window():
    global _N
    _N += 1
    app = Gtk.Application(application_id=f"org.netcross.test675postes.n{_N}")
    app.register(None)
    return MainWindow(app)


@pytest.fixture()
def threads(monkeypatch):
    crees = []

    class _T:
        def __init__(self, target=None, args=(), kwargs=None, daemon=None):
            self.target, self.args, self.kwargs = target, args, kwargs or {}
            crees.append(self)

        def start(self):
            pass

    monkeypatch.setattr(app_module.threading, "Thread", _T)
    return crees


def _log(window):
    buf = window.log_view.get_buffer()
    return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)


def test_groupes_transmis_au_thread(window, threads):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.client_groups_entry.set_text("OK=10.0.0.5; KO=10.0.0.12")
    window.client_reference_entry.set_text(" KO ")
    window.on_run_analysis(None)
    (thread,) = threads
    assert thread.kwargs["client_groups"] == {"OK": {"10.0.0.5"}, "KO": {"10.0.0.12"}}
    assert thread.kwargs["client_reference"] == "KO"


def test_sans_groupes_rien_transmis(window, threads):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.on_run_analysis(None)
    (thread,) = threads
    assert thread.kwargs["client_groups"] is None
    assert thread.kwargs["client_reference"] is None


@pytest.mark.parametrize(
    ("groupes", "reference", "redact", "motif"),
    [
        ("OK", "", False, "groupe invalide"),
        ("OK=10.0.0.5", "", False, "au moins 2 postes"),
        ("OK=10.0.0.5; KO=10.0.0.12", "Z", False, "absente des groupes"),
        ("OK=10.0.0.5; KO=10.0.0.12", "", True, "anonymisation"),
    ],
)
def test_saisie_invalide_bloque_le_lancement(window, threads, groupes, reference, redact, motif):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.client_groups_entry.set_text(groupes)
    window.client_reference_entry.set_text(reference)
    window.redact_check.set_active(redact)
    window.on_run_analysis(None)
    assert threads == []
    assert motif in _log(window)
    assert "analyse non lancee" in _log(window)


def test_resultat_alimente_le_panneau(window, monkeypatch):
    monkeypatch.setattr(window, "_appliquer_outcome", lambda *a, **k: None)
    comp = _comparaison()
    window._on_analysis_done("single", None, [], None, "", None, None, None, None, None, comp)
    assert window.client_compare_panel.comparison is comp
    window._on_diff_done([], None, None, "")
    assert window.client_compare_panel.comparison is None


def test_thread_d_analyse_transmet_la_comparaison(window, monkeypatch):
    from gi.repository import GLib

    from netcross_gtk4.analysis_pipeline import AnalysisResult

    comp = _comparaison()
    vus = []

    def faux_pipeline(captures, options, on_progress=None):
        vus.append((options.client_groups, options.client_reference))
        return AnalysisResult(client_comparison=comp)

    monkeypatch.setattr("netcross_gtk4.analysis_pipeline.run_analysis_pipeline", faux_pipeline)
    recus = []
    monkeypatch.setattr(window, "_on_analysis_done", lambda *a: recus.append(a))
    window._run_analysis_thread(
        [("A", "/a.pcap")],
        100.0,
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
        client_groups={"OK": {"1.1.1.1"}, "KO": {"2.2.2.2"}},
        client_reference="OK",
    )
    ctx = GLib.MainContext.default()
    while ctx.iteration(False):
        pass
    assert vus == [({"OK": {"1.1.1.1"}, "KO": {"2.2.2.2"}}, "OK")]
    assert recus[0][-1] is comp
