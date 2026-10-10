"""Issue #675 : panneau « Recherche forensic » (page Resultats) et case
« Index de recherche forensic » (Configuration).

Ignore sans GTK4 ou sans affichage, meme garde que test_app_gtk4_lot4.py.
"""

import json

import pytest
from conftest import make_pkt
from gtk4_display import exiger_gtk4_avec_affichage

Gtk = exiger_gtk4_avec_affichage()

import netcross_gtk4.app as app_module  # noqa: E402
from netcross_core.forensic_search import ForensicSearchIndex  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402
from netcross_gtk4.forensic_panel import NO_INDEX_MESSAGE, ForensicSearchPanel  # noqa: E402
from netcross_gtk4.forensic_view import MAX_DISPLAYED, SEARCH_FIELDS  # noqa: E402

_N = 0


def _pump():
    from gi.repository import GLib

    ctx = GLib.MainContext.default()
    while ctx.iteration(False):
        pass


def _index():
    return ForensicSearchIndex(
        [
            make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", dport=443, ts=1.0),
            make_pkt(point="B", src="10.0.0.7", dst="10.0.0.8", dport=53, ts=2.0),
        ]
    )


def _lignes(panel):
    out = []
    child = panel.list_box.get_first_child()
    while child is not None:
        out.append(child.get_child().get_text())
        child = child.get_next_sibling()
    return out


@pytest.fixture()
def panel():
    return ForensicSearchPanel()


def test_sans_index_recherche_indisponible(panel):
    assert panel.status_label.get_text() == NO_INDEX_MESSAGE
    assert not panel.search_btn.get_sensitive()
    assert not panel.export_btn.get_sensitive()
    assert panel.run_search() == []


def test_recherche_par_adresse(panel):
    panel.set_index(_index())
    assert panel.search_btn.get_sensitive()
    assert "indexe(s)" in panel.status_label.get_text()
    panel.address_entry.set_text("10.0.0.7")

    resultats = panel.run_search()

    assert resultats
    assert all("[B]" in ligne for ligne in _lignes(panel) if " packet " in ligne)
    assert "resultat(s)" in panel.status_label.get_text()
    assert panel.export_btn.get_sensitive()


def test_saisie_invalide_motivee(panel):
    panel.set_index(_index())
    panel.port_entry.set_text("http")
    assert panel.run_search() == []
    assert "port invalide" in panel.status_label.get_text()
    panel.port_entry.set_text("")
    assert panel.run_search() == []
    assert "au moins un critere" in panel.status_label.get_text()


def test_champ_choisi_transmis(panel, monkeypatch):
    vues = []
    index = _index()
    monkeypatch.setattr(index, "search", lambda q: vues.append(q) or [])
    panel.set_index(index)
    panel.field_drop.set_selected(SEARCH_FIELDS.index("dns_name") + 1)
    panel.value_entry.set_text("example")
    panel.run_search()
    assert vues[0].field == "dns_name"
    assert vues[0].field_value == "example"
    assert panel.status_label.get_text() == "Aucun resultat."


def test_affichage_borne(panel, monkeypatch):
    from netcross_core.forensic_search import ForensicSearchResult

    index = _index()
    beaucoup = [ForensicSearchResult("packet", "A", i, 1.0) for i in range(MAX_DISPLAYED + 3)]
    monkeypatch.setattr(index, "search", lambda q: beaucoup)
    panel.set_index(index)
    panel.text_entry.set_text("x")
    panel.run_search()
    assert len(_lignes(panel)) == MAX_DISPLAYED
    assert "500 premiers affiches" in panel.status_label.get_text()


def test_export_json(panel, tmp_path):
    panel.set_index(_index())
    panel.protocol_entry.set_text("TCP")
    resultats = panel.run_search()
    cible = tmp_path / "r.json"
    panel.export_to(cible)
    relu = json.loads(cible.read_text(encoding="utf-8"))
    assert relu["query"] == {"protocol": "TCP"}
    assert relu["count"] == len(resultats)
    assert str(cible) in panel.status_label.get_text()


def test_nouvel_index_efface_les_resultats(panel):
    panel.set_index(_index())
    panel.address_entry.set_text("10.0.0.1")
    panel.run_search()
    assert _lignes(panel)
    panel.set_index(None)
    assert _lignes(panel) == []
    assert not panel.export_btn.get_sensitive()
    assert panel.status_label.get_text() == NO_INDEX_MESSAGE


# -- fenetre principale --


@pytest.fixture()
def window():
    global _N
    _N += 1
    app = Gtk.Application(application_id=f"org.netcross.test675search.n{_N}")
    app.register(None)
    return MainWindow(app)


class _FauxThread:
    crees: list = []  # noqa: RUF012

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self.target, self.args, self.kwargs = target, args, kwargs or {}
        _FauxThread.crees.append(self)

    def start(self):
        pass


def test_case_transmise_au_thread_d_analyse(window, monkeypatch):
    _FauxThread.crees = []
    monkeypatch.setattr(app_module.threading, "Thread", _FauxThread)
    window.add_capture_row("/tmp/a.pcap", "A")
    window.forensic_index_check.set_active(True)
    window.on_run_analysis(None)
    (thread,) = _FauxThread.crees
    assert thread.kwargs["forensic_index"] is True


def test_thread_d_analyse_passe_l_option_et_l_index(window, monkeypatch):
    from netcross_gtk4.analysis_pipeline import AnalysisResult

    vus = []
    index = _index()

    def faux_pipeline(captures, options, on_progress=None):
        vus.append(options.forensic_index)
        return AnalysisResult(search_index=index)

    monkeypatch.setattr("netcross_gtk4.analysis_pipeline.run_analysis_pipeline", faux_pipeline)
    # vrai GLib.idle_add (arguments positionnels seulement), boucle videe ensuite
    recus = []
    monkeypatch.setattr(window, "_on_analysis_done", lambda *a, **k: recus.append(a))
    window._run_analysis_thread(
        captures=[("A", "/tmp/a.pcap")],
        bucket_ms=100.0,
        rtp_rate=8000,
        nat_tolerant=False,
        parallel=False,
        auto_topology=True,
        triage=False,
        triage_topn=10,
        tls=False,
        quic=False,
        security=False,
        redact=False,
        topn=25,
        detect_duplicates=False,
        exclude_duplicates=False,
        duplicate_threshold_ms=2.0,
        forensic_index=True,
    )
    _pump()
    assert vus == [True]
    assert recus[0][9] is index  # apres security_report


def test_fin_d_analyse_alimente_le_panneau(window, monkeypatch):
    # rapport factice : seul l'index compte ici, le reste de l'affichage
    # (couvert ailleurs) est neutralise
    monkeypatch.setattr(window, "_appliquer_outcome", lambda *a, **k: None)
    index = _index()
    window._on_analysis_done("single", None, [], None, "", search_index=index)
    assert window.forensic_panel.index is index
    window._on_diff_done([], None, None, "")
    assert window.forensic_panel.index is None


def test_capture_en_direct_construit_l_index(window, monkeypatch):
    import threading

    recus = []
    monkeypatch.setattr(window, "_on_analysis_done", lambda *a, **k: recus.append(a))
    monkeypatch.setattr(window, "_reset_live_ui", lambda: None)
    window._live_capturing = True
    window._live_stop_event = threading.Event()
    window._live_lock = threading.Lock()
    window._live_threads = []
    window._live_packets = [
        make_pkt(point="A", src="10.0.0.5", dst="10.0.0.9", ts=0.0),
        make_pkt(point="B", src="10.0.0.5", dst="10.0.0.9", ts=0.001),
    ]
    window._live_bucket_ms = 100.0
    window._live_rtp_rate = 50
    window._live_nat_tolerant = False
    window._live_triage = False
    window._live_triage_topn = 5
    window._live_points_order = None
    window._live_detect_duplicates = False
    window._live_exclude_duplicates = False
    window._live_duplicate_threshold_ms = 50.0
    window._live_forensic_index = True

    window._join_live_and_analyze()
    _pump()

    assert isinstance(recus[0][-1], ForensicSearchIndex)
