"""Issue #676 : rapport HTML en continu dans la fenetre principale (case,
reglages, demarrage avec la capture en direct, alimentation par les threads
de capture, derniere publication a l'arret).

Ignore sans GTK4 ou sans affichage, meme garde que test_app_gtk4_lot5.py.
"""

import threading

import pytest
from conftest import make_pkt
from gtk4_display import exiger_gtk4_avec_affichage

Gtk = exiger_gtk4_avec_affichage()

import netcross_gtk4.app as app_module  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402
from netcross_gtk4.live_report_session import LiveReportError  # noqa: E402

_N = 0


@pytest.fixture()
def window():
    global _N
    _N += 1
    app = Gtk.Application(application_id=f"org.netcross.test676live.n{_N}")
    app.register(None)
    return MainWindow(app)


@pytest.fixture(autouse=True)
def _idle_immediat(monkeypatch):
    monkeypatch.setattr(app_module.GLib, "idle_add", lambda func, *a, **k: func(*a, **k) or 0)


class _Session:
    def __init__(self):
        self.paquets = []
        self.arrets = []
        self.stoppee = False

    def add(self, pkt):
        self.paquets.append(pkt)

    def point_stopped(self, label, error=None):
        self.arrets.append((label, error))

    def stop(self):
        self.stoppee = True
        return ["Rapport en continu : derniere publication dans /tmp/live/index.html"]


class _FauxThread:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self.target, self.args = target, args

    def start(self):
        pass

    def join(self, timeout=None):
        pass


def _log(window):
    buf = window.log_view.get_buffer()
    return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)


def test_reglages_actifs_seulement_avec_la_case(window):
    assert not window.live_report_dir_entry.get_sensitive()
    assert not window.live_report_port_spin.get_sensitive()
    window.live_report_check.set_active(True)
    assert window.live_report_dir_entry.get_sensitive()
    assert window.live_report_interval_spin.get_sensitive()
    assert not window.live_report_port_spin.get_sensitive()
    window.live_report_serve_check.set_active(True)
    assert window.live_report_port_spin.get_sensitive()


def test_visible_en_mode_capture_live_uniquement(window):
    assert not window.live_report_box.get_visible()
    window.live_check.set_active(True)
    assert window.live_report_box.get_visible()


def test_demarrage_transmet_les_reglages(window, monkeypatch):
    appels = []

    def faux_start(labels, out_dir, interval, serve_port):
        appels.append((labels, out_dir, interval, serve_port))
        return _Session(), ["Rapport en continu : /tmp/live/index.html"]

    monkeypatch.setattr(app_module, "start_live_report", faux_start)
    monkeypatch.setattr(app_module.threading, "Thread", _FauxThread)
    window.live_check.set_active(True)
    window.live_panel.add_row("P1", "eth0")
    window.live_report_check.set_active(True)
    window.live_report_dir_entry.set_text("  /tmp/live  ")
    window.live_report_interval_spin.set_value(7)
    window.live_report_serve_check.set_active(True)
    window.live_report_port_spin.set_value(8123)

    window._begin_live_capture()

    assert appels == [(["P1"], "/tmp/live", 7.0, 8123)]
    assert window._live_capturing
    assert not window.live_report_box.get_sensitive()
    assert "Rapport en continu : /tmp/live/index.html" in _log(window)


def test_sans_service_ni_repertoire(window, monkeypatch):
    appels = []
    monkeypatch.setattr(app_module, "start_live_report", lambda *a: appels.append(a) or (_Session(), []))
    monkeypatch.setattr(app_module.threading, "Thread", _FauxThread)
    window.live_check.set_active(True)
    window.live_panel.add_row("P1", "eth0")
    window.live_report_check.set_active(True)

    window._begin_live_capture()

    assert appels == [(["P1"], None, 5.0, None)]


def test_case_decochee_aucun_rapport(window, monkeypatch):
    monkeypatch.setattr(app_module, "start_live_report", lambda *a: pytest.fail("ne doit pas demarrer"))
    monkeypatch.setattr(app_module.threading, "Thread", _FauxThread)
    window.live_check.set_active(True)
    window.live_panel.add_row("P1", "eth0")

    window._begin_live_capture()

    assert window._live_capturing
    assert window._live_report_session is None


def test_refus_annule_la_capture_et_arrete_la_rotation(window, monkeypatch):
    arretes = []

    def refuse(*a):
        raise LiveReportError("impossible d'ecouter sur le port 8123")

    monkeypatch.setattr(app_module, "start_live_report", refuse)
    monkeypatch.setattr(app_module, "start_ring_recorders", lambda *a: ({"P1": ("proc", "/tmp/r")}, []))
    monkeypatch.setattr(app_module, "stop_ring_recorders", lambda rec: arretes.append(dict(rec)) or [])
    monkeypatch.setattr(app_module.threading, "Thread", _FauxThread)
    window.live_check.set_active(True)
    window.live_panel.add_row("P1", "eth0")
    window.ring_buffer_check.set_active(True)
    window.live_report_check.set_active(True)

    window._begin_live_capture()

    assert not window._live_capturing
    assert arretes == [{"P1": ("proc", "/tmp/r")}]
    assert window._live_ring_recorders == {}
    assert "Rapport en continu impossible -- capture annulee" in _log(window)


def _etat_live(window, session):
    window._live_capturing = True
    window._live_stop_event = threading.Event()
    window._live_packets = []
    window._live_lock = threading.Lock()
    window._live_threads = []
    window._live_report_session = session


def test_le_thread_de_capture_alimente_le_rapport(window, monkeypatch):
    session = _Session()
    _etat_live(window, session)
    paquets = [make_pkt(point="P1", sport=1), make_pkt(point="P1", sport=2)]
    monkeypatch.setattr(app_module, "parse_live", lambda *a, **k: iter(paquets))

    window._live_capture_worker("P1", "eth0", None)

    assert session.paquets == paquets
    assert session.arrets == [("P1", None)]


def test_erreur_de_capture_signalee_au_rapport(window, monkeypatch):
    session = _Session()
    _etat_live(window, session)

    def en_erreur(*a, **k):
        raise RuntimeError("interface absente")
        yield  # pragma: no cover -- generateur

    monkeypatch.setattr(app_module, "parse_live", en_erreur)

    window._live_capture_worker("P1", "eth9", None)

    assert session.arrets == [("P1", "interface absente")]


def test_arret_derniere_publication_avant_l_analyse(window, monkeypatch):
    session = _Session()
    _etat_live(window, session)
    window._live_bucket_ms = 100.0
    window._live_rtp_rate = 8000
    window._live_nat_tolerant = False
    window._live_triage = False
    window._live_points_order = None
    window._live_detect_duplicates = False
    window._live_exclude_duplicates = False
    window._live_duplicate_threshold_ms = 2.0
    monkeypatch.setattr(app_module, "correlate", lambda *a, **k: (_ for _ in ()).throw(ValueError("stop")))

    window._join_live_and_analyze()

    assert session.stoppee
    assert window._live_report_session is None
    assert "derniere publication dans /tmp/live/index.html" in _log(window)
