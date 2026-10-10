"""Issue #676 : comparaison d'un baseline enregistre avec un courant capture
en direct dans la fenetre principale (equivalent de --live-current) :
demarrage, reglages releves, fin de capture -> comparaison.

Ignore sans GTK4 ou sans affichage, meme garde que test_app_gtk4_lot4.py.
"""

import pytest
from conftest import make_pkt
from gtk4_display import exiger_gtk4_avec_affichage

Gtk = exiger_gtk4_avec_affichage()

import netcross_gtk4.app as app_module  # noqa: E402
import netcross_gtk4.diff_pipeline as diff_mod  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402
from netcross_gtk4.diff_pipeline import DiffResult  # noqa: E402
from netcross_gtk4.panel_state import LABEL_DEMARRER_CAPTURE  # noqa: E402

_N = 0


@pytest.fixture()
def window(monkeypatch):
    global _N
    _N += 1
    app = Gtk.Application(application_id=f"org.netcross.test676livecur.n{_N}")
    app.register(None)
    monkeypatch.setattr(app_module.GLib, "idle_add", lambda f, *a, **k: f(*a, **k) or 0)
    return MainWindow(app)


class _FauxThread:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self.target, self.args, self.kwargs = target, args, kwargs or {}

    def start(self):
        pass

    def join(self, timeout=None):
        pass


@pytest.fixture()
def threads(monkeypatch):
    crees = []

    class _Enregistre(_FauxThread):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            crees.append(self)

    monkeypatch.setattr(app_module.threading, "Thread", _Enregistre)
    return crees


def _log(window):
    buf = window.log_view.get_buffer()
    return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)


def _configurer(window, baseline=2):
    window.diff_check.set_active(True)
    window.live_check.set_active(True)
    for i in range(baseline):
        window.baseline_panel.add_row(f"/base/{i}.pcap", f"P{i}")
    window.live_panel.add_row("LAN", "eth0")
    window.live_panel.add_row("WAN", "eth1")


def test_bouton_demarrer_capture_avec_baseline_et_points_live(window):
    _configurer(window)
    assert window.current_panel.get_visible() is False
    assert window.ring_buffer_box.get_visible() is False
    assert window.live_report_box.get_visible() is False
    etat = window._run_button_state()
    assert etat.enabled, etat.raison
    assert etat.label == LABEL_DEMARRER_CAPTURE


def test_demarrage_releve_baseline_et_reglages(window, threads):
    _configurer(window)
    window.loss_threshold_spin.set_value(7)
    window.latency_threshold_spin.set_value(3)
    window.diff_triage_check.set_active(True)
    window.auto_topology_check.set_active(False)

    window.on_run_analysis(None)

    assert window._live_capturing
    assert [t.args[:2] for t in threads] == [("LAN", "eth0"), ("WAN", "eth1")]
    baseline, points, options = window._live_diff
    assert baseline == [("P0", "/base/0.pcap"), ("P1", "/base/1.pcap")]
    assert points == ["LAN", "WAN"]
    assert options.loss_min_pp == 7
    assert options.latency_min_ms == 3
    assert options.triage is True
    assert options.auto_topology is False
    assert options.tls is False and options.quic is False


def test_baseline_insuffisant_bloque_le_demarrage(window, threads):
    _configurer(window, baseline=1)

    window._begin_live_capture()

    assert threads == []
    assert not window._live_capturing
    assert "2 captures de reference minimum" in _log(window)


def test_capture_simple_sans_comparaison(window, threads):
    window.live_check.set_active(True)
    window.live_panel.add_row("LAN", "eth0")
    window.live_panel.add_row("WAN", "eth1")

    window._begin_live_capture()

    assert window._live_diff is None


def test_fin_de_capture_compare_avec_le_courant_capture(window, threads, monkeypatch):
    _configurer(window)
    window._begin_live_capture()
    paquets = [make_pkt(point="LAN", ts=1.0), make_pkt(point="WAN", ts=1.001)]
    window._live_packets = list(paquets)
    appels = {}

    def faux_pipeline(baseline, current, options, on_progress=None, **kw):
        appels.update(baseline=baseline, current=current, **kw)
        on_progress("Comparaison terminée.")
        return DiffResult(findings=["ecart"], baseline_report="B", current_report="C", text="TEXTE")

    monkeypatch.setattr(diff_mod, "run_diff_pipeline", faux_pipeline)
    fin = []
    monkeypatch.setattr(window, "_on_diff_done", lambda *a: fin.append(a))
    monkeypatch.setattr(window, "_on_analysis_done", lambda *a: pytest.fail("pas d'analyse simple"))

    window._join_live_and_analyze()

    assert appels["baseline"] == [("P0", "/base/0.pcap"), ("P1", "/base/1.pcap")]
    assert appels["current"] == []
    assert appels["current_packets"] == paquets
    assert appels["current_points"] == ["LAN", "WAN"]
    # 4 emplacements TLS/QUIC vides (pas de fichiers en direct), puis la
    # table d'anonymisation (issue #876)
    assert fin == [(["ecart"], "B", "C", "TEXTE", None, None, None, None, ())]
    assert "Comparaison..." in _log(window)
    assert window._live_capturing is False


def test_erreur_de_comparaison_remonte_et_reinitialise(window, threads, monkeypatch):
    _configurer(window)
    window._begin_live_capture()
    window._live_packets = []

    def casse(*a, **k):
        raise ValueError("baseline illisible")

    monkeypatch.setattr(diff_mod, "run_diff_pipeline", casse)

    window._join_live_and_analyze()

    assert "ERREUR : baseline illisible" in _log(window)
    assert "Erreur : baseline illisible" in window.work_status_label.get_text()
    assert window._live_capturing is False


def test_fin_reelle_avec_le_vrai_pipeline(window, threads, monkeypatch):
    """Bout en bout sans tshark : baseline lu via parse_capture factice,
    courant = paquets « captures » ; le resultat arrive a _on_diff_done."""
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_capture",
        lambda label, path: [make_pkt(point=label, src="10.0.0.1", dst="10.0.0.2", ts=1.0)],
    )
    _configurer(window)
    window.parallel_check.set_active(False)
    window._begin_live_capture()
    window._live_packets = [
        make_pkt(point="LAN", src="10.0.0.1", dst="10.0.0.2", ts=5.0),
        make_pkt(point="WAN", src="10.0.0.1", dst="10.0.0.2", ts=5.001),
    ]
    fin = []
    monkeypatch.setattr(window, "_on_diff_done", lambda *a: fin.append(a))

    window._join_live_and_analyze()

    assert len(fin) == 1
    _findings, baseline_report, current_report, text, *_tls_quic, redaction_map = fin[0]
    assert redaction_map == ()
    assert baseline_report is not None and current_report is not None
    assert isinstance(text, str)
