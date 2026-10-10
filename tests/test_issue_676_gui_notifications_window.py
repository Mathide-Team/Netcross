"""Issue #676 : reglages de notification dans la fenetre principale (menu
« Notifier si », canaux, detail), validation avant lancement et
transmission au thread d'analyse.

Ignore sans GTK4 ou sans affichage, meme garde que test_app_gtk4_lot4.py.
"""

from typing import ClassVar

import pytest
from gtk4_display import exiger_gtk4_avec_affichage

Gtk = exiger_gtk4_avec_affichage()

import netcross_gtk4.app as app_module  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402
from netcross_gtk4.notifications import NotifySettings  # noqa: E402

_N = 0


@pytest.fixture()
def window():
    global _N
    _N += 1
    app = Gtk.Application(application_id=f"org.netcross.test676notify.n{_N}")
    app.register(None)
    return MainWindow(app)


class _FauxThread:
    crees: ClassVar[list] = []

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self.target, self.args, self.kwargs = target, args, kwargs or {}
        _FauxThread.crees.append(self)

    def start(self):
        pass


@pytest.fixture()
def threads(monkeypatch):
    _FauxThread.crees = []
    monkeypatch.setattr(app_module.threading, "Thread", _FauxThread)
    return _FauxThread.crees


def _log(window):
    buf = window.log_view.get_buffer()
    return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)


def test_canaux_reglables_seulement_avec_un_seuil(window):
    assert window.notify_threshold_drop.get_selected() == 0
    assert not window.notify_webhook_entry.get_sensitive()
    assert not window.notify_complete_check.get_sensitive()
    window.notify_threshold_drop.set_selected(1)
    assert window.notify_webhook_entry.get_sensitive()
    assert window.notify_slack_entry.get_sensitive()
    assert window.notify_email_entry.get_sensitive()
    assert window.notify_complete_check.get_sensitive()


def test_reglages_lus_sur_les_widgets(window):
    window.notify_threshold_drop.set_selected(3)
    window.notify_webhook_entry.set_text(" https://hook.example/x ")
    window.notify_email_entry.set_text("a@b.fr")
    window.notify_complete_check.set_active(True)
    assert window._notify_settings() == NotifySettings("moyenne", "https://hook.example/x", None, "a@b.fr", "complet")


def test_seuil_sans_rapport_de_securite_bloque_le_lancement(window, threads):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.notify_threshold_drop.set_selected(1)

    window.on_run_analysis(None)

    assert threads == []
    assert "Rapport de securite" in _log(window)
    assert "analyse non lancee" in _log(window)


def test_url_invalide_bloque_le_lancement(window, threads):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.security_check.set_active(True)
    window.notify_threshold_drop.set_selected(1)
    window.notify_webhook_entry.set_text("file:///etc/passwd")

    window.on_run_analysis(None)

    assert threads == []
    assert "URL webhook invalide" in _log(window)


def test_reglages_transmis_au_thread_d_analyse(window, threads):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.security_check.set_active(True)
    window.notify_threshold_drop.set_selected(2)
    window.notify_slack_entry.set_text("https://hooks.slack.com/x")

    window.on_run_analysis(None)

    (thread,) = threads
    assert thread.target == window._run_analysis_thread
    assert thread.kwargs["notify"] == NotifySettings("elevee", slack="https://hooks.slack.com/x")


def test_sans_seuil_transmis_inactif(window, threads):
    window.add_capture_row("/tmp/a.pcap", "A")

    window.on_run_analysis(None)

    (thread,) = threads
    assert thread.kwargs["notify"] == NotifySettings()
    assert not thread.kwargs["notify"].active


def test_thread_d_analyse_passe_les_reglages_au_pipeline(window, monkeypatch):
    vus = []

    def faux_pipeline(captures, options, on_progress=None):
        vus.append(options.notify)
        raise ValueError("arret du test")

    monkeypatch.setattr("netcross_gtk4.analysis_pipeline.run_analysis_pipeline", faux_pipeline)
    monkeypatch.setattr(app_module.GLib, "idle_add", lambda f, *a, **k: f(*a, **k) or 0)
    settings = NotifySettings("critique", webhook="https://hook.example/x")
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
        security=True,
        redact=False,
        topn=25,
        detect_duplicates=False,
        exclude_duplicates=False,
        duplicate_threshold_ms=2.0,
        notify=settings,
    )
    assert vus == [settings]
