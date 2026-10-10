"""Issue #866 : champs « Module IA local » de la fenetre principale,
validation avant lancement et transmission au thread d'analyse.

Ignore sans GTK4 ou sans affichage, meme garde que test_app_gtk4_lot4.py.
"""

from typing import ClassVar

import pytest
from gtk4_display import exiger_gtk4_avec_affichage

Gtk = exiger_gtk4_avec_affichage()

import netcross_gtk4.app as app_module  # noqa: E402
from netcross_gtk4.ai_settings import AISettings  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402

_N = 0


@pytest.fixture()
def window():
    global _N
    _N += 1
    app = Gtk.Application(application_id=f"org.netcross.test866ai.n{_N}")
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


def test_champs_lus(window, tmp_path):
    base = tmp_path / "b.json"
    base.write_text("{}", encoding="utf-8")
    window.ai_baseline_save_entry.set_text(f"{tmp_path}/s.json")
    window.ai_baseline_label_entry.set_text("bureau")
    window.ai_anomalies_option.set_path(str(base))
    window.ai_summary_entry.set_text("template")
    window.ai_report_entry.set_text(f"{tmp_path}/ia.json")
    assert window.ai_settings() == AISettings(
        baseline_save=f"{tmp_path}/s.json",
        baseline_label="bureau",
        anomalies=str(base),
        summary="template",
        report=f"{tmp_path}/ia.json",
    )


def test_option_sans_usage_bloque_le_lancement(window, threads):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.ai_report_entry.set_text("/tmp/ia.json")

    window.on_run_analysis(None)

    assert threads == []
    assert "necessitent une option --ai-*" in _log(window)
    assert "analyse non lancee" in _log(window)


def test_moteur_hors_boucle_locale_bloque(window, threads):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.ai_summary_entry.set_text("ollama:m")
    window.ai_endpoint_entry.set_text("http://203.0.113.5:11434")

    window.on_run_analysis(None)

    assert threads == []
    assert "Module IA" in _log(window)


def test_reglages_transmis_au_thread(window, threads):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.ai_summary_entry.set_text("template")

    window.on_run_analysis(None)

    (thread,) = threads
    assert thread.kwargs["ai"] == AISettings(summary="template")


def test_sans_usage_transmis_inactif(window, threads):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.on_run_analysis(None)
    (thread,) = threads
    assert not thread.kwargs["ai"].requested


def test_thread_d_analyse_passe_les_reglages_au_pipeline(window, monkeypatch):
    vus = []

    def faux_pipeline(captures, options, on_progress=None):
        vus.append(options.ai)
        raise ValueError("arret du test")

    monkeypatch.setattr("netcross_gtk4.analysis_pipeline.run_analysis_pipeline", faux_pipeline)
    monkeypatch.setattr(app_module.GLib, "idle_add", lambda f, *a, **k: f(*a, **k) or 0)
    settings = AISettings(summary="template")
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
        ai=settings,
    )
    assert vus == [settings]
