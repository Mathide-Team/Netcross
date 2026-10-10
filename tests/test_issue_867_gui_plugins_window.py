"""Issue #867 : champs « Plugins » de la fenetre principale, bouton
« Lister », validation avant lancement et transmission au thread d'analyse.

Ignore sans GTK4 ou sans affichage, meme garde que test_app_gtk4_lot4.py.
"""

import textwrap
from typing import ClassVar

import pytest
from gtk4_display import exiger_gtk4_avec_affichage

Gtk = exiger_gtk4_avec_affichage()

import netcross_gtk4.app as app_module  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402
from netcross_gtk4.plugin_settings import PluginSettings, PreparedPlugins  # noqa: E402

_N = 0

PLUGIN_SOURCE = textwrap.dedent("""
    class Maison:
        name = "maison"
        def analyse(self, contexte):
            return []

    class Csv:
        name = "csv"
        def export(self, report, chemin):
            chemin.write_text("x")

    DETECTORS = [Maison]
    EXPORTERS = [Csv]
    """)


@pytest.fixture()
def window():
    global _N
    _N += 1
    app = Gtk.Application(application_id=f"org.netcross.test867plugins.n{_N}")
    app.register(None)
    return MainWindow(app)


@pytest.fixture
def plugin_file(tmp_path, monkeypatch):
    path = tmp_path / "maison.py"
    path.write_text(PLUGIN_SOURCE, encoding="utf-8")
    monkeypatch.setattr("netcross_core.plugins.loader._entry_points", lambda group: [])
    return str(path)


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
    window.plugins_entry.set_text("maison, csv")
    window.plugin_path_entry.set_text(f"{tmp_path}/a.py;{tmp_path}/b.py")
    window.plugin_export_entry.set_text(f"csv={tmp_path}/o.csv")
    assert window.plugin_settings() == PluginSettings(
        ("maison", "csv"), (f"{tmp_path}/a.py", f"{tmp_path}/b.py"), (("csv", f"{tmp_path}/o.csv"),)
    )


def test_bouton_lister_ecrit_dans_le_journal(window, plugin_file):
    window.plugins_entry.set_text("maison")
    window.plugin_path_entry.set_text(plugin_file)
    window._on_list_plugins(None)
    assert window.stack.get_visible_child_name() == "log"
    texte = _log(window)
    assert "NOM" in texte and "maison" in texte and "csv" in texte


def test_bouton_lister_export_mal_forme(window):
    window.plugin_export_entry.set_text("csv")
    window._on_list_plugins(None)
    assert "NOM=FICHIER" in _log(window)


def test_detecteur_sans_securite_bloque_le_lancement(window, threads, plugin_file):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.plugins_entry.set_text("maison")
    window.plugin_path_entry.set_text(plugin_file)

    window.on_run_analysis(None)

    assert threads == []
    assert "Rapport de securite" in _log(window)
    assert "analyse non lancee" in _log(window)


def test_export_mal_forme_bloque_le_lancement(window, threads):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.plugins_entry.set_text("csv")
    window.plugin_export_entry.set_text("csv")

    window.on_run_analysis(None)

    assert threads == []
    assert "NOM=FICHIER" in _log(window)


def test_plugins_transmis_au_thread(window, threads, plugin_file, tmp_path):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.security_check.set_active(True)
    window.plugins_entry.set_text("maison,csv")
    window.plugin_path_entry.set_text(plugin_file)
    window.plugin_export_entry.set_text(f"csv={tmp_path}/o.csv")

    window.on_run_analysis(None)

    (thread,) = threads
    prepared = thread.kwargs["plugins"]
    assert isinstance(prepared, PreparedPlugins)
    assert [d.name for d in prepared.loaded.detectors] == ["maison"]
    assert prepared.exports == [("csv", f"{tmp_path}/o.csv")]


def test_sans_plugin_rien_transmis(window, threads):
    window.add_capture_row("/tmp/a.pcap", "A")
    window.on_run_analysis(None)
    (thread,) = threads
    assert thread.kwargs["plugins"] is None


def test_thread_d_analyse_passe_les_plugins_au_pipeline(window, monkeypatch):
    vus = []

    def faux_pipeline(captures, options, on_progress=None):
        vus.append(options.plugins)
        raise ValueError("arret du test")

    monkeypatch.setattr("netcross_gtk4.analysis_pipeline.run_analysis_pipeline", faux_pipeline)
    monkeypatch.setattr(app_module.GLib, "idle_add", lambda f, *a, **k: f(*a, **k) or 0)
    prepared = PreparedPlugins(loaded=None)
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
        plugins=prepared,
    )
    assert vus == [prepared]
