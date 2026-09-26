"""Lot 4/10 de couverture de netcross_gtk4/app.py (issue #425, sous-issue de

#421) : `add_capture_row`, `_log`, `on_run_analysis` et
`_begin_live_capture` (lignes 1074-1544), pilotes via pygobject.

Ignore si GTK4/pygobject ou un affichage manquent (CI sans libgtk-4), meme
garde-fou que test_gui_security_window.py (lot #357).

Contrairement au lot 3, ces quatre methodes mutent lourdement l'etat de la
fenetre (lignes de capture ajoutees aux panneaux, `_live_capturing`,
desactivation des boutons...). Une fixture `window` de scope "module"
partagee entre tous les tests du fichier rendrait chaque test dependant de
l'ordre d'execution des precedents ; on utilise donc une fixture dediee de
scope "function" (une `MainWindow` neuve par test), tout en reutilisant la
meme `Gtk.Application` (scope "module", cout d'enregistrement negligeable
mais pas nul) comme le permet l'issue.

Aucun vrai thread d'analyse/capture n'est jamais demarre : `threading.Thread`
est monkeypatche pour enregistrer la cible et les arguments avec lesquels il
aurait ete construit sans jamais appeler `start()` -- donc jamais de vrai
tshark ni de vrai fichier pcap requis pour ces tests.
"""

import pytest

gi = pytest.importorskip("gi", reason="pygobject absent")
try:
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk
except (ValueError, ImportError):
    pytest.skip("GTK4 absent", allow_module_level=True)
if not Gtk.init_check():
    pytest.skip("pas d'affichage pour GTK4", allow_module_level=True)

import netcross_gtk4.app as app_module  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402


class _RecordedThread:
    """Remplace `threading.Thread` : ne demarre jamais de vrai thread (donc

    jamais de vrai tshark/pcap) et garde une trace de la cible/des arguments
    passes, pour verifier le cablage reel de on_run_analysis/
    _begin_live_capture sans dependre de fichiers ou d'interfaces reelles.
    """

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self.target = target
        self.args = args
        self.kwargs = kwargs or {}
        self.daemon = daemon

    def start(self):
        pass

    def join(self, timeout=None):
        pass

    def is_alive(self):
        return False


@pytest.fixture(scope="module")
def gtk_app():
    app = Gtk.Application(application_id="org.netcross.test425")
    app.register(None)
    return app


@pytest.fixture()
def window(gtk_app):
    """Une `MainWindow` neuve par test (voir le docstring du module)."""
    return MainWindow(gtk_app)


@pytest.fixture()
def recorded_threads(monkeypatch):
    """Intercepte tous les `threading.Thread(...)` construits pendant le

    test et renvoie la liste des instances (fausses) creees, dans l'ordre.
    """
    created = []

    class _Recording(_RecordedThread):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            created.append(self)

    monkeypatch.setattr(app_module.threading, "Thread", _Recording)
    return created


def _log_text(window):
    buf = window.log_view.get_buffer()
    return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)


# ------------------------- add_capture_row / _log -------------------------


def test_add_capture_row_delegue_au_panneau_simple(window):
    window.add_capture_row("/tmp/a.pcap", "Site A")
    assert window.single_panel.captures() == [("Site A", "/tmp/a.pcap")]

    # Sans libelle explicite : derive automatiquement du nom de fichier
    # (comportement reel de CaptureListPanel.add_row, non redevine ici).
    window.add_capture_row("/tmp/site_b.pcap")
    labels = [label for label, _path in window.single_panel.captures()]
    assert labels[0] == "Site A"
    assert labels[1] and labels[1] != "Site A"


def test_log_ajoute_les_messages_dans_lordre_et_renvoie_false(window):
    assert _log_text(window) == ""

    ret1 = window._log("premiere ligne")
    assert ret1 is False
    assert _log_text(window) == "premiere ligne\n"

    ret2 = window._log("deuxieme ligne")
    assert ret2 is False
    assert _log_text(window) == "premiere ligne\ndeuxieme ligne\n"


# ------------------------------ on_run_analysis ----------------------------


def test_on_run_analysis_sans_capture_lance_quand_meme_un_thread(window, recorded_threads):
    # Comportement reel du code (verifie par execution, pas suppose) :
    # on_run_analysis ne bloque pas lui-meme sur une liste de captures
    # vide -- c'est la sensibilite du bouton "Lancer" (_update_run_
    # sensitivity, lot 3) qui empeche normalement l'utilisateur de cliquer
    # dessus. Ici on appelle directement la methode, sans capture ajoutee.
    window.on_run_analysis(None)

    assert len(recorded_threads) == 1
    thread = recorded_threads[0]
    assert thread.target == window._run_analysis_thread
    captures = thread.args[0]
    assert list(captures) == []
    assert not window.run_btn.get_sensitive()


def test_on_run_analysis_mode_simple_cible_run_analysis_thread(window, recorded_threads):
    window.add_capture_row("/tmp/c.pcap", "C")

    window.on_run_analysis(None)

    assert len(recorded_threads) == 1
    thread = recorded_threads[0]
    assert thread.target == window._run_analysis_thread
    assert list(thread.args[0]) == [("C", "/tmp/c.pcap")]


def test_on_run_analysis_mode_diff_cible_run_diff_thread(window, recorded_threads):
    window.diff_check.set_active(True)
    window.baseline_panel.add_row("/tmp/a.pcap", "A")
    window.current_panel.add_row("/tmp/b.pcap", "B")

    window.on_run_analysis(None)

    assert len(recorded_threads) == 1
    thread = recorded_threads[0]
    assert thread.target == window._run_diff_thread
    assert thread.target != window._run_analysis_thread
    baseline_arg, courant_arg = thread.args[0], thread.args[1]
    assert list(baseline_arg) == [("A", "/tmp/a.pcap")]
    assert list(courant_arg) == [("B", "/tmp/b.pcap")]


def test_on_run_analysis_desactive_les_boutons_et_bascule_la_page(window, recorded_threads):
    window.add_capture_row("/tmp/c.pcap", "C")
    window.run_btn.set_sensitive(True)

    window.on_run_analysis(None)

    assert not window.run_btn.get_sensitive()
    assert window.stack.get_visible_child_name() == "log"
    # Le journal a ete vide avant le lancement (pas de residu d'un appel
    # precedent).
    assert _log_text(window) == ""


def test_on_run_analysis_redact_incompatible_avec_tls_ne_lance_rien(window, recorded_threads):
    window.add_capture_row("/tmp/c.pcap", "C")
    window.redact_check.set_active(True)
    window.tls_check.set_active(True)

    window.on_run_analysis(None)

    assert recorded_threads == []
    assert "redact" in _log_text(window)
    assert "TLS" in _log_text(window) or "QUIC" in _log_text(window)


def test_on_run_analysis_mode_live_delegue_selon_letat_de_capture(window, monkeypatch):
    window.live_check.set_active(True)
    appels = []
    monkeypatch.setattr(window, "_begin_live_capture", lambda: appels.append("begin"))
    monkeypatch.setattr(window, "_end_live_capture", lambda: appels.append("end"))

    window.on_run_analysis(None)
    assert appels == ["begin"]

    window._live_capturing = True
    window.on_run_analysis(None)
    assert appels == ["begin", "end"]


# ---------------------------- _begin_live_capture --------------------------


def test_begin_live_capture_interface_manquante_bloque_le_demarrage(window, recorded_threads):
    window.live_panel.add_row("P1", "")

    window._begin_live_capture()

    assert recorded_threads == []
    assert not window._live_capturing
    assert "Interface manquante" in _log_text(window)
    assert "P1" in _log_text(window)


def test_begin_live_capture_source_invalide_bloque_le_demarrage(window, recorded_threads):
    window.live_panel.add_row("P1", "rpcap://bad url with space")

    window._begin_live_capture()

    assert recorded_threads == []
    assert not window._live_capturing
    assert "invalide" in _log_text(window)


def test_begin_live_capture_doublons_de_labels_bloque_le_demarrage(window, recorded_threads):
    window.live_panel.add_row("P1", "eth0")
    window.live_panel.add_row("P1", "eth1")

    window._begin_live_capture()

    assert recorded_threads == []
    assert not window._live_capturing
    assert "double" in _log_text(window)


def test_begin_live_capture_mono_interface_demarre_un_thread(window, recorded_threads):
    window.live_panel.add_row("P1", "eth0")
    # Duree max > 0 : couvre aussi la programmation du minuteur d'arret
    # automatique (GLib.timeout_add_seconds), sans attendre qu'il se
    # declenche (hors perimetre du lot : _on_live_duration_elapsed).
    window.live_duration_spin.set_value(30)

    window._begin_live_capture()

    assert window._live_capturing
    assert not window.live_panel.get_sensitive()
    assert len(recorded_threads) == 1
    thread = recorded_threads[0]
    assert thread.target == window._live_capture_worker
    assert thread.args == ("P1", "eth0", None)


def test_begin_live_capture_multi_interface_eclate_les_points(window, recorded_threads):
    # "eth0, eth1" sur un seul point nomme "GW" -> deux points de capture
    # distincts, un thread par interface, expandes via
    # netcross_gtk4.live_capture_points.expand_live_points.
    window.live_panel.add_row("GW", "eth0, eth1")

    window._begin_live_capture()

    assert window._live_capturing
    assert len(recorded_threads) == 2
    cibles = {(t.target, t.args) for t in recorded_threads}
    assert cibles == {
        (window._live_capture_worker, ("GW:eth0", "eth0", None)),
        (window._live_capture_worker, ("GW:eth1", "eth1", None)),
    }
