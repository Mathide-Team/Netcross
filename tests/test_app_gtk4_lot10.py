"""Tests app.py -- Lot 10/10 : fin export securite + NetcrossApp/main
(issue #431, sous-issue de #421).

Perimetre : lignes 2594-2637 de netcross_gtk4/app.py, dernier lot (17
instructions non couvertes) -- `_on_security_path_chosen` (fin du dialogue
d'export du rapport de securite) et `NetcrossApp` (__init__/do_activate).

Meme garde-fou que test_gui_security_window.py (issue #285/#421) : aucun
test ici n'exige GTK4 en CI. Ignore proprement si pygobject, GTK4 ou un
affichage manquent -- ces trois methodes sont du pur cablage GTK (dialogue
de sauvegarde, activation de l'application), rien n'est testable sans un
vrai Gtk.Application/Gtk.Window.
"""

import pytest

gi = pytest.importorskip("gi", reason="pygobject absent")
try:
    gi.require_version("Gtk", "4.0")
    from gi.repository import GLib, Gtk
except (ValueError, ImportError):
    pytest.skip("GTK4 absent", allow_module_level=True)
if not Gtk.init_check():
    pytest.skip("pas d'affichage pour GTK4", allow_module_level=True)

from netcross_gtk4.app import MainWindow, NetcrossApp  # noqa: E402


@pytest.fixture(scope="module")
def window():
    app = Gtk.Application(application_id="org.netcross.test431")
    app.register(None)
    return MainWindow(app)


# ================= _on_security_path_chosen =================
# Meme forme que _on_csv_path_chosen/_on_pdf_path_chosen (non couverts par
# ailleurs, cf. recherche de code sur ces callbacks) : un GLib.Error du
# dialogue (annulation) ne doit rien ecrire, un chemin choisi doit
# transmettre le chemin a export_security_to tel quel.


class _FakeGFile:
    def __init__(self, path):
        self._path = path

    def get_path(self):
        return self._path


class _DialogueCheminChoisi:
    def __init__(self, path):
        self._path = path

    def save_finish(self, _result):
        return _FakeGFile(self._path)


class _DialogueAnnule:
    def save_finish(self, _result):
        raise GLib.Error("annule par l'utilisateur")


def test_chemin_choisi_appelle_export_security_to(window, monkeypatch, tmp_path):
    appels = []
    monkeypatch.setattr(window, "export_security_to", lambda path: appels.append(path))
    chemin = str(tmp_path / "rapport_securite.html")

    window._on_security_path_chosen(_DialogueCheminChoisi(chemin), None)

    assert appels == [chemin]


def test_annulation_du_dialogue_ne_declenche_aucun_export(window, monkeypatch):
    appels = []
    monkeypatch.setattr(window, "export_security_to", lambda path: appels.append(path))

    window._on_security_path_chosen(_DialogueAnnule(), None)

    assert appels == []


# ================= NetcrossApp =================


def test_netcrossapp_init():
    app = NetcrossApp()
    assert app.get_application_id() == "org.netcross.analyzer"
    assert app.main_window is None


def test_do_activate_cree_et_presente_la_mainwindow(monkeypatch):
    """`do_activate` cree la MainWindow au premier appel et la reutilise
    (sans la recreer) aux appels suivants -- `present()` est appele a
    chaque fois. `present()` est remplace : il exige un gestionnaire de
    fenetres reel, absent du bac a sable/CI meme quand Gtk.init_check()
    reussit (affichage virtuel sans compositeur)."""
    app = NetcrossApp()
    app.register(None)

    presentees = []
    monkeypatch.setattr(MainWindow, "present", lambda self: presentees.append(self))

    app.do_activate()

    assert isinstance(app.main_window, MainWindow)
    assert presentees == [app.main_window]

    fenetre_existante = app.main_window
    app.do_activate()

    assert app.main_window is fenetre_existante
    assert presentees == [fenetre_existante, fenetre_existante]


def test_main_construit_lapplication_et_lance_run(monkeypatch):
    """`main()` -- hors du perimetre demande (methodes concernees :
    _on_security_path_chosen, NetcrossApp.__init__/do_activate) mais compte
    dans les 17 instructions de la ligne 2594-2637 : autant clore le lot
    completement. `NetcrossApp` est remplacee : `app.run(argv)` entre dans
    la vraie boucle d'evenements GTK, qui ne se termine jamais toute
    seule -- rien a voir avec do_activate(), deja teste ci-dessus."""
    import sys as sys_module

    from netcross_gtk4 import app as app_module

    appels = []

    class _ApplicationFactice:
        def __init__(self):
            appels.append("construite")

        def run(self, argv):
            appels.append(("run", list(argv)))
            return 0

    monkeypatch.setattr(app_module, "NetcrossApp", _ApplicationFactice)
    monkeypatch.setattr(sys_module, "argv", ["netcross-gtk4", "--exemple"])

    resultat = app_module.main()

    assert resultat == 0
    assert appels == ["construite", ("run", ["netcross-gtk4", "--exemple"])]
