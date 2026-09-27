"""#468 -- lancement de la GUI sans affichage accessible (root, SSH) :
message explicite et code de sortie, pas de trace Gtk-CRITICAL."""

from __future__ import annotations

import pytest

gi = pytest.importorskip("gi")
try:
    gi.require_version("Gtk", "4.0")
except ValueError:
    pytest.skip("GTK4 absent", allow_module_level=True)

from netcross_gtk4 import app  # noqa: E402


def test_message_root_sans_affichage():
    msg = app.display_unavailable_message(environ={}, euid=0)
    assert "DISPLAY" in msg
    assert "sans sudo" in msg
    assert "netcross --help" in msg


def test_message_utilisateur_avec_display():
    msg = app.display_unavailable_message(environ={"DISPLAY": ":0"}, euid=1000)
    assert "sans sudo" not in msg
    assert "ni DISPLAY" not in msg


def test_main_sans_affichage_sort_proprement(monkeypatch, capsys):
    monkeypatch.setattr(app, "display_available", lambda: False)
    monkeypatch.setattr(app.sys, "argv", ["netcross-gui"])

    def interdit():  # pragma: no cover - ne doit pas etre appele
        raise AssertionError("NetcrossApp ne doit pas etre construite sans affichage")

    monkeypatch.setattr(app, "NetcrossApp", interdit)
    assert app.main() == 2
    assert "impossible d'ouvrir l'interface graphique" in capsys.readouterr().err
