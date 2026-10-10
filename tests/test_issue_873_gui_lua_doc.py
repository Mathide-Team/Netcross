"""Issue #873 : fenêtre « Documentation Lua » de la GUI, même texte et même
JSON que ``netcross-lua-doc``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import netcross_lua_doc_cli as cli
from netcross_core import lua_doc
from netcross_gtk4.lua_doc_view import LuaDocBrowser, LuaDocUnavailableError

JSON_PATH = Path(__file__).resolve().parent.parent / "data" / "lua_api.json"


@pytest.fixture
def browser(tmp_path):
    b = LuaDocBrowser(db_path=tmp_path / "gui.db", source=JSON_PATH)
    yield b
    b.close()


def _cli(tmp_path, capsys, *args):
    rc = cli.main(["--db", str(tmp_path / "cli.db"), "--source", str(JSON_PATH), *args])
    out, err = capsys.readouterr()
    return rc, out.rstrip(), err.rstrip()


def test_classes_comme_la_cli(browser, tmp_path, capsys):
    assert browser.classes_text() == _cli(tmp_path, capsys, "--classes")[1]
    assert "Tvb" in browser.classes()


def test_fiche_comme_la_cli(browser, tmp_path, capsys):
    assert browser.class_text("tvb") == _cli(tmp_path, capsys, "--class", "Tvb")[1]


def test_classe_inconnue_meme_message(browser, tmp_path, capsys):
    rc, _, err = _cli(tmp_path, capsys, "--class", "Tvbx")
    assert rc == 1
    assert browser.class_text("Tvbx") == err


@pytest.mark.parametrize("full", [False, True])
def test_recherche_comme_la_cli(browser, tmp_path, capsys, full):
    texte, classes = browser.search("tvb range", 3, full)
    args = ["--limit", "3", *(["--full"] if full else []), "tvb", "range"]
    assert texte == _cli(tmp_path, capsys, *args)[1]
    assert classes and classes[0] == "Tvb"


def test_recherche_sans_resultat_et_vide(browser):
    assert browser.search("zzzzaucunresultat")[0].startswith("Aucun resultat pour « zzzzaucunresultat »")
    assert browser.search("   ") == ("", [])


def test_json_comme_la_cli(browser, tmp_path, capsys):
    for kwargs, args in (
        ({}, ["--classes"]),
        ({"name": "Tvb"}, ["--class", "Tvb"]),
        ({"terme": "add", "limit": 3, "full": True}, ["--limit", "3", "--full", "add"]),
    ):
        assert json.loads(browser.json_text(**kwargs)) == json.loads(_cli(tmp_path, capsys, "--json", *args)[1])


def test_json_introuvable(tmp_path):
    with pytest.raises(LuaDocUnavailableError, match="introuvable"):
        LuaDocBrowser(db_path=tmp_path / "x.db", find_json=lambda: None)


def _gtk():
    from gtk4_display import exiger_gtk4_avec_affichage

    return exiger_gtk4_avec_affichage()


def test_fenetre(browser):
    _gtk()
    from netcross_gtk4.lua_doc_window import LuaDocWindow

    win = LuaDocWindow(browser=browser)
    assert win.text() == browser.classes_text()
    win.search_entry.set_text("tvb range")
    win.limit_spin.set_value(3)
    win.full_check.set_active(True)
    win.run_search()
    assert win.text() == browser.search("tvb range", 3, True)[0]
    win.open_class("Tvb")
    assert win.text() == browser.class_text("Tvb")
    win.show_json()
    assert json.loads(win.text())["classe"]["nom"] == "Tvb"
    win.search_entry.set_text("")
    win.run_search()
    assert win.text() == browser.classes_text()


def test_fenetre_sans_json():
    _gtk()
    from netcross_gtk4 import lua_doc_window

    orig = lua_doc.find_json
    try:
        lua_doc.find_json = lambda: None
        win = lua_doc_window.LuaDocWindow()
    finally:
        lua_doc.find_json = orig
    assert win.browser is None
    assert "introuvable" in win.text()
    assert not win.search_entry.get_sensitive()


def test_bouton_de_la_fenetre_principale(monkeypatch, tmp_path):
    gtk = _gtk()
    from netcross_gtk4.app import MainWindow

    monkeypatch.setattr(lua_doc, "DEFAULT_DB_PATH", tmp_path / "main.db")
    monkeypatch.setenv(lua_doc.ENV_JSON, str(JSON_PATH))
    app = gtk.Application(application_id="org.netcross.test873")
    app.register(None)
    window = MainWindow(app)
    assert window.lua_doc_btn.get_label() == "Documentation Lua"
    doc = window.open_lua_doc()
    assert window.open_lua_doc() is doc  # une seule fenetre
    assert "Tvb" in doc.browser.classes()
    doc.close()
