# ruff: noqa: E501 -- CSV de test sur une ligne par dissecteur
"""Issue #917 : catalogue des dissecteurs Lua (recensement wireshark-lua) dans
la banque Lua -- même texte et même JSON en CLI, API et GUI."""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

import netcross_lua_doc_cli as cli
from netcross_core import lua_dissectors, lua_doc

RACINE = Path(__file__).resolve().parent.parent
CSV_PATH = RACINE / "data" / "lua_dissectors.csv"
JSON_PATH = RACINE / "data" / "lua_api.json"

MINI = """url,domaine,protocole,etoiles,forks,derniere_maj,date_creation,licence,archive,topics,langage_confirme,natif_wireshark_4_6_4,ajout
https://github.com/a/modbus-lua,Automatismes industriels / SCADA,Dissecteur Modbus étendu.,12,3,2026-01-02,2020-01-01,MIT,non,scada plc,Lua,Oui : mbtcp,v1
https://github.com/b/umas/,Automatismes industriels / SCADA,UMAS sur Modbus.,40,5,2025-01-02,2021-01-01,—,oui,,Lua,Non,v1
https://gitlab.com/c/jeu,Jeux vidéo,Protocole de jeu Minecraft.,7,0,2024-05-01,2019-01-01,GPL-3.0,non,minecraft,Lua,Non,26/09 v2
https://codeberg.org/d/linky,Énergie / smart grid,Téléinfo Linky.,1,0,,,,non,,Lua,Non,v1
https://github.com/a/modbus-lua,Divers,doublon ignoré,99,0,,,,non,,Lua,Non,v1
"""


@pytest.fixture
def conn(tmp_path):
    c = lua_doc.connect(tmp_path / "cat.db")
    csv_path = tmp_path / "mini.csv"
    csv_path.write_text(MINI, encoding="utf-8")
    assert lua_dissectors.ensure_catalogue(c, csv_path)
    yield c
    c.close()


def test_chargement_et_normalisation(conn):
    assert lua_dissectors.count(conn) == 4  # doublon d'URL ignoré
    total, res = lua_dissectors.search(conn, limit=10)
    assert total == 4
    assert [d.depot for d in res] == ["b/umas", "a/modbus-lua", "c/jeu", "d/linky"]  # étoiles décroissantes
    umas, modbus = res[0], res[1]
    assert umas.url == "https://github.com/b/umas" and umas.archive is True and umas.natif is False
    assert modbus.natif is True and modbus.natif_protocole == "mbtcp" and modbus.hebergeur == "github.com"
    assert res[2].hebergeur == "gitlab.com"


def test_recherche(conn):
    assert [d.depot for d in lua_dissectors.search(conn, "modbus")[1]] == ["b/umas", "a/modbus-lua"]
    assert lua_dissectors.search(conn, "modbus étendu")[0] == 1  # tous les mots
    assert lua_dissectors.search(conn, "etendu")[0] == 1  # sans accents
    assert lua_dissectors.search(conn, "mine")[0] == 1  # préfixe
    assert lua_dissectors.search(conn, "plc")[0] == 1  # topics
    assert lua_dissectors.search(conn, "zzz")[0] == 0
    assert lua_dissectors.search(conn, '"')[0] == 4  # terme vide une fois nettoyé


def test_filtres(conn):
    assert lua_dissectors.search(conn, domaine="ENERGIE")[0] == 1  # sans accents ni casse
    assert lua_dissectors.search(conn, domaine="scada", non_natif=True)[1][0].depot == "b/umas"
    assert lua_dissectors.search(conn, domaine="scada", non_natif=True)[0] == 1
    assert lua_dissectors.search(conn, domaine="inexistant")[0] == 0
    assert lua_dissectors.search(conn, limit=1)[0] == 4


def test_domaines(conn):
    assert lua_dissectors.domains(conn)[0] == ("Automatismes industriels / SCADA", 2)
    doc = lua_dissectors.domains_document(conn)
    assert doc["catalogue"] == 4 and len(doc["domaines"]) == 3


def test_rechargement_seulement_si_le_csv_change(tmp_path):
    c = lua_doc.connect(tmp_path / "r.db")
    p = tmp_path / "c.csv"
    p.write_text(MINI, encoding="utf-8")
    lua_dissectors.ensure_catalogue(c, p)
    c.execute("DELETE FROM dissecteurs WHERE depot = 'd/linky'")
    lua_dissectors.ensure_catalogue(c, p)
    assert lua_dissectors.count(c) == 3  # même empreinte : pas de rechargement
    p.write_text(MINI.replace("Téléinfo", "Teleinfo"), encoding="utf-8")
    lua_dissectors.ensure_catalogue(c, p)
    assert lua_dissectors.count(c) == 4
    c.close()


def test_csv_absent_ou_invalide(tmp_path, monkeypatch):
    c = lua_doc.connect(tmp_path / "x.db")
    monkeypatch.setattr(lua_dissectors, "csv_candidates", lambda: [tmp_path / "absent.csv"])
    assert lua_dissectors.ensure_catalogue(c) is False
    assert lua_dissectors.count(c) == 0
    with pytest.raises(lua_dissectors.CatalogueError, match="colonnes manquantes"):
        lua_dissectors.read_csv("a,b\n1,2\n")
    with pytest.raises(lua_dissectors.CatalogueError, match="ligne 2"):
        lua_dissectors.read_csv("url,domaine,protocole\nftp://x,y,z\n")
    c.close()


def test_variable_d_environnement(tmp_path, monkeypatch):
    p = tmp_path / "env.csv"
    p.write_text(MINI, encoding="utf-8")
    monkeypatch.setenv(lua_dissectors.ENV_CSV, str(p))
    assert lua_dissectors.find_csv() == p


def test_catalogue_versionne():
    """data/lua_dissectors.csv : recensement complet et normalisé."""
    c = lua_doc.connect(":memory:")
    assert lua_dissectors.ensure_catalogue(c, CSV_PATH)
    assert lua_dissectors.count(c) >= 1000
    assert {d for d, _n in lua_dissectors.domains(c)} >= {"Jeux vidéo", "Automatismes industriels / SCADA"}
    rc = subprocess.run(
        [sys.executable, str(RACINE / "scripts" / "import_lua_dissectors.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert rc.returncode == 0, rc.stderr
    c.close()


def test_import_fusionne(tmp_path):
    sys.path.insert(0, str(RACINE / "scripts"))
    try:
        imp = importlib.import_module("import_lua_dissectors")
    finally:
        sys.path.pop(0)
    nouveau = MINI.splitlines()[0] + "\nhttps://github.com/e/neuf,Divers,Nouveau.,0,0,,,,non,,Lua,Non,v3\n"
    texte = imp.normaliser([MINI, nouveau])
    lignes = texte.splitlines()
    assert lignes[0] == ",".join(lua_dissectors.COLONNES)
    assert len(lignes) == 6 and "https://github.com/b/umas," in texte  # / final retiré
    sortie = tmp_path / "out.csv"
    src = tmp_path / "in.csv"
    src.write_text(MINI, encoding="utf-8")
    assert imp.main([str(src), "--output", str(sortie)]) == 0
    assert imp.main([str(tmp_path / "absent.csv"), "--output", str(sortie)]) == 1


# -- CLI ------------------------------------------------------------------------------------


def _cli(tmp_path, capsys, *args):
    rc = cli.main(["--db", str(tmp_path / "cli.db"), "--catalog", str(tmp_path / "mini.csv"), *args])
    out, err = capsys.readouterr()
    return rc, out.rstrip(), err.rstrip()


@pytest.fixture
def mini(tmp_path):
    (tmp_path / "mini.csv").write_text(MINI, encoding="utf-8")
    return tmp_path


def test_cli_dissecteurs(mini, capsys):
    rc, out, _ = _cli(mini, capsys, "--dissectors", "modbus")
    assert rc == 0
    assert out.splitlines()[0] == "2 dissecteur(s) Lua sur 4 -- « modbus »"
    assert "b/umas [archivé]  (40 étoiles, licence inconnue" in out
    assert "natif Wireshark : mbtcp" in out
    rc, out, _ = _cli(mini, capsys, "--dissectors", "--domain", "scada", "--non-native", "--limit", "1")
    assert out.splitlines()[0] == "1 dissecteur(s) Lua sur 4 -- domaine « scada », sans dissecteur natif"
    rc, out, _ = _cli(mini, capsys, "--dissectors", "--limit", "1")
    assert out.splitlines()[0].endswith("tout le catalogue (1 affichés, voir --limit)")


def test_cli_json_et_domaines(mini, capsys):
    rc, out, _ = _cli(mini, capsys, "--dissectors", "--json", "jeu")
    assert rc == 0 and json.loads(out)["dissecteurs"][0]["depot"] == "c/jeu"
    rc, out, _ = _cli(mini, capsys, "--domains")
    assert out.splitlines()[0] == "3 domaines -- 4 dissecteurs Lua"
    rc, out, _ = _cli(mini, capsys, "--domains", "--json")
    assert json.loads(out)["catalogue"] == 4


def test_cli_erreurs(mini, capsys):
    assert _cli(mini, capsys, "--dissectors", "zzz")[0:3:2] == (1, "Aucun dissecteur Lua pour « zzz ».")
    rc = cli.main(["--db", str(mini / "x.db"), "--catalog", str(mini / "absent.csv"), "--domains"])
    assert rc == 1 and "introuvable" in capsys.readouterr().err
    for args in (["--domain", "x", "tvb"], ["--non-native", "tvb"], ["--domains", "x"], ["--dissectors", "--classes"]):
        with pytest.raises(SystemExit):
            cli.main(args)
        capsys.readouterr()


def test_cli_sans_json_de_l_api(mini, capsys, monkeypatch):
    """Le catalogue ne dépend pas de data/lua_api.json."""
    monkeypatch.setattr(lua_doc, "find_json", lambda: None)
    assert _cli(mini, capsys, "--dissectors", "linky")[0] == 0


# -- API ------------------------------------------------------------------------------------


@pytest.fixture
def client(mini, monkeypatch):
    pytest.importorskip("fastapi", reason="extra [api] non installé")
    from fastapi.testclient import TestClient

    api = importlib.import_module("netcross_api.app")
    monkeypatch.setattr(lua_doc, "DEFAULT_DB_PATH", mini / "api.db")
    monkeypatch.setenv(lua_dissectors.ENV_CSV, str(mini / "mini.csv"))
    monkeypatch.setattr(api, "_API_TOKEN", None)
    return TestClient(api.app)


def test_api_comme_la_cli(client, mini, capsys):
    rep = client.get("/lua-doc/dissectors", params={"q": "modbus", "domain": "scada", "limit": 5})
    assert rep.status_code == 200
    assert rep.json() == json.loads(_cli(mini, capsys, "--dissectors", "--json", "--domain", "scada", "modbus")[1])
    rep = client.get("/lua-doc/dissectors/domains")
    assert rep.json() == json.loads(_cli(mini, capsys, "--domains", "--json")[1])


def test_api_filtres_et_erreurs(client, mini, monkeypatch):
    assert client.get("/lua-doc/dissectors", params={"non_native": True}).json()["total"] == 3
    assert client.get("/lua-doc/dissectors", params={"q": "zzz"}).json()["dissecteurs"] == []
    assert client.get("/lua-doc/dissectors", params={"limit": 0}).status_code == 422
    monkeypatch.setenv(lua_dissectors.ENV_CSV, str(mini / "absent.csv"))
    monkeypatch.setattr(lua_dissectors, "csv_candidates", lambda: [mini / "absent.csv"])
    rep = client.get("/lua-doc/dissectors")
    assert rep.status_code == 503 and "introuvable" in rep.json()["detail"]


# -- GUI ------------------------------------------------------------------------------------


@pytest.fixture
def browser(mini, monkeypatch):
    from netcross_gtk4.lua_doc_view import LuaDocBrowser

    monkeypatch.setenv(lua_dissectors.ENV_CSV, str(mini / "mini.csv"))
    b = LuaDocBrowser(db_path=mini / "gui.db", source=JSON_PATH)
    yield b
    b.close()


def test_gui_comme_la_cli(browser, mini, capsys):
    assert browser.dissectors_text("modbus") == _cli(mini, capsys, "--dissectors", "modbus")[1]
    assert (
        browser.dissectors_text(domaine="scada", non_natif=True, limit=1)
        == (_cli(mini, capsys, "--dissectors", "--domain", "scada", "--non-native", "--limit", "1")[1])
    )
    assert browser.domains_text() == _cli(mini, capsys, "--domains")[1]
    assert json.loads(browser.dissectors_json("jeu")) == json.loads(
        _cli(mini, capsys, "--dissectors", "--json", "jeu")[1]
    )
    assert browser.dissectors_text("zzz") == "Aucun dissecteur Lua pour « zzz »."
    assert browser.domains()[0] == "Automatismes industriels / SCADA"


def test_gui_sans_catalogue(mini, monkeypatch):
    from netcross_gtk4.lua_doc_view import LuaDocBrowser

    monkeypatch.setattr(lua_dissectors, "csv_candidates", lambda: [mini / "absent.csv"])
    monkeypatch.delenv(lua_dissectors.ENV_CSV, raising=False)
    b = LuaDocBrowser(db_path=mini / "g2.db", source=JSON_PATH)
    assert b.dissectors_text("x").startswith("Catalogue des dissecteurs Lua introuvable")
    assert b.domains_text().startswith("Catalogue des dissecteurs Lua introuvable")
    b.close()


def test_fenetre_mode_dissecteurs(browser):
    from gtk4_display import exiger_gtk4_avec_affichage

    exiger_gtk4_avec_affichage()
    from netcross_gtk4.lua_doc_window import LuaDocWindow

    win = LuaDocWindow(browser=browser)
    assert not win.domain_dropdown.get_visible()
    win.mode_dropdown.set_selected(1)
    assert win.dissectors_mode() and win.domain_dropdown.get_visible() and not win.full_check.get_visible()
    assert win.text() == browser.domains_text()
    win.search_entry.set_text("modbus")
    win.run_search()
    assert win.text() == browser.dissectors_text("modbus", limit=win.limit_spin.get_value_as_int())
    win.domain_dropdown.set_selected(win._domains.index("Jeux vidéo"))
    win.native_check.set_active(True)
    win.search_entry.set_text("")
    win.run_search()
    assert win.text() == browser.dissectors_text("", "Jeux vidéo", True, win.limit_spin.get_value_as_int())
    win.show_json()
    assert json.loads(win.text())["domaine"] == "Jeux vidéo"
    # liste de gauche = domaines : un clic filtre
    row = win.class_list.get_row_at_index(0)
    win._on_row_activated(win.class_list, row)
    assert win._domain() == row.get_child().get_label()
    win.mode_dropdown.set_selected(0)
    assert win.text() == browser.classes_text()
    win.close()
