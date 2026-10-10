"""Issue #873 : documentation Lua dans l'API, mêmes documents JSON que
``netcross-lua-doc --json``."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

import netcross_lua_doc_cli as cli
from netcross_core import lua_doc

pytest.importorskip("fastapi", reason="extra [api] non installé")

from fastapi.testclient import TestClient  # noqa: E402

api = importlib.import_module("netcross_api.app")
client = TestClient(api.app)
JSON_PATH = Path(__file__).resolve().parent.parent / "data" / "lua_api.json"


@pytest.fixture(autouse=True)
def _banque(tmp_path, monkeypatch):
    monkeypatch.setattr(lua_doc, "DEFAULT_DB_PATH", tmp_path / "lua.db")
    monkeypatch.setenv(lua_doc.ENV_JSON, str(JSON_PATH))
    return tmp_path


def _cli(tmp_path, capsys, *args):
    rc = cli.main(["--db", str(tmp_path / "cli.db"), "--source", str(JSON_PATH), "--json", *args])
    out, _ = capsys.readouterr()
    return rc, json.loads(out)


def test_classes_identiques_a_la_cli(_banque, capsys):
    rep = client.get("/lua-doc/classes")
    assert rep.status_code == 200
    assert rep.json() == _cli(_banque, capsys, "--classes")[1]
    assert "Tvb" in rep.json()["classes"]


def test_fiche_identique_a_la_cli_insensible_a_la_casse(_banque, capsys):
    rep = client.get("/lua-doc/classes/tvb")
    assert rep.status_code == 200
    assert rep.json() == _cli(_banque, capsys, "--class", "Tvb")[1]
    assert rep.json()["classe"]["nom"] == "Tvb"


def test_classe_inconnue_404_avec_suggestions():
    rep = client.get("/lua-doc/classes/Tvbx")
    assert rep.status_code == 404
    assert rep.json()["detail"].startswith("Classe inconnue : Tvbx")


@pytest.mark.parametrize("full", [False, True])
def test_recherche_identique_a_la_cli(_banque, capsys, full):
    rep = client.get("/lua-doc/search", params={"q": "tvb range", "limit": 3, "full": full})
    assert rep.status_code == 200
    args = ["--limit", "3", *(["--full"] if full else []), "tvb", "range"]
    assert rep.json() == _cli(_banque, capsys, *args)[1]
    assert len(rep.json()["resultats"]) == 3
    assert ("detail" in rep.json()["resultats"][0]) is full


def test_recherche_sans_resultat_liste_vide():
    rep = client.get("/lua-doc/search", params={"q": "zzzzaucunresultat"})
    assert rep.status_code == 200
    assert rep.json()["resultats"] == []


@pytest.mark.parametrize("params", [{}, {"q": ""}, {"q": "   "}, {"q": "tvb", "limit": 0}])
def test_parametres_invalides_422(params):
    assert client.get("/lua-doc/search", params=params).status_code == 422


def test_json_introuvable_503(monkeypatch):
    monkeypatch.setattr(lua_doc, "find_json", lambda: None)
    rep = client.get("/lua-doc/classes")
    assert rep.status_code == 503
    assert "introuvable" in rep.json()["detail"]


def test_meme_authentification_que_le_reste(monkeypatch):
    monkeypatch.setattr(api, "_API_TOKEN", "secret")
    assert client.get("/lua-doc/classes").status_code == 401
    assert client.get("/lua-doc/classes", headers={"X-API-Key": "secret"}).status_code == 200
