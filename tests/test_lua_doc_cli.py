"""Tests de la CLI netcross-lua-doc (issue #388) et de lua_doc.ensure_db."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import netcross_lua_doc_cli as cli
from netcross_core import lua_doc

ROOT = Path(__file__).resolve().parent.parent
JSON_PATH = ROOT / "data" / "lua_api.json"


@pytest.fixture
def run(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """Lance la CLI sur le vrai data/lua_api.json, base dans tmp_path."""

    def _run(*args: str) -> tuple[int, str, str]:
        rc = cli.main(["--db", str(tmp_path / "lua.db"), "--source", str(JSON_PATH), *args])
        out, err = capsys.readouterr()
        return rc, out, err

    return _run


# -- recherche ----------------------------------------------------------------


def test_search_text(run) -> None:
    rc, out, _ = run("tvb", "range")
    assert rc == 0
    assert "Wireshark 4." in out.splitlines()[0]
    assert "tvb:range([offset], [length])" in out
    assert "[Tvb, methode]" in out
    assert "--class" in out


def test_search_attribute(run) -> None:
    rc, out, _ = run("src_port")
    assert rc == 0
    assert "pinfo.src_port" in out and "attribut" in out


def test_search_full_detail(run) -> None:
    rc, out, _ = run("--full", "--limit", "1", "tvb", "range")
    assert rc == 0
    assert "Arguments :" in out and "offset (optionnel)" in out and "Retourne :" in out


def test_search_limit(run) -> None:
    rc, out, _ = run("--json", "--limit", "3", "add")
    assert rc == 0
    assert len(json.loads(out)["resultats"]) == 3


def test_search_no_result(run) -> None:
    rc, out, err = run("zzzqqqxxx")
    assert rc == 1
    assert out == "" and "Aucun resultat" in err


def test_search_json(run) -> None:
    rc, out, _ = run("--json", "--full", "tvb", "range")
    assert rc == 0
    data = json.loads(out)
    assert data["meta"]["version_wireshark"].startswith("4.")
    assert data["terme"] == "tvb range"
    premier = data["resultats"][0]
    assert {"classe", "nom", "signature", "genre", "ref_id", "est_attribut", "detail"} <= set(premier)
    assert premier["detail"]["parametres"]


def test_search_json_no_result(run) -> None:
    rc, out, _ = run("--json", "zzzqqqxxx")
    assert rc == 1
    assert json.loads(out)["resultats"] == []


# -- fiche de classe ----------------------------------------------------------


def test_class_sheet(run) -> None:
    rc, out, _ = run("--class", "Tvb")
    assert rc == 0
    assert out.startswith("Tvb  (module Tvb)")
    assert "Methodes (" in out and "tvb:range([offset], [length])" in out
    assert "Arguments :" in out and "Retourne :" in out
    assert "Warning:" in out  # encadre [WARNING] de la doc officielle


def test_class_sheet_case_insensitive_and_attributes(run) -> None:
    rc, out, _ = run("--class", "pinfo")
    assert rc == 0
    assert "Attributs (" in out
    assert "pinfo.src_port  [lecture/ecriture]" in out


def test_class_sheet_examples_and_tables(run) -> None:
    rc, out, _ = run("--class", "Columns")
    assert rc == 0
    assert "Exemple :" in out and "pinfo.cols.info = 'foo bar'" in out
    assert "  src_port" in out  # tableau rendu en lignes alignees


def test_class_unknown(run) -> None:
    rc, _, err = run("--class", "Tv")
    assert rc == 1
    assert "Classe inconnue : Tv" in err and "Tvb" in err


def test_class_json(run) -> None:
    rc, out, _ = run("--json", "--class", "Tvb")
    assert rc == 0
    fiche = json.loads(out)["classe"]
    assert fiche["nom"] == "Tvb"
    assert {m["nom"] for m in fiche["methodes"]} >= {"range", "len", "reported_len"}


def test_list_classes(run) -> None:
    rc, out, _ = run("--classes")
    assert rc == 0
    assert "  Tvb" in out and "  ProtoField" in out
    rc, out, _ = run("--classes", "--json")
    assert "Tvb" in json.loads(out)["classes"]


# -- erreurs d'usage et JSON introuvable --------------------------------------


@pytest.mark.parametrize(
    "args",
    [[], ["--classes", "tvb"], ["--limit", "0", "tvb"], ["--class", "Tvb", "--classes"]],
)
def test_usage_errors(tmp_path: Path, args: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--db", str(tmp_path / "x.db"), *args])
    assert exc.value.code == 2


def test_missing_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["--db", str(tmp_path / "x.db"), "--source", str(tmp_path / "absent.json"), "tvb"])
    assert rc == 1
    assert "extract_lua_api.py" in capsys.readouterr().err


def test_env_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(lua_doc.ENV_JSON, str(tmp_path / "perso.json"))
    assert lua_doc.json_candidates()[0] == tmp_path / "perso.json"
    assert lua_doc.find_json() != tmp_path / "perso.json"  # absent : on passe au suivant
    monkeypatch.delenv(lua_doc.ENV_JSON)
    assert lua_doc.find_json() == JSON_PATH  # depuis le depot


# -- ensure_db ----------------------------------------------------------------


def _mini(version: str) -> dict:
    return {
        "version_wireshark": version,
        "date_generation": "2026-09-24",
        "source": "test",
        "classes": {
            "Tvb": {"nom": "Tvb", "module": "Tvb", "description": "", "exemples": [], "methodes": [], "attributs": []}
        },
    }


def test_ensure_db_builds_then_reuses_then_rebuilds(tmp_path: Path) -> None:
    src = tmp_path / "api.json"
    db = tmp_path / "cache" / "sub" / "lua.db"
    src.write_text(json.dumps(_mini("4.4.0")), encoding="utf-8")
    conn = lua_doc.ensure_db(db, src)
    assert lua_doc.get_meta(conn)["version_wireshark"] == "4.4.0"
    conn.close()
    mtime = os.stat(db).st_mtime_ns

    conn = lua_doc.ensure_db(db, src)  # JSON inchange : pas de rechargement
    conn.close()
    assert os.stat(db).st_mtime_ns == mtime

    src.write_text(json.dumps(_mini("4.6.9")), encoding="utf-8")
    conn = lua_doc.ensure_db(db, src)
    assert lua_doc.get_meta(conn)["version_wireshark"] == "4.6.9"
    conn.close()


# -- points d'entree ----------------------------------------------------------


def _env() -> dict[str, str]:
    return {**os.environ, "PYTHONPATH": str(ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")}


def test_subprocess_help() -> None:
    res = subprocess.run(
        [sys.executable, str(ROOT / "src" / "netcross_lua_doc_cli.py"), "--help"],
        capture_output=True,
        text=True,
        env=_env(),
        check=False,
    )
    assert res.returncode == 0
    assert "--class" in res.stdout and "--json" in res.stdout


def test_netcross_lua_doc_subcommand(tmp_path: Path) -> None:
    res = subprocess.run(
        [
            sys.executable,
            str(ROOT / "src" / "cross_capture_analyzer_cli.py"),
            "lua-doc",
            "--db",
            str(tmp_path / "l.db"),
            "--classes",
        ],
        capture_output=True,
        text=True,
        env=_env(),
        check=False,
    )
    assert res.returncode == 0, res.stderr
    assert "Tvb" in res.stdout
    assert res.stderr == ""  # pas de log de construction sur la sortie


# -- Issue #721 : rendus des erreurs, exemples et attributs en mode --full ----


def test_render_methode_et_fiche_affichent_erreurs_et_exemples():
    """Lignes 110, 112 et 143 : erreurs et version d'une methode, exemples
    d'une fiche."""
    m = lua_doc.Methode(
        classe="Tvb",
        nom="len",
        genre="methode",
        signature="tvb:len()",
        description="Longueur.",
        depuis_version="1.99.8",
        parametres=[],
        retours=[],
        erreurs=["tampon expire"],
        exemples=[],
    )
    rendu = cli.render_methode(m)
    assert any("Erreur : tampon expire" in ligne for ligne in rendu)
    assert any("Depuis Wireshark 1.99.8" in ligne for ligne in rendu)
    fiche = lua_doc.FicheClasse(
        nom="Tvb", module="tvb", description="", exemples=["local n = tvb:len()"], methodes=[], attributs=[]
    )
    lignes = cli.render_fiche(fiche, "4.2")
    assert "Exemple :" in lignes
    assert any("tvb:len()" in ligne for ligne in lignes)


def test_render_resultats_full_detaille_un_attribut(monkeypatch):
    """Lignes 174-176 : en mode --full, un attribut est rendu en detail."""
    attribut = lua_doc.Attribut(
        classe="Pinfo", nom="src", nom_complet="pinfo.src", mode="lecture", description="Source.", depuis_version=None
    )
    monkeypatch.setattr(cli.lua_doc, "get_meta", lambda conn: {})
    monkeypatch.setattr(cli.lua_doc, "get_attribut", lambda conn, ref_id: attribut)
    res = [
        lua_doc.ResultatRecherche(
            classe="Pinfo", nom="src", signature="", description="", genre=lua_doc.GENRE_ATTRIBUT, ref_id=1
        )
    ]
    lignes = cli.render_resultats(None, "src", res, full=True)
    assert "[Pinfo]" in lignes
    assert any("pinfo.src" in ligne for ligne in lignes)
