"""Issue #910 : annotations et signets en CLI (`netcross annotations`, même
sidecar que la GUI), dans le rapport texte et dans l'API
(`/analyses/{analysis_id}/annotations`)."""

from __future__ import annotations

import importlib
import json
import sys

import pytest

import cross_capture_analyzer_cli as analyzer
import netcross_annotations_cli as cli
from netcross_core import annotations as core
from netcross_core.forensic import read_annotations, write_annotations
from netcross_core.models import PacketAnnotation
from netcross_core.report_text import load_capture_annotations, print_capture_annotations

# -- cœur ------------------------------------------------------------------------------


@pytest.mark.parametrize(("saisie", "attendu"), [(3, 3), ("12", 12), (" #7 ", 7)])
def test_parse_frame_number_valide(saisie, attendu):
    assert core.parse_frame_number(saisie) == attendu


@pytest.mark.parametrize("saisie", [0, -1, "abc", "", None, True, "0"])
def test_parse_frame_number_invalide(saisie):
    with pytest.raises(ValueError):
        core.parse_frame_number(saisie)


def test_make_annotation_nettoie_et_valide():
    ann = core.make_annotation("5", " suspect ", " RST ", " #f00 ")
    assert ann == PacketAnnotation(frame_number=5, tag="suspect", comment="RST", color="#f00")
    assert core.make_annotation(1, "a", None).comment == ""
    for args in [(1, ""), (1, "  "), (1, None), (1, "a", 3), (1, "a", "", ""), (1, "a", "", 5)]:
        with pytest.raises(ValueError):
            core.make_annotation(*args)


def test_add_met_a_jour_la_meme_paire():
    a = core.make_annotation(1, "x", "un")
    b = core.make_annotation(2, "x")
    liste = core.add_annotation(core.add_annotation([], a), b)
    maj = core.add_annotation(liste, core.make_annotation(1, "x", "deux"))
    assert [(x.frame_number, x.comment) for x in maj] == [(1, "deux"), (2, "")]
    assert liste[0].comment == "un"  # fonction pure


def test_remove_et_absente():
    liste = [core.make_annotation(1, "x"), core.make_annotation(1, "y")]
    assert core.remove_annotation(liste, "1", " y ") == [liste[0]]
    with pytest.raises(KeyError):
        core.remove_annotation(liste, 2, "x")
    with pytest.raises(ValueError):
        core.remove_annotation(liste, 0, "x")


def test_conversion_dict():
    ann = core.make_annotation(4, "t", "c", "#000")
    assert core.annotation_from_dict(core.annotation_to_dict(ann)) == ann
    with pytest.raises(ValueError):
        core.annotation_from_dict(["pas", "un", "objet"])
    with pytest.raises(ValueError):
        core.annotation_from_dict({"tag": "sans trame"})


# -- CLI -------------------------------------------------------------------------------


@pytest.fixture
def capture(tmp_path):
    chemin = tmp_path / "a.pcapng"
    chemin.write_bytes(b"")
    return str(chemin)


def _run(capsys, *argv):
    rc = cli.main(list(argv))
    out, err = capsys.readouterr()
    return rc, out, err


def test_cli_add_list_remove_meme_sidecar_que_la_gui(capture, capsys):
    assert _run(capsys, "add", capture, "--frame", "42", "--tag", "suspect", "--comment", "RST")[0] == 0
    assert _run(capsys, "add", capture, "--frame", "#7", "--tag", "dns", "--color", "#00f")[0] == 0
    # écrit dans le sidecar lu par la GUI (netcross_core.forensic)
    assert {(a.frame_number, a.tag) for a in read_annotations(capture)} == {(42, "suspect"), (7, "dns")}
    rc, out, _ = _run(capsys, "list", capture)
    assert rc == 0
    assert out.splitlines() == ["trame #7 [dns]", "trame #42 [suspect] -- RST"]
    rc, out, _ = _run(capsys, "list", capture, "--tag", "dns", "--json")
    assert json.loads(out) == [{"frame_number": 7, "tag": "dns", "comment": "", "color": "#00f"}]
    rc, out, _ = _run(capsys, "remove", capture, "--frame", "7", "--tag", "dns", "--json")
    assert rc == 0
    assert [a["tag"] for a in json.loads(out)] == ["suspect"]


def test_cli_lit_un_sidecar_ecrit_par_la_gui(capture, capsys):
    write_annotations(capture, [PacketAnnotation(frame_number=3, tag="gui", comment="depuis la GUI")])
    assert _run(capsys, "list", capture)[1].strip() == "trame #3 [gui] -- depuis la GUI"


def test_cli_liste_vide(capture, capsys):
    assert _run(capsys, "list", capture) == (0, "aucune annotation\n", "")


def test_cli_remove_absente_rc1(capture, capsys):
    rc, _, err = _run(capsys, "remove", capture, "--frame", "1", "--tag", "x")
    assert rc == 1
    assert "introuvable" in err


def test_cli_saisie_invalide_rc2(capture, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["add", capture, "--frame", "0", "--tag", "x"])
    assert exc.value.code == 2
    assert "commence a 1" in capsys.readouterr().err


def test_cli_capture_absente(tmp_path, capsys):
    rc, _, err = _run(capsys, "list", str(tmp_path / "absente.pcap"))
    assert rc == 1
    assert "Capture introuvable" in err


def test_cli_sidecar_illisible_jamais_reecrit(capture, capsys):
    sidecar = capture + ".annotations.json"
    with open(sidecar, "w", encoding="utf-8") as f:
        f.write("{corrompu")
    rc, _, err = _run(capsys, "add", capture, "--frame", "1", "--tag", "x")
    assert rc == 1
    assert "Sidecar illisible" in err
    with open(sidecar, encoding="utf-8") as f:
        assert f.read() == "{corrompu"


def test_sous_commande_netcross_annotations(monkeypatch):
    recus = []
    monkeypatch.setattr(cli, "main", lambda argv: recus.append(argv) or 0)
    monkeypatch.setattr(sys, "argv", ["netcross", "annotations", "list", "a.pcap"])
    with pytest.raises(SystemExit) as exc:
        analyzer.main()
    assert exc.value.code == 0
    assert recus == [["list", "a.pcap"]]


# -- rapport texte ---------------------------------------------------------------------


def test_rapport_texte_reprend_les_annotations(tmp_path, capsys):
    a, b, c = (str(tmp_path / n) for n in ("a.pcap", "b.pcap", "c.pcap"))
    write_annotations(a, [PacketAnnotation(frame_number=9, tag="perte", comment="trou")])
    with open(c + ".annotations.json", "w", encoding="utf-8") as f:
        f.write("[")  # illisible : ignoré, jamais bloquant
    par_point = load_capture_annotations([("A", a), ("B", b), ("C", c)])
    assert list(par_point) == ["A"]
    print_capture_annotations(par_point)
    out = capsys.readouterr().out
    assert "[Point A]" in out
    assert "[perte] 1 paquet(s)" in out
    assert "trame #9 -- trou" in out


def test_rapport_texte_sans_annotation_inchange(capsys):
    print_capture_annotations(load_capture_annotations([]))
    print_capture_annotations(load_capture_annotations(None))
    assert capsys.readouterr().out == ""


# -- API -------------------------------------------------------------------------------

pytest.importorskip("fastapi", reason="extra [api] non installé")

from fastapi.testclient import TestClient  # noqa: E402

api = importlib.import_module("netcross_api.app")
store_mod = importlib.import_module("netcross_api.store")
client = TestClient(api.app)


def _analyse(store, points=("A", "B")):
    analysis_id = store.create_pending({"label": "test"})
    store.complete(analysis_id, {"points": list(points)}, {"points": list(points)})
    return analysis_id


@pytest.fixture
def analyse():
    analysis_id = _analyse(api.store)
    yield analysis_id
    api.store._store.pop(analysis_id, None)


def _url(analysis_id):
    return f"/analyses/{analysis_id}/annotations"


def test_api_cycle_complet(analyse):
    assert client.get(_url(analyse)).json() == {"annotations": {}}
    rep = client.post(_url(analyse), json={"point": "A", "frame_number": 42, "tag": "suspect", "comment": "RST"})
    assert rep.status_code == 200
    client.post(_url(analyse), json={"point": "B", "frame_number": 3, "tag": "dns"})
    rep = client.post(_url(analyse), json={"point": "A", "frame_number": 5, "tag": "suspect", "color": "#f00"})
    assert rep.json() == {
        "annotations": {
            "A": [
                {"frame_number": 5, "tag": "suspect", "comment": "", "color": "#f00"},
                {"frame_number": 42, "tag": "suspect", "comment": "RST", "color": None},
            ],
            "B": [{"frame_number": 3, "tag": "dns", "comment": "", "color": None}],
        }
    }
    assert list(client.get(_url(analyse), params={"point": "B"}).json()["annotations"]) == ["B"]
    filtre = client.get(_url(analyse), params={"tag": "dns"}).json()["annotations"]
    assert filtre == {"B": [{"frame_number": 3, "tag": "dns", "comment": "", "color": None}]}
    rep = client.delete(_url(analyse), params={"point": "B", "frame_number": 3, "tag": "dns"})
    assert rep.status_code == 200
    assert list(rep.json()["annotations"]) == ["A"]


def test_api_meme_paire_mise_a_jour(analyse):
    client.post(_url(analyse), json={"point": "A", "frame_number": 1, "tag": "x", "comment": "un"})
    rep = client.post(_url(analyse), json={"point": "A", "frame_number": 1, "tag": "x", "comment": "deux"})
    assert rep.json()["annotations"]["A"] == [{"frame_number": 1, "tag": "x", "comment": "deux", "color": None}]


def test_api_erreurs(analyse):
    assert client.post(_url(analyse), json={"point": "Z", "frame_number": 1, "tag": "x"}).status_code == 404
    assert client.get(_url(analyse), params={"point": "Z"}).status_code == 404
    assert client.post(_url(analyse), json={"point": "A", "frame_number": 0, "tag": "x"}).status_code == 422
    assert client.post(_url(analyse), json={"point": "A", "frame_number": 1, "tag": " "}).status_code == 422
    assert client.post(_url(analyse), json={"point": "A", "tag": "x"}).status_code == 422
    params = {"point": "A", "frame_number": 1, "tag": "x"}
    assert client.delete(_url(analyse), params=params).status_code == 404
    assert client.delete(_url(analyse), params={**params, "frame_number": 0}).status_code == 422
    assert client.get(_url("inconnue")).status_code == 404


def test_api_analyse_en_cours_409():
    analysis_id = api.store.create_pending({})
    try:
        assert client.get(_url(analysis_id)).status_code == 409
    finally:
        api.store._store.pop(analysis_id, None)


def test_api_authentification(monkeypatch, analyse):
    monkeypatch.setattr(api, "_API_TOKEN", "secret")
    assert client.get(_url(analyse)).status_code == 401
    assert client.get(_url(analyse), headers={"X-API-Key": "secret"}).status_code == 200


def test_api_persistance_sqlite(tmp_path, monkeypatch):
    db = str(tmp_path / "api.db")
    monkeypatch.setattr(api, "store", store_mod.AnalysesStore(db_path=db))
    analysis_id = _analyse(api.store)
    client.post(_url(analysis_id), json={"point": "A", "frame_number": 8, "tag": "garde"})
    relu = store_mod.AnalysesStore(db_path=db).get(analysis_id)
    assert relu["metadata"]["annotations"] == {"A": [{"frame_number": 8, "tag": "garde", "comment": "", "color": None}]}


def test_store_set_metadata_analyse_inconnue():
    with pytest.raises(KeyError):
        store_mod.AnalysesStore(db_path="").set_metadata("absente", "annotations", {})
