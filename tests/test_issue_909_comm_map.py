"""Issue #909 : cartographie des communications en CLI (--comm-map) et dans
l'API (GET /analyses/{analysis_id}/comm-map), exports JSON et DOT."""

from __future__ import annotations

import importlib
import json
import shutil
import subprocess
from types import SimpleNamespace

import pytest

import cross_capture_analyzer_cli as cli
from netcross_report.comm_map import build_comm_map, comm_map_to_dict, comm_map_to_dot, write_comm_map
from tests.conftest import make_pkt


def _flows():
    return {
        ("TCP", "10.0.0.1", 1, "10.0.0.2", 443): {
            "A": [
                make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TCP", length=100),
                make_pkt(point="A", src="10.0.0.2", dst="10.0.0.1", proto="TCP", length=60, is_retransmission=True),
            ]
        },
        ("UDP", "10.0.0.1", 2, "10.0.0.53", 53): {
            "A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.53", proto="DNS", length=80)]
        },
    }


def test_json_complet_et_stable():
    d = comm_map_to_dict(build_comm_map(_flows()))
    assert d["total_edges"] == 3
    assert d["total_hosts"] == 3
    assert d["protocols"] == ["DNS", "TCP"]
    assert [(e["src"], e["dst"]) for e in d["edges"]] == [
        ("10.0.0.1", "10.0.0.2"),
        ("10.0.0.1", "10.0.0.53"),
        ("10.0.0.2", "10.0.0.1"),
    ]
    retour = d["edges"][2]
    assert retour == {
        "src": "10.0.0.2",
        "dst": "10.0.0.1",
        "packets": 1,
        "bytes": 60,
        "protocols": ["TCP"],
        "anomalies": 1,
        "flows": 1,
    }
    assert {n["host"]: n["anomalies"] for n in d["nodes"]} == {"10.0.0.1": 1, "10.0.0.2": 1, "10.0.0.53": 0}
    json.dumps(d)  # sérialisable tel quel


def test_dot_anomalies_en_rouge():
    dot = comm_map_to_dot(build_comm_map(_flows()))
    assert dot.startswith("digraph netcross_comm_map {")
    assert dot.rstrip().endswith("}")
    assert '"10.0.0.2" -> "10.0.0.1" [label="TCP 1 pq / 1 anomalie(s)", color=red' in dot
    assert '"10.0.0.1" -> "10.0.0.53" [label="DNS 1 pq"];' in dot
    assert '"10.0.0.53" [label="10.0.0.53\\n80 o"];' in dot


def test_dot_echappe_les_guillemets():
    flows = {("X",): {"A": [make_pkt(point="A", src='a"b', dst="c", proto=None, length=1)]}}
    dot = comm_map_to_dot(build_comm_map(flows))
    assert '"a\\"b" -> "c" [label="? 1 pq"];' in dot


@pytest.mark.skipif(shutil.which("dot") is None, reason="Graphviz absent")
def test_dot_accepte_par_graphviz(tmp_path):
    chemin = tmp_path / "carte.dot"
    write_comm_map(str(chemin), build_comm_map(_flows()))
    sortie = subprocess.run(["dot", "-Tsvg", str(chemin)], capture_output=True, text=True, check=True)
    assert "<svg" in sortie.stdout


@pytest.mark.parametrize(("nom", "fmt"), [("c.dot", "dot"), ("c.GV", "dot"), ("c.json", "json"), ("c", "json")])
def test_write_comm_map_choisit_le_format(tmp_path, nom, fmt):
    chemin = tmp_path / nom
    assert write_comm_map(str(chemin), build_comm_map(_flows())) == fmt
    contenu = chemin.read_text(encoding="utf-8")
    if fmt == "json":
        assert json.loads(contenu)["total_edges"] == 3
    else:
        assert contenu.startswith("digraph")


# -- CLI -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("valeurs", "attendu"),
    [(None, None), ([], None), (["TCP"], ["TCP"]), (["TCP, DNS", "UDP", " "], ["TCP", "DNS", "UDP"])],
)
def test_comm_map_protocols(valeurs, attendu):
    assert cli.comm_map_protocols(valeurs) == attendu


def _args(**kw):
    base = {"comm_map": None, "comm_map_protocol": None, "comm_map_top_n": None, "comm_map_anomalies_only": False}
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.mark.parametrize(
    "kw", [{"comm_map_protocol": ["TCP"]}, {"comm_map_top_n": 3}, {"comm_map_anomalies_only": True}]
)
def test_filtres_sans_comm_map_refuses(kw, capsys):
    with pytest.raises(SystemExit) as exc:
        cli._check_comm_map_args(_args(**kw))
    assert exc.value.code == 1
    assert "necessitent --comm-map" in capsys.readouterr().err


def test_top_n_invalide(capsys):
    with pytest.raises(SystemExit):
        cli._check_comm_map_args(_args(comm_map="c.json", comm_map_top_n=0))
    assert "1 minimum" in capsys.readouterr().err


def test_options_valides():
    cli._check_comm_map_args(_args())
    cli._check_comm_map_args(_args(comm_map="c.dot", comm_map_top_n=5, comm_map_protocol=["TCP"]))


# -- API -------------------------------------------------------------------------------

pytest.importorskip("fastapi", reason="extra [api] non installé")

from fastapi.testclient import TestClient  # noqa: E402

api = importlib.import_module("netcross_api.app")
client = TestClient(api.app)


@pytest.fixture
def analyse():
    analysis_id = api.store.create_pending({})
    api.store.complete(analysis_id, {"points": ["A"]}, {"points": ["A"]}, flows=_flows())
    yield analysis_id
    api.store._store.pop(analysis_id, None)


def _url(analysis_id):
    return f"/analyses/{analysis_id}/comm-map"


def test_api_json(analyse):
    rep = client.get(_url(analyse))
    assert rep.status_code == 200
    assert rep.json() == comm_map_to_dict(build_comm_map(_flows()))


def test_api_filtres(analyse):
    d = client.get(_url(analyse), params={"protocol": "TCP"}).json()
    assert d["protocols"] == ["DNS", "TCP"] and {p for e in d["edges"] for p in e["protocols"]} == {"TCP"}
    d = client.get(_url(analyse), params=[("protocol", "DNS"), ("protocol", "TCP")]).json()
    assert len(d["edges"]) == 3
    d = client.get(_url(analyse), params={"protocol": "TCP,DNS", "top_n": 1}).json()
    assert len(d["edges"]) == 1 and d["total_edges"] == 3
    d = client.get(_url(analyse), params={"anomalies_only": "true"}).json()
    assert [(e["src"], e["dst"]) for e in d["edges"]] == [("10.0.0.2", "10.0.0.1")]


def test_api_dot(analyse):
    rep = client.get(_url(analyse), params={"format": "dot"})
    assert rep.status_code == 200
    assert rep.headers["content-type"].startswith("text/vnd.graphviz")
    assert rep.text == comm_map_to_dot(build_comm_map(_flows()))


def test_api_erreurs(analyse):
    assert client.get(_url(analyse), params={"format": "svg"}).status_code == 400
    assert client.get(_url(analyse), params={"top_n": 0}).status_code == 422
    assert client.get(_url("inconnue")).status_code == 404
    sans_flux = api.store.create_pending({})
    api.store.complete(sans_flux, {"points": []}, {})
    try:
        assert client.get(_url(sans_flux)).status_code == 404
    finally:
        api.store._store.pop(sans_flux, None)
    en_cours = api.store.create_pending({})
    try:
        assert client.get(_url(en_cours)).status_code == 409
    finally:
        api.store._store.pop(en_cours, None)


def test_api_authentification(monkeypatch, analyse):
    monkeypatch.setattr(api, "_API_TOKEN", "secret")
    assert client.get(_url(analyse)).status_code == 401
    assert client.get(_url(analyse), headers={"X-API-Key": "secret"}).status_code == 200
