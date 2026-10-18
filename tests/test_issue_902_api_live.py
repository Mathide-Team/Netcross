"""Issue #902 : POST /live-captures, GET /live-captures/{id},
POST /live-captures/{id}/stop -- capture en direct puis analyse.

L'enregistreur tshark est remplacé par un faux qui écrit un fichier, et
parse_capture est mocké comme dans tests/test_api.py : ni tshark ni
privilège réseau requis."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.conftest import make_pkt

pytest.importorskip("fastapi", reason="extra [api] non installé")

import importlib  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from netcross_api import live_routes  # noqa: E402

api = importlib.import_module("netcross_api.app")
client = TestClient(api.app)
CLE = {"X-API-Key": "secret"}


class _FakeProc:
    def __init__(self, err=""):
        self.err = err


@pytest.fixture
def recorder(monkeypatch):
    """Faux enregistreur : un fichier par point, appels mémorisés."""
    appels = {"start": [], "stop": 0, "fichier": True, "err": "", "raise": None}

    def start(interface, directory, **kw):
        if appels["raise"]:
            raise appels["raise"]
        appels["start"].append((interface, kw["bpf_filter"], kw["prefix"]))
        Path(directory).mkdir(parents=True, exist_ok=True)
        if appels["fichier"]:
            (Path(directory) / f"{kw['prefix']}_00001.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 60)
        return _FakeProc(appels["err"])

    def stop(proc):
        appels["stop"] += 1
        return proc.err

    monkeypatch.setitem(api.live_captures._deps, "start_recorder", start)
    monkeypatch.setitem(api.live_captures._deps, "stop_recorder", stop)
    return appels


@pytest.fixture
def actif(monkeypatch):
    monkeypatch.setenv(live_routes.LIVE_ENV, "1")
    monkeypatch.setenv(live_routes.INTERFACES_ENV, "eth0, eth1")
    monkeypatch.delenv(live_routes.MAX_DURATION_ENV, raising=False)
    monkeypatch.setattr(api, "_API_TOKEN", "secret")
    api.live_captures._entries.clear()
    yield
    for e in api.live_captures._entries.values():
        e["_stop"].set()
    _attendre_tout()
    api.live_captures._entries.clear()


def _pkts(label, _path):
    return [
        make_pkt(src="10.0.0.1", dst="10.0.0.2", dport=443, ts=1000.0, point=label),
        make_pkt(src="10.0.0.2", dst="10.0.0.1", dport=50000, ts=1000.1, point=label),
    ]


def _attendre(capture_id, statuts=("completed", "failed"), delai=10.0):
    fin = time.monotonic() + delai
    while time.monotonic() < fin:
        etat = client.get(f"/live-captures/{capture_id}", headers=CLE).json()
        if etat["status"] in statuts:
            return etat
        time.sleep(0.02)
    raise AssertionError(f"capture {capture_id} toujours {etat['status']}")


def _attendre_tout():
    fin = time.monotonic() + 10
    while time.monotonic() < fin and any(
        e["status"] in ("capturing", "analysing") for e in api.live_captures._entries.values()
    ):
        time.sleep(0.02)


def _corps(**kw):
    corps = {
        "points": [
            {"name": "LAN", "interface": "eth0", "bpf": "tcp port 443"},
            {"name": "WAN", "interface": "eth1"},
        ],
        "duration": 0.05,
    }
    corps.update(kw)
    return corps


def test_deux_points_capture_puis_analyse(actif, recorder):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post("/live-captures", json=_corps(points_order=["LAN", "WAN"]), headers=CLE)
        assert rep.status_code == 202
        assert rep.headers["Location"] == f"/live-captures/{rep.json()['capture_id']}"
        assert rep.json()["status"] == "capturing"
        etat = _attendre(rep.json()["capture_id"])
    assert etat["status"] == "completed", etat
    assert recorder["start"] == [("eth0", "tcp port 443", "LAN"), ("eth1", None, "WAN")]
    assert recorder["stop"] == 2
    assert [p["name"] for p in etat["points"]] == ["LAN", "WAN"]
    assert all(p["bytes_captured"] == 64 for p in etat["points"])  # conservé après suppression
    assert etat["elapsed_seconds"] >= 0.05
    analyse = api.store.get(etat["analysis_id"])
    assert analyse["status"] == "completed"
    assert analyse["metadata"]["live_capture_id"] == etat["capture_id"]
    assert analyse["metadata"]["interfaces"] == {"LAN": "eth0", "WAN": "eth1"}
    assert etat["analysis_url"] == f"/analyses/{etat['analysis_id']}"
    # fichiers temporaires supprimés
    assert not Path(api.live_captures._entries[etat["capture_id"]]["_workdir"]).exists()


def test_un_point_et_options(actif, recorder):
    corps = _corps(points=[{"name": "A", "interface": "eth0"}], options={"nat_tolerant": True, "max_packets": 10})
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post("/live-captures", json=corps, headers=CLE)
        etat = _attendre(rep.json()["capture_id"])
    assert etat["status"] == "completed", etat
    options = api.store.get(etat["analysis_id"])["metadata"]["options"]
    assert options["nat_tolerant"] is True
    assert options["max_packets"] == 10


def test_arret_anticipe(actif, recorder):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post("/live-captures", json=_corps(duration=60), headers=CLE)
        capture_id = rep.json()["capture_id"]
        assert client.post("/live-captures", json=_corps(), headers=CLE).status_code == 409
        assert client.get(f"/live-captures/{capture_id}", headers=CLE).json()["points"][0]["bytes_captured"] > 0
        assert client.post(f"/live-captures/{capture_id}/stop", headers=CLE).status_code == 200
        etat = _attendre(capture_id)
    assert etat["status"] == "completed"
    assert etat["elapsed_seconds"] < 30


@pytest.mark.parametrize(
    ("env", "token", "detail"),
    [
        ({live_routes.LIVE_ENV: ""}, "secret", "désactivée"),
        ({}, None, "NETCROSS_API_TOKEN"),
        ({live_routes.INTERFACES_ENV: ""}, "secret", "(vide)"),
        ({live_routes.INTERFACES_ENV: "eth0"}, "secret", "'eth1' non autorisée"),
    ],
)
def test_securite_403(actif, recorder, monkeypatch, env, token, detail):
    for nom, valeur in env.items():
        monkeypatch.setenv(nom, valeur)
    monkeypatch.setattr(api, "_API_TOKEN", token)
    rep = client.post("/live-captures", json=_corps(), headers=CLE)
    assert rep.status_code == 403
    assert detail in rep.json()["detail"]
    assert recorder["start"] == []


def test_cle_api_exigee(actif, recorder):
    assert client.post("/live-captures", json=_corps()).status_code == 401
    assert client.get("/live-captures/x").status_code == 401


@pytest.mark.parametrize(
    ("corps", "code", "detail"),
    [
        (_corps(points=[]), 400, "au moins un point"),
        (_corps(points=[{"name": "A", "interface": "eth0"}, {"name": "A", "interface": "eth1"}]), 400, "distinct"),
        (_corps(points=[{"name": " ", "interface": "eth0"}]), 400, "distinct"),
        (_corps(duration=301), 400, "300 s au plus"),
        (_corps(points_order=["LAN", "ZZZ"]), 400, "ZZZ"),
        (_corps(options={"inconnue": 1}), 422, "inconnue"),
        (_corps(options={"split_interfaces": True}), 422, "split_interfaces"),
        (_corps(options={"redact": True, "tls": True}), 400, "redact"),
        (_corps(duration=0), 422, None),
    ],
)
def test_requetes_invalides(actif, recorder, corps, code, detail):
    rep = client.post("/live-captures", json=corps, headers=CLE)
    assert rep.status_code == code, rep.json()
    if detail:
        assert detail in str(rep.json()["detail"])
    assert recorder["start"] == []


def test_interface_vide(actif, recorder, monkeypatch):
    monkeypatch.setenv(live_routes.INTERFACES_ENV, " ,eth0")
    rep = client.post("/live-captures", json=_corps(points=[{"name": "A", "interface": " "}]), headers=CLE)
    assert rep.status_code == 403


def test_trop_de_points(actif, recorder, monkeypatch):
    monkeypatch.setattr(api, "_MAX_FILES", 1)
    assert client.post("/live-captures", json=_corps(), headers=CLE).status_code == 400


def test_duree_max_configurable(actif, recorder, monkeypatch):
    monkeypatch.setenv(live_routes.MAX_DURATION_ENV, "0.01")
    assert client.post("/live-captures", json=_corps(), headers=CLE).status_code == 400


def test_capture_inconnue(actif):
    assert client.get("/live-captures/absente", headers=CLE).status_code == 404
    assert client.post("/live-captures/absente/stop", headers=CLE).status_code == 404


def test_echec_tshark_sans_fichier(actif, recorder):
    recorder["fichier"] = False
    recorder["err"] = "tshark: permission denied"
    rep = client.post("/live-captures", json=_corps(), headers=CLE)
    etat = _attendre(rep.json()["capture_id"])
    assert etat["status"] == "failed"
    assert "LAN : tshark: permission denied" in etat["error"]
    assert etat["analysis_id"] is None


def test_aucun_fichier_sans_message(actif, recorder):
    recorder["fichier"] = False
    rep = client.post("/live-captures", json=_corps(), headers=CLE)
    etat = _attendre(rep.json()["capture_id"])
    assert etat["status"] == "failed"
    assert "aucun fichier enregistré pour : LAN, WAN" in etat["error"]


def test_demarrage_impossible(actif, recorder):
    recorder["raise"] = FileNotFoundError("tshark introuvable")
    rep = client.post("/live-captures", json=_corps(), headers=CLE)
    etat = _attendre(rep.json()["capture_id"])
    assert etat["status"] == "failed"
    assert "capture impossible : tshark introuvable" in etat["error"]


def test_analyse_en_echec(actif, recorder):
    with patch("netcross_api.app.parse_capture", return_value=[]):
        rep = client.post("/live-captures", json=_corps(), headers=CLE)
        etat = _attendre(rep.json()["capture_id"])
    assert etat["status"] == "failed"
    assert etat["analysis_id"]
    assert etat["error"]


def test_reglages_env():
    assert live_routes.live_enabled({live_routes.LIVE_ENV: "true"})
    assert not live_routes.live_enabled({})
    assert live_routes.allowed_interfaces({live_routes.INTERFACES_ENV: "a, b,,"}) == {"a", "b"}
    assert live_routes.max_duration({}) == live_routes.DEFAULT_MAX_DURATION
    assert live_routes.max_duration({live_routes.MAX_DURATION_ENV: "12"}) == 12
    assert live_routes.max_duration({live_routes.MAX_DURATION_ENV: "abc"}) == live_routes.DEFAULT_MAX_DURATION
    assert live_routes.max_duration({live_routes.MAX_DURATION_ENV: "-3"}) == live_routes.DEFAULT_MAX_DURATION
    assert live_routes._safe_name("a b/c") == "a_b_c"
    assert live_routes._safe_name("") == "point"
    assert live_routes._size("/chemin/absent") == 0
