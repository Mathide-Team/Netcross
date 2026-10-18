# ruff: noqa: F811 -- fixtures pytest importées de test_issue_902_api_live
"""Issue #905 : ring_buffer de POST /live-captures (équiv. --ring-buffer N:SECONDES),
liste, téléchargement et suppression des fichiers conservés."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from tests.test_issue_902_api_live import CLE, _attendre, _corps, _pkts, actif, api, client, recorder  # noqa: F401

pytest.importorskip("fastapi", reason="extra [api] non installé")


@pytest.fixture
def appels(recorder, monkeypatch):
    """Enregistreur qui mémorise aussi la rotation demandée."""
    kwargs = []
    start = api.live_captures._deps["start_recorder"]

    def start_kw(interface, directory, **kw):
        kwargs.append({"directory": directory, **kw})
        return start(interface, directory, **kw)

    monkeypatch.setitem(api.live_captures._deps, "start_recorder", start_kw)
    return kwargs


def _ring(**kw):
    return _corps(ring_buffer={"files": 3, "seconds": 30}, **kw)


def test_deux_enregistreurs_par_point(actif, appels):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post("/live-captures", json=_ring(), headers=CLE)
        assert rep.status_code == 202, rep.text
        assert rep.json()["ring_buffer"] == {"files": 3, "seconds": 30.0}
        capture_id = rep.json()["capture_id"]
        etat = _attendre(capture_id)
    assert etat["status"] == "completed"
    assert etat["files_url"] == f"/live-captures/{capture_id}/files"
    rotations = [(k["max_files"], k["max_duration_per_file"]) for k in appels]
    assert rotations.count((3, 30.0)) == 2  # un enregistreur tournant par point
    assert len(appels) == 4  # + l'enregistreur de l'analyse, inchangé
    ring = [k for k in appels if k["max_files"] == 3]
    assert all(k["bpf_filter"] == b for k, b in zip(ring, ["tcp port 443", None], strict=True))


def test_fichiers_conserves_apres_analyse(actif, appels):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        capture_id = client.post("/live-captures", json=_ring(), headers=CLE).json()["capture_id"]
        _attendre(capture_id)
    doc = client.get(f"/live-captures/{capture_id}/files", headers=CLE).json()
    assert doc["purged"] is False
    assert [p["name"] for p in doc["points"]] == ["LAN", "WAN"]
    fichier = doc["points"][0]["files"][0]
    assert fichier["filename"] == "LAN_00001.pcapng" and fichier["bytes"] > 0
    rep = client.get(fichier["url"], headers=CLE)
    assert rep.status_code == 200
    assert rep.content.startswith(b"\x0a\x0d\x0d\x0a")
    assert rep.headers["content-type"] == "application/vnd.tcpdump.pcap"


def test_telechargement_refuse(actif, appels):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        capture_id = client.post("/live-captures", json=_ring(), headers=CLE).json()["capture_id"]
        _attendre(capture_id)
    base = f"/live-captures/{capture_id}/files"
    assert client.get(f"{base}/LAN/absent.pcapng", headers=CLE).status_code == 404
    assert client.get(f"{base}/DMZ/LAN_00001.pcapng", headers=CLE).status_code == 404
    assert client.get(f"{base}/LAN/..%2F..%2Fetc%2Fpasswd", headers=CLE).status_code == 404
    assert client.get(f"{base}/LAN/LAN_00001.pcapng").status_code == 401


def test_purge(actif, appels):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        capture_id = client.post("/live-captures", json=_ring(), headers=CLE).json()["capture_id"]
        _attendre(capture_id)
    ringdir = api.live_captures._entries[capture_id]["_ringdir"]
    assert Path(ringdir).is_dir()
    doc = client.delete(f"/live-captures/{capture_id}/files", headers=CLE).json()
    assert doc["purged"] is True
    assert all(p["files"] == [] for p in doc["points"])
    assert not Path(ringdir).exists()


def test_purge_pendant_capture_409_puis_abandon(actif, appels):
    capture_id = client.post("/live-captures", json=_ring(duration=60), headers=CLE).json()["capture_id"]
    ringdir = api.live_captures._entries[capture_id]["_ringdir"]
    assert client.delete(f"/live-captures/{capture_id}/files", headers=CLE).status_code == 409
    # l'abandon (#904) supprime aussi la capture brute
    assert client.delete(f"/live-captures/{capture_id}", headers=CLE).json()["status"] == "cancelled"
    assert not Path(ringdir).exists()
    assert client.get(f"/live-captures/{capture_id}/files", headers=CLE).json()["purged"] is True


def test_sans_ring_buffer(actif, appels):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post("/live-captures", json=_corps(), headers=CLE)
        capture_id = rep.json()["capture_id"]
        etat = _attendre(capture_id)
    assert etat["ring_buffer"] is None and etat["files_url"] is None
    assert len(appels) == 2
    assert client.get(f"/live-captures/{capture_id}/files", headers=CLE).status_code == 404
    assert client.delete(f"/live-captures/{capture_id}/files", headers=CLE).status_code == 404
    assert client.get("/live-captures/inconnue/files", headers=CLE).status_code == 404


@pytest.mark.parametrize(
    ("ring", "code"),
    [({"files": 0, "seconds": 30}, 422), ({"files": 2, "seconds": 0}, 422), ({"files": 2}, 422)],
)
def test_ring_buffer_invalide(actif, appels, ring, code):
    assert client.post("/live-captures", json=_corps(ring_buffer=ring), headers=CLE).status_code == code
    assert appels == []


def test_pipe_incompatible(actif, appels, monkeypatch):
    from netcross_api import live_routes

    monkeypatch.setenv(live_routes.INTERFACES_ENV, "pipe://capture")
    corps = _ring(points=[{"name": "LAN", "interface": "pipe://capture"}])
    rep = client.post("/live-captures", json=corps, headers=CLE)
    assert rep.status_code == 400
    assert "pipe://" in rep.json()["detail"]
    assert appels == []


def test_echec_enregistreur_tournant(actif, recorder, monkeypatch):
    """Un enregistreur tournant qui ne démarre pas fait échouer la capture, comme la CLI."""
    start = api.live_captures._deps["start_recorder"]

    def start_ko(interface, directory, **kw):
        if kw["max_files"] == 3:
            raise OSError("tshark absent")
        return start(interface, directory, **kw)

    monkeypatch.setitem(api.live_captures._deps, "start_recorder", start_ko)
    capture_id = client.post("/live-captures", json=_ring(), headers=CLE).json()["capture_id"]
    etat = _attendre(capture_id)
    assert etat["status"] == "failed"
    assert "tshark absent" in etat["error"]
