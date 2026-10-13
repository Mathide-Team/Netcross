# ruff: noqa: F811 -- fixtures pytest importées de test_issue_902_api_live
"""Issue #904 : POST /live-captures/{id}/stop renvoie l'analysis_id ;
DELETE /live-captures/{id} abandonne sans analyser. Issue #903 : la borne
de durée (refus 400 au-delà de NETCROSS_API_LIVE_MAX_DURATION).

Mêmes faux enregistreur et parse_capture que tests/test_issue_902_api_live.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from tests.test_issue_902_api_live import CLE, _attendre, _corps, _pkts, actif, api, client, recorder  # noqa: F401

pytest.importorskip("fastapi", reason="extra [api] non installé")

from netcross_api import live_routes  # noqa: E402


def _demarrer():
    rep = client.post("/live-captures", json=_corps(duration=60), headers=CLE)
    assert rep.status_code == 202
    return rep.json()["capture_id"]


def test_stop_renvoie_analysis_id(actif, recorder):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        capture_id = _demarrer()
        rep = client.post(f"/live-captures/{capture_id}/stop", headers=CLE)
        assert rep.status_code == 200
        corps = rep.json()
        assert corps["analysis_id"]
        assert corps["analysis_url"] == f"/analyses/{corps['analysis_id']}"
        assert corps["status"] in ("analysing", "completed")
        etat = _attendre(capture_id)
    assert etat["status"] == "completed"
    assert etat["analysis_id"] == corps["analysis_id"]
    assert client.get(f"/analyses/{corps['analysis_id']}", headers=CLE).status_code == 200


def test_stop_sur_capture_finie_sans_effet(actif, recorder):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post("/live-captures", json=_corps(), headers=CLE)
        capture_id = rep.json()["capture_id"]
        etat = _attendre(capture_id)
        rep = client.post(f"/live-captures/{capture_id}/stop", headers=CLE)
    assert rep.status_code == 200
    assert rep.json()["analysis_id"] == etat["analysis_id"]


def test_abandon_sans_analyse(actif, recorder):
    avant = set(api.store._store)
    capture_id = _demarrer()
    workdir = api.live_captures._entries[capture_id]["_workdir"]
    rep = client.delete(f"/live-captures/{capture_id}", headers=CLE)
    assert rep.status_code == 200
    corps = rep.json()
    assert corps["status"] == "cancelled"
    assert corps["analysis_id"] is None
    assert recorder["stop"] == 2  # les deux tshark arrêtés
    assert not Path(workdir).exists()  # fichiers supprimés
    assert set(api.store._store) == avant  # aucune analyse créée
    # le serveur est de nouveau libre pour une capture
    assert client.post("/live-captures", json=_corps(), headers=CLE).status_code == 202


def test_abandon_capture_finie_409(actif, recorder):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post("/live-captures", json=_corps(), headers=CLE)
        capture_id = rep.json()["capture_id"]
        _attendre(capture_id)
    rep = client.delete(f"/live-captures/{capture_id}", headers=CLE)
    assert rep.status_code == 409
    assert "déjà terminée (completed)" in rep.json()["detail"]


def test_abandon_inconnu_et_cle(actif, recorder):
    assert client.delete("/live-captures/inconnue", headers=CLE).status_code == 404
    capture_id = _demarrer()
    assert client.delete(f"/live-captures/{capture_id}").status_code == 401
    assert client.delete(f"/live-captures/{capture_id}", headers=CLE).status_code == 200


def test_attente_bornee(actif, recorder, monkeypatch):
    """Si l'arrêt traîne, /stop et DELETE rendent la main après STOP_WAIT_SECONDS."""
    monkeypatch.setattr(live_routes, "STOP_WAIT_SECONDS", 0.0)
    capture_id = _demarrer()
    entry = api.live_captures._entries[capture_id]
    entry["_handoff"].wait = lambda _t: False  # simule un arrêt qui n'aboutit pas à temps
    assert client.delete(f"/live-captures/{capture_id}", headers=CLE).status_code == 200
    _attendre(capture_id, statuts=("cancelled",))


def test_stop_attente_bornee(actif, recorder, monkeypatch):
    monkeypatch.setattr(live_routes, "STOP_WAIT_SECONDS", 0.0)
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        capture_id = _demarrer()
        api.live_captures._entries[capture_id]["_handoff"].wait = lambda _t: False
        assert client.post(f"/live-captures/{capture_id}/stop", headers=CLE).status_code == 200
        _attendre(capture_id)


@pytest.mark.parametrize(("borne", "duree", "code"), [("10", 10, 202), ("10", 10.5, 400), (None, 301, 400)])
def test_903_duree_bornee(actif, recorder, monkeypatch, borne, duree, code):
    if borne is not None:
        monkeypatch.setenv(live_routes.MAX_DURATION_ENV, borne)
    rep = client.post("/live-captures", json=_corps(duration=duree), headers=CLE)
    assert rep.status_code == code
    if code == 400:
        assert live_routes.MAX_DURATION_ENV in rep.json()["detail"]
    else:
        client.delete(f"/live-captures/{rep.json()['capture_id']}", headers=CLE)


# -- bpf_library par point (annoncé par docs/parite-surfaces.md, bibliothèque de #906) ------


def test_bpf_library_par_point(actif, recorder, monkeypatch, tmp_path):
    from netcross_api import bpf_routes

    monkeypatch.setenv("NETCROSS_API_BPF_FILTERS", str(tmp_path / "filtres.json"))
    assert client.put("/bpf-filters/web", json={"expression": "tcp port 80"}, headers=CLE).status_code == 200
    corps = _corps(
        points=[
            {"name": "LAN", "interface": "eth0", "bpf_library": "WEB"},  # nom insensible à la casse
            {"name": "WAN", "interface": "eth1", "bpf": "udp"},
        ]
    )
    rep = client.post("/live-captures", json=corps, headers=CLE)
    assert rep.status_code == 202, rep.text
    capture_id = rep.json()["capture_id"]
    assert [p["bpf"] for p in rep.json()["points"]] == ["tcp port 80", "udp"]
    client.delete(f"/live-captures/{capture_id}", headers=CLE)
    assert bpf_routes.resolve_bpf_library  # même résolution que GET /bpf-filters


@pytest.mark.parametrize(
    ("point", "detail"),
    [
        ({"name": "LAN", "interface": "eth0", "bpf_library": "absent"}, "introuvable"),
        ({"name": "LAN", "interface": "eth0", "bpf": "tcp", "bpf_library": "web"}, "exclusifs"),
    ],
)
def test_bpf_library_refus(actif, recorder, monkeypatch, tmp_path, point, detail):
    monkeypatch.setenv("NETCROSS_API_BPF_FILTERS", str(tmp_path / "filtres.json"))
    rep = client.post("/live-captures", json=_corps(points=[point]), headers=CLE)
    assert rep.status_code == 400
    assert detail in rep.json()["detail"]
    assert recorder["start"] == []
