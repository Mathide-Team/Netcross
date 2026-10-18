# ruff: noqa: F811 -- fixtures pytest importées de test_issue_902_api_live
"""Issue #908 : POST /comparisons avec current_live (équiv. --live-current) :
le baseline en fichiers, le courant capturé en direct sur le serveur."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.test_issue_902_api_live import CLE, _attendre, _corps, _pkts, actif, api, client, recorder  # noqa: F401

pytest.importorskip("fastapi", reason="extra [api] non installé")


def _baseline():
    return [
        ("baseline_files", ("lan.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 40, "application/octet-stream")),
        ("baseline_files", ("wan.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 40, "application/octet-stream")),
    ]


def _poster(live=None, data=None, files=None, **params):
    form = {"baseline_labels": "LAN,WAN"}
    if live is not None:
        form["current_live"] = live if isinstance(live, str) else json.dumps(live)
    form.update(data or {})
    return client.post(
        "/comparisons", data=form, files=files if files is not None else _baseline(), headers=CLE, params=params
    )


def _attendre_comparaison(comparison_id, delai=10.0):
    """(statut de _comparisons, réponse de GET /comparisons/{id}) une fois terminée."""
    fin = time.monotonic() + delai
    while time.monotonic() < fin:
        statut = api._comparisons[comparison_id]["status"]
        if statut in ("completed", "failed"):
            return statut, client.get(f"/comparisons/{comparison_id}", headers=CLE)
        time.sleep(0.02)
    raise AssertionError(f"comparaison {comparison_id} toujours {statut}")


def test_courant_capture_puis_compare(actif, recorder):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts) as parse:
        rep = _poster(_corps())
        assert rep.status_code == 202, rep.text
        corps = rep.json()
        assert corps["status_url"] == f"/comparisons/{corps['analysis_id']}"
        assert corps["live_capture_url"] == f"/live-captures/{corps['live_capture_id']}"
        live = _attendre(corps["live_capture_id"])
        statut, rep = _attendre_comparaison(corps["analysis_id"])
    assert live["status"] == "completed"
    assert live["analysis_id"] is None
    assert live["comparison_id"] == corps["analysis_id"]
    assert live["comparison_url"] == corps["status_url"]
    assert statut == "completed" and rep.status_code == 200, rep.text
    assert set(rep.json()) >= {"findings", "health_score", "regression", "current_summary"}
    # 2 points baseline + 2 points capturés, sur les interfaces demandées
    assert parse.call_count == 4
    assert sorted(i for i, _b, _p in recorder["start"]) == ["eth0", "eth1"]


def test_fichiers_supprimes(actif, recorder):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts) as parse:
        corps = _poster(_corps()).json()
        _attendre_comparaison(corps["analysis_id"])
        _attendre(corps["live_capture_id"])
    chemins = [Path(c.args[1]) for c in parse.call_args_list]
    assert chemins and not any(p.exists() for p in chemins)


@pytest.mark.parametrize(
    ("data", "params", "attendu"),
    [
        ({"tls": "true"}, {}, "tls/quic"),
        ({"quic": "true"}, {}, "tls/quic"),
        ({}, {"wait": "true"}, "wait"),
    ],
)
def test_limites_de_live_current(actif, recorder, data, params, attendu):
    rep = _poster(_corps(), data=data, **params)
    assert rep.status_code == 400 and attendu in rep.json()["detail"]
    assert recorder["start"] == []


def test_exclusif_avec_current_files(actif, recorder):
    fichiers = [*_baseline(), ("current_files", ("cur.pcap", b"\x00" * 20, "application/octet-stream"))]
    rep = _poster(_corps(), files=fichiers)
    assert rep.status_code == 400 and "exclusifs" in rep.json()["detail"]


def test_ni_fichiers_ni_live(actif, recorder):
    rep = _poster()
    assert rep.status_code == 400 and "current_live" in rep.json()["detail"]


@pytest.mark.parametrize(
    "live",
    ["{pas du json", "[1, 2]", json.dumps({"points": []}), json.dumps(_corps(options={"tls": True}))],
)
def test_current_live_invalide(actif, recorder, live):
    assert _poster(live).status_code == 422
    assert recorder["start"] == []


def test_live_desactive(actif, recorder, monkeypatch):
    monkeypatch.delenv(
        api.live_captures_module.LIVE_ENV if hasattr(api, "live_captures_module") else "X", raising=False
    )
    from netcross_api import live_routes

    monkeypatch.delenv(live_routes.LIVE_ENV)
    rep = _poster(_corps())
    assert rep.status_code == 403
    assert recorder["start"] == []


def test_interface_non_autorisee(actif, recorder):
    rep = _poster(_corps(points=[{"name": "LAN", "interface": "wlan0"}]))
    assert rep.status_code == 403
    assert recorder["start"] == []


def test_capture_deja_en_cours(actif, recorder):
    premier = client.post("/live-captures", json=_corps(duration=60), headers=CLE)
    assert premier.status_code == 202
    rep = _poster(_corps())
    assert rep.status_code == 409
    client.delete(f"/live-captures/{premier.json()['capture_id']}", headers=CLE)


def test_arret_anticipe(actif, recorder):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        corps = _poster(_corps(duration=60)).json()
        rep = client.post(f"/live-captures/{corps['live_capture_id']}/stop", headers=CLE)
        assert rep.status_code == 200
        assert _attendre_comparaison(corps["analysis_id"])[0] == "completed"


def test_abandon(actif, recorder):
    corps = _poster(_corps(duration=60)).json()
    rep = client.delete(f"/live-captures/{corps['live_capture_id']}", headers=CLE)
    assert rep.json()["status"] == "cancelled"
    statut, rep = _attendre_comparaison(corps["analysis_id"])
    assert statut == "failed" and "abandonnée" in rep.json()["detail"]


def test_capture_en_echec(actif, recorder):
    recorder["fichier"] = False  # aucun fichier enregistré
    corps = _poster(_corps()).json()
    statut, rep = _attendre_comparaison(corps["analysis_id"])
    assert statut == "failed" and "aucun fichier" in rep.json()["detail"]
    assert _attendre(corps["live_capture_id"])["status"] == "failed"


def test_comparaison_en_echec(actif, recorder):
    with patch("netcross_api.app.parse_capture", side_effect=RuntimeError("pcap illisible")):
        corps = _poster(_corps()).json()
        statut, rep = _attendre_comparaison(corps["analysis_id"])
        live = _attendre(corps["live_capture_id"])
    assert statut == "failed" and "pcap illisible" in rep.json()["detail"]
    assert live["status"] == "completed"  # la capture elle-même a réussi
