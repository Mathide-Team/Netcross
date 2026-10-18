# ruff: noqa: F811 -- fixtures pytest importées de test_issue_902_api_live
"""Issue #907 : live_report de POST /live-captures (équiv. --live-report,
--live-report-interval), GET /live-captures/{id}/report et URL de consultation
à jeton (équiv. --live-report-serve)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.conftest import make_pkt
from tests.test_issue_902_api_live import CLE, _attendre, _corps, _pkts, actif, api, client, recorder  # noqa: F401

pytest.importorskip("fastapi", reason="extra [api] non installé")


@pytest.fixture
def flux(monkeypatch):
    """Faux parse_live : 3 paquets par point puis attend l'arrêt."""
    appels = []

    def parse_live(label, interface, bpf_filter=None, stop_event=None):
        appels.append((label, interface, bpf_filter))
        for i in range(3):
            yield make_pkt(src="10.0.0.1", dst="10.0.0.2", dport=443, ts=1000.0 + i, point=label, length=100)
        stop_event.wait(10)

    monkeypatch.setitem(api.live_captures._deps, "parse_live", parse_live)
    return appels


def _report(**kw):
    return _corps(live_report={"interval": 1}, **kw)


def test_rapport_pendant_la_capture(actif, recorder, flux):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post("/live-captures", json=_report(duration=60), headers=CLE)
        assert rep.status_code == 202, rep.text
        etat = rep.json()
        capture_id = etat["capture_id"]
        assert etat["live_report"] == {"interval": 1.0}
        assert etat["report_url"].startswith(f"/live-captures/{capture_id}/report/")
        time.sleep(1.5)  # au moins un relevé après les paquets
        rep = client.get(f"/live-captures/{capture_id}/report", headers=CLE)
        assert rep.status_code == 200
        assert rep.headers["refresh"] == "1"
        assert rep.headers["content-type"].startswith("text/html")
        snap = json.loads(client.get(etat["report_url"] + "live.json").text)
        assert {p: d["packets"] for p, d in snap["points"].items()} == {"LAN": 3, "WAN": 3}
        assert snap["final"] is False
        assert sorted((a, b, c) for a, b, c in flux) == [("LAN", "eth0", "tcp port 443"), ("WAN", "eth1", None)]
        client.post(f"/live-captures/{capture_id}/stop", headers=CLE)
        _attendre(capture_id)
    # après l'arrêt : dernier relevé final, plus d'en-tête Refresh
    rep = client.get(f"/live-captures/{capture_id}/report", headers=CLE)
    assert "refresh" not in rep.headers
    snap = json.loads(client.get(etat["report_url"] + "live.json").text)
    assert snap["final"] is True
    assert {d["status"] for d in snap["points"].values()} == {"arrete"}


def test_url_de_consultation(actif, recorder, flux):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        etat = client.post("/live-captures", json=_report(), headers=CLE).json()
        _attendre(etat["capture_id"])
    url = etat["report_url"]
    page = client.get(url)  # sans clé API
    assert page.status_code == 200 and "<html" in page.text.lower()
    assert client.get(url + "index.html").status_code == 200
    journal = client.get(url + "live.jsonl")
    assert journal.headers["content-type"].startswith("application/x-ndjson")
    assert [json.loads(ligne)["seq"] for ligne in journal.text.splitlines() if ligne.strip()]
    base = f"/live-captures/{etat['capture_id']}/report"
    assert client.get(f"{base}/mauvais-jeton/").status_code == 404
    assert client.get(f"{base}/mauvais-jeton/live.json").status_code == 404
    assert client.get(url + "autre.txt").status_code == 404
    assert client.get("/live-captures/inconnue/report/x/").status_code == 404
    assert client.get(base).status_code == 401  # la route principale exige la clé


def test_sans_live_report(actif, recorder, flux):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        etat = client.post("/live-captures", json=_corps(), headers=CLE).json()
        _attendre(etat["capture_id"])
    assert etat["live_report"] is None and etat["report_url"] is None
    assert flux == []  # aucun flux de dissection sans rapport
    assert client.get(f"/live-captures/{etat['capture_id']}/report", headers=CLE).status_code == 404


def test_abandon_supprime_le_rapport(actif, recorder, flux):
    etat = client.post("/live-captures", json=_report(duration=60), headers=CLE).json()
    report_dir = api.live_captures._entries[etat["capture_id"]]["_report_dir"]
    assert client.delete(f"/live-captures/{etat['capture_id']}", headers=CLE).json()["status"] == "cancelled"
    assert not Path(report_dir).exists()
    assert client.get(etat["report_url"]).status_code == 404


def test_point_en_erreur(actif, recorder, monkeypatch):
    def parse_live(label, interface, bpf_filter=None, stop_event=None):
        if label == "WAN":
            raise OSError("interface tombée")
        stop_event.wait(10)
        yield from ()

    monkeypatch.setitem(api.live_captures._deps, "parse_live", parse_live)
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        etat = client.post("/live-captures", json=_report(), headers=CLE).json()
        fin = _attendre(etat["capture_id"])
    assert fin["status"] == "completed"  # l'analyse ne dépend pas du rapport
    snap = json.loads(client.get(etat["report_url"] + "live.json").text)
    assert snap["points"]["WAN"]["status"] == "erreur"


@pytest.mark.parametrize("corps", [{"interval": 0.5}, {"interval": "x"}])
def test_intervalle_invalide(actif, recorder, flux, corps):
    assert client.post("/live-captures", json=_corps(live_report=corps), headers=CLE).status_code == 422


def test_intervalle_par_defaut(actif, recorder, flux):
    etat = client.post("/live-captures", json=_corps(live_report={}), headers=CLE).json()
    assert etat["live_report"] == {"interval": 5.0}
    client.delete(f"/live-captures/{etat['capture_id']}", headers=CLE)
