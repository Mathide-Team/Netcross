"""Issue #875 : notifications de l'API (notify_on, notify_webhook,
notify_slack, notify_email, notify_detail), mêmes règles que la CLI et la
GUI, URL jamais conservées dans les métadonnées."""

from __future__ import annotations

import importlib
from unittest.mock import patch

import pytest

from tests.conftest import make_pkt

pytest.importorskip("fastapi", reason="extra [api] non installé")
pytest.importorskip("multipart", reason="python-multipart non installé")

from fastapi.testclient import TestClient  # noqa: E402

from netcross_api.store import store  # noqa: E402
from netcross_core.notify.request import NotifySettings  # noqa: E402

api = importlib.import_module("netcross_api.app")
client = TestClient(api.app)
SLACK = "https://hooks.slack.com/services/T000/B000/SECRET"


def _pkts(label, _path):
    return [make_pkt(point=label, src="192.168.1.1", dst="192.168.1.2", dport=80, ts=1000.0 + i) for i in range(3)]


@pytest.fixture(autouse=True)
def _store_vide():
    store._store.clear()
    yield
    store._store.clear()


def _post(data):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        return client.post(
            "/captures?wait=true",
            files={"file": ("a.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 64, "application/octet-stream")},
            data={"label": "LAN", **data},
        )


def test_envoi_trace_et_url_non_conservee(monkeypatch):
    vus = []

    def faux(report, security_report, settings):
        vus.append(settings)
        return [{"channel": "slack", "status": "sent", "reason": None, "line": "notification slack : envoyee"}]

    monkeypatch.setattr(api, "send_notifications", faux)
    rep = _post({"notify_on": "faible", "notify_slack": f"  {SLACK} ", "notify_detail": "complet"})
    assert rep.status_code == 201, rep.text
    assert vus == [NotifySettings(threshold="faible", slack=SLACK, detail="complet")]
    analysis_id = rep.json()["analysis_id"]
    entry = store.get(analysis_id)
    assert entry["metadata"]["options"]["notify"] == {"threshold": "faible", "detail": "complet", "channels": ["slack"]}
    assert "SECRET" not in str(entry["metadata"])
    doc = client.get(f"/analyses/{analysis_id}/report").json()
    assert doc["security_report"]["notifications"][0]["line"] == "notification slack : envoyee"


def test_sans_seuil_aucun_envoi(monkeypatch):
    monkeypatch.setattr(api, "send_notifications", lambda *a: pytest.fail("envoi sans seuil"))
    rep = _post({})
    assert rep.status_code == 201, rep.text
    assert store.get(rep.json()["analysis_id"])["metadata"]["options"]["notify"] is None


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"notify_slack": SLACK}, "notify_slack sans notify_on"),
        ({"notify_detail": "complet"}, "notify_detail sans notify_on"),
        ({"notify_on": "enorme"}, "seuil inconnu : enorme"),
        ({"notify_on": "faible", "notify_detail": "tout"}, "niveau de detail inconnu"),
        ({"notify_on": "faible", "notify_webhook": "ftp://x"}, "URL webhook invalide"),
        ({"notify_on": "faible", "redact": "true"}, "pas calcule avec redact=true"),
    ],
)
def test_refus_comme_la_cli(data, message):
    rep = _post(data)
    assert rep.status_code == 400
    assert message in rep.json()["detail"]


def test_la_gui_reutilise_le_coeur():
    import netcross_gtk4.notifications as gui
    from netcross_core.notify import request

    assert gui.NotifySettings is request.NotifySettings
    assert gui.send_notifications is request.send_notifications
    assert "cochez « Rapport de securite »" in gui.validate_settings(NotifySettings(threshold="faible"), False)[0]
