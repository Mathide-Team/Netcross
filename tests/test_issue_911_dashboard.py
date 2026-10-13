"""Issue #911 : dashboard en CLI (--dashboard) et dans l'API
(GET /analyses/{analysis_id}/dashboard), même calcul que la GUI."""

from __future__ import annotations

import enum
import importlib
import json
from types import SimpleNamespace

import pytest

import cross_capture_analyzer_cli as cli
from netcross_core import dashboard as core_dashboard
from netcross_core.correlate import build_flows, correlate
from netcross_core.dashboard import DASHBOARD_VIEWS, _json_safe, dashboard_document
from netcross_core.models import Report
from netcross_gtk4 import dashboard_context
from tests.conftest import make_pkt


def _paquets():
    return [
        make_pkt(point="LAN", src="10.0.0.1", dst="10.0.0.2", sport=1000, dport=443, proto="TCP", length=500, ts=1.0),
        make_pkt(point="LAN", src="10.0.0.2", dst="10.0.0.1", sport=443, dport=1000, proto="TCP", length=60, ts=1.1),
        make_pkt(point="LAN", src="10.0.0.1", dst="10.0.0.53", sport=2000, dport=53, proto="UDP", length=80, ts=1.2),
    ]


def _report():
    return Report(points=["LAN"])


def test_ancien_module_est_un_alias():
    assert dashboard_context is core_dashboard
    assert dashboard_context.build_dashboard_snapshot is core_dashboard.build_dashboard_snapshot


def test_document_complet_et_serialisable():
    doc = dashboard_document(_report(), correlate(_paquets()))
    assert set(DASHBOARD_VIEWS) <= set(doc)
    assert doc["filters"] == {"segment": None, "host": None, "protocol": None}
    assert doc["selection_summary"] == "aucune selection active"
    assert {f["protocol"] for f in doc["flows"]} == {"TCP", "UDP"}
    json.dumps(doc)  # pas de tuple ni d'objet non sérialisable


def test_dict_ou_liste_de_flows():
    flows = correlate(_paquets())
    assert dashboard_document(_report(), flows) == dashboard_document(_report(), build_flows(flows))


def test_filtres():
    flows = correlate(_paquets())
    doc = dashboard_document(_report(), flows, protocol="UDP")
    assert [f["protocol"] for f in doc["flows"]] == ["UDP"]
    assert "proto=UDP" in doc["selection_summary"]
    doc = dashboard_document(_report(), flows, host="10.0.0.53")
    assert all("10.0.0.53" in f["endpoints"] for f in doc["flows"]) and doc["flows"]
    doc = dashboard_document(_report(), flows, segment="LAN")
    assert len(doc["flows"]) == len(build_flows(flows))  # tous les flux passent par LAN
    assert doc["filters"]["segment"] == "LAN"


def test_segment_inconnu():
    with pytest.raises(ValueError, match="segment inconnu"):
        dashboard_document(_report(), correlate(_paquets()), segment="DMZ")


def test_entrees_vides():
    doc = dashboard_document(None, None)
    assert all(doc[v] == [] for v in DASHBOARD_VIEWS)


def test_evenements_filtres_par_protocole():
    ev_tcp = SimpleNamespace(protocol="TCP", segment="LAN", category="c", severity="s", message="m")
    ev_udp = SimpleNamespace(protocol="UDP", segment="LAN", category="c", severity="s", message="m")
    doc = dashboard_document(_report(), correlate(_paquets()), [ev_tcp, ev_udp], protocol="TCP")
    assert [e["protocol"] for e in doc["events"]] == ["TCP"]


class _Gravite(enum.Enum):
    HAUTE = "haute"


def test_json_safe():
    assert _json_safe({"a": (1, 2), 3: {4, 2}, "e": _Gravite.HAUTE, "o": object}) == {
        "a": [1, 2],
        "3": [2, 4],
        "e": "haute",
        "o": str(object),
    }


# -- CLI -------------------------------------------------------------------------------


def _args(**kw):
    base = {"dashboard": None, "dashboard_segment": None, "dashboard_host": None, "dashboard_protocol": None}
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.mark.parametrize(
    "kw", [{"dashboard_segment": "LAN"}, {"dashboard_host": "10.0.0.1"}, {"dashboard_protocol": "TCP"}]
)
def test_filtres_sans_dashboard_refuses(kw, capsys):
    with pytest.raises(SystemExit) as exc:
        cli._check_dashboard_args(_args(**kw))
    assert exc.value.code == 1
    assert "necessitent --dashboard" in capsys.readouterr().err


def test_options_valides():
    cli._check_dashboard_args(_args())
    cli._check_dashboard_args(_args(dashboard="d.json", dashboard_protocol="TCP"))


# -- API -------------------------------------------------------------------------------

pytest.importorskip("fastapi", reason="extra [api] non installé")

from fastapi.testclient import TestClient  # noqa: E402

api = importlib.import_module("netcross_api.app")
client = TestClient(api.app)


@pytest.fixture
def analyse():
    analysis_id = api.store.create_pending({})
    api.store.complete(
        analysis_id, {"points": ["LAN"]}, {}, flows=correlate(_paquets()), report_obj=_report(), findings=[]
    )
    yield analysis_id
    api.store._store.pop(analysis_id, None)


def _url(analysis_id):
    return f"/analyses/{analysis_id}/dashboard"


def test_api_sans_filtre(analyse):
    rep = client.get(_url(analyse))
    assert rep.status_code == 200
    assert rep.json() == dashboard_document(_report(), correlate(_paquets()), [])


def test_api_filtres(analyse):
    d = client.get(_url(analyse), params={"protocol": "TCP", "host": "10.0.0.2", "segment": "LAN"}).json()
    assert d["filters"] == {"segment": "LAN", "host": "10.0.0.2", "protocol": "TCP"}
    assert d["flows"] and {f["protocol"] for f in d["flows"]} == {"TCP"}


def test_api_erreurs(analyse):
    assert client.get(_url(analyse), params={"segment": "DMZ"}).status_code == 400
    assert client.get(_url("inconnue")).status_code == 404
    sans_rapport = api.store.create_pending({})
    api.store.complete(sans_rapport, {"points": []}, {})
    try:
        assert client.get(_url(sans_rapport)).status_code == 404
    finally:
        api.store._store.pop(sans_rapport, None)


def test_api_authentification(monkeypatch, analyse):
    monkeypatch.setattr(api, "_API_TOKEN", "secret")
    assert client.get(_url(analyse)).status_code == 401
    assert client.get(_url(analyse), headers={"X-API-Key": "secret"}).status_code == 200
