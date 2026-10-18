"""Issue #912 : exploration statistique en CLI (--stats) et dans l'API
(GET /analyses/{analysis_id}/stats), même calcul que la vue GUI."""

from __future__ import annotations

import csv
import importlib
import io
import json
from types import SimpleNamespace

import pytest

import cross_capture_analyzer_cli as cli
from netcross_core.correlate import correlate
from netcross_core.models import Report
from netcross_core.stats import (
    build_events_by_segment,
    explore_stats,
    export_json,
    render_stats,
    stats_format_for,
)
from netcross_gtk4 import stats_view
from tests.conftest import make_pkt


def _paquets():
    return [
        make_pkt(point="LAN", src="10.0.0.1", dst="10.0.0.2", sport=1000, dport=443, proto="TCP", length=500, ts=1.0),
        make_pkt(point="LAN", src="10.0.0.2", dst="10.0.0.1", sport=443, dport=1000, proto="TCP", length=60, ts=1.1),
        make_pkt(point="LAN", src="10.0.0.1", dst="10.0.0.53", sport=2000, dport=53, proto="UDP", length=80, ts=1.2),
    ]


def _flows():
    return correlate(_paquets())


def _report():
    return Report(points=["LAN"])


def test_explore_depuis_dict_ou_liste():
    from netcross_core.correlate import build_flows

    par_dict = explore_stats(_flows(), _report(), group_by="protocol")
    par_liste = explore_stats(build_flows(_flows()), _report(), group_by="protocol")
    assert export_json(par_dict) == export_json(par_liste)
    assert [r.label for r in par_dict] == ["TCP", "UDP"]


def test_tri_et_top_n():
    rows = explore_stats(_flows(), _report(), group_by="protocol", sort_by="bytes", top_n=1)
    assert [r.label for r in rows] == ["TCP"]
    assert len(explore_stats(_flows(), _report(), group_by="protocol", top_n=0)) == 2
    assert len(explore_stats(_flows(), _report(), group_by="protocol", top_n=None)) == 2


def test_vide_et_erreurs():
    assert explore_stats({}, _report()) == []
    assert explore_stats(_flows(), None) == []
    with pytest.raises(ValueError, match="regroupement"):
        explore_stats(_flows(), _report(), group_by="pays")
    with pytest.raises(ValueError, match="tri"):
        explore_stats(_flows(), _report(), sort_by="couleur")


def test_evenements_comme_la_gui():
    findings = [SimpleNamespace(segment="LAN"), SimpleNamespace(pair="LAN"), SimpleNamespace()]
    assert build_events_by_segment(findings) == {"LAN": findings[:2], "?": findings[2:]}
    assert build_events_by_segment(None) == {}
    # la GUI passe par le même calcul
    assert stats_view.build_events_by_segment(findings, None) == build_events_by_segment(findings)
    rows = explore_stats(_flows(), _report(), findings, group_by="protocol")
    assert all(r.events == 2 * len(r.flow_keys) for r in rows)  # 2 événements sur LAN par flux, comme compute_stats


@pytest.mark.parametrize(
    ("chemin", "fmt", "attendu"),
    [
        ("s.csv", None, "csv"),
        ("s.CSV", None, "csv"),
        ("s.json", None, "json"),
        ("s", None, "json"),
        ("s.csv", "json", "json"),
    ],
)
def test_stats_format_for(chemin, fmt, attendu):
    assert stats_format_for(chemin, fmt) == attendu


def test_stats_format_inconnu():
    with pytest.raises(ValueError):
        stats_format_for("s", "xml")


def test_render_csv_et_json():
    rows = explore_stats(_flows(), _report(), group_by="protocol")
    lignes = list(csv.DictReader(io.StringIO(render_stats(rows, "csv"))))
    assert [ligne["label"] for ligne in lignes] == ["TCP", "UDP"]
    assert json.loads(render_stats(rows, "json"))[0]["flow_keys"]


# -- CLI -------------------------------------------------------------------------------


def _args(**kw):
    base = {"stats": None, "stats_group_by": "endpoint", "stats_sort": "bytes", "stats_top_n": 10, "stats_format": None}
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.mark.parametrize(
    "kw", [{"stats_group_by": "protocol"}, {"stats_sort": "packets"}, {"stats_top_n": 3}, {"stats_format": "csv"}]
)
def test_options_sans_stats_refusees(kw, capsys):
    with pytest.raises(SystemExit) as exc:
        cli._check_stats_args(_args(**kw))
    assert exc.value.code == 1
    assert "necessitent --stats" in capsys.readouterr().err


def test_top_n_negatif(capsys):
    with pytest.raises(SystemExit):
        cli._check_stats_args(_args(stats="s.csv", stats_top_n=-1))
    assert "0 (toutes)" in capsys.readouterr().err


def test_options_valides():
    cli._check_stats_args(_args())
    cli._check_stats_args(_args(stats="s.json", stats_top_n=0, stats_group_by="flow"))


# -- API -------------------------------------------------------------------------------

pytest.importorskip("fastapi", reason="extra [api] non installé")

from fastapi.testclient import TestClient  # noqa: E402

api = importlib.import_module("netcross_api.app")
client = TestClient(api.app)


@pytest.fixture
def analyse():
    analysis_id = api.store.create_pending({})
    api.store.complete(analysis_id, {"points": ["LAN"]}, {}, flows=_flows(), report_obj=_report(), findings=[])
    yield analysis_id
    api.store._store.pop(analysis_id, None)


def _url(analysis_id):
    return f"/analyses/{analysis_id}/stats"


def test_api_json(analyse):
    rep = client.get(_url(analyse), params={"group_by": "protocol"})
    assert rep.status_code == 200
    d = rep.json()
    assert d["group_by"] == "protocol" and d["sort"] == "bytes"
    assert d["rows"] == export_json(explore_stats(_flows(), _report(), [], group_by="protocol"))


def test_api_csv_et_parametres(analyse):
    rep = client.get(_url(analyse), params={"group_by": "protocol", "sort": "packets", "top_n": 1, "format": "csv"})
    assert rep.status_code == 200
    assert rep.headers["content-type"].startswith("text/csv")
    assert [ligne["label"] for ligne in csv.DictReader(io.StringIO(rep.text))] == ["TCP"]
    assert len(client.get(_url(analyse), params={"group_by": "protocol", "top_n": 0}).json()["rows"]) == 2


def test_api_erreurs(analyse):
    assert client.get(_url(analyse), params={"format": "xml"}).status_code == 400
    assert client.get(_url(analyse), params={"group_by": "pays"}).status_code == 400
    assert client.get(_url(analyse), params={"sort": "couleur"}).status_code == 400
    assert client.get(_url(analyse), params={"top_n": -1}).status_code == 422
    assert client.get(_url("inconnue")).status_code == 404
    sans_flux = api.store.create_pending({})
    api.store.complete(sans_flux, {"points": []}, {})
    try:
        assert client.get(_url(sans_flux)).status_code == 404
    finally:
        api.store._store.pop(sans_flux, None)


def test_api_authentification(monkeypatch, analyse):
    monkeypatch.setattr(api, "_API_TOKEN", "secret")
    assert client.get(_url(analyse)).status_code == 401
    assert client.get(_url(analyse), headers={"X-API-Key": "secret"}).status_code == 200
