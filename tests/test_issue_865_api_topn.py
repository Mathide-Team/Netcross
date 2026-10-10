"""Issue #865 : le topn de GET /analyses/{id}/pdf (équivalent de
--topn-charts) change vraiment les graphiques Top-N, comme la CLI."""

from __future__ import annotations

import importlib
from unittest.mock import patch

import pytest

from tests.conftest import make_pkt

pytest.importorskip("fastapi", reason="extra [api] non installé")
pytest.importorskip("multipart", reason="python-multipart non installé")

from fastapi.testclient import TestClient  # noqa: E402

from netcross_api.store import store  # noqa: E402
from netcross_core import analyse, correlate  # noqa: E402

api = importlib.import_module("netcross_api.app")
client = TestClient(api.app)


def _pkts(label, _path):
    # 8 ports de destination differents : un Top-2 regroupe le reste sous « autres »
    return [make_pkt(point=label, src="10.0.0.1", dst="10.0.0.2", dport=1000 + i, ts=1000.0 + i) for i in range(8)]


@pytest.fixture(autouse=True)
def _store_vide():
    store._store.clear()
    yield
    store._store.clear()


def _analyse():
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post(
            "/captures?wait=true",
            files={"file": ("a.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 64, "application/octet-stream")},
            data={"label": "LAN"},
        )
    assert rep.status_code == 201, rep.text
    return rep.json()["analysis_id"]


def test_series_identiques_a_la_cli():
    analysis_id = _analyse()
    entry = store.get(analysis_id)
    copie = api._report_with_topn(entry["report_obj"], entry, 2)
    paquets = _pkts("LAN", "a.pcap")
    cli = analyse(correlate(paquets), ["LAN"], paquets, 1.0, False, 8000, 2)  # --topn-charts 2
    assert copie.topn_timeseries == cli.topn_timeseries
    assert copie is not entry["report_obj"]
    assert entry["report_obj"].topn_timeseries != cli.topn_timeseries  # analyse stockee intacte (topn 5)


def test_sans_paquets_series_d_origine():
    report = object()
    assert api._report_with_topn(report, {"all_packets": None}, 3) is report


def test_la_route_pdf_transmet_topn(monkeypatch):
    analysis_id = _analyse()
    vus = []

    def faux_pdf(report, path, **_kw):
        vus.append(report.topn_timeseries)
        with open(path, "wb") as fh:
            fh.write(b"%PDF-1.4\n")

    monkeypatch.setattr("netcross_report.pdf.generate_pdf", faux_pdf)
    assert client.get(f"/analyses/{analysis_id}/pdf?topn=2").status_code == 200
    entry = store.get(analysis_id)
    assert vus == [api._report_with_topn(entry["report_obj"], entry, 2).topn_timeseries]
