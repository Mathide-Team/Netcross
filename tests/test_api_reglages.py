"""
Issue #330 (suite de l'écart 2) : réglages d'analyse de l'API déjà
présents en GUI et en CLI -- bucket_ms, rtp_clock_rate,
idle_timeout_seconds, detect_duplicates, exclude_duplicates,
duplicate_threshold_ms. Mêmes noms, mêmes défauts et même sens que la CLI.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tests.conftest import make_pkt

pytest.importorskip("fastapi", reason="extra [api] non installé")
pytest.importorskip("multipart", reason="python-multipart non installé")

from fastapi.testclient import TestClient  # noqa: E402

import netcross_core  # noqa: E402
from netcross_api.app import app  # noqa: E402
from netcross_api.store import store  # noqa: E402

client = TestClient(app)
PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 64


def _pkts(label, _path):
    # Même paquet vu par les deux points à 0,2 ms d'écart : un doublon
    # inter-captures sous le seuil par défaut (1 ms).
    return [
        make_pkt(
            point=label,
            src="192.168.1.1",
            dst="192.168.1.2",
            dport=80,
            ts=1000.0 + (0.0002 if label == "B" else 0),
            payload_hash="h1",
        ),
        make_pkt(point=label, src="192.168.1.2", dst="192.168.1.1", dport=50000, ts=1001.0),
    ]


@pytest.fixture(autouse=True)
def _store_vide():
    store._store.clear()
    yield
    store._store.clear()


def _post_multi(data):
    files = [
        ("files", ("a.pcap", PCAP, "application/octet-stream")),
        ("files", ("b.pcap", PCAP, "application/octet-stream")),
    ]
    with (
        patch("netcross_api.app.parse_capture", side_effect=_pkts),
        patch("netcross_api.app.correlate", wraps=netcross_core.correlate) as corr,
        patch("netcross_api.app.analyse", wraps=netcross_core.analyse) as ana,
        patch(
            "netcross_api.app.detect_cross_capture_duplicates",
            wraps=__import__("netcross_core.forensic", fromlist=["x"]).detect_cross_capture_duplicates,
        ) as dup,
    ):
        rep = client.post("/captures/multi?wait=true", files=files, data={"labels": "A,B", **data})
    return rep, corr, ana, dup


def test_defauts_identiques_a_la_cli():
    rep, corr, ana, dup = _post_multi({})
    assert rep.status_code == 201, rep.text
    kw = ana.call_args.kwargs
    assert kw["bucket_seconds"] == 1.0
    assert kw["rtp_clock_rate"] == 8000
    assert kw["idle_timeout_seconds"] is None
    assert kw["exclude_duplicates"] is False
    assert kw["duplicate_counts"] is None
    assert corr.call_args.args[3] is False
    dup.assert_not_called()


def test_reglages_transmis_a_l_analyse():
    rep, _corr, ana, _dup = _post_multi({"bucket_ms": "250", "rtp_clock_rate": "48000", "idle_timeout_seconds": "12.5"})
    assert rep.status_code == 201, rep.text
    kw = ana.call_args.kwargs
    assert kw["bucket_seconds"] == 0.25
    assert kw["rtp_clock_rate"] == 48000
    assert kw["idle_timeout_seconds"] == 12.5
    options = store.get(rep.json()["analysis_id"])["metadata"]["options"]
    assert options["bucket_ms"] == 250 and options["rtp_clock_rate"] == 48000


def test_detect_duplicates_compte_sans_exclure():
    rep, corr, ana, dup = _post_multi({"detect_duplicates": "true", "duplicate_threshold_ms": "0.5"})
    assert rep.status_code == 201, rep.text
    assert dup.call_args.args[1] == 0.5
    assert ana.call_args.kwargs["duplicate_counts"] is not None
    assert ana.call_args.kwargs["exclude_duplicates"] is False
    assert corr.call_args.args[3] is False


def test_exclude_duplicates_implique_la_detection_et_retire_les_copies():
    rep, corr, ana, dup = _post_multi({"exclude_duplicates": "true"})
    assert rep.status_code == 201, rep.text
    dup.assert_called_once()
    assert sum(ana.call_args.kwargs["duplicate_counts"].values()) >= 1
    assert corr.call_args.args[3] is True
    assert ana.call_args.kwargs["exclude_duplicates"] is True
    paquets = corr.call_args.args[0]
    assert not any(p.is_duplicate for p in paquets)


@pytest.mark.parametrize(
    "data",
    [
        {"bucket_ms": "0"},
        {"rtp_clock_rate": "-1"},
        {"idle_timeout_seconds": "0"},
        {"duplicate_threshold_ms": "-0.1"},
    ],
)
def test_valeurs_invalides_refusees(data):
    rep, *_ = _post_multi(data)
    assert rep.status_code == 422, rep.text


def test_route_simple_accepte_les_reglages():
    with (
        patch("netcross_api.app.parse_capture", side_effect=_pkts),
        patch("netcross_api.app.analyse", wraps=netcross_core.analyse) as ana,
    ):
        rep = client.post(
            "/captures?wait=true",
            files={"file": ("a.pcap", PCAP, "application/octet-stream")},
            data={"label": "A", "bucket_ms": "500", "idle_timeout_seconds": "30"},
        )
    assert rep.status_code == 201, rep.text
    assert ana.call_args.kwargs["bucket_seconds"] == 0.5
    assert ana.call_args.kwargs["idle_timeout_seconds"] == 30.0
