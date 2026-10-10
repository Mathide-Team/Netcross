"""
Issue #330 (écart 2 de docs/parite-surfaces.md) : options d'analyse de
l'API, mêmes noms et même sens que la CLI (nat_tolerant, nat_window_ms,
tls, quic, redact).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tests.conftest import make_pkt

pytest.importorskip("fastapi", reason="extra [api] non installé")
pytest.importorskip("multipart", reason="python-multipart non installé")

from fastapi.testclient import TestClient  # noqa: E402

from netcross_api.app import app  # noqa: E402
from netcross_api.store import store  # noqa: E402

client = TestClient(app)
PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 64


def _pkts(label, _path):
    return [
        make_pkt(point=label, src="192.168.1.1", dst="192.168.1.2", dport=80, ts=1000.0),
        make_pkt(point=label, src="192.168.1.2", dst="192.168.1.1", dport=50000, ts=1001.0),
    ]


@pytest.fixture(autouse=True)
def _store_vide():
    store._store.clear()
    yield
    store._store.clear()


def _post(data, route="/captures"):
    files = (
        {"file": ("a.pcap", PCAP, "application/octet-stream")}
        if route == "/captures"
        else [
            ("files", ("a.pcap", PCAP, "application/octet-stream")),
            ("files", ("b.pcap", PCAP, "application/octet-stream")),
        ]
    )
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        return client.post(f"{route}?wait=true", files=files, data=data)


def test_options_par_defaut_enregistrees():
    rep = _post({"label": "LAN"})
    assert rep.status_code == 201, rep.text
    meta = store.get(rep.json()["analysis_id"])["metadata"]
    assert meta["options"] == {
        "nat_tolerant": False,
        "nat_window_ms": 200.0,
        "tls": False,
        "quic": False,
        "redact": False,
        "max_packets": None,
        "sample_n": None,
        "test_net_external": False,
        "parallel_workers": None,
        "notify": None,
        "known_destinations": None,
        "known_hosts": None,
        "names_path": None,
        "rule_engine": False,
        "expert_section": False,
        "media_quality": False,
        "tshark_stats": False,
        "flow_timeline": False,
        "flow_timeline_window": 1.0,
        "split_interfaces": False,
        # Issue #330 (suite, #841) : réglages d'analyse alignés sur la CLI
        "bucket_ms": 1000.0,
        "rtp_clock_rate": 8000,
        "idle_timeout_seconds": None,
        "detect_duplicates": False,
        "exclude_duplicates": False,
        "duplicate_threshold_ms": 1.0,
        "plugins": (),
    }


def test_nat_tolerant_transmis_a_la_correlation():
    with (
        patch("netcross_api.app.correlate", wraps=__import__("netcross_core").correlate) as corr,
        patch("netcross_api.app.analyse", wraps=__import__("netcross_core").analyse) as ana,
    ):
        rep = _post({"label": "LAN", "nat_tolerant": "true", "nat_window_ms": "500"})
    assert rep.status_code == 201, rep.text
    args = corr.call_args.args
    assert args[1] is True and args[2] == 500.0
    assert ana.call_args.kwargs["nat_tolerant"] is True


def test_nat_window_invalide():
    assert _post({"label": "LAN", "nat_window_ms": "0"}).status_code == 422


@pytest.mark.parametrize("diag", ["tls", "quic"])
def test_redact_incompatible_avec_tls_quic(diag):
    rep = _post({"label": "LAN", "redact": "true", diag: "true"})
    assert rep.status_code == 400
    assert "redact" in rep.json()["detail"]
    assert store.list_ids() == []  # refusé avant toute analyse


def test_redact_anonymise_et_saute_la_securite():
    with patch("netcross_api.app.scan_capture_exploits") as scan:
        rep = _post({"label": "LAN", "redact": "true"})
    assert rep.status_code == 201, rep.text
    scan.assert_not_called()
    analysis_id = rep.json()["analysis_id"]
    doc = client.get(f"/analyses/{analysis_id}/report").json()
    assert doc["security_report"] is None
    assert "redact" in doc["security_report_absent"]
    assert "Anonymisation" in doc["meta"]
    brut = client.get(f"/analyses/{analysis_id}").json()
    assert "192.168.1.1" not in str(brut)


def test_tls_ajoute_la_cle_tls_findings():
    with patch("netcross_core.tls_diagnostics.parse_tls_capture", return_value=[]) as parse:
        rep = _post({"label": "LAN", "tls": "true"})
    assert rep.status_code == 201, rep.text
    parse.assert_called_once()
    doc = client.get(f"/analyses/{rep.json()['analysis_id']}/report").json()
    assert doc["tls_findings"] == []
    assert "quic_findings" not in doc


def test_quic_ajoute_la_cle_quic_findings():
    pytest.importorskip("cryptography")
    with patch("netcross_core.quic_diagnostics.parse_quic_capture", return_value=[]):
        rep = _post({"label": "LAN", "quic": "true"})
    assert rep.status_code == 201, rep.text
    doc = client.get(f"/analyses/{rep.json()['analysis_id']}/report").json()
    assert doc["quic_findings"] == []


def test_options_sur_multi():
    rep = _post({"labels": "LAN,DC", "nat_tolerant": "true", "redact": "true"}, route="/captures/multi")
    assert rep.status_code == 201, rep.text
    opts = store.get(rep.json()["analysis_id"])["metadata"]["options"]
    assert opts["nat_tolerant"] and opts["redact"]
    assert _post({"labels": "LAN,DC", "redact": "true", "tls": "true"}, route="/captures/multi").status_code == 400
