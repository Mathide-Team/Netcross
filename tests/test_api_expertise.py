"""Tests pour l'issue #673 : sections d'expertise dans l'API."""

from __future__ import annotations

from unittest.mock import patch

import pytest

try:
    from fastapi.testclient import TestClient

    from netcross_api.app import app

    client = TestClient(app)
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    pytest.skip("fastapi non installe (extra [api])", allow_module_level=True)


def _fake_pcap_data() -> bytes:
    """Contenu pcap minimal valide (en-tête global + 1 paquet)."""
    return b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"


def test_rule_engine_option():
    """rule_engine=true ajoute rule_engine_findings au rapport structuré."""
    pcap = _fake_pcap_data()
    from conftest import make_pkt

    pkts = [make_pkt(point="LAN")]
    with (
        patch("netcross_api.app.parse_capture", return_value=pkts),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        response = client.post(
            "/captures?wait=true",
            files=[("file", ("test.pcap", pcap, "application/octet-stream"))],
            data={"label": "LAN", "rule_engine": "true"},
        )
    assert response.status_code == 201, response.text
    from netcross_api.store import store

    entry = store.get(response.json()["analysis_id"])
    assert entry is not None
    assert "rule_engine" in entry["report"]


def test_expert_section_option():
    """expert_section=true ajoute session_objects au rapport structuré."""
    pcap = _fake_pcap_data()
    from conftest import make_pkt

    pkts = [make_pkt(point="LAN")]
    with (
        patch("netcross_api.app.parse_capture", return_value=pkts),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        response = client.post(
            "/captures?wait=true",
            files=[("file", ("test.pcap", pcap, "application/octet-stream"))],
            data={"label": "LAN", "expert_section": "true"},
        )
    assert response.status_code == 201, response.text
    from netcross_api.store import store

    entry = store.get(response.json()["analysis_id"])
    assert entry is not None
    assert "session_objects" in entry["report"]


def test_flow_timeline_option():
    """flow_timeline=true ajoute flow_timelines au rapport structuré."""
    pcap = _fake_pcap_data()
    from conftest import make_pkt

    pkts = [make_pkt(point="LAN")]
    with (
        patch("netcross_api.app.parse_capture", return_value=pkts),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        response = client.post(
            "/captures?wait=true",
            files=[("file", ("test.pcap", pcap, "application/octet-stream"))],
            data={"label": "LAN", "flow_timeline": "true", "flow_timeline_window": "2.0"},
        )
    assert response.status_code == 201, response.text
    from netcross_api.store import store

    entry = store.get(response.json()["analysis_id"])
    assert entry is not None
    assert "flow_timelines" in entry["report"]


def test_options_enregistrees_dans_metadata():
    """Les options d'expertise sont enregistrées dans les métadonnées."""
    pcap = _fake_pcap_data()
    from conftest import make_pkt

    pkts = [make_pkt(point="LAN")]
    with (
        patch("netcross_api.app.parse_capture", return_value=pkts),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        response = client.post(
            "/captures?wait=true",
            files=[("file", ("test.pcap", pcap, "application/octet-stream"))],
            data={
                "label": "LAN",
                "rule_engine": "true",
                "expert_section": "true",
                "flow_timeline": "true",
            },
        )
    assert response.status_code == 201
    from netcross_api.store import store

    entry = store.get(response.json()["analysis_id"])
    assert entry is not None
    opts = entry["metadata"]["options"]
    assert opts["rule_engine"] is True
    assert opts["expert_section"] is True
    assert opts["flow_timeline"] is True


def test_sections_absentes_sans_option():
    """Sans les options d'expertise, les sections sont absentes du rapport."""
    pcap = _fake_pcap_data()
    from conftest import make_pkt

    pkts = [make_pkt(point="LAN")]
    with (
        patch("netcross_api.app.parse_capture", return_value=pkts),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        response = client.post(
            "/captures?wait=true",
            files=[("file", ("test.pcap", pcap, "application/octet-stream"))],
            data={"label": "LAN"},
        )
    assert response.status_code == 201
    from netcross_api.store import store

    entry = store.get(response.json()["analysis_id"])
    assert entry is not None
    assert "rule_engine" not in entry["report"]
    assert "session_objects" not in entry["report"]
    assert "flow_timelines" not in entry["report"]


def test_params_expertise_openapi():
    """Les paramètres d'expertise figurent dans la spec OpenAPI."""
    spec = client.get("/openapi.json").json()
    captures_post = spec["paths"]["/captures"]["post"]
    body_schema = (
        captures_post.get("requestBody", {}).get("content", {}).get("multipart/form-data", {}).get("schema", {})
    )
    ref = body_schema.get("$ref", "")
    if ref:
        schema_name = ref.split("/")[-1]
        properties = spec["components"]["schemas"][schema_name].get("properties", {})
    else:
        properties = body_schema.get("properties", {})
    assert "rule_engine" in properties
    assert "expert_section" in properties
    assert "flow_timeline" in properties
    assert "tshark_stats" in properties
    assert "media_quality" in properties
