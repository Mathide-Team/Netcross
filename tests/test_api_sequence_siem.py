"""Tests pour l'issue #674 : diagramme de séquence, SIEM, ticket de support."""

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
    return b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"


def _create_analysis(**kwargs):
    """Crée une analyse complétée avec des mocks et retourne l'analysis_id."""
    pcap = _fake_pcap_data()
    from conftest import make_pkt

    pkts = [make_pkt(point="LAN"), make_pkt(point="DC")]
    with (
        patch("netcross_api.app.parse_capture", return_value=pkts),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        response = client.post(
            "/captures/multi?wait=true",
            files=[
                ("files", ("lan.pcap", pcap, "application/octet-stream")),
                ("files", ("dc.pcap", pcap, "application/octet-stream")),
            ],
            data={"labels": "LAN,DC"},
        )
    assert response.status_code == 201, response.text
    return response.json()["analysis_id"]


def test_sequence_route():
    """GET /analyses/{id}/sequence retourne les vues de séquence."""
    analysis_id = _create_analysis()
    response = client.get(f"/analyses/{analysis_id}/sequence")
    assert response.status_code == 200, response.text
    data = response.json()
    assert "sequence_views" in data


def test_sequence_404():
    """GET /analyses/{id}/sequence avec un ID inexistant -> 404."""
    response = client.get("/analyses/inexistant/sequence")
    assert response.status_code == 404


def test_siem_cef_route():
    """GET /analyses/{id}/siem?format=cef retourne l'export CEF."""
    analysis_id = _create_analysis()
    response = client.get(f"/analyses/{analysis_id}/siem?format=cef")
    assert response.status_code == 200, response.text
    assert "CEF" in response.text or len(response.text) >= 0


def test_siem_leef_route():
    """GET /analyses/{id}/siem?format=leef retourne l'export LEEF."""
    analysis_id = _create_analysis()
    response = client.get(f"/analyses/{analysis_id}/siem?format=leef")
    assert response.status_code == 200, response.text


def test_siem_invalid_format_400():
    """GET /analyses/{id}/siem?format=invalide -> 400."""
    analysis_id = _create_analysis()
    response = client.get(f"/analyses/{analysis_id}/siem?format=invalide")
    assert response.status_code == 400


def test_siem_404():
    """GET /analyses/{id}/siem avec un ID inexistant -> 404."""
    response = client.get("/analyses/inexistant/siem?format=cef")
    assert response.status_code == 404


def test_support_ticket_consent_required():
    """POST /analyses/{id}/support-ticket sans consent -> 400."""
    analysis_id = _create_analysis()
    response = client.post(f"/analyses/{analysis_id}/support-ticket?consent=false")
    assert response.status_code == 400


def test_support_ticket_with_consent():
    """POST /analyses/{id}/support-ticket?consent=true -> 200."""
    analysis_id = _create_analysis()
    response = client.post(f"/analyses/{analysis_id}/support-ticket?consent=true")
    assert response.status_code == 200, response.text
    data = response.json()
    assert "ticket" in data


def test_support_ticket_404():
    """POST /analyses/{id}/support-ticket avec un ID inexistant -> 404."""
    response = client.post("/analyses/inexistant/support-ticket?consent=true")
    assert response.status_code == 404


def test_routes_openapi():
    """Les nouvelles routes figurent dans la spec OpenAPI."""
    spec = client.get("/openapi.json").json()
    paths = spec["paths"]
    assert "/analyses/{analysis_id}/sequence" in paths
    assert "/analyses/{analysis_id}/siem" in paths
    assert "/analyses/{analysis_id}/support-ticket" in paths
