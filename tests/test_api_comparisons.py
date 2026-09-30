"""
Tests des routes de comparaison baseline/courant de l'API (issue #669).

POST /comparisons          — upload baseline + current, diff
GET  /comparisons/{id}      — écarts, triage, score de santé
GET  /comparisons/{id}/csv  — CSV des écarts
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tests.conftest import make_pkt

try:
    from fastapi.testclient import TestClient

    from netcross_api.app import _comparisons, app

    client = TestClient(app)
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi non installé (extra [api])")


@pytest.fixture(autouse=True)
def reset_comparisons():
    _comparisons.clear()
    yield
    _comparisons.clear()


def _fake_capture_file() -> bytes:
    return b"\xd4\xc3\xb2\xa1" + b"\x00" * 100


def _mock_parse_capture(label, path):
    return [
        make_pkt(src="192.168.1.1", dst="192.168.1.2", dport=80, ts=1000.0),
        make_pkt(src="192.168.1.2", dst="192.168.1.1", dport=50000, ts=1001.0),
    ]


def _upload_comparison(wait: bool = True) -> str:
    """Upload une comparaison baseline + courant et retourne son ID."""
    with (
        patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        response = client.post(
            "/comparisons?wait=true" if wait else "/comparisons",
            files=[
                ("baseline_files", ("base.pcap", _fake_capture_file(), "application/octet-stream")),
                ("current_files", ("curr.pcap", _fake_capture_file(), "application/octet-stream")),
            ],
            data={
                "baseline_labels": "point-A",
                "current_labels": "point-A",
            },
        )
    assert response.status_code == 201, response.text
    # L'ID est dans l'en-tête Location: /comparisons/{id}
    location = response.headers.get("location", "")
    return location.split("/")[-1] if location else "unknown"


def test_create_comparison_success():
    """POST /comparisons doit retourner 201 avec le résultat."""
    with (
        patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        response = client.post(
            "/comparisons?wait=true",
            files=[
                ("baseline_files", ("base.pcap", _fake_capture_file(), "application/octet-stream")),
                ("current_files", ("curr.pcap", _fake_capture_file(), "application/octet-stream")),
            ],
            data={"baseline_labels": "point-A", "current_labels": "point-A"},
        )
    assert response.status_code == 201
    data = response.json()
    assert "findings" in data
    assert "health_score" in data
    assert "regression" in data
    assert "triage" in data


def test_create_comparison_accepted_pending():
    """POST /comparisons sans wait doit retourner 202."""
    with (
        patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        response = client.post(
            "/comparisons",
            files=[
                ("baseline_files", ("base.pcap", _fake_capture_file(), "application/octet-stream")),
                ("current_files", ("curr.pcap", _fake_capture_file(), "application/octet-stream")),
            ],
            data={"baseline_labels": "point-A", "current_labels": "point-A"},
        )
    assert response.status_code == 202
    assert "analysis_id" in response.json()
    assert response.json()["status"] == "pending"


def test_create_comparison_missing_files():
    """POST /comparisons sans fichiers doit retourner 400."""
    response = client.post(
        "/comparisons?wait=true",
        files=[],
        data={"baseline_labels": "point-A", "current_labels": "point-A"},
    )
    # FastAPI retourne 422 pour les champs requis manquants
    assert response.status_code in (400, 422)


def test_get_comparison_success():
    """GET /comparisons/{id} doit retourner le résultat."""
    comparison_id = _upload_comparison()
    response = client.get(f"/comparisons/{comparison_id}")
    assert response.status_code == 200
    data = response.json()
    assert "findings" in data
    assert "health_score" in data


def test_get_comparison_not_found():
    """GET /comparisons/{id} avec un ID inexistant doit retourner 404."""
    response = client.get("/comparisons/inexistant12345")
    assert response.status_code == 404


def test_get_comparison_csv():
    """GET /comparisons/{id}/csv doit retourner un CSV."""
    comparison_id = _upload_comparison()
    response = client.get(f"/comparisons/{comparison_id}/csv")
    assert response.status_code == 200
    # Le CSV a un en-tête
    assert "severity" in response.text
    assert "category" in response.text


def test_get_comparison_csv_not_found():
    """GET /comparisons/{id}/csv avec un ID inexistant doit retourner 404."""
    response = client.get("/comparisons/inexistant12345/csv")
    assert response.status_code == 404


def test_comparisons_in_openapi_spec():
    """Les routes /comparisons doivent apparaître dans la spec OpenAPI."""
    spec = client.get("/openapi.json").json()
    paths = spec.get("paths", {})
    assert "/comparisons" in paths
    assert "/comparisons/{comparison_id}" in paths
    assert "/comparisons/{comparison_id}/csv" in paths
