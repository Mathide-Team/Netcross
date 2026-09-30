"""
Tests des exports texte, PDF et CSV de l'API (issue #670).

GET /analyses/{id}/text       — rapport texte (équivalent sortie console)
GET /analyses/{id}/pdf        — rapport PDF (équivalent --pdf-report)
GET /analyses/{id}/detail.csv — CSV du détail par flux (équivalent --detail-csv)

Mêmes patterns que tests/test_api.py : mock de parse_capture, paquets
synthétiques via tests.conftest.make_pkt.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tests.conftest import make_pkt

try:
    from fastapi.testclient import TestClient

    from netcross_api.app import app
    from netcross_api.store import store

    client = TestClient(app)
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi non installé (extra [api])")


@pytest.fixture(autouse=True)
def reset_store():
    """Réinitialise le store entre les tests."""
    store._store.clear()
    yield
    store._store.clear()


def _fake_capture_file() -> bytes:
    """Crée un faux pcap (bytes quelconques, le parsing est mocké)."""
    return b"\xd4\xc3\xb2\xa1" + b"\x00" * 100


def _mock_parse_capture(label, path):
    """Mock de parse_capture qui retourne des paquets synthétiques."""
    return [
        make_pkt(src="192.168.1.1", dst="192.168.1.2", dport=80, ts=1000.0),
        make_pkt(src="192.168.1.2", dst="192.168.1.1", dport=50000, ts=1001.0),
    ]


def _upload_analysis() -> str:
    """Upload une analyse mockée et retourne son ID."""
    with patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture):
        response = client.post(
            "/captures?wait=true",
            files={"file": ("test.pcap", _fake_capture_file(), "application/octet-stream")},
            data={"label": "point-A"},
        )
    assert response.status_code == 201, response.text
    return response.json()["analysis_id"]


# --- Text export -----------------------------------------------------------


def test_text_export_success():
    """GET /analyses/{id}/text doit retourner le rapport texte (200, text/plain)."""
    analysis_id = _upload_analysis()
    response = client.get(f"/analyses/{analysis_id}/text")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    # Le rapport texte contient au moins le titre
    assert "ANALYSE" in response.text or "analyse" in response.text.lower()


def test_text_export_not_found():
    """GET /analyses/{id}/text avec un ID inexistant doit retourner 404."""
    response = client.get("/analyses/inexistant12345/text")
    assert response.status_code == 404


def test_text_export_pending():
    """GET /analyses/{id}/text sur une analyse pending doit retourner 409."""
    analysis_id = store.create_pending({"filename": "test.pcap"})
    response = client.get(f"/analyses/{analysis_id}/text")
    assert response.status_code == 409


# --- PDF export ------------------------------------------------------------


def test_pdf_export_success():
    """GET /analyses/{id}/pdf doit retourner un PDF (200, application/pdf)."""
    analysis_id = _upload_analysis()
    response = client.get(f"/analyses/{analysis_id}/pdf")
    assert response.status_code == 200
    assert "application/pdf" in response.headers.get("content-type", "")
    # Un PDF commence par %PDF
    assert response.content[:4] == b"%PDF"
    # Content-Disposition doit suggérer un nom de fichier
    assert "attachment" in response.headers.get("content-disposition", "")


def test_pdf_export_with_topn():
    """GET /analyses/{id}/pdf?topn=10 doit accepter le paramètre."""
    analysis_id = _upload_analysis()
    response = client.get(f"/analyses/{analysis_id}/pdf?topn=10")
    assert response.status_code == 200
    assert response.content[:4] == b"%PDF"


def test_pdf_export_invalid_topn():
    """GET /analyses/{id}/pdf?topn=0 doit retourner 422 (validation)."""
    analysis_id = _upload_analysis()
    response = client.get(f"/analyses/{analysis_id}/pdf?topn=0")
    assert response.status_code == 422


def test_pdf_export_not_found():
    """GET /analyses/{id}/pdf avec un ID inexistant doit retourner 404."""
    response = client.get("/analyses/inexistant12345/pdf")
    assert response.status_code == 404


# --- CSV export ------------------------------------------------------------


def test_csv_export_success():
    """GET /analyses/{id}/detail.csv doit retourner un CSV (200, text/csv)."""
    analysis_id = _upload_analysis()
    response = client.get(f"/analyses/{analysis_id}/detail.csv")
    assert response.status_code == 200
    # Le CSV a un en-tête avec proto, src, dst...
    assert "proto" in response.text
    assert "src" in response.text
    assert "dst" in response.text


def test_csv_export_not_found():
    """GET /analyses/{id}/detail.csv avec un ID inexistant doit retourner 404."""
    response = client.get("/analyses/inexistant12345/detail.csv")
    assert response.status_code == 404


def test_csv_export_pending():
    """GET /analyses/{id}/detail.csv sur une analyse pending doit retourner 409."""
    analysis_id = store.create_pending({"filename": "test.pcap"})
    response = client.get(f"/analyses/{analysis_id}/detail.csv")
    assert response.status_code == 409


# --- Parité avec OpenAPI ---------------------------------------------------


def test_exports_in_openapi_spec():
    """Les routes /text, /pdf et /detail.csv doivent apparaître dans la spec."""
    spec = client.get("/openapi.json").json()
    paths = spec.get("paths", {})
    assert "/analyses/{analysis_id}/text" in paths
    assert "/analyses/{analysis_id}/pdf" in paths
    assert "/analyses/{analysis_id}/detail.csv" in paths
