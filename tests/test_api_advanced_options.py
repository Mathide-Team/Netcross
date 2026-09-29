"""
Tests des options d'analyse avancées de l'API (issue #672).

Vérifie que les options max_packets, sample, test_net_external,
known_destinations, known_hosts et names sont acceptées par les routes
POST /captures et POST /captures/multi, et qu'elles modifient le résultat
comme les équivalents CLI.
"""

from __future__ import annotations

import json
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
    store._store.clear()
    yield
    store._store.clear()


def _fake_capture_file() -> bytes:
    return b"\xd4\xc3\xb2\xa1" + b"\x00" * 100


def _mock_parse_capture(label, path):
    return [
        make_pkt(src="192.168.1.1", dst="192.168.1.2", dport=80, ts=1000.0),
        make_pkt(src="192.168.1.2", dst="192.168.1.1", dport=50000, ts=1001.0),
    ]


# --- max_packets ----------------------------------------------------------


def test_max_packets_limits_packet_count():
    """max_packets doit limiter le nombre de paquets analysés."""
    with patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture):
        response = client.post(
            "/captures?wait=true",
            files={"file": ("test.pcap", _fake_capture_file(), "application/octet-stream")},
            data={"label": "point-A", "max_packets": "1"},
        )
    assert response.status_code == 201
    data = response.json()
    assert data["packet_count"] == 1


# --- sample ---------------------------------------------------------------


def test_sample_reduces_packets():
    """sample 1/2 doit garder un paquet sur deux."""
    with patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture):
        response = client.post(
            "/captures?wait=true",
            files={"file": ("test.pcap", _fake_capture_file(), "application/octet-stream")},
            data={"label": "point-A", "sample": "1/2"},
        )
    assert response.status_code == 201
    data = response.json()
    # 2 paquets, échantillonnage 1/2 -> 1 paquet
    assert data["packet_count"] == 1


def test_sample_invalid_format():
    """sample avec un format invalide doit retourner 400."""
    response = client.post(
        "/captures?wait=true",
        files={"file": ("test.pcap", _fake_capture_file(), "application/octet-stream")},
        data={"label": "point-A", "sample": "invalid"},
    )
    assert response.status_code == 400


def test_max_packets_invalid():
    """max_packets <= 0 doit retourner 400."""
    response = client.post(
        "/captures?wait=true",
        files={"file": ("test.pcap", _fake_capture_file(), "application/octet-stream")},
        data={"label": "point-A", "max_packets": "0"},
    )
    assert response.status_code == 400


# --- test_net_external ----------------------------------------------------


def test_test_net_external_accepted():
    """test_net_external doit être accepté sans erreur."""
    with patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture):
        response = client.post(
            "/captures?wait=true",
            files={"file": ("test.pcap", _fake_capture_file(), "application/octet-stream")},
            data={"label": "point-A", "test_net_external": "true"},
        )
    assert response.status_code == 201


# --- known_destinations / known_hosts (fichiers joints) -------------------


def test_known_destinations_file_accepted():
    """known_destinations en fichier joint doit être accepté."""
    hosts_json = json.dumps(["10.0.0.1", "10.0.0.2"]).encode()
    with patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture):
        response = client.post(
            "/captures?wait=true",
            files={
                "file": ("test.pcap", _fake_capture_file(), "application/octet-stream"),
                "known_destinations": ("hosts.json", hosts_json, "application/json"),
            },
            data={"label": "point-A"},
        )
    assert response.status_code == 201


def test_known_hosts_file_accepted():
    """known_hosts en fichier joint doit être accepté."""
    hosts_json = json.dumps(["10.0.0.1"]).encode()
    with patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture):
        response = client.post(
            "/captures?wait=true",
            files={
                "file": ("test.pcap", _fake_capture_file(), "application/octet-stream"),
                "known_hosts": ("known.json", hosts_json, "application/json"),
            },
            data={"label": "point-A"},
        )
    assert response.status_code == 201


def test_names_file_accepted():
    """names en fichier joint doit être accepté."""
    names_json = json.dumps([{"ip": "192.168.1.1", "name": "server"}]).encode()
    with patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture):
        response = client.post(
            "/captures?wait=true",
            files={
                "file": ("test.pcap", _fake_capture_file(), "application/octet-stream"),
                "names": ("names.json", names_json, "application/json"),
            },
            data={"label": "point-A"},
        )
    assert response.status_code == 201


# --- Parité : les nouveaux paramètres sont dans la spec OpenAPI -----------


def test_advanced_options_in_openapi_spec():
    """Les nouveaux paramètres doivent apparaître dans la spec OpenAPI."""
    spec = client.get("/openapi.json").json()
    captures_post = spec["paths"]["/captures"]["post"]
    # Vérifier que les nouveaux paramètres de formulaire existent
    body_schema = (
        captures_post.get("requestBody", {}).get("content", {}).get("multipart/form-data", {}).get("schema", {})
    )
    ref = body_schema.get("$ref", "")
    # Le schema peut être en référence — vérifier les composants
    if ref:
        schema_name = ref.split("/")[-1]
        properties = spec["components"]["schemas"][schema_name].get("properties", {})
    else:
        properties = body_schema.get("properties", {})
    assert "max_packets" in properties
    assert "sample" in properties
    assert "test_net_external" in properties
