"""Tests pour l'issue #671 : plusieurs fichiers par point et split_interfaces."""

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


def _fake_capture_file(name: str = "test.pcap") -> tuple[bytes, str, str]:
    """Retourne un tuple (content, filename, content_type) pour un faux pcap."""
    return (b"\xd4\xc3\xb2\xa1" + b"\x00" * 40, name, "application/octet-stream")


def _fake_pcap_data() -> bytes:
    """Contenu pcap minimal valide (en-tête global + 1 paquet)."""
    # Global header: magic + version 2.4 + thiszone + sigfigs + snaplen + linktype
    return b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"


def test_extra_files_rotation():
    """POST /captures avec extra_files : fichiers multiples concaténés pour le même point."""
    pcap = _fake_pcap_data()
    with (
        patch("netcross_api.app.parse_capture", return_value=[]),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        # parse_capture retourne [] -> AnalysisError "Aucun paquet trouvé"
        # On mock pour retourner des paquets
        from conftest import make_pkt

        pkts = [make_pkt(point="LAN"), make_pkt(point="LAN")]
        with patch("netcross_api.app.parse_capture", return_value=pkts):
            response = client.post(
                "/captures?wait=true",
                files=[
                    ("file", ("base.pcap", pcap, "application/octet-stream")),
                    ("extra_files", ("rot1.pcap", pcap, "application/octet-stream")),
                    ("extra_files", ("rot2.pcap", pcap, "application/octet-stream")),
                ],
                data={"label": "LAN"},
            )
    assert response.status_code == 201, response.text
    body = response.json()
    assert "analysis_id" in body


def test_extra_files_empty_filename_400():
    """extra_files avec un nom de fichier vide -> 400."""
    pcap = _fake_pcap_data()
    response = client.post(
        "/captures?wait=true",
        files=[
            ("file", ("base.pcap", pcap, "application/octet-stream")),
            ("extra_files", ("", pcap, "application/octet-stream")),
        ],
        data={"label": "LAN"},
    )
    assert response.status_code in (400, 422)


def test_split_interfaces_parametre_present():
    """Le paramètre split_interfaces est accepté sur POST /captures."""
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
            data={"label": "LAN", "split_interfaces": "true"},
        )
    assert response.status_code == 201, response.text


def test_split_interfaces_multi_capture():
    """split_interfaces sur POST /captures/multi est accepté."""
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
            data={"labels": "LAN,DC", "split_interfaces": "true"},
        )
    assert response.status_code == 201, response.text


def test_labels_dupliquees_autorisees():
    """POST /captures/multi avec labels dupliquées (rotation) -> 201."""
    pcap = _fake_pcap_data()
    from conftest import make_pkt

    pkts = [make_pkt(point="LAN"), make_pkt(point="LAN")]
    with (
        patch("netcross_api.app.parse_capture", return_value=pkts),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        response = client.post(
            "/captures/multi?wait=true",
            files=[
                ("files", ("a.pcap", pcap, "application/octet-stream")),
                ("files", ("b.pcap", pcap, "application/octet-stream")),
            ],
            data={"labels": "LAN,LAN"},
        )
    assert response.status_code == 201, response.text


def test_split_interfaces_option_enregistree():
    """L'option split_interfaces est enregistrée dans les métadonnées."""
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
            data={"label": "LAN", "split_interfaces": "true"},
        )
    assert response.status_code == 201
    from netcross_api.store import store

    entry = store.get(response.json()["analysis_id"])
    assert entry is not None
    assert entry["metadata"]["options"]["split_interfaces"] is True


def test_routes_split_interfaces_openapi():
    """Les paramètres extra_files et split_interfaces figurent dans la spec OpenAPI."""
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
    assert "split_interfaces" in properties
    assert "extra_files" in properties

    multi_post = spec["paths"]["/captures/multi"]["post"]
    multi_schema = multi_post.get("requestBody", {}).get("content", {}).get("multipart/form-data", {}).get("schema", {})
    multi_ref = multi_schema.get("$ref", "")
    if multi_ref:
        multi_name = multi_ref.split("/")[-1]
        multi_props = spec["components"]["schemas"][multi_name].get("properties", {})
    else:
        multi_props = multi_schema.get("properties", {})
    assert "split_interfaces" in multi_props
