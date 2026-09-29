"""Issue #675 : API recherche forensique, extraction, comparaison, NetFlow.

Tests des endpoints POST /analyses/{id}/search, /extract, /client-diff, /netflow.
"""

import io
import zipfile

import pytest
from conftest import make_pkt

try:
    import importlib

    from fastapi.testclient import TestClient

    api_module = importlib.import_module("netcross_api.app")
    from netcross_api.app import app
    from netcross_api.store import store
except ImportError:
    pytest.skip("fastapi non installe (extra [api])", allow_module_level=True)

client = TestClient(app)

PAQUETS = {
    "LAN": [
        make_pkt(point="LAN", src="10.0.0.5", dst="10.0.0.1", sport=1),
        make_pkt(point="LAN", src="10.0.0.5", dst="10.0.0.1", sport=2, ts=1000.0),
    ],
    "DC": [
        make_pkt(point="DC", src="10.0.0.5", dst="10.0.0.1", sport=2, ts=1000.004),
    ],
}


@pytest.fixture(autouse=True)
def _setup(monkeypatch):
    store._store.clear()
    monkeypatch.setattr(api_module, "parse_capture", lambda label, path: list(PAQUETS.get(label, [])))
    monkeypatch.setattr(api_module, "scan_capture_exploits", lambda label, path: [])
    yield
    store._store.clear()


def _create_analysis() -> str:
    """Cree une analyse multi-points synchronisée et retourne l'ID."""
    files = [
        ("files", ("lan.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20, "application/octet-stream")),
        ("files", ("dc.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20, "application/octet-stream")),
    ]
    resp = client.post(
        "/captures/multi?wait=true",
        files=files,
        data={"labels": "LAN,DC", "points_order": "LAN,DC"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["analysis_id"]


def test_forensic_search_by_text():
    """POST /analyses/{id}/search : recherche textuelle sur les paquets."""
    analysis_id = _create_analysis()
    resp = client.post(
        f"/analyses/{analysis_id}/search",
        json={"text": "10.0.0.5"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["analysis_id"] == analysis_id
    assert body["total"] >= 1
    result = body["results"][0]
    assert result["kind"] in ("packet", "flow", "event")
    assert "10.0.0.5" in result["snippet"]


def test_forensic_search_by_point():
    """POST /analyses/{id}/search : filtre par point de capture."""
    analysis_id = _create_analysis()
    resp = client.post(
        f"/analyses/{analysis_id}/search",
        json={"point": "LAN"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Au moins les paquets du LAN doivent etre trouves
    assert body["total"] >= 1
    for r in body["results"]:
        if r["point"]:
            assert r["point"] == "LAN"


def test_forensic_search_no_results():
    """POST /analyses/{id}/search : aucun resultat pour un texte absent."""
    analysis_id = _create_analysis()
    resp = client.post(
        f"/analyses/{analysis_id}/search",
        json={"text": "ZZZZNOTFOUND"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["total"] == 0


def test_forensic_search_unknown_field_ignored():
    """Les champs non reconnus du corps JSON sont ignores silencieusement."""
    analysis_id = _create_analysis()
    resp = client.post(
        f"/analyses/{analysis_id}/search",
        json={"text": "10.0.0.5", "unknown_field": "ignored"},
    )
    assert resp.status_code == 200, resp.text


def test_extract_returns_zip():
    """POST /analyses/{id}/extract : retourne une archive ZIP."""
    analysis_id = _create_analysis()
    # Cree un faux pcap
    pcap_data = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20
    resp = client.post(
        f"/analyses/{analysis_id}/extract",
        files=[("files", ("test.pcap", pcap_data, "application/octet-stream"))],
        data={"labels": "test", "kinds": ""},
    )
    assert resp.status_code == 200, resp.text
    assert "application/zip" in resp.headers.get("content-type", "")
    # Verifie que c'est un ZIP valide
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    assert "manifest.json" in zf.namelist()


def test_client_diff_requires_two_groups():
    """POST /analyses/{id}/client-diff : 400 si moins de 2 groupes."""
    analysis_id = _create_analysis()
    resp = client.post(
        f"/analyses/{analysis_id}/client-diff",
        json={"groups": {"PosteA": ["10.0.0.5"]}},
    )
    assert resp.status_code == 400, resp.text


def test_client_diff_invalid_reference():
    """POST /analyses/{id}/client-diff : 400 si reference inconnue."""
    analysis_id = _create_analysis()
    resp = client.post(
        f"/analyses/{analysis_id}/client-diff",
        json={
            "groups": {
                "PosteA": ["10.0.0.5"],
                "PosteB": ["10.0.0.99"],
            },
            "reference": "PosteC",
        },
    )
    assert resp.status_code == 400, resp.text


def test_client_diff_success():
    """POST /analyses/{id}/client-diff : comparaison reussie."""
    analysis_id = _create_analysis()
    resp = client.post(
        f"/analyses/{analysis_id}/client-diff",
        json={
            "groups": {
                "PosteA": ["10.0.0.5"],
                "PosteB": ["10.0.0.99"],
            },
            "reference": "PosteA",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["reference"] == "PosteA"
    assert len(body["clients"]) == 2
    assert "PosteB" in body["diffs"]


def test_netflow_empty_on_invalid_file():
    """POST /analyses/{id}/netflow : fichier invalide -> 0 flux, pas d'erreur."""
    analysis_id = _create_analysis()
    resp = client.post(
        f"/analyses/{analysis_id}/netflow",
        files=[("files", ("bad.netflow", b"not a netflow file", "application/octet-stream"))],
        data={"exporters": "", "top": "5"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["flow_count"] == 0


def test_search_404_unknown_analysis():
    """POST /analyses/{id}/search : 404 si l'analyse n'existe pas."""
    resp = client.post(
        "/analyses/nonexistent/search",
        json={"text": "test"},
    )
    assert resp.status_code == 404, resp.text


def test_extract_404_unknown_analysis():
    """POST /analyses/{id}/extract : 404 si l'analyse n'existe pas."""
    resp = client.post(
        "/analyses/nonexistent/extract",
        files=[("files", ("test.pcap", b"data", "application/octet-stream"))],
        data={"labels": "test", "kinds": ""},
    )
    assert resp.status_code == 404, resp.text


def test_client_diff_404_unknown_analysis():
    """POST /analyses/{id}/client-diff : 404 si l'analyse n'existe pas."""
    resp = client.post(
        "/analyses/nonexistent/client-diff",
        json={"groups": {"A": ["1.1.1.1"], "B": ["2.2.2.2"]}},
    )
    assert resp.status_code == 404, resp.text
