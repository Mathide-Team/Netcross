"""Issue #866 (API) : module IA local sur une analyse terminée.

``POST /analyses/{analysis_id}/ai`` est l'équivalent des options ``--ai-*`` :
baseline (enregistrement, anomalies), jeu d'entraînement (export,
classification) et résumé exécutif. Aucun chemin du serveur n'est exposé :
les documents produits sont rendus dans la réponse.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

try:
    from fastapi.testclient import TestClient

    from netcross_api.app import app
except ImportError:
    pytest.skip("fastapi non installe (extra [api])", allow_module_level=True)

from conftest import make_pkt

from netcross_ai.optional import ml_available

client = TestClient(app)
PCAP = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
needs_ml = pytest.mark.skipif(not ml_available(), reason="scikit-learn absent (extra [ai])")


def _paquets():
    # Assez de flux distincts pour les minimums du module IA (20 flux pour
    # une baseline, 10 exemples pour l'entraînement).
    return [
        make_pkt(
            point=point,
            src=f"10.0.0.{1 + i}",
            dst=f"10.0.1.{1 + i % 7}",
            sport=40000 + i,
            dport=443 if i % 3 else 53,
            ts=1000.0 + i * 0.5 + j * 0.01,
        )
        for i in range(30)
        for j in range(3)
        for point in ("LAN", "DC")
    ]


@pytest.fixture(scope="module")
def analysis_id():
    with (
        patch(
            "netcross_api.app.parse_capture",
            side_effect=lambda label, path: [p for p in _paquets() if p.point == label],
        ),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        r = client.post(
            "/captures/multi?wait=true",
            files=[
                ("files", ("lan.pcap", PCAP, "application/octet-stream")),
                ("files", ("dc.pcap", PCAP, "application/octet-stream")),
            ],
            data={"labels": "LAN,DC"},
        )
    assert r.status_code == 201, r.text
    return r.json()["analysis_id"]


def _ai(analysis_id, data=None, files=None):
    return client.post(f"/analyses/{analysis_id}/ai", data=data or {}, files=files or {})


def _json_file(name, doc):
    return (name, json.dumps(doc).encode(), "application/json")


def test_aucun_usage_400(analysis_id):
    r = _ai(analysis_id)
    assert r.status_code == 400
    assert "aucun usage" in r.json()["detail"]


@pytest.mark.parametrize(
    ("data", "attendu"),
    [
        ({"summary": "template", "baseline_label": "x"}, "baseline_label"),
        ({"endpoint": "http://127.0.0.1:11434", "training_export": "true"}, "endpoint"),
        ({"summary": "inconnu"}, "moteur inconnu"),
        ({"summary": "ollama:llama3", "endpoint": "http://203.0.113.5:11434"}, "Module IA"),
    ],
)
def test_validations_comme_la_cli(analysis_id, data, attendu):
    r = _ai(analysis_id, data)
    assert r.status_code == 400, r.text
    assert attendu in r.json()["detail"]


def test_baseline_base_sans_baseline_save_400(analysis_id):
    r = _ai(analysis_id, {"summary": "template"}, {"baseline_base": _json_file("b.json", {})})
    assert r.status_code == 400
    assert "baseline_base" in r.json()["detail"]


def test_analyse_inconnue_404():
    assert _ai("inexistante", {"summary": "template"}).status_code == 404


def test_baseline_save_rendue_sans_chemin(analysis_id):
    r = _ai(analysis_id, {"baseline_save": "true", "baseline_label": "bureau"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["analysis_id"] == analysis_id
    assert data["baseline_saved"]["flows"] == data["flows"] > 0
    assert "path" not in data["baseline_saved"]
    assert data["baseline_document"]["label"] == "bureau"
    assert "/tmp" not in json.dumps(data)


def test_baseline_save_enrichit_baseline_base(analysis_id):
    first = _ai(analysis_id, {"baseline_save": "true"}).json()
    r = _ai(analysis_id, {"baseline_save": "true"}, {"baseline_base": _json_file("b.json", first["baseline_document"])})
    assert r.status_code == 200, r.text
    assert r.json()["baseline_saved"]["flows"] == 2 * first["baseline_saved"]["flows"]


def test_baseline_base_invalide_400(analysis_id):
    r = _ai(analysis_id, {"baseline_save": "true"}, {"baseline_base": ("b.json", b"pas du json", "application/json")})
    assert r.status_code == 400
    assert "Module IA" in r.json()["detail"]


def test_training_export_et_resume_template(analysis_id):
    r = _ai(analysis_id, {"training_export": "true", "summary": "template"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["training_exported"] == {"samples": data["flows"]}
    assert len(data["training_document"]["samples"]) == data["flows"]
    assert data["summary"]["engine"] == "template"
    assert data["summary"]["text"]


@needs_ml
def test_anomalies_contre_une_baseline(analysis_id):
    doc = _ai(analysis_id, {"baseline_save": "true", "baseline_label": "ref"}).json()["baseline_document"]
    r = _ai(analysis_id, files={"baseline": _json_file("base.json", doc)})
    assert r.status_code == 200, r.text
    data = r.json()
    assert len(data["anomalies"]) == data["flows"]
    assert data["baseline"] == {"flows": len(doc["vectors"]), "label": "ref"}


@needs_ml
def test_classification_sur_jeu_d_entrainement(analysis_id):
    doc = _ai(analysis_id, {"training_export": "true"}).json()["training_document"]
    # Deux étiquettes au moins pour entraîner la forêt.
    for i, sample in enumerate(doc["samples"]):
        sample["label"] = "normal" if i % 2 else "scan"
    r = _ai(analysis_id, files={"training": _json_file("t.json", doc)})
    assert r.status_code == 200, r.text
    data = r.json()
    assert len(data["classification"]) == data["flows"]
    assert set(data["training"]) == {"labels"}


def test_sans_scikit_learn_503(analysis_id):
    with patch("netcross_ai.optional.ml_available", return_value=False):
        r = _ai(analysis_id, files={"baseline": _json_file("b.json", {})})
    assert r.status_code == 503
    assert "scikit-learn" in r.json()["detail"]


def test_openapi_expose_la_route():
    spec = client.get("/openapi.json").json()
    assert "post" in spec["paths"]["/analyses/{analysis_id}/ai"]
