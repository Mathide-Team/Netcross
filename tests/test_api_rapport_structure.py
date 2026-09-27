"""
Issue #330 (écart 1 de docs/parite-surfaces.md) : l'API sert le même
rapport structuré que ``netcross --json-report`` et l'export JSON de la GUI.

``GET /analyses/{id}/report`` expose constats, triage et score de santé ;
``GET /analyses/{id}`` reste la copie brute des mesures (compatibilité).
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from tests.conftest import make_pkt

pytest.importorskip("fastapi", reason="extra [api] non installé")
pytest.importorskip("multipart", reason="python-multipart non installé")

from fastapi.testclient import TestClient  # noqa: E402

from netcross_api.app import app  # noqa: E402
from netcross_api.store import AnalysesStore, store  # noqa: E402
from netcross_core import analyse, correlate  # noqa: E402
from netcross_core.security.findings import apply_security_findings  # noqa: E402
from netcross_report import build_findings, build_json_report_document, build_security_report  # noqa: E402

client = TestClient(app)

CLES_CLI = {"findings", "triage", "health_score", "health_label", "security_report", "meta", "title", "generated_at"}


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


def _analyser(label="LAN"):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post(
            "/captures?wait=true",
            files={"file": ("a.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 64, "application/octet-stream")},
            data={"label": label},
        )
    assert rep.status_code == 201, rep.text
    return rep.json()["analysis_id"]


def test_report_porte_les_cles_de_la_cli():
    analysis_id = _analyser()
    rep = client.get(f"/analyses/{analysis_id}/report")
    assert rep.status_code == 200
    doc = rep.json()
    assert set(doc) >= CLES_CLI
    assert doc["_analysis_id"] == analysis_id
    assert isinstance(doc["health_score"], (int, float))
    # l'API calcule toujours la sécurité : jamais « non demandé »
    assert doc["security_report"] is not None
    assert "security_report_absent" not in doc


def test_report_identique_au_document_de_la_cli():
    """Mêmes paquets -> mêmes clés et mêmes constats que --json-report."""
    analysis_id = _analyser()
    api_doc = client.get(f"/analyses/{analysis_id}/report").json()

    pkts = _pkts("LAN", None)
    report = analyse(correlate(pkts), points_order=["LAN"], all_packets=pkts)
    apply_security_findings(report, pkts, detections=[])
    cli_doc = build_json_report_document(
        report, findings=build_findings(report), security_report=build_security_report(report)
    )
    assert set(api_doc) - {"_analysis_id"} == set(cli_doc)
    for cle in ("findings", "triage", "health_score", "health_label", "points"):
        assert api_doc[cle] == json.loads(json.dumps(cli_doc[cle])), cle


def test_document_brut_inchange():
    """GET /analyses/{id} garde son format (dump brut du Report)."""
    analysis_id = _analyser()
    doc = client.get(f"/analyses/{analysis_id}").json()
    assert "triage" not in doc
    assert "points" in doc


def test_report_404_et_409():
    assert client.get("/analyses/inconnue/report").status_code == 404
    analysis_id = store.create_pending({})
    assert client.get(f"/analyses/{analysis_id}/report").status_code == 409


def test_report_absent_analyse_anterieure():
    analysis_id = store.create_pending({})
    store.complete(analysis_id, {"points": ["A"]}, {"point_count": 1})  # sans rapport
    rep = client.get(f"/analyses/{analysis_id}/report")
    assert rep.status_code == 409
    assert "relancer" in rep.json()["detail"]


def test_rapport_persiste_en_sqlite(tmp_path):
    db = str(tmp_path / "api.db")
    premier = AnalysesStore(db_path=db)
    analysis_id = premier.create_pending({})
    premier.complete(analysis_id, {"points": ["A"]}, {"point_count": 1}, report={"triage": [], "health_score": 100})
    relu = AnalysesStore(db_path=db).get(analysis_id)
    assert relu["report"] == {"triage": [], "health_score": 100}


def test_generate_json_report_ecrit_le_meme_document(tmp_path):
    pkts = _pkts("LAN", None)
    report = analyse(correlate(pkts), points_order=["LAN"], all_packets=pkts)
    from netcross_report import generate_json_report

    chemin = tmp_path / "r.json"
    generate_json_report(report, str(chemin), meta={"Ticket": "X"})
    ecrit = json.loads(chemin.read_text(encoding="utf-8"))
    attendu = build_json_report_document(report, meta={"Ticket": "X"})
    ecrit.pop("generated_at")
    attendu.pop("generated_at")
    assert ecrit == json.loads(json.dumps(attendu))
