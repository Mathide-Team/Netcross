"""Issue #670 : exports texte, CSV du détail et PDF de l'API REST, produits
en fin d'analyse et relus tels quels après un redémarrage."""

from __future__ import annotations

import importlib
from unittest.mock import patch

import pytest

from tests.conftest import make_pkt

pytest.importorskip("fastapi", reason="extra [api] non installé")
pytest.importorskip("multipart", reason="python-multipart non installé")

from fastapi.testclient import TestClient  # noqa: E402

from netcross_api.app import app  # noqa: E402
from netcross_api.store import AnalysesStore, store  # noqa: E402

api_module = importlib.import_module("netcross_api.app")
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
    with patch("netcross_api.app.scan_capture_exploits", return_value=[]):
        yield
    store._store.clear()


def _post(data=None, route="/captures"):
    files = (
        {"file": ("a.pcap", PCAP, "application/octet-stream")}
        if route == "/captures"
        else [
            ("files", ("a.pcap", PCAP, "application/octet-stream")),
            ("files", ("b.pcap", PCAP, "application/octet-stream")),
        ]
    )
    data = data or ({"label": "LAN"} if route == "/captures" else {"labels": "LAN,DC"})
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post(f"{route}?wait=true", files=files, data=data)
    assert rep.status_code == 201, rep.text
    return rep.json()["analysis_id"]


def test_texte_identique_a_la_sortie_standard():
    analysis_id = _post()
    rep = client.get(f"/analyses/{analysis_id}/text")
    assert rep.status_code == 200
    assert rep.headers["content-type"].startswith("text/plain")
    assert "-- Paquets/flux identifies par point --" in rep.text
    assert "TRIAGE -- PAR OU COMMENCER" in rep.text
    assert "Score de sante" in rep.text


def test_texte_multi_points():
    analysis_id = _post(route="/captures/multi")
    rep = client.get(f"/analyses/{analysis_id}/text")
    assert rep.status_code == 200
    assert "Capture unique" not in rep.text


def test_detail_csv_une_ligne_par_flux():
    analysis_id = _post()
    rep = client.get(f"/analyses/{analysis_id}/detail.csv")
    assert rep.status_code == 200
    assert rep.headers["content-type"].startswith("text/csv")
    assert f"netcross-{analysis_id}-detail.csv" in rep.headers["content-disposition"]
    lignes = rep.text.strip().splitlines()
    assert len(lignes) >= 2  # en-tête + au moins un flux
    assert "192.168.1.1" in rep.text


def test_detail_csv_anonymise_avec_redact():
    analysis_id = _post({"label": "LAN", "redact": "true"})
    rep = client.get(f"/analyses/{analysis_id}/detail.csv")
    assert rep.status_code == 200
    assert "192.168.1.1" not in rep.text


def test_pdf_non_demande_409():
    analysis_id = _post()
    rep = client.get(f"/analyses/{analysis_id}/pdf")
    assert rep.status_code == 409
    assert "pdf=true" in rep.json()["detail"]


def test_pdf_produit_avec_pdf_true():
    pytest.importorskip("reportlab")
    pytest.importorskip("matplotlib")
    pytest.importorskip("networkx")
    analysis_id = _post({"label": "LAN", "pdf": "true", "topn_charts": "3"})
    rep = client.get(f"/analyses/{analysis_id}/pdf")
    assert rep.status_code == 200
    assert rep.headers["content-type"] == "application/pdf"
    assert rep.content.startswith(b"%PDF")
    assert store.get(analysis_id)["metadata"]["options"]["topn_charts"] == 3


def test_pdf_dependances_absentes_echec_explicite():
    from netcross_api.exports import PdfUnavailableError

    with (
        patch("netcross_api.app.pdf_report", side_effect=PdfUnavailableError("pdf nécessite reportlab")),
        patch("netcross_api.app.parse_capture", side_effect=_pkts),
    ):
        rep = client.post(
            "/captures?wait=true",
            files={"file": ("a.pcap", PCAP, "application/octet-stream")},
            data={"label": "LAN", "pdf": "true"},
        )
    assert rep.status_code == 400
    assert "reportlab" in rep.json()["detail"]


def test_topn_charts_borne():
    rep = client.post(
        "/captures?wait=true",
        files={"file": ("a.pcap", PCAP, "application/octet-stream")},
        data={"label": "LAN", "topn_charts": "0"},
    )
    assert rep.status_code == 422


@pytest.mark.parametrize("route", ["text", "detail.csv", "pdf"])
def test_analyse_inconnue_404(route):
    assert client.get(f"/analyses/inconnue/{route}").status_code == 404


def test_export_absent_d_une_ancienne_analyse_409():
    analysis_id = store.create_pending()
    store.complete(analysis_id, {"points": ["LAN"]}, {"point_count": 1})
    rep = client.get(f"/analyses/{analysis_id}/text")
    assert rep.status_code == 409
    assert "relancer" in rep.json()["detail"]


def test_exports_relus_apres_redemarrage(monkeypatch, tmp_path):
    db = str(tmp_path / "api.db")
    monkeypatch.setattr(api_module, "store", AnalysesStore(db_path=db))
    analysis_id = _post()
    texte = client.get(f"/analyses/{analysis_id}/text").text
    csv = client.get(f"/analyses/{analysis_id}/detail.csv").text

    monkeypatch.setattr(api_module, "store", AnalysesStore(db_path=db))  # « redémarrage »
    assert client.get(f"/analyses/{analysis_id}/text").text == texte
    assert client.get(f"/analyses/{analysis_id}/detail.csv").text == csv
    assert client.get(f"/analyses/{analysis_id}/pdf").status_code == 409


def test_pdf_relu_apres_redemarrage(monkeypatch, tmp_path):
    db = str(tmp_path / "api.db")
    monkeypatch.setattr(api_module, "store", AnalysesStore(db_path=db))
    with patch("netcross_api.app.pdf_report", return_value=b"%PDF-1.4 factice"):
        analysis_id = _post({"label": "LAN", "pdf": "true"})
    monkeypatch.setattr(api_module, "store", AnalysesStore(db_path=db))
    rep = client.get(f"/analyses/{analysis_id}/pdf")
    assert rep.status_code == 200
    assert rep.content == b"%PDF-1.4 factice"
