"""Issue #672 (API) : parallel_workers, base CVE NETCROSS_CVE_DB, et note de
troncature de max_packets/sample comme la CLI."""

from __future__ import annotations

import importlib
from unittest.mock import patch

import pytest

from tests.conftest import make_pkt

pytest.importorskip("fastapi", reason="extra [api] non installé")
pytest.importorskip("multipart", reason="python-multipart non installé")

from fastapi.testclient import TestClient  # noqa: E402

from netcross_api.app import AnalysisError, _open_cve_db, _read_captures, app  # noqa: E402
from netcross_api.store import store  # noqa: E402

api_module = importlib.import_module("netcross_api.app")

client = TestClient(app)
PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 64


def _pkts(label, _path):
    return [make_pkt(point=label, src="192.168.1.1", dst="192.168.1.2", dport=80, ts=1000.0 + i) for i in range(6)]


@pytest.fixture(autouse=True)
def _store_vide():
    store._store.clear()
    yield
    store._store.clear()


def _post(data):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        return client.post(
            "/captures?wait=true", files={"file": ("a.pcap", PCAP, "application/octet-stream")}, data=data
        )


def test_troncature_annoncee():
    rep = _post({"label": "LAN", "max_packets": "2"})
    assert rep.status_code == 201, rep.text
    report = store.get(rep.json()["analysis_id"])["report_obj"]
    assert report.truncated
    assert "limitee aux 2 premiers paquets sur 6" in report.truncation_note


@pytest.mark.parametrize("valeur", ["0", "65"])
def test_parallel_workers_borne(valeur):
    rep = _post({"label": "LAN", "parallel_workers": valeur})
    assert rep.status_code == 400
    assert "parallel_workers doit etre entre 1 et 64" in rep.text


def test_parallel_workers_transmis(monkeypatch):
    import pcap_parser.capture as capture

    vus = []

    def faux(captures, max_workers=None):
        vus.append(max_workers)
        pkts = [p for label, path in captures for p in _pkts(label, path)]
        return pkts, [{"label": label, "path": path, "count": 6, "error": None} for label, path in captures]

    monkeypatch.setattr(capture, "parse_captures_parallel", faux)
    rep = _post({"label": "LAN", "parallel_workers": "3"})
    assert rep.status_code == 201, rep.text
    assert vus == [3]
    assert store.get(rep.json()["analysis_id"])["metadata"]["options"]["parallel_workers"] == 3


def test_lecture_parallele_memes_erreurs(monkeypatch):
    import pcap_parser.capture as capture

    stats = [{"label": "A", "path": "a", "count": 0, "error": "tshark absent"}]
    monkeypatch.setattr(capture, "parse_captures_parallel", lambda caps, max_workers=None: ([], stats))
    with pytest.raises(AnalysisError, match="Erreur de parsing pour A: tshark absent"):
        _read_captures([("A", "a")], 2)
    stats[0]["error"] = None
    with pytest.raises(AnalysisError, match="Aucun paquet"):
        _read_captures([("A", "a")], 2)


def test_base_cve(monkeypatch, tmp_path):
    monkeypatch.delenv("NETCROSS_CVE_DB", raising=False)
    conn = _open_cve_db()  # base embarquee, comme la CLI sans --cve-db
    assert conn is not None
    conn.close()
    monkeypatch.setenv("NETCROSS_CVE_DB", str(tmp_path / "absente.db"))
    with pytest.raises(AnalysisError, match="base CVE introuvable"):
        _open_cve_db()
    assert not (tmp_path / "absente.db").exists()
    vus = []
    (tmp_path / "nvd.db").write_bytes(b"")
    monkeypatch.setenv("NETCROSS_CVE_DB", str(tmp_path / "nvd.db"))
    monkeypatch.setattr("netcross_core.security.connect_cve_db", lambda path: vus.append(path) or "CONN")
    assert _open_cve_db() == "CONN" and vus == [str(tmp_path / "nvd.db")]


def test_base_embarquee_illisible(monkeypatch):
    monkeypatch.delenv("NETCROSS_CVE_DB", raising=False)

    def illisible():
        raise ValueError("json invalide")

    monkeypatch.setattr("netcross_core.security.cve_seed.open_seed_db", illisible)
    assert _open_cve_db() is None


def test_la_securite_recoit_la_base(monkeypatch):
    vus = {}
    fermees = []
    monkeypatch.setattr(api_module, "_open_cve_db", lambda: "CONN")
    monkeypatch.setattr("netcross_core.security.cve_db.close_db", fermees.append)
    monkeypatch.setattr(api_module, "apply_security_findings", lambda report, pkts, **kw: vus.update(kw))
    rep = _post({"label": "LAN"})
    assert rep.status_code == 201, rep.text
    assert vus["cve_conn"] == "CONN" and fermees == ["CONN"]
