"""Issue #890 : POST /captures et /captures/multi écrivent dans l'historique
(history, history_label), comme --history-db / --history-label de la CLI."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from netcross_report.history import list_history
from tests.conftest import make_pkt

pytest.importorskip("fastapi", reason="extra [api] non installé")
pytest.importorskip("multipart", reason="python-multipart non installé")
from fastapi.testclient import TestClient  # noqa: E402

from netcross_api import history_routes  # noqa: E402
from netcross_api.app import app, store  # noqa: E402

client = TestClient(app)
PCAP = b"\xd4\xc3\xb2\xa1" + bytes(100)


def _pkts(label, path):
    return [
        make_pkt(point=label, src="192.168.1.1", dst="192.168.1.2", dport=80, ts=1000.0),
        make_pkt(point=label, src="192.168.1.2", dst="192.168.1.1", dport=50000, ts=1001.0),
    ]


def _post(path, files, **data):
    with (
        patch("netcross_api.app.parse_capture", side_effect=_pkts),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        return client.post(f"{path}?wait=true", files=files, data=data)


def _simple(**data):
    return _post("/captures", [("file", ("a.pcap", PCAP, "application/octet-stream"))], label="LAN", **data)


def _multi(**data):
    files = [
        ("files", ("a.pcap", PCAP, "application/octet-stream")),
        ("files", ("b.pcap", PCAP, "application/octet-stream")),
    ]
    return _post("/captures/multi", files, labels="LAN,DC", **data)


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "h.db"
    monkeypatch.setenv(history_routes.HISTORY_DB_ENV, str(path))
    return path


def test_analyse_simple_enregistree(db):
    rep = _simple(history="true", history_label="Site-A")
    assert rep.status_code == 201, rep.text
    assert rep.json()["history_id"] == 1
    (entree,) = list_history(db)
    assert (entree.run_type, entree.label) == ("analyse", "Site-A")
    assert entree.points == ["LAN"]


def test_analyse_multi_enregistree_et_visible_dans_get_history(db):
    rep = _multi(history="true")
    assert rep.status_code == 201, rep.text
    assert rep.json()["history_id"] == 1
    (entree,) = client.get("/history", params={"run_type": "analyse"}).json()["entries"]
    assert set(entree["points"]) == {"LAN", "DC"}
    assert entree["label"] is None


def test_statut_porte_history_id(db):
    rep = _simple(history="true", history_label="Nuit")
    assert rep.status_code == 201, rep.text
    statut = client.get(f"/analyses/{rep.json()['analysis_id']}/status").json()
    assert statut["status"] == "completed", statut
    assert statut["summary"]["history_id"] == 1
    assert list_history(db, label="Nuit")


def test_sans_history_rien_n_est_ecrit(db):
    rep = _simple()
    assert rep.status_code == 201
    assert rep.json()["history_id"] is None
    assert not db.exists()


def test_history_refuse_sans_base(monkeypatch):
    monkeypatch.delenv(history_routes.HISTORY_DB_ENV, raising=False)
    for envoi in (_simple, _multi):
        rep = envoi(history="true")
        assert rep.status_code == 400
        assert "NETCROSS_HISTORY_DB" in rep.json()["detail"]


def test_label_sans_history_refuse(db):
    rep = _multi(history_label="Site-A")
    assert rep.status_code == 400
    assert "history_label necessite history=true" in rep.json()["detail"]


def test_base_illisible_garde_l_analyse(tmp_path, monkeypatch):
    db = tmp_path / "pas-une-base.db"
    db.write_text("ceci n'est pas sqlite" * 50)
    monkeypatch.setenv(history_routes.HISTORY_DB_ENV, str(db))
    rep = _simple(history="true")
    assert rep.status_code == 201, rep.text
    assert rep.json()["history_error"]
    assert rep.json()["packet_count"] == 2
    assert store.get(rep.json()["analysis_id"])["status"] == "completed"


def test_findings_tls_quic_transmis_comme_la_cli(db):
    with patch("netcross_report.record_run", return_value=7) as record:
        rep = _simple(history="true", redact="true")
    assert rep.status_code == 201, rep.text
    assert rep.json()["history_id"] == 7
    kwargs = record.call_args.kwargs
    assert {"findings", "tls_findings", "quic_findings", "label", "meta"} <= set(kwargs)
    assert kwargs["meta"] == {"Anonymisation": "adresses IP/MAC anonymisees (--redact)"}


def test_options_enregistrees_avec_l_analyse(db):
    rep = _simple(history="true", history_label="Site-A")
    options = store.get(rep.json()["analysis_id"])["metadata"]["options"]
    assert (options["history"], options["history_label"]) == (True, "Site-A")
