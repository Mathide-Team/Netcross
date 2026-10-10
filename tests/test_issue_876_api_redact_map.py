"""Issue #876 : table d'anonymisation (--redact-map) dans l'API, et
anonymisation partagée baseline/courant des comparaisons."""

from __future__ import annotations

import csv
import importlib
import io
from unittest.mock import patch

import pytest

from tests.conftest import make_pkt

pytest.importorskip("fastapi", reason="extra [api] non installé")
pytest.importorskip("multipart", reason="python-multipart non installé")

from fastapi.testclient import TestClient  # noqa: E402

from netcross_api.store import store  # noqa: E402
from netcross_core.redact import AddressRedactor, redaction_map_csv, write_redaction_map_csv  # noqa: E402

api = importlib.import_module("netcross_api.app")
client = TestClient(api.app)
PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 64


_APPELS: list[str] = []


def _pkts(label, path):
    # 2e lecture (le courant d'une comparaison) : un hote en plus, qui doit
    # recevoir un pseudonyme neuf dans la meme table
    _APPELS.append(path)
    extra = [make_pkt(point=label, src="10.9.9.9", dst="192.168.1.2", dport=80, ts=1003.0)] if len(_APPELS) == 2 else []
    return [
        make_pkt(point=label, src="192.168.1.1", dst="192.168.1.2", dport=80, ts=1000.0),
        make_pkt(point=label, src="192.168.1.2", dst="192.168.1.1", dport=50000, ts=1001.0),
        *extra,
    ]


@pytest.fixture(autouse=True)
def _vide():
    _APPELS.clear()
    store._store.clear()
    api._comparisons.clear()
    yield
    store._store.clear()
    api._comparisons.clear()


def _analyse(redact: bool):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post(
            "/captures?wait=true",
            files={"file": ("a.pcap", PCAP, "application/octet-stream")},
            data={"label": "LAN", "redact": str(redact).lower()},
        )
    assert rep.status_code == 201, rep.text
    return rep.json()["analysis_id"]


def _rows(text):
    return list(csv.reader(io.StringIO(text)))


def test_table_d_une_analyse_meme_format_que_la_cli(tmp_path):
    analysis_id = _analyse(True)
    rep = client.get(f"/analyses/{analysis_id}/redact-map")
    assert rep.status_code == 200
    assert rep.headers["content-type"].startswith("text/csv")
    assert rep.headers["cache-control"] == "no-store"
    assert "redact-map" in rep.headers["content-disposition"]
    rows = _rows(rep.text)
    assert rows[0] == ["adresse_reelle", "pseudonyme", "type"]
    assert {r[0] for r in rows[1:]} >= {"192.168.1.1", "192.168.1.2"}
    # --redact-map de la CLI : meme redacteur, meme fichier
    cli = AddressRedactor()
    _APPELS.clear()
    cli.redact(_pkts("LAN", "a.pcap"))
    out = tmp_path / "map.csv"
    write_redaction_map_csv(cli, str(out))
    assert out.read_bytes().decode("utf-8") == rep.text
    assert redaction_map_csv(cli.entries()) == rep.text


def test_sans_anonymisation_404():
    analysis_id = _analyse(False)
    rep = client.get(f"/analyses/{analysis_id}/redact-map")
    assert rep.status_code == 404
    assert "redact=true" in rep.json()["detail"]


def test_relue_apres_redemarrage_409():
    analysis_id = _analyse(True)
    store._store[analysis_id]["redaction_map"] = None  # comme une entree relue depuis SQLite
    assert client.get(f"/analyses/{analysis_id}/redact-map").status_code == 409


def _comparaison(redact: bool):
    with (
        patch("netcross_api.app.parse_capture", side_effect=_pkts),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        rep = client.post(
            "/comparisons?wait=true",
            files=[
                ("baseline_files", ("base.pcap", PCAP, "application/octet-stream")),
                ("current_files", ("curr.pcap", PCAP, "application/octet-stream")),
            ],
            data={"baseline_labels": "A", "current_labels": "A", "redact": str(redact).lower()},
        )
    assert rep.status_code == 201, rep.text
    return rep.headers["location"].split("/")[-1]


def test_comparaison_table_commune():
    comparison_id = _comparaison(True)
    rep = client.get(f"/comparisons/{comparison_id}/redact-map")
    assert rep.status_code == 200
    rows = _rows(rep.text)[1:]
    reelles = [r[0] for r in rows]
    # un seul pseudonyme par adresse pour baseline + courant (avant #876 :
    # deux redacteurs, la meme adresse pouvait changer de pseudonyme)
    assert sorted(reelles) == sorted(set(reelles))
    assert set(reelles) == {"192.168.1.1", "192.168.1.2", "10.9.9.9"}


def test_comparaison_sans_anonymisation_404():
    comparison_id = _comparaison(False)
    assert client.get(f"/comparisons/{comparison_id}/redact-map").status_code == 404


def test_comparaison_inconnue_404():
    assert client.get("/comparisons/inconnue/redact-map").status_code == 404
