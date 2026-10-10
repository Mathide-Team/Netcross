"""Issue #872 (API) : lots de captures, équivalent de ``cross_capture_batch_cli.py``.

``POST /batches`` (captures ou archive ZIP) puis ``GET /batches/{id}``,
``/index`` et ``/reports/{name}``. Le moteur est celui de la CLI
(``netcross_report.batch_runner``) : mêmes groupes, mêmes rapports.
"""

from __future__ import annotations

import dataclasses
import io
import os
import sys
import time
import zipfile

import pytest

try:
    from fastapi.testclient import TestClient

    from netcross_api import batches
    from netcross_api.app import app
except ImportError:
    pytest.skip("fastapi non installe (extra [api])", allow_module_level=True)

from conftest import make_pkt

from netcross_report import batch_runner as runner

client = TestClient(app)
api_module = sys.modules["netcross_api.app"]
T0 = 1_700_000_000.0


def _flux(t0, n=20, src="10.0.0.5", dst="10.0.0.9"):
    return [make_pkt(point="x", ts=t0 + i, src=src, dst=dst) for i in range(n)]


CONTENU = {
    "amont": _flux(T0),
    "aval": _flux(T0 + 0.003, 18),
    "autre": _flux(T0 + 86400, 5, src="192.168.1.1", dst="192.168.1.2"),
    "casse": None,
}


@pytest.fixture(autouse=True)
def faux_parse(monkeypatch):
    def _parse(label, path, raise_on_error=False):
        stem = os.path.basename(path).split(".")[0].split("_")[0]
        pk = CONTENU[stem]
        if pk is None:
            raise RuntimeError("tshark: The file appears to be damaged or corrupt.")
        return [dataclasses.replace(p, point=label) for p in pk]

    monkeypatch.setattr(runner, "parse_capture", _parse)
    yield
    batches.batch_store.clear()


def _files(*names):
    return [("files", (name, b"\0", "application/octet-stream")) for name in names]


def _post(files, data=None, wait=True):
    return client.post(f"/batches?wait={'true' if wait else 'false'}", files=files, data=data or {})


def test_lot_complet_groupe_isolees_echec():
    r = _post(_files("amont.pcap", "aval.pcapng", "autre.pcap", "casse.pcap"))
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["status"] == "completed"
    assert "workdir" not in data
    res = data["result"]
    assert [g["members"] for g in res["groups"]] == [["amont", "aval"]]
    assert res["groups"][0]["report"] == "rapport-groupe-1.txt"
    assert res["groups"][0]["justification"]
    assert [i["label"] for i in res["isolated"]] == ["autre"]
    assert [f["label"] for f in res["failures"]] == ["casse"]
    assert res["has_failures"] is True
    assert any("inventaire casse : ECHEC" in line for line in data["progress"])
    assert set(res["capture_reports"]) == {"amont", "aval", "autre"}


def test_index_et_rapports():
    batch_id = _post(_files("amont.pcap", "aval.pcap")).json()["batch_id"]
    index = client.get(f"/batches/{batch_id}/index")
    assert index.status_code == 200
    assert "groupe" in index.text.lower()
    rapport = client.get(f"/batches/{batch_id}/reports/rapport-groupe-1.txt")
    assert rapport.status_code == 200 and rapport.text
    assert client.get(f"/batches/{batch_id}/reports/rapport-amont.txt").status_code == 200


@pytest.mark.parametrize("name", ["../../etc/passwd", "index.txt", "inconnu.txt"])
def test_rapport_hors_lot_404(name):
    batch_id = _post(_files("amont.pcap")).json()["batch_id"]
    assert client.get(f"/batches/{batch_id}/reports/{name}").status_code == 404


def test_no_group_et_securite():
    r = _post(_files("amont.pcap", "aval.pcap"), {"no_group": "true", "security_report": "true"})
    assert r.status_code == 201, r.text
    res = r.json()["result"]
    assert res["groups"] == []
    assert {i["label"] for i in res["isolated"]} == {"amont", "aval"}
    assert set(res["findings"]) == {"amont", "aval"}
    assert r.json()["options"]["security_report"] is True


def test_archive_zip_extraite_a_plat():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("site-a/amont.pcap", b"\0")
        zf.writestr("site-b/aval.pcap", b"\0")
        zf.writestr("../evil/notes.txt", b"x")
    r = _post([("files", ("lot.zip", buf.getvalue(), "application/zip"))])
    assert r.status_code == 201, r.text
    res = r.json()["result"]
    assert [g["members"] for g in res["groups"]] == [["amont", "aval"]]
    assert res["ignored"] == ["notes.txt"]


def test_archive_invalide_400():
    r = _post([("files", ("lot.zip", b"pas un zip", "application/zip"))])
    assert r.status_code == 400
    assert "ZIP" in r.json()["detail"]


def test_archive_bombe_refusee(monkeypatch):
    monkeypatch.setattr(api_module, "_MAX_UPLOAD_BYTES", 10)
    monkeypatch.setattr(api_module, "_MAX_FILES", 1)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("amont.pcap", b"\0" * 1000)
    r = _post([("files", ("lot.zip", buf.getvalue(), "application/zip"))])
    assert r.status_code in (400, 413)


def test_aucune_capture_400():
    r = _post(_files("notes.txt"))
    assert r.status_code == 400
    assert "aucune capture" in r.json()["detail"]


@pytest.mark.parametrize(
    ("data", "attendu"),
    [
        ({"min_overlap": "0"}, "min_overlap doit etre dans ]0, 1]."),
        ({"min_common_ips": "0"}, "min_common_ips doit etre >= 1."),
        ({"group_window": "-1"}, "group_window doit etre >= 0."),
        ({"jobs": "0"}, "jobs doit etre >= 1."),
        ({"jobs": "999"}, "jobs doit etre <= 64."),
    ],
)
def test_validations_comme_la_cli(data, attendu):
    r = _post(_files("amont.pcap"), data)
    assert r.status_code == 400
    assert r.json()["detail"] == attendu


def test_mode_asynchrone_202_puis_statut():
    r = _post(_files("amont.pcap", "aval.pcap"), wait=False)
    assert r.status_code == 202, r.text
    batch_id = r.json()["batch_id"]
    assert r.headers["Location"] == f"/batches/{batch_id}"
    for _ in range(100):
        status = client.get(f"/batches/{batch_id}").json()["status"]
        if status == "completed":
            break
        time.sleep(0.05)
    assert status == "completed"
    assert batch_id in {b["batch_id"] for b in client.get("/batches").json()["batches"]}


def test_lot_inconnu_404_et_en_cours_409():
    assert client.get("/batches/inexistant").status_code == 404
    batch_id = batches.batch_store.create(runner.BatchOptions(), [], batches.new_workdir()[0])
    assert client.get(f"/batches/{batch_id}/index").status_code == 409


def test_eviction_supprime_le_repertoire(monkeypatch):
    store = batches.BatchStore(max_batches=1)
    first_dir = batches.new_workdir()[0]
    first = store.create(runner.BatchOptions(), [], first_dir)
    store.update(first, status=batches.COMPLETED)
    store.create(runner.BatchOptions(), [], batches.new_workdir()[0])
    assert store.get(first) is None
    assert not os.path.exists(first_dir)
    store.clear()


def test_noms_nettoyes():
    assert batches.safe_name("../../x/..evil.pcap") == "evil.pcap"
    assert batches.safe_name("a b\\c.pcap") == "c.pcap"


def test_noms_en_double_conserves():
    r = _post(_files("amont.pcap", "amont.pcap"))
    assert r.status_code == 201, r.text
    assert set(r.json()["result"]["capture_reports"]) == {"amont", "amont_2"}


def test_trop_de_fichiers_400(monkeypatch):
    monkeypatch.setattr(api_module, "_MAX_FILES", 1)
    assert _post(_files("amont.pcap", "aval.pcap")).status_code == 400


def test_openapi_expose_les_routes():
    paths = client.get("/openapi.json").json()["paths"]
    assert {
        "/batches",
        "/batches/{batch_id}",
        "/batches/{batch_id}/index",
        "/batches/{batch_id}/reports/{name}",
    } <= set(paths)


def test_extract_archive_borne_la_taille_decompressee(tmp_path):
    archive = tmp_path / "bombe.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("amont.pcap", b"\0" * 10_000)
    with pytest.raises(batches.BatchInputError, match="trop volumineuse"):
        batches.extract_archive(str(archive), str(tmp_path), max_bytes=1000)
    assert not (tmp_path / "amont.pcap").exists()
