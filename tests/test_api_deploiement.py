"""API deployable (issue #356) : jeton, limite d'upload, analyse en tache
de fond avec statut, persistance SQLite optionnelle.

parse_capture est remplace par des paquets synthetiques ; pour observer
``pending``, il attend un threading.Event que le test libere.
"""

import importlib
import sqlite3
import tempfile
import threading
import time

import pytest
from conftest import make_pkt

try:
    from fastapi.testclient import TestClient

    api_module = importlib.import_module("netcross_api.app")
    from netcross_api.store import ERREUR_INTERROMPUE, AnalysesStore, store
except ImportError:
    pytest.skip("fastapi non installe (extra [api])", allow_module_level=True)

client = TestClient(api_module.app)
PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 100
PAQUETS = {
    "LAN": [make_pkt(point="LAN", sport=1), make_pkt(point="LAN", sport=2, ts=1000.0)],
    "DC": [make_pkt(point="DC", sport=2, ts=1000.004)],
}


@pytest.fixture(autouse=True)
def _api(monkeypatch, tmp_path):
    store.clear()
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(uploads))
    monkeypatch.setattr(api_module, "parse_capture", lambda label, path: list(PAQUETS.get(label, PAQUETS["LAN"])))
    monkeypatch.setattr(api_module, "scan_capture_exploits", lambda label, path: [])
    yield uploads
    store.clear()


def _upload(path="/captures", label="LAN", headers=None, contenu=PCAP):
    return client.post(
        path, files={"file": ("lan.pcap", contenu, "application/octet-stream")}, data={"label": label}, headers=headers
    )


def _attendre(analysis_id, statut, headers=None, delai=5.0):
    fin = time.monotonic() + delai
    while time.monotonic() < fin:
        body = client.get(f"/analyses/{analysis_id}/status", headers=headers).json()
        if body["status"] == statut:
            return body
        time.sleep(0.02)
    raise AssertionError(f"statut {statut} non atteint : {body}")


# --- Authentification --------------------------------------------------------


def test_401_sans_jeton_sur_toutes_les_routes(monkeypatch):
    monkeypatch.setattr(api_module, "_API_TOKEN", "s3cret")
    assert _upload().status_code == 401
    for route in ("/analyses", "/analyses/abc", "/analyses/abc/status", "/analyses/abc/security"):
        response = client.get(route)
        assert response.status_code == 401, route
        assert "Jeton" in response.json()["detail"]
    assert client.get("/analyses", headers={"X-API-Key": "mauvais"}).status_code == 401
    assert client.get("/health").status_code == 200  # sonde de vie jamais authentifiee


def test_jeton_valide_accepte(monkeypatch):
    monkeypatch.setattr(api_module, "_API_TOKEN", "s3cret")
    headers = {"X-API-Key": "s3cret"}
    response = client.post(
        "/captures?wait=true", files={"file": ("a.pcap", PCAP)}, data={"label": "LAN"}, headers=headers
    )
    assert response.status_code == 201, response.text
    assert client.get(f"/analyses/{response.json()['analysis_id']}", headers=headers).status_code == 200


# --- Limite d'upload ------------------------------------------------------------


def test_413_au_dela_de_la_limite_sans_fichier_residuel(monkeypatch, _api):
    monkeypatch.setattr(api_module, "_MAX_UPLOAD_BYTES", 50)
    appels = []
    monkeypatch.setattr(api_module, "parse_capture", lambda label, path: appels.append(label) or [])
    response = _upload()
    assert response.status_code == 413
    assert "LAN trop volumineux" in response.json()["detail"]
    assert appels == []
    assert store.list_ids() == []
    assert list(_api.iterdir()) == []


def test_413_multi_nettoie_les_fichiers_deja_recus(monkeypatch, _api):
    monkeypatch.setattr(api_module, "_MAX_UPLOAD_BYTES", 50)
    files = [("files", ("lan.pcap", b"x" * 10)), ("files", ("dc.pcap", b"x" * 60))]
    response = client.post("/captures/multi", files=files, data={"labels": "LAN,DC"})
    assert response.status_code == 413
    assert "DC" in response.json()["detail"]
    assert list(_api.iterdir()) == []


def test_413_sur_content_length_avant_lecture(monkeypatch):
    monkeypatch.setattr(api_module, "_MAX_UPLOAD_BYTES", 10)
    monkeypatch.setattr(api_module, "_MAX_FILES", 1)
    monkeypatch.setattr(api_module, "_MULTIPART_MARGIN", 0)
    response = _upload(contenu=b"x" * 500)
    assert response.status_code == 413
    assert "Requête trop volumineuse" in response.json()["detail"]


def test_trop_de_fichiers_refuse(monkeypatch):
    monkeypatch.setattr(api_module, "_MAX_FILES", 2)
    files = [("files", (f"{i}.pcap", PCAP)) for i in range(3)]
    response = client.post("/captures/multi", files=files, data={"labels": "A,B,C"})
    assert response.status_code == 400
    assert "Au plus 2 fichiers" in response.json()["detail"]


# --- Tache de fond et statut ----------------------------------------------------


def test_statut_pending_puis_completed(monkeypatch, _api):
    libere = threading.Event()

    def parse_bloquant(label, path):
        assert libere.wait(5), "le test n'a pas libere l'analyse"
        return list(PAQUETS["LAN"])

    monkeypatch.setattr(api_module, "parse_capture", parse_bloquant)
    response = _upload()
    assert response.status_code == 202
    body = response.json()
    analysis_id = body["analysis_id"]
    assert body["status"] == "pending"
    assert body["status_url"] == f"/analyses/{analysis_id}/status"
    assert response.headers["location"] == body["status_url"]

    status = client.get(body["status_url"]).json()
    assert status == {"analysis_id": analysis_id, "status": "pending", "error": None, "summary": None}
    en_cours = client.get(f"/analyses/{analysis_id}")
    assert en_cours.status_code == 409
    assert "pending" in en_cours.json()["detail"]
    assert client.get(f"/analyses/{analysis_id}/security").status_code == 409

    libere.set()
    termine = _attendre(analysis_id, "completed")
    assert termine["summary"] == {"point_count": 1, "packet_count": 2, "security_finding_count": 0}
    doc = client.get(f"/analyses/{analysis_id}")
    assert doc.status_code == 200
    assert doc.json()["points"] == ["LAN"]
    assert client.get(f"/analyses/{analysis_id}/security").status_code == 200
    assert list(_api.iterdir()) == []  # fichier temporaire supprime apres analyse


def test_statut_failed_avec_cause(monkeypatch):
    def parse_casse(label, path):
        raise RuntimeError("pcap tronque")

    monkeypatch.setattr(api_module, "parse_capture", parse_casse)
    analysis_id = _upload().json()["analysis_id"]
    echec = _attendre(analysis_id, "failed")
    assert echec["error"] == "Erreur de parsing pour LAN: pcap tronque"
    response = client.get(f"/analyses/{analysis_id}")
    assert response.status_code == 409
    assert "pcap tronque" in response.json()["detail"]


def test_multi_en_tache_de_fond_resume_avec_segments():
    files = [("files", ("lan.pcap", PCAP)), ("files", ("dc.pcap", PCAP))]
    response = client.post("/captures/multi", files=files, data={"labels": "LAN,DC", "points_order": "LAN,DC"})
    assert response.status_code == 202
    summary = _attendre(response.json()["analysis_id"], "completed")["summary"]
    assert summary["points"] == ["LAN", "DC"]
    (segment,) = summary["segments"]
    assert (segment["segment"], segment["loss_count"]) == ("LAN -> DC", 1)


def test_statut_inconnu_404():
    assert client.get("/analyses/inconnue/status").status_code == 404


# --- Persistance SQLite ---------------------------------------------------------


def test_analyse_relue_apres_redemarrage(monkeypatch, tmp_path):
    db = str(tmp_path / "api.db")
    monkeypatch.setattr(api_module, "store", AnalysesStore(db_path=db))
    analysis_id = _upload("/captures?wait=true").json()["analysis_id"]
    avant = client.get(f"/analyses/{analysis_id}").json()

    monkeypatch.setattr(api_module, "store", AnalysesStore(db_path=db))  # « redemarrage »
    assert client.get("/analyses").json()["analyses"] == [analysis_id]
    assert client.get(f"/analyses/{analysis_id}/status").json()["status"] == "completed"
    assert client.get(f"/analyses/{analysis_id}").json() == avant
    assert client.get(f"/analyses/{analysis_id}/security").status_code == 200


def test_pending_au_redemarrage_devient_failed(tmp_path):
    db = str(tmp_path / "api.db")
    analysis_id = AnalysesStore(db_path=db).create_pending({"label": "LAN"})
    relu = AnalysesStore(db_path=db).get(analysis_id)
    assert relu["status"] == "failed"
    assert relu["error"] == ERREUR_INTERROMPUE
    assert AnalysesStore(db_path=db).get_status(analysis_id) == "failed"  # ecrit en base


def test_base_de_la_premiere_version_migree(tmp_path):
    db = str(tmp_path / "ancienne.db")
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE analyses (id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'completed', "
            "metadata TEXT NOT NULL DEFAULT '{}', report_json TEXT, "
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        conn.execute("INSERT INTO analyses (id, report_json) VALUES ('ancien', '\"Report(points=[])\"')")
    conn.close()
    relu = AnalysesStore(db_path=db)
    assert relu.get_status("ancien") == "failed"
    assert "ancien format" in relu.get("ancien")["error"]
    nouveau = relu.create_pending()
    relu.complete(nouveau, {"points": ["A"]}, {"point_count": 1})
    assert AnalysesStore(db_path=db).get(nouveau)["document"] == {"points": ["A"]}


def test_sans_db_path_rien_n_est_ecrit(monkeypatch, tmp_path):
    monkeypatch.delenv("NETCROSS_DB_PATH", raising=False)
    memoire = AnalysesStore()
    assert not memoire.persistent
    memoire.complete(memoire.create_pending(), {}, {})
    assert list(tmp_path.glob("*.db")) == []


# -- Issue #719 : couverture des branches defensives de store.py --------------


def test_jsonable_dataclass(tmp_path, _api):
    """Lignes 60-61 : jsonable convertit un dataclass en dict."""
    from dataclasses import dataclass

    from netcross_api.store import jsonable

    @dataclass
    class FakeData:
        name: str
        count: int

    result = jsonable(FakeData(name="test", count=42))
    assert result == {"name": "test", "count": 42}


def test_jsonable_primitive_and_str(tmp_path, _api):
    """Lignes 68-69 : jsonable retourne la valeur pour les primitives
    et str() pour les autres types."""
    from netcross_api.store import jsonable

    assert jsonable(None) is None
    assert jsonable(42) == 42
    assert jsonable("hello") == "hello"
    assert jsonable(True) is True
    # Un type non-primitive -> str()
    assert jsonable(object())  # retourne une string non vide


def test_update_analyse_inconnue_ignoree(_api):
    """Lignes 142-144 : _update sur une analyse inconnue est ignoree."""
    from netcross_api.store import AnalysesStore

    store = AnalysesStore()
    # Aucune exception ne doit etre levee
    store._update("inexistant", status="completed")
    # L'analyse inexistante n'a pas ete creee
    assert store.get("inexistant") is None


# -- Issue #736 : couverture des handlers d'erreur de app.py ----------------


def test_run_job_erreur_interne_ne_restre_pas_pending(monkeypatch):
    """Lignes 341-343 : _run_job avec une exception non-AnalysisError
    appelle store.fail() et ne reste pas pending."""
    import sys

    from netcross_api.app import _run_job
    from netcross_api.store import AnalysesStore

    store = AnalysesStore()
    app_module = sys.modules["netcross_api.app"]
    monkeypatch.setattr(app_module, "store", store)

    # Forcer _analyse_captures a lever une exception non-AnalysisError
    def raise_runtime(*a, **kw):
        raise RuntimeError("bug interne")

    monkeypatch.setattr(app_module, "_analyse_captures", raise_runtime)

    analysis_id = store.create_pending()
    _run_job(analysis_id, [], None, False)

    result = store.get(analysis_id)
    assert result is not None
    assert result.get("status") == "failed"
    assert "Erreur interne" in result.get("error", "")


def test_run_job_analysis_error_appelle_fail(monkeypatch):
    """Lignes 308-313 et 339-340 : _run_job avec AnalysisError appelle
    store.fail() avec le message d'erreur."""
    import sys

    from netcross_api.app import AnalysisError, _run_job
    from netcross_api.store import AnalysesStore

    store = AnalysesStore()
    app_module = sys.modules["netcross_api.app"]
    monkeypatch.setattr(app_module, "store", store)

    # Forcer _analyse_captures a lever AnalysisError
    def raise_analysis(*a, **kw):
        raise AnalysisError("erreur d'analyse")

    monkeypatch.setattr(app_module, "_analyse_captures", raise_analysis)

    # Creer l'analyse dans le store avant _run_job
    analysis_id = store.create_pending()
    _run_job(analysis_id, [], None, False)

    result = store.get(analysis_id)
    assert result is not None
    assert result.get("status") == "failed"
    assert "erreur d'analyse" in result.get("error", "")
