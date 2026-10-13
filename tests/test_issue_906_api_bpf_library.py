"""Issue #906 : bibliothèque de filtres BPF dans l'API, même fichier et
mêmes règles que ``--bpf-library`` (CLI) et le panneau BPF de la GUI."""

from __future__ import annotations

import importlib
import json

import pytest

from netcross_core import bpf_filters
from netcross_core.models import BPFFilter

pytest.importorskip("fastapi", reason="extra [api] non installé")

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

api = importlib.import_module("netcross_api.app")
routes = importlib.import_module("netcross_api.bpf_routes")
client = TestClient(api.app)
NB_CATALOGUE = len(bpf_filters.PREDEFINED_BPF_FILTERS)


@pytest.fixture(autouse=True)
def fichier(tmp_path, monkeypatch):
    chemin = tmp_path / "bpf_filters.json"
    monkeypatch.setenv(routes.BPF_FILTERS_ENV, str(chemin))
    return chemin


def _noms(rep):
    return [f["name"] for f in rep.json()["filters"]]


def test_liste_initiale_catalogue_seul(fichier):
    rep = client.get("/bpf-filters")
    assert rep.status_code == 200
    filtres = rep.json()["filters"]
    assert len(filtres) == NB_CATALOGUE
    assert all(f["predefined"] for f in filtres)
    assert filtres[0] == {
        "name": "HTTP",
        "expression": "tcp port 80",
        "description": bpf_filters.PREDEFINED_BPF_FILTERS[0].description,
        "predefined": True,
    }
    assert not fichier.exists()


def test_put_cree_puis_remplace(fichier):
    rep = client.put("/bpf-filters/Mon filtre", json={"expression": " host 10.0.0.1 ", "description": "poste"})
    assert rep.status_code == 200
    dernier = rep.json()["filters"][-1]
    assert dernier == {"name": "Mon filtre", "expression": "host 10.0.0.1", "description": "poste", "predefined": False}
    # même nom, autre casse : remplacement, pas de doublon
    rep = client.put("/bpf-filters/MON FILTRE", json={"expression": "host 10.0.0.2"})
    assert rep.status_code == 200
    assert len(rep.json()["filters"]) == NB_CATALOGUE + 1
    assert rep.json()["filters"][-1]["expression"] == "host 10.0.0.2"
    # même fichier que la GUI et la CLI
    sur_disque = json.loads(fichier.read_text(encoding="utf-8"))
    assert [f["expression"] for f in sur_disque["filters"]] == ["host 10.0.0.2"]


def test_filtre_api_visible_par_la_cli(fichier, monkeypatch):
    client.put("/bpf-filters/Serveur", json={"expression": "host 192.0.2.10"})
    import cross_capture_analyzer_cli as cli

    monkeypatch.setattr(bpf_filters, "default_bpf_filters_path", lambda: fichier)
    assert cli._load_bpf_from_library("serveur") == "host 192.0.2.10"


def test_put_refuse_un_nom_du_catalogue(fichier):
    rep = client.put("/bpf-filters/https", json={"expression": "tcp port 8443"})
    assert rep.status_code == 409
    assert "reserve" in rep.json()["detail"]
    assert not fichier.exists()


@pytest.mark.parametrize("corps", [{"expression": "   "}, {"expression": ""}])
def test_put_refuse_une_expression_vide(fichier, corps):
    rep = client.put("/bpf-filters/vide", json=corps)
    assert rep.status_code == 422
    assert not fichier.exists()


def test_put_sans_expression_422():
    assert client.put("/bpf-filters/x", json={}).status_code == 422


def test_put_nom_blanc_422(fichier):
    rep = client.put("/bpf-filters/%20%20", json={"expression": "tcp"})
    assert rep.status_code == 422
    assert not fichier.exists()


def test_delete_supprime(fichier):
    client.put("/bpf-filters/a", json={"expression": "tcp"})
    client.put("/bpf-filters/b", json={"expression": "udp"})
    rep = client.delete("/bpf-filters/A")
    assert rep.status_code == 200
    assert _noms(rep)[NB_CATALOGUE:] == ["b"]
    assert _noms(client.get("/bpf-filters"))[NB_CATALOGUE:] == ["b"]


def test_delete_inconnu_404(fichier):
    rep = client.delete("/bpf-filters/fantome")
    assert rep.status_code == 404
    assert not fichier.exists()


def test_delete_catalogue_409():
    rep = client.delete("/bpf-filters/DNS")
    assert rep.status_code == 409


def test_fichier_illisible_jamais_ecrase(fichier):
    fichier.write_text("{pas du json", encoding="utf-8")
    assert client.get("/bpf-filters").status_code == 500
    assert client.put("/bpf-filters/x", json={"expression": "tcp"}).status_code == 500
    assert client.delete("/bpf-filters/x").status_code == 500
    assert fichier.read_text(encoding="utf-8") == "{pas du json"


def test_sans_variable_fichier_par_defaut(tmp_path, monkeypatch):
    monkeypatch.delenv(routes.BPF_FILTERS_ENV)
    assert routes.filters_path() is None
    monkeypatch.setattr(bpf_filters, "default_bpf_filters_path", lambda: tmp_path / "defaut.json")
    assert client.put("/bpf-filters/d", json={"expression": "arp"}).status_code == 200
    assert (tmp_path / "defaut.json").is_file()


def test_resolve_bpf_library(fichier):
    client.put("/bpf-filters/Perso", json={"expression": "host 198.51.100.1"})
    assert routes.resolve_bpf_library(" perso ") == "host 198.51.100.1"
    assert routes.resolve_bpf_library("dns") == "port 53"
    with pytest.raises(HTTPException) as exc:
        routes.resolve_bpf_library("inconnu")
    assert exc.value.status_code == 400
    assert "Perso" in exc.value.detail


def test_resolve_bpf_library_fichier_illisible(fichier):
    fichier.write_text("[1]", encoding="utf-8")
    with pytest.raises(HTTPException) as exc:
        routes.resolve_bpf_library("dns")
    assert exc.value.status_code == 500


def test_authentification_exigee(monkeypatch):
    monkeypatch.setattr(api, "_API_TOKEN", "secret")
    assert client.get("/bpf-filters").status_code == 401
    assert client.put("/bpf-filters/x", json={"expression": "tcp"}).status_code == 401
    assert client.delete("/bpf-filters/x").status_code == 401
    assert client.get("/bpf-filters", headers={"X-API-Key": "secret"}).status_code == 200


def test_coeur_delete_bpf_filter(tmp_path):
    chemin = tmp_path / "f.json"
    bpf_filters.upsert_bpf_filter(BPFFilter("x", "tcp"), chemin)
    restants = bpf_filters.delete_bpf_filter(" X ", chemin)
    assert len(restants) == NB_CATALOGUE
    with pytest.raises(KeyError):
        bpf_filters.delete_bpf_filter("x", chemin)
    with pytest.raises(ValueError, match="catalogue"):
        bpf_filters.delete_bpf_filter("http", chemin)
