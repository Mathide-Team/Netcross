"""Issue #877 (API) : portées, marqueurs et table de correspondance du ticket
de support sur ``POST /analyses/{analysis_id}/support-ticket``.

Pendant API de ``--support-scope``, ``--support-marker`` et ``--support-map``
de la CLI. L'analyse est simulée (``store.get`` remplacé) pour contrôler les
erreurs de traitement, donc ce qui est rédigé.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

try:
    from fastapi.testclient import TestClient

    from netcross_api.app import app
except ImportError:
    pytest.skip("fastapi non installe (extra [api])", allow_module_level=True)

from netcross_core.support.ticket import SCOPES

client = TestClient(app)
URL = "/analyses/a877/support-ticket"
ENTRY = {"status": "completed", "errors": ["capture lan.pcap : echec de lecture depuis 10.1.2.3"]}


def _post(params):
    with patch("netcross_api.app.store.get", return_value=ENTRY):
        return client.post(URL, params=params)


def test_sans_option_toutes_portees_et_pas_de_table():
    r = _post({"consent": "true"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ticket"]["consentement"]["portees"] == list(SCOPES)
    assert data["ticket"]["consentement"]["origine"] == "api"
    assert data["ticket"]["consentement"]["accorde_le"]
    assert "support_map" not in data


def test_scopes_restreint_les_portees_et_omet_les_autres():
    r = _post({"consent": "true", "scopes": "journal, environnement"})
    assert r.status_code == 200, r.text
    ticket = r.json()["ticket"]
    assert ticket["consentement"]["portees"] == ["journal", "environnement"]
    assert ticket["marqueurs"] == {}
    omis = {c["controle"] for c in ticket["auto_verification"] if c["statut"] == "omis"}
    assert "marqueurs" in omis


@pytest.mark.parametrize("scopes", ["inconnue", "journal,inconnue", " , "])
def test_scopes_invalide_400(scopes):
    r = _post({"consent": "true", "scopes": scopes})
    assert r.status_code == 400
    assert "scopes" in r.json()["detail"]


def test_markers_repetables_joints_au_ticket():
    r = _post({"consent": "true", "marker": ["trace_id=T-042", "capture_id = C-7"]})
    assert r.status_code == 200, r.text
    marqueurs = r.json()["ticket"]["marqueurs"]
    assert marqueurs["trace_id"] == "T-042"
    assert marqueurs["capture_id"] == "C-7"
    assert "run_id" in marqueurs


@pytest.mark.parametrize("spec", ["sans_egal", "=valeur"])
def test_marker_mal_forme_400(spec):
    r = _post({"consent": "true", "marker": [spec]})
    assert r.status_code == 400
    assert "CLE=VALEUR" in r.json()["detail"]


def test_include_map_renvoie_la_correspondance_hors_ticket():
    r = _post({"consent": "true", "include_map": "true"})
    assert r.status_code == 200, r.text
    data = r.json()
    rows = data["support_map"]
    assert {"valeur_reelle": "10.1.2.3", "pseudonyme": rows[0]["pseudonyme"], "categorie": rows[0]["categorie"]} in rows
    # Le ticket lui-même reste anonymisé : la valeur réelle n'y figure pas.
    assert "10.1.2.3" not in str(data["ticket"])
    assert data["ticket"]["anonymisation"]["mapping_joint"] is False


def test_kind_inconnu_400():
    r = _post({"consent": "true", "kind": "inconnu"})
    assert r.status_code == 400
    assert "kind" in r.json()["detail"]


def test_consentement_toujours_exige():
    r = _post({"consent": "false", "scopes": "journal", "include_map": "true"})
    assert r.status_code == 400


def test_openapi_expose_les_nouveaux_parametres():
    spec = client.get("/openapi.json").json()
    params = {p["name"] for p in spec["paths"]["/analyses/{analysis_id}/support-ticket"]["post"]["parameters"]}
    assert {"consent", "kind", "scopes", "marker", "include_map"} <= params
