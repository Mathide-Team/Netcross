"""Issue #867 (API) : plugins côté serveur.

- ``GET /plugins`` : équivalent de ``--list-plugins`` (installés + fichiers de
  ``NETCROSS_PLUGIN_PATH``, autorisés ou non) ;
- champ ``plugins`` de ``POST /captures`` et ``POST /captures/multi`` :
  équivalent de ``--plugins``, détecteurs exécutés dans le rapport de sécurité.

Le chemin des plugins est fixé par l'administrateur (variable
d'environnement) : le client ne peut que nommer un plugin déjà présent.
"""

from __future__ import annotations

import os
import textwrap
from unittest.mock import patch

import pytest

try:
    from fastapi.testclient import TestClient

    from netcross_api.app import app
except ImportError:
    pytest.skip("fastapi non installe (extra [api])", allow_module_level=True)

from conftest import make_pkt

client = TestClient(app)
PCAP = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"

PLUGIN_SOURCE = textwrap.dedent("""
    class Maison:
        name = "maison"
        def analyse(self, contexte):
            return [{"category": "anomalie", "severity": "elevee",
                     "detail": "protocole maison vu", "point": "LAN"}]

    class Muet:
        name = "muet"
        def analyse(self, contexte):
            return []

    class Csv:
        name = "csv"
        def export(self, report, chemin):
            chemin.write_text("x")

    DETECTORS = [Maison, Muet]
    EXPORTERS = [Csv]
    """)


@pytest.fixture
def plugin_path(tmp_path, monkeypatch):
    path = tmp_path / "maison.py"
    path.write_text(PLUGIN_SOURCE, encoding="utf-8")
    monkeypatch.setenv("NETCROSS_PLUGIN_PATH", str(path))
    with patch("netcross_core.plugins.loader._entry_points", return_value=[]):
        yield str(path)


def _analyse(endpoint="/captures", **data):
    pkts = [make_pkt(point="LAN"), make_pkt(point="DC")]
    with (
        patch("netcross_api.app.parse_capture", return_value=pkts),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        if endpoint == "/captures":
            r = client.post(
                "/captures?wait=true",
                files={"file": ("lan.pcap", PCAP, "application/octet-stream")},
                data={"label": "LAN", **data},
            )
        else:
            r = client.post(
                "/captures/multi?wait=true",
                files=[
                    ("files", ("lan.pcap", PCAP, "application/octet-stream")),
                    ("files", ("dc.pcap", PCAP, "application/octet-stream")),
                ],
                data={"labels": "LAN,DC", **data},
            )
    return r


def _report(analysis_id):
    r = client.get(f"/analyses/{analysis_id}/report")
    assert r.status_code == 200, r.text
    return r.json()


def test_get_plugins_liste_les_fichiers_de_l_administrateur(plugin_path):
    r = client.get("/plugins", params={"plugins": "maison,fantome"})
    assert r.status_code == 200, r.text
    data = r.json()
    rows = {row["name"]: row for row in data["plugins"]}
    assert set(rows) == {"maison", "muet", "csv"}
    assert rows["maison"]["authorized"] is True
    assert rows["muet"]["authorized"] is False
    assert rows["csv"]["kind"] == "exporter"
    assert rows["maison"]["origin"] == f"fichier:{plugin_path}"
    assert data["unknown"] == ["fantome"]
    assert data["plugin_path_configured"] is True


def test_get_plugins_sans_configuration(monkeypatch):
    monkeypatch.delenv("NETCROSS_PLUGIN_PATH", raising=False)
    with patch("netcross_core.plugins.loader._entry_points", return_value=[]):
        r = client.get("/plugins")
    assert r.status_code == 200
    assert r.json() == {"plugins": [], "unknown": [], "plugin_path_configured": False}


@pytest.mark.parametrize("endpoint", ["/captures", "/captures/multi"])
def test_detecteur_autorise_dans_le_rapport_de_securite(plugin_path, endpoint):
    r = _analyse(endpoint, plugins="maison")
    assert r.status_code == 201, r.text
    doc = _report(r.json()["analysis_id"])
    runs = doc["security_report"]["plugins"]
    assert [(run["plugin"], run["status"]) for run in runs] == [("maison", "ok")]
    anomalies = [a for a in doc["security_report"]["anomalies"] if a.get("plugin") == "maison"]
    assert [a["detail"] for a in anomalies] == ["protocole maison vu"]
    assert anomalies[0]["detector"] == "plugin:maison"


def test_plugin_non_nomme_jamais_execute(plugin_path):
    r = _analyse(plugins="muet")
    assert r.status_code == 201, r.text
    doc = _report(r.json()["analysis_id"])
    assert [run["plugin"] for run in doc["security_report"]["plugins"]] == ["muet"]
    assert not any("protocole maison" in f["detail"] for f in doc["security_report"]["anomalies"])


def test_plugin_introuvable_et_exporteur_traces_sans_echec(plugin_path):
    r = _analyse(plugins="fantome, csv ,fantome")
    assert r.status_code == 201, r.text
    runs = {run["plugin"]: run for run in _report(r.json()["analysis_id"])["security_report"]["plugins"]}
    assert runs["fantome"]["status"] == "refuse"
    assert runs["csv"]["status"] == "ignore"
    assert "API" in runs["csv"]["reason"]


def test_sans_plugins_aucune_ligne(plugin_path):
    r = _analyse()
    assert r.status_code == 201, r.text
    assert _report(r.json()["analysis_id"])["security_report"]["plugins"] == []


def test_plugins_refuse_avec_redact(plugin_path):
    r = _analyse(plugins="maison", redact="true")
    assert r.status_code == 400
    assert "redact" in r.json()["detail"]


def test_plusieurs_chemins_separes_par_pathsep(tmp_path, monkeypatch):
    a = tmp_path / "a.py"
    a.write_text(PLUGIN_SOURCE, encoding="utf-8")
    absent = tmp_path / "absent.py"
    monkeypatch.setenv("NETCROSS_PLUGIN_PATH", f"{a}{os.pathsep}{absent}{os.pathsep}")
    with patch("netcross_core.plugins.loader._entry_points", return_value=[]):
        rows = client.get("/plugins").json()["plugins"]
    assert {"maison", "muet", "csv"} <= {row["name"] for row in rows}
    assert any(row["error"] for row in rows if row["name"] == str(absent))


def test_openapi_expose_plugins():
    spec = client.get("/openapi.json").json()
    assert "/plugins" in spec["paths"]
    schema = spec["components"]["schemas"]
    forms = [name for name in schema if name.startswith("Body_upload_capture")]
    assert forms and "plugins" in schema[forms[0]]["properties"]
