"""Tests de couverture de netcross_report/stix_export.py (issue #713, suite #665).

Complète tests/test_stix_leef_export.py par les entrées incomplètes ou
invalides d'un rapport : le bundle doit rester valide et déterministe, et ce
qui ne peut pas être représenté est compté dans ``x_netcross_skipped`` ou
rangé en notes rattachées au report.

- services sans point, sans hôte, avec hôte invalide ;
- CVE sans détail, sans CVSS numérique, sans service ;
- exploit sans CVE ni point ;
- anomalies : hôte invalide, port hors plage ou non entier, source valide,
  sans port ni source, sans point ;
- ``_Builder.traffic`` indisponible (retour ``None``, contrat annoté ``str | None``).
"""

from __future__ import annotations

import datetime as dt

from netcross_core.models import Report
from netcross_report.stix_export import _Builder, to_stix_bundle

T0 = dt.datetime(2026, 3, 4, 10, 0, 0, tzinfo=dt.UTC)


def _bundle(*, services=(), findings=()) -> dict:
    r = Report(points=["LAN"])
    r.service_fingerprints = list(services)
    r.security_findings = list(findings)
    return to_stix_bundle(r, observed_from=T0)


def _of_type(bundle: dict, stix_type: str) -> list[dict]:
    return [o for o in bundle["objects"] if o["type"] == stix_type]


def _traffic(bundle: dict) -> list[dict]:
    return _of_type(bundle, "network-traffic")


# -- services -------------------------------------------------------------------


def test_service_sans_point_n_ajoute_pas_x_netcross_point():
    bundle = _bundle(services=[{"service": "nginx", "version": "1.18.0", "host": "10.0.0.5", "port": 80}])
    (observed,) = _of_type(bundle, "observed-data")
    assert "x_netcross_point" not in observed


def test_service_sans_hote_ne_porte_que_le_logiciel():
    bundle = _bundle(services=[{"service": "nginx", "point": "LAN"}])
    (observed,) = _of_type(bundle, "observed-data")
    assert len(observed["object_refs"]) == 1
    assert _of_type(bundle, "software") and not _of_type(bundle, "ipv4-addr") and not _traffic(bundle)


def test_service_avec_hote_invalide_ne_porte_que_le_logiciel():
    bundle = _bundle(services=[{"service": "nginx", "host": "pas-une-ip", "port": 80, "point": "LAN"}])
    (observed,) = _of_type(bundle, "observed-data")
    assert len(observed["object_refs"]) == 1
    assert not _of_type(bundle, "ipv4-addr") and not _traffic(bundle)


# -- CVE ------------------------------------------------------------------------


def test_cve_minimale_sans_detail_ni_cvss_ni_service():
    bundle = _bundle(findings=[{"category": "cve", "cve_id": "CVE-2020-0001", "severity": "elevee"}])
    (vuln,) = _of_type(bundle, "vulnerability")
    assert "description" not in vuln and "x_netcross_cvss" not in vuln
    assert not _of_type(bundle, "relationship") and not _of_type(bundle, "software")


def test_cve_cvss_non_numerique_est_ignore():
    bundle = _bundle(
        findings=[{"category": "cve", "cve_id": "CVE-2020-0002", "cvss": "critique", "detail": "d", "service": "x"}]
    )
    (vuln,) = _of_type(bundle, "vulnerability")
    assert vuln["description"] == "d"
    assert "x_netcross_cvss" not in vuln
    assert len(_of_type(bundle, "relationship")) == 1  # avec service : relation software -> vulnerability


# -- exploit --------------------------------------------------------------------


def test_exploit_sans_cve_ni_point():
    bundle = _bundle(
        findings=[{"category": "exploit", "severity": "inconnue", "host": "10.0.0.5", "src": "203.0.113.9"}]
    )
    (indicator,) = _of_type(bundle, "indicator")
    assert "external_references" not in indicator and "x_netcross_point" not in indicator
    assert indicator["pattern"] == (
        "[network-traffic:src_ref.value = '203.0.113.9' AND network-traffic:dst_ref.value = '10.0.0.5']"
    )


# -- anomalies ------------------------------------------------------------------


def test_anomalie_avec_hote_invalide_devient_une_note_du_report():
    bundle = _bundle(findings=[{"category": "anomalie", "host": "pas-une-ip", "detail": "d"}])
    assert not _of_type(bundle, "observed-data")
    (report,) = _of_type(bundle, "report")
    (note,) = _of_type(bundle, "note")
    assert note["object_refs"] == [report["id"]]


def test_anomalie_avec_source_valide_relie_la_source_au_trafic():
    bundle = _bundle(
        findings=[{"category": "anomalie", "host": "10.0.0.5", "src": "203.0.113.9", "port": 443, "point": "LAN"}]
    )
    (traffic,) = _traffic(bundle)
    assert traffic["dst_port"] == 443
    assert traffic["src_ref"] in {o["id"] for o in _of_type(bundle, "ipv4-addr")}
    (observed,) = _of_type(bundle, "observed-data")
    assert traffic["id"] in observed["object_refs"]
    assert len(_of_type(bundle, "ipv4-addr")) == 2


def test_anomalie_source_seule_sans_port():
    bundle = _bundle(findings=[{"category": "anomalie", "host": "10.0.0.5", "src": "203.0.113.9"}])
    (traffic,) = _traffic(bundle)
    assert "dst_port" not in traffic and "src_ref" in traffic


def test_anomalie_hote_seul_sans_port_ni_source_ni_point():
    bundle = _bundle(findings=[{"category": "anomalie", "host": "10.0.0.5"}])
    assert not _traffic(bundle)
    (observed,) = _of_type(bundle, "observed-data")
    assert "x_netcross_point" not in observed
    (note,) = _of_type(bundle, "note")
    assert "x_netcross_point" not in note


def test_anomalie_port_hors_plage_ou_non_entier_est_omis_du_trafic():
    for port in (70000, -1, "443"):
        bundle = _bundle(findings=[{"category": "anomalie", "host": "10.0.0.5", "port": port}])
        (traffic,) = _traffic(bundle)
        assert "dst_port" not in traffic, port


# -- garde defensive sur traffic() ----------------------------------------------


def test_traffic_indisponible_n_ajoute_pas_de_reference(monkeypatch):
    # _Builder.traffic est annote `str | None` : les appelants ignorent un
    # retour None. Le code actuel renvoie toujours un identifiant ; on double la
    # methode pour figer ce contrat plutot que de marquer les gardes no cover.
    monkeypatch.setattr(_Builder, "traffic", lambda self, **kwargs: None)
    bundle = _bundle(
        services=[{"service": "nginx", "host": "10.0.0.5", "port": 80, "point": "LAN"}],
        findings=[{"category": "anomalie", "host": "10.0.0.6", "port": 443, "point": "LAN"}],
    )
    assert not _traffic(bundle)
    assert len(_of_type(bundle, "observed-data")) == 2
    assert len(_of_type(bundle, "ipv4-addr")) == 2
