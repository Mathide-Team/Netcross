"""netcross_report.markdown_report -- sections sécurité, expertise et
optionnelles du rapport Markdown (suite #665 et #761).

La section sécurité lisait des clés que ``security_report_to_dict()`` ne
produit pas (``global_score``, ``critical_count``, ``service_count``,
``items``, ``fingerprints``). Résultat : pour un Apache 2.4.49 porteur de
5 CVE critiques, le Markdown affichait « Score global : — »,
« Vulnérabilités critiques : 0 », « Services analysés : 0 », sans lister
aucune CVE. La section expertise lisait de même des attributs inexistants
(``group``, ``verdict``, ``framework``).
"""

from __future__ import annotations

from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.expert_model import ComplianceResult, Diagnosis, ExpertEvent, ReferenceProfile
from netcross_core.models import Banner, Report
from netcross_core.security.cve_seed import open_seed_db
from netcross_core.security.findings import apply_security_findings
from netcross_report.markdown_report import (
    _cell,
    _security_section,
    _session_objects_section,
    build_markdown_report_document,
)
from netcross_report.security_report import SecurityItem, SecurityReport, build_security_report
from netcross_report.session_objects import SessionObjects
from netcross_report.synthesis import Finding


def _report(**overrides):
    r = Report(points=["A", "B"], pairs=[("A", "B")])
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


def _apache_vulnerable():
    """Même scénario que tests/test_gui_security_window.py : Apache 2.4.49
    vu sur le point A, CVE confirmées par la base embarquée."""
    banner = Banner("http", "Apache", "2.4.49", "Apache/2.4.49")
    pkts = [make_pkt(point="A", src="10.0.0.5", dst="10.0.0.9", sport=80, dport=51000, service_banners=(banner,))]
    report = analyse(correlate(pkts), ["A"], pkts)
    conn, _seed = open_seed_db()
    try:
        apply_security_findings(report, pkts, cve_conn=conn)
    finally:
        conn.close()
    return build_security_report(report)


# -- _cell ------------------------------------------------------------------------------


def test_cellule_vide_barre_verticale_et_saut_de_ligne():
    assert _cell(None) == "—"
    assert _cell("") == "—"
    assert _cell(0) == "0"
    assert _cell("a|b\nc\rd") == "a\\|b c d"
    assert _cell("C:\\temp") == "C:\\\\temp"


# -- section sécurité ------------------------------------------------------------------------


def test_securite_absente():
    assert _security_section(None) == ""


def test_securite_tableau_de_bord_services_et_cve_reels():
    sr = _apache_vulnerable()
    md = _security_section(sr)
    d = sr.dashboard
    assert d.cves >= 1 and d.services_total == 1
    assert f"- Score de risque global : **{d.score}/100** (niveau : **{d.level}**)" in md
    assert f"- Services détectés : **{d.services_total}** (dont {d.services_vulnerable} vulnérable(s))" in md
    assert f"- CVE confirmées : **{d.cves}**" in md
    assert "| 10.0.0.5 | 80 | Apache | 2.4.49 |" in md
    assert "CVE-2021-41773" in md
    # une ligne de constat par CVE confirmée (hors en-tête du tableau des services)
    assert sum(1 for line in md.splitlines() if line.startswith("| CVE | ")) == len(sr.cves)
    # plus aucune des anciennes clés inexistantes
    assert "Score global : **—**" not in md
    assert "Services analysés" not in md


def test_securite_rapport_vide():
    md = _security_section(SecurityReport())
    assert "- Score de risque global : **0/100**" in md
    assert "### Services détectés" not in md
    assert "### Constats de sécurité" not in md


def test_securite_exploit_et_anomalie_sans_port_ni_cve():
    sr = SecurityReport(
        exploits=[
            SecurityItem(
                category="exploit", severity="elevee", detail="log4shell | JNDI", host="10.0.0.7", port=None, point="A"
            )
        ],
        anomalies=[SecurityItem(category="anomalie", severity="moyenne", detail="beaconing\nrégulier", host="")],
    )
    md = _security_section(sr)
    assert "| Exploit | elevee | 10.0.0.7:— | A | log4shell \\| JNDI |" in md
    assert "| Anomalie | moyenne | —:— | — | beaconing régulier |" in md


# -- section expertise -------------------------------------------------------------------------


def _session_objects(n_events=2):
    events = [
        ExpertEvent(
            category="perte", severity="elevee", segment=f"A->B #{i}", message="pertes", cause="congestion", impact=None
        )
        for i in range(n_events)
    ]
    ref = ReferenceProfile(
        id="Y1541-perte", metric="loss_ratio", operator="<=", threshold=0.001, unit="", source="Y.1541"
    )
    ref_ms = ReferenceProfile(
        id="G114-delai", metric="delay_ms", operator="<=", threshold=150, unit="ms", source="G.114"
    )
    return SessionObjects(
        expert_events=events,
        diagnoses=[Diagnosis(segment="A->B", events=events, cause="congestion", impact="VoIP dégradée")],
        compliance=[
            ComplianceResult(reference=ref, observed=None, status="INDETERMINE"),
            ComplianceResult(reference=ref_ms, observed=180.5, status="VIOLATION"),
        ],
    )


def test_expertise_absente_ou_vide():
    assert _session_objects_section(None) == ""
    assert _session_objects_section(SessionObjects()) == "## Expertise — objets enrichis\n"


def test_expertise_evenements_diagnostics_conformite():
    md = _session_objects_section(_session_objects())
    assert "| elevee | perte | A->B #0 | pertes | congestion | netcross |" in md
    assert "| A->B | 2 | congestion | VoIP dégradée |" in md
    assert "| INDETERMINE | Y1541-perte | loss_ratio : non mesuré (seuil <= 0.001) | Y.1541 |" in md
    assert "| VIOLATION | G114-delai | delay_ms : 180.5 ms (seuil <= 150 ms) | G.114 |" in md


def test_expertise_limite_a_20_evenements():
    md = _session_objects_section(SessionObjects(expert_events=_session_objects(23).expert_events))
    assert md.count("| elevee | perte |") == 20
    assert "*…et 3 autre(s)*" in md
    assert "### Diagnostics par segment" not in md
    assert "### Conformité" not in md


# -- sections optionnelles du document ---------------------------------------------------------


def test_document_complet_sections_optionnelles():
    findings = [Finding("anomalie", "perte", f"A->B{i}", "pertes") for i in range(17)]
    tls = [Finding("moyenne", "tls", "A->B", "certificat expiré")]
    quic = [Finding("faible", "quic", "A->B", "version inconnue")]
    rules = {"R1": [Finding("elevee", "regle", "A->B", "seuil dépassé")], "R2": []}
    r = _report(
        topology_ambiguous=[("A", "B")],
        http_objects=[{"point": "A", "uri": "/f.zip", "content_type": "application/zip", "size": 10}],
        extracted_files=[{"point": "A", "proto_source": "http", "uri": "f.zip", "size": 10, "hash_md5": "abc"}],
        capture_comments=["capture du 30/09"],
        packet_comments=["trame suspecte"],
    )
    md = build_markdown_report_document(
        r,
        findings=findings,
        tls_findings=tls,
        quic_findings=quic,
        rule_engine_findings=rules,
        session_objects=_session_objects(),
        security_report=_apache_vulnerable(),
    )
    # 17 segments A->B0..16 + le segment A->B des constats TLS/QUIC = 18, dont 15 affichés
    assert "*…et 3 autre(s) segment(s)*" in md
    assert "- A <-> B" in md
    assert "| A | /f.zip | application/zip | 10 |" in md
    assert "| A | http | f.zip | 10 | `abc` |" in md
    assert "## Diagnostics TLS" in md and "certificat expiré" in md
    assert "## Diagnostics QUIC" in md and "version inconnue" in md
    assert "### R1" in md and "### R2" not in md
    assert "- [section] capture du 30/09" in md and "- [paquet] trame suspecte" in md
    assert "## Rapport de sécurité" in md and "CVE-2021-41773" in md
    assert "## Expertise — objets enrichis" in md
