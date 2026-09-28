"""tests/test_session_objects_couverture.py -- couverture >= 98 % de netcross_report/session_objects.py (issue #731).

Complete tests/test_session_objects.py sur les branches du rendu console et de
`build_session_objects()` que la suite ne prenait pas : flux sans endpoints,
evenements/diagnostics sans cause ni impact, lignes « ... et N autre(s) »,
section tshark du rendu console, calcul de l'expertise tshark depuis
`all_packets`. Fichier separe pour ne pas alourdir le fichier principal.
"""

from conftest import make_pkt

from netcross_core.expert_model import Diagnosis, ExpertEvent, Flow, ReferenceProfile
from netcross_core.models import Report
from netcross_report.session_objects import (
    DEFAULT_TOP_N,
    SessionObjects,
    build_session_objects,
    format_session_objects,
)


def _report_congestion():
    r = Report(points=["A", "B"])
    r.pairs = [("A", "B")]
    return r


def _flow(key, endpoints, points, packets, octets):
    return Flow(
        key=key,
        points=list(points),
        packet_count=dict(packets),
        byte_count=dict(octets),
        first_ts=dict.fromkeys(points, 0.0),
        last_ts=dict.fromkeys(points, 1.0),
        endpoints=endpoints,
    )


def _event(message="msg", cause=None, impact=None, **kw):
    return ExpertEvent(
        category=kw.pop("category", "TCP"),
        severity=kw.pop("severity", "a_surveiller"),
        segment=kw.pop("segment", "A -> B"),
        message=message,
        cause=cause,
        impact=impact,
        **kw,
    )


def test_format_session_objects_flux_sans_endpoints_retombe_sur_la_cle_brute():
    """Un Flow sans endpoints ne disparait pas du rendu : sa cle brute sert de libelle."""
    flow = _flow(("k-sans-endpoints",), None, ["A"], {"A": 3}, {"A": 30})
    objs = SessionObjects(flows=[flow], conversations=[])
    texte = "\n".join(format_session_objects(objs))
    assert "('k-sans-endpoints',) -- 3 paquet(s), 30 octet(s), vu a : A" in texte


def test_format_session_objects_evenement_sans_cause_ni_impact_n_affiche_que_le_message():
    objs = SessionObjects(expert_events=[_event("rien a expliquer")])
    lignes = format_session_objects(objs)
    assert "  [a_surveiller] TCP -- A -> B" in lignes
    assert "      rien a expliquer" in lignes
    assert not any("Cause probable" in ligne or "Impact" in ligne for ligne in lignes)


def test_format_session_objects_evenement_avec_cause_seule_ou_impact_seul():
    objs = SessionObjects(
        expert_events=[
            _event("cause seule", cause="congestion"),
            _event("impact seul", impact="latence accrue"),
        ]
    )
    lignes = format_session_objects(objs)
    assert lignes.count("      Cause probable : congestion") == 1
    assert lignes.count("      Impact : latence accrue") == 1
    # la cause n'apparait que sous l'evenement qui la porte
    assert lignes.index("      cause seule") + 1 == lignes.index("      Cause probable : congestion")
    assert lignes.index("      impact seul") + 1 == lignes.index("      Impact : latence accrue")


def test_format_session_objects_plafonne_les_evenements_et_annonce_le_reste():
    evenements = [_event(f"evt {i}") for i in range(DEFAULT_TOP_N + 3)]
    objs = SessionObjects(expert_events=evenements)
    lignes = format_session_objects(objs)
    assert f"Evenements d'expertise (netcross) : {DEFAULT_TOP_N + 3}" in lignes
    assert "  ... et 3 autre(s) evenement(s) (voir --json-report)" in lignes
    assert "      evt 0" in lignes
    assert f"      evt {DEFAULT_TOP_N}" not in lignes


def test_format_session_objects_diagnostic_sans_cause_ni_impact():
    objs = SessionObjects(diagnoses=[Diagnosis(segment="A -> B", events=[_event()])])
    lignes = format_session_objects(objs)
    assert "Diagnostics par segment : 1" in lignes
    assert "  A -> B -- 1 evenement(s)" in lignes
    assert not any("Cause probable" in ligne or "Impact" in ligne for ligne in lignes)


def test_format_session_objects_diagnostic_avec_cause_seule_ou_impact_seul():
    objs = SessionObjects(
        diagnoses=[
            Diagnosis(segment="A -> B", events=[_event()], cause="congestion"),
            Diagnosis(segment="B -> C", events=[_event()], impact="latence accrue"),
        ]
    )
    lignes = format_session_objects(objs)
    assert lignes.index("  A -> B -- 1 evenement(s)") + 1 == lignes.index("      Cause probable : congestion")
    assert lignes.index("  B -> C -- 1 evenement(s)") + 1 == lignes.index("      Impact : latence accrue")
    assert sum("Cause probable" in ligne for ligne in lignes) == 1
    assert sum("Impact" in ligne for ligne in lignes) == 1


def test_format_session_objects_plafonne_les_diagnostics_et_annonce_le_reste():
    diagnoses = [Diagnosis(segment=f"S{i} -> T{i}", events=[_event()]) for i in range(DEFAULT_TOP_N + 2)]
    objs = SessionObjects(diagnoses=diagnoses)
    lignes = format_session_objects(objs)
    assert "  ... et 2 autre(s) segment(s) (voir --json-report)" in lignes


def test_format_session_objects_plafonne_la_conformite_et_annonce_le_reste():
    from netcross_core.compliance import ComplianceResult

    resultats = [
        ComplianceResult(
            reference=ReferenceProfile(
                id=f"ref-{i:02d}", metric="latence", operator="<=", threshold=20.0, unit="ms", source="RFC test"
            ),
            observed=5.0,
            status="CONFORME",
        )
        for i in range(DEFAULT_TOP_N + 5)
    ]
    objs = SessionObjects(compliance=resultats)
    lignes = format_session_objects(objs)
    assert "  ... et 5 autre(s) referentiel(s) (voir --json-report)" in lignes


def test_format_session_objects_affiche_la_section_tshark_quand_presente():
    """Les signaux tshark bruts ont leur propre bloc dans le rendu console, separe des evenements netcross."""
    objs = SessionObjects(
        wireshark_expert_events=[_event("tcp.analysis.retransmission", source="tshark", segment="A")],
    )
    lignes = format_session_objects(objs)
    assert "Expertise tshark (signaux bruts) : 1" in lignes
    assert "      tcp.analysis.retransmission" in lignes
    # le bloc netcross reste affiche (0 evenement), les deux ne sont jamais fondus
    assert "Evenements d'expertise (netcross) : 0" in lignes


def test_build_session_objects_calcule_wireshark_depuis_all_packets(monkeypatch):
    """Sans signaux deja construits, `all_packets` alimente l'expertise tshark (pas de tshark reel requis)."""
    paquets = [make_pkt(ts=1.0, src="10.0.0.1", dst="10.0.0.2", proto="TCP", length=100)]
    attendu = [_event("tcp.analysis.retransmission", source="tshark", segment="A")]
    appels = []

    def faux_builder(pkts):
        appels.append(pkts)
        return attendu

    monkeypatch.setattr("netcross_report.session_objects.build_wireshark_expert_events", faux_builder)
    objs = build_session_objects(_report_congestion(), [], all_packets=paquets)
    assert appels == [paquets]
    assert objs.wireshark_expert_events == attendu


def test_build_session_objects_prefere_les_signaux_wireshark_deja_construits(monkeypatch):
    """`wireshark_expert_events` fourni est prioritaire sur `all_packets` : jamais recalcule."""

    def builder_interdit(pkts):
        raise AssertionError("les signaux tshark ne doivent pas etre recalcules")

    monkeypatch.setattr("netcross_report.session_objects.build_wireshark_expert_events", builder_interdit)
    deja_la = [_event("deja calcule", source="tshark", segment="A")]
    paquets = [make_pkt(ts=1.0, src="10.0.0.1", dst="10.0.0.2", proto="TCP", length=100)]
    objs = build_session_objects(_report_congestion(), [], all_packets=paquets, wireshark_expert_events=deja_la)
    assert objs.wireshark_expert_events is deja_la
