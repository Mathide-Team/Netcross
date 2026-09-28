"""
netcross_report.session_objects -- extraction du bloc de construction des
objets enrichis (Job 4/issue #13) et rendu console/PDF.

Verifie trois choses distinctes :

1. `build_session_objects()` produit EXACTEMENT ce que le bloc en ligne de
   `cross_capture_analyzer_cli.py` produisait sous `--json-report` (memes
   appels, meme ordre, notamment cause/impact deja correles) ;
2. la convention d'absence est respectee -- `flows` absent -> pas de
   Flow/Conversation, `all_packets` absent -> `wireshark_expert_events`
   reste `None` et la cle JSON disparait (et non `[]`, qui affirmerait a
   tort qu'aucun signal tshark n'existe) ;
3. le rendu console (`format_session_objects`) et le rendu PDF
   (`netcross_report.pdf.expert_section_story`) exposent bien cause/impact
   et la conformite, plafonnent leurs listes, et ne produisent RIEN quand
   il n'y a rien a montrer.
"""

import pytest
from conftest import make_pkt

from netcross_core.expert_model import Diagnosis, ExpertEvent, Flow, ReferenceProfile
from netcross_core.models import Report
from netcross_report.session_objects import (
    DEFAULT_TOP_N,
    SessionObjects,
    build_session_objects,
    format_session_objects,
    print_session_objects,
)
from netcross_report.synthesis import Finding


def _report_congestion():
    """Report portant les trois symptomes du pattern "congestion" de
    netcross_core.causality (pertes + retransmission TCP + bufferbloat sur
    le MEME segment) -- le seul moyen d'obtenir des cause/impact non nuls
    sans dupliquer ici la logique du moteur de correlation."""
    r = Report(points=["A", "B"])
    r.pairs = [("A", "B")]
    return r


def _findings_congestion(segment="A -> B"):
    return [
        Finding("anomalie", "Pertes", segment, "12% de pertes", rule_id="loss_per_segment"),
        Finding("anomalie", "TCP", segment, "retransmissions RTO", rule_id="tcp_retransmission_rto"),
        Finding("a_surveiller", "Bufferbloat", segment, "file d'attente qui gonfle", rule_id="bufferbloat"),
    ]


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


# -- build_session_objects ---------------------------------------------


def test_build_session_objects_convertit_les_findings_en_expert_events():
    r = _report_congestion()
    findings = _findings_congestion()
    objs = build_session_objects(r, findings)
    assert len(objs.expert_events) == 3
    assert [ev.rule_id for ev in objs.expert_events] == [
        "loss_per_segment",
        "tcp_retransmission_rto",
        "bufferbloat",
    ]


def test_build_session_objects_groupe_les_diagnoses_par_segment():
    r = _report_congestion()
    findings = [*_findings_congestion(), Finding("anomalie", "DNS", "C", "timeout DNS", rule_id="dns_timeout")]
    objs = build_session_objects(r, findings)
    assert [d.segment for d in objs.diagnoses] == ["A -> B", "C"]
    assert len(objs.diagnoses[0].events) == 3
    assert len(objs.diagnoses[1].events) == 1


def test_build_session_objects_applique_le_moteur_de_causalite():
    """cause/impact ne doivent PAS rester None : le bloc CLI appelait
    correlate_event_causes()/correlate_diagnosis_causes(), c'est la
    difference entre cette fonction et un simple build_expert_events()."""
    r = _report_congestion()
    objs = build_session_objects(r, _findings_congestion())
    causes = [ev.cause for ev in objs.expert_events if ev.cause]
    assert causes, "aucun ExpertEvent enrichi : le moteur de causalite n'a pas tourne"
    assert any("congestion" in c.lower() for c in causes)


def test_build_session_objects_propage_la_cause_aux_diagnoses():
    r = _report_congestion()
    objs = build_session_objects(r, _findings_congestion())
    diag = objs.diagnoses[0]
    assert diag.cause is not None
    assert diag.impact is not None


def test_build_session_objects_evalue_toujours_la_conformite():
    """evaluate_compliance() ne depend que du Report : elle doit tourner
    meme sans flows ni paquets bruts."""
    objs = build_session_objects(_report_congestion(), [])
    assert objs.compliance, "aucun referentiel evalue"
    assert all(res.status in {"CONFORME", "DEVIATION", "VIOLATION", "INDETERMINE"} for res in objs.compliance)


def test_build_session_objects_sans_flows_ne_produit_ni_flow_ni_conversation():
    objs = build_session_objects(_report_congestion(), _findings_congestion())
    assert objs.flows == []
    assert objs.conversations == []
    # ... mais les evenements, eux, ne dependent pas des flux :
    assert objs.expert_events


def test_build_session_objects_sans_paquets_laisse_wireshark_a_none():
    """None et [] doivent rester distinguables : "non calcule" n'est pas
    "calcule, rien trouve"."""
    objs = build_session_objects(_report_congestion(), [])
    assert objs.wireshark_expert_events is None


def test_build_session_objects_avec_flows_construit_flows_et_conversations():
    pkt = make_pkt(ts=1.0, src="10.0.0.1", dst="10.0.0.2", proto="TCP", length=100)
    flows = {("10.0.0.1", "10.0.0.2", 1234, 80, "TCP"): {"A": [pkt], "B": [pkt]}}
    objs = build_session_objects(_report_congestion(), [], flows=flows)
    assert len(objs.flows) == 1
    assert len(objs.conversations) == 1
    assert objs.flows[0].points == ["A", "B"]


# -- json_kwargs -------------------------------------------------------


def test_json_kwargs_omet_wireshark_quand_non_calcule():
    objs = SessionObjects(flows=[], conversations=[], expert_events=[], diagnoses=[], compliance=[])
    assert "wireshark_expert_events" not in objs.json_kwargs()


def test_json_kwargs_inclut_wireshark_meme_vide_quand_calcule():
    objs = SessionObjects(wireshark_expert_events=[])
    kwargs = objs.json_kwargs()
    assert kwargs["wireshark_expert_events"] == []


def test_json_kwargs_expose_les_cinq_cles_attendues_par_generate_json_report():
    objs = SessionObjects()
    assert set(objs.json_kwargs()) == {
        "flows",
        "conversations",
        "expert_events",
        "diagnoses",
        "compliance",
    }


# -- rendu console -----------------------------------------------------


def test_format_session_objects_expose_cause_et_impact():
    objs = build_session_objects(_report_congestion(), _findings_congestion())
    texte = "\n".join(format_session_objects(objs))
    assert "EXPERTISE -- OBJETS ENRICHIS" in texte
    assert "Cause probable :" in texte
    assert "Impact :" in texte


def test_format_session_objects_compte_les_evenements():
    objs = build_session_objects(_report_congestion(), _findings_congestion())
    lignes = format_session_objects(objs)
    assert any(ligne.startswith("Evenements d'expertise (netcross) : 3") for ligne in lignes)


def test_format_session_objects_affiche_zero_evenement():
    """Bloc TOUJOURS present, meme a zero : "l'analyse a tourne et n'a rien
    diagnostique" est une information, contrairement a une section flux
    absente parce que l'appelant n'a pas passe flows."""
    objs = build_session_objects(_report_congestion(), [])
    lignes = format_session_objects(objs)
    assert any(ligne.startswith("Evenements d'expertise (netcross) : 0") for ligne in lignes)


def test_format_session_objects_omet_le_bloc_flux_quand_absent():
    objs = build_session_objects(_report_congestion(), [])
    texte = "\n".join(format_session_objects(objs))
    assert "Flux correles" not in texte


def test_format_session_objects_omet_le_bloc_tshark_quand_non_calcule():
    objs = build_session_objects(_report_congestion(), [])
    texte = "\n".join(format_session_objects(objs))
    assert "Expertise tshark" not in texte


def test_format_session_objects_trie_les_flux_par_volume_decroissant():
    objs = SessionObjects(
        flows=[
            _flow(("a",), ("10.0.0.1", "10.0.0.2"), ["A"], {"A": 10}, {"A": 1000}),
            _flow(("b",), ("10.0.0.3", "10.0.0.4"), ["A"], {"A": 900}, {"A": 90000}),
        ],
        conversations=[],
    )
    lignes = [line for line in format_session_objects(objs) if line.startswith("  10.")]
    assert "10.0.0.3" in lignes[0]
    assert "10.0.0.1" in lignes[1]


def test_format_session_objects_plafonne_les_flux_et_annonce_le_reste():
    flows = [
        _flow((f"k{i}",), (f"10.0.0.{i}", "10.0.1.1"), ["A"], {"A": 100 - i}, {"A": 10})
        for i in range(DEFAULT_TOP_N + 4)
    ]
    objs = SessionObjects(flows=flows, conversations=[])
    texte = "\n".join(format_session_objects(objs))
    assert "... et 4 autre(s) flux" in texte


def test_format_session_objects_top_n_nul_desactive_le_plafond():
    flows = [
        _flow((f"k{i}",), (f"10.0.0.{i}", "10.0.1.1"), ["A"], {"A": 100 - i}, {"A": 10})
        for i in range(DEFAULT_TOP_N + 4)
    ]
    objs = SessionObjects(flows=flows, conversations=[])
    texte = "\n".join(format_session_objects(objs, top_n=0))
    assert "autre(s) flux" not in texte


def test_format_session_objects_resume_les_statuts_de_conformite():
    ref = ReferenceProfile(
        id="rfc6349-test",
        metric="latence",
        operator="<=",
        threshold=20.0,
        unit="ms",
        source="RFC 6349",
    )
    from netcross_core.compliance import ComplianceResult

    objs = SessionObjects(
        compliance=[
            ComplianceResult(reference=ref, observed=50.0, status="VIOLATION"),
            ComplianceResult(reference=ref, observed=5.0, status="CONFORME"),
        ]
    )
    ligne = next(line for line in format_session_objects(objs) if line.startswith("Conformite"))
    # ordre du plus grave au moins grave, jamais l'ordre d'insertion
    assert "1 VIOLATION, 1 CONFORME" in ligne


def test_format_session_objects_affiche_non_mesure_quand_observed_est_none():
    from netcross_core.compliance import ComplianceResult

    ref = ReferenceProfile(
        id="rfc9544-test",
        metric="jitter",
        operator="<=",
        threshold=5.0,
        unit="ms",
        source="RFC 9544",
    )
    objs = SessionObjects(compliance=[ComplianceResult(reference=ref, observed=None, status="INDETERMINE")])
    texte = "\n".join(format_session_objects(objs))
    assert "non mesure" in texte


def test_print_session_objects_ecrit_sur_stdout(capsys):
    objs = build_session_objects(_report_congestion(), _findings_congestion())
    print_session_objects(objs)
    out = capsys.readouterr().out
    assert "EXPERTISE -- OBJETS ENRICHIS" in out
    assert out.endswith("\n")


# -- rendu PDF ---------------------------------------------------------

pdf = pytest.importorskip("netcross_report.pdf", reason="reportlab/matplotlib absents")


def test_expert_section_story_vide_quand_session_objects_absent():
    """Un PDF genere sans ces objets doit rester identique a celui des
    sessions precedentes : aucune section, aucun titre orphelin."""
    assert pdf.expert_section_story(None, pdf._styles()) == []


def test_expert_section_story_contient_les_trois_sous_sections_de_base():
    objs = build_session_objects(_report_congestion(), _findings_congestion())
    story = pdf.expert_section_story(objs, pdf._styles())
    textes = [f.getPlainText() for f in story if hasattr(f, "getPlainText")]
    assert "Expertise -- objets enrichis" in textes
    assert "Evenements d'expertise" in textes
    assert "Diagnostics par segment" in textes
    assert "Conformite aux referentiels" in textes


def test_expert_section_story_omet_flux_et_tshark_quand_absents():
    objs = build_session_objects(_report_congestion(), _findings_congestion())
    story = pdf.expert_section_story(objs, pdf._styles())
    textes = [f.getPlainText() for f in story if hasattr(f, "getPlainText")]
    assert "Flux correles" not in textes
    assert "Expertise tshark (signaux bruts)" not in textes


def test_expert_section_story_ajoute_la_section_tshark_quand_presente():
    objs = build_session_objects(_report_congestion(), _findings_congestion())
    objs.wireshark_expert_events = [
        ExpertEvent(
            category="TCP",
            severity="a_surveiller",
            segment="A",
            message="tcp.analysis.retransmission",
            source="tshark",
        )
    ]
    story = pdf.expert_section_story(objs, pdf._styles())
    textes = [f.getPlainText() for f in story if hasattr(f, "getPlainText")]
    assert "Expertise tshark (signaux bruts)" in textes


def test_expert_event_table_affiche_cause_et_impact():
    objs = build_session_objects(_report_congestion(), _findings_congestion())
    table = pdf._expert_event_table(objs.expert_events, pdf._styles())
    entetes = [str(c) for c in table._cellvalues[0]]
    assert entetes == ["Gravite", "Categorie", "Segment", "Constat", "Cause probable / impact"]
    colonne_cause = [row[4].getPlainText() for row in table._cellvalues[1:]]
    assert any("congestion" in c.lower() for c in colonne_cause)


def test_expert_event_table_sans_evenement_renvoie_un_paragraphe():
    flowable = pdf._expert_event_table([], pdf._styles())
    assert flowable.getPlainText() == "Aucun evenement d'expertise."


def test_expert_event_table_plafonne_les_lignes():
    events = [
        ExpertEvent(category="Pertes", severity="anomalie", segment=f"S{i}", message="m")
        for i in range(pdf.EXPERT_TABLE_TOP_N + 5)
    ]
    table = pdf._expert_event_table(events, pdf._styles())
    assert len(table._cellvalues) == pdf.EXPERT_TABLE_TOP_N + 1  # + l'en-tete


def test_diagnosis_table_remplace_cause_absente_par_un_tiret():
    table = pdf._diagnosis_table([Diagnosis(segment="A -> B")], pdf._styles())
    ligne = table._cellvalues[1]
    assert ligne[2].getPlainText() == "-"
    assert ligne[3].getPlainText() == "-"


def test_compliance_table_met_les_violations_en_premier():
    from netcross_core.compliance import ComplianceResult

    def _ref(rid):
        return ReferenceProfile(id=rid, metric="latence", operator="<=", threshold=20.0, unit="ms", source="RFC 6349")

    results = [
        ComplianceResult(reference=_ref("conforme-1"), observed=1.0, status="CONFORME"),
        ComplianceResult(reference=_ref("violation-1"), observed=99.0, status="VIOLATION"),
        ComplianceResult(reference=_ref("deviation-1"), observed=21.0, status="DEVIATION"),
    ]
    table = pdf._compliance_table(results, pdf._styles())
    statuts = [row[0] for row in table._cellvalues[1:]]
    assert statuts == ["VIOLATION", "DEVIATION", "CONFORME"]


def test_flow_table_trie_par_volume_et_affiche_les_totaux():
    flows = [
        _flow(("a",), ("10.0.0.1", "10.0.0.2"), ["A", "B"], {"A": 5, "B": 5}, {"A": 100, "B": 100}),
        _flow(("b",), ("10.0.0.3", "10.0.0.4"), ["A"], {"A": 50}, {"A": 5000}),
    ]
    table = pdf._flow_table(flows, pdf._styles())
    premiere = table._cellvalues[1]
    assert "10.0.0.3" in premiere[0].getPlainText()
    assert premiere[2] == "50"
    # totaux sommes sur TOUS les points du flux, pas seulement le premier
    seconde = table._cellvalues[2]
    assert seconde[2] == "10"
    assert seconde[3] == "200"


def test_compliance_table_expose_le_seuil_dans_la_colonne_mesure():
    from netcross_core.compliance import ComplianceResult

    ref = ReferenceProfile(
        id="rfc6349-rtt-50ms",
        metric="avg_rtt_ms",
        operator="<=",
        threshold=50.0,
        unit="ms",
        source="RFC 6349 section 4.3",
    )
    table = pdf._compliance_table([ComplianceResult(reference=ref, observed=12.0, status="CONFORME")], pdf._styles())
    assert [str(c) for c in table._cellvalues[0]] == ["Statut", "Referentiel", "Mesure", "Source"]
    mesure = table._cellvalues[1][2].getPlainText()
    assert "avg_rtt_ms" in mesure
    assert "12 ms" in mesure
    assert "seuil <= 50 ms" in mesure


def test_compliance_table_assez_large_pour_les_identifiants_du_catalogue():
    """Garde-fou de mise en page : reportlab coupe les identifiants en plein
    mot quand ils depassent la colonne (et les espaces de largeur nulle
    s'affichent en carre noir avec les polices de base). Si un referentiel
    au nom plus long arrive dans DEFAULT_REFERENCES, ce test casse AVANT
    que le PDF ne devienne illisible."""
    from reportlab.lib.units import cm
    from reportlab.pdfbase.pdfmetrics import stringWidth

    from netcross_core.compliance import DEFAULT_REFERENCES

    style = pdf._styles()["Cell"]
    largeur_id, largeur_mesure = 4.3 * cm, 5.2 * cm
    marge = 0.45 * cm  # padding gauche + droite des cellules de _grid_table
    for ref in DEFAULT_REFERENCES:
        assert stringWidth(ref.id, style.fontName, style.fontSize) <= largeur_id - marge, ref.id
        # colonne "Mesure" : le nom de la metrique occupe sa propre ligne,
        # c'est donc lui le plus long jeton insecable (la valeur et le seuil
        # se replient aux espaces en dessous)
        assert stringWidth(ref.metric, style.fontName, style.fontSize) <= largeur_mesure - marge, ref.metric


# -- Issue #731 : troncatures et libelles de secours --------------------------


def test_flow_label_sans_endpoints_utilise_la_cle():
    """Lignes 166-167 : un Flow sans endpoints est libelle par sa cle."""
    from netcross_report.session_objects import _flow_label

    assert _flow_label(Flow(key=("10.0.0.1", 80))) == str(("10.0.0.1", 80))


def test_format_session_objects_tronque_chaque_bloc():
    """Lignes 228, 248, 286 et 312 : au-dela de top_n, chaque bloc
    (evenements, diagnostics, conformite, expertise tshark) annonce le reste."""
    from netcross_core.compliance import ComplianceResult

    evs = [ExpertEvent(category="perte", severity="critique", segment="A", message=f"m{i}") for i in range(3)]
    diags = [Diagnosis(segment=f"S{i}") for i in range(3)]
    ref = ReferenceProfile(id="r", metric="latency", operator="<=", threshold=20.0, unit="ms", source="RFC")
    comp = [ComplianceResult(reference=ref, observed=float(i), status="CONFORME") for i in range(3)]
    objs = SessionObjects(
        expert_events=evs,
        diagnoses=diags,
        compliance=comp,
        wireshark_expert_events=evs,
    )
    texte = "\n".join(format_session_objects(objs, top_n=1))
    assert "autre(s) evenement(s)" in texte
    assert "autre(s) segment(s)" in texte
    assert "autre(s) referentiel(s)" in texte
    assert "Expertise tshark (signaux bruts)" in texte
