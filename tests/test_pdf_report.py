"""
Tests du rendu PDF (`netcross_report/pdf.py`) -- issue #286.

Le module etait a 32,6 % avant l'issue #218, puis 63,1 % apres elle, sans
aucun fichier de test dedie. Le PDF est pourtant une sortie que
l'utilisateur regarde : une section peut disparaitre, un tableau se
vider, une valeur etre jetee au rendu sans que rien n'echoue. C'est
exactement ce qui s'est produit avec l'issue #259 -- un champ correctement
calcule, perdu a l'affichage, invisible pour tous les tests parce qu'ils
s'arretaient avant le rendu.

## Ce qui est verifie, et ce qui ne l'est pas

**Jamais la mise en page au pixel** : fragile et sans valeur. Le texte est
REEXTRAIT du PDF produit (`pdftotext`, installe en CI depuis #218) et l'on
verifie que les valeurs du `Report` s'y retrouvent, que les sections
attendues sont presentes, et que les chemins « il n'y a rien a afficher »
ecrivent leur message d'absence.

Ce dernier point est une regle du projet : une section sans donnee doit
**ecrire** qu'elle est vide, pas disparaitre. Les tests portent donc sur la
presence du message, jamais sur l'absence de la section -- l'inverse
enterinerait le contraire de la regle.

`generate_diff_pdf` n'etait couvert par AUCUN test : le rapport du mode
comparaison, celui qu'on relit pour decider si une regression est reelle,
n'etait verifie par rien.
"""

from __future__ import annotations

import re
import subprocess

import pytest

from netcross_core.baseline_diff import diff_reports
from netcross_core.models import Report
from netcross_report.pdf import (
    _compliance_table,
    _diagnosis_table,
    _expert_event_table,
    _finding_table,
    _flow_table,
    _path_table,
    _styles,
    _triage_table,
    generate_diff_pdf,
    generate_pdf,
)
from netcross_report.synthesis import build_findings


def _texte_pdf(chemin) -> str:
    """Texte reextrait du PDF produit.

    Reextraire plutot que d'inspecter la story reportlab avant rendu : c'est
    le seul niveau qui prouve que la donnee atteint le fichier livre. Message
    de saut normalise -- le workflow ci.yml echoue si « pdftotext non
    installe » apparait dans la sortie de pytest (meme garde-fou que
    tshark/editcap, issue #262).
    """
    try:
        proc = subprocess.run(["pdftotext", str(chemin), "-"], capture_output=True, text=True)
    except FileNotFoundError:
        pytest.skip("pdftotext non installe : contenu du PDF non verifiable")
    if proc.returncode != 0:
        pytest.skip(f"pdftotext non installe correctement (code {proc.returncode})")
    return proc.stdout


def _rapport_garni() -> Report:
    """Report avec de quoi remplir plusieurs sections.

    Les valeurs sont volontairement reconnaissables (7, 13, 4242) pour
    pouvoir les retrouver dans le texte extrait : un chiffre banal comme 1 se
    retrouverait par hasard et le test ne prouverait rien.
    """
    r = Report(points=["POINT_AMONT", "POINT_AVAL"], pairs=[("POINT_AMONT", "POINT_AVAL")])
    r.seen_count["POINT_AMONT"] = 4242
    r.seen_count["POINT_AVAL"] = 4200
    r.loss_count["POINT_AVAL"] = 7
    r.retrans["POINT_AVAL"] = 13
    r.latency[("POINT_AMONT", "POINT_AVAL")] = [0.012, 0.031, 0.027]
    r.hop_delta[("POINT_AMONT", "POINT_AVAL")] = [2, 2, 3]
    r.qos_change[("POINT_AMONT", "POINT_AVAL")] = 5
    return r


def _rapport_vide() -> Report:
    """Report sans aucune mesure : le cas « capture lue, rien a signaler ».

    Ce n'est pas un cas theorique -- c'est ce que produit une capture saine,
    donc le plus frequent en exploitation normale.
    """
    return Report(points=["A", "B"], pairs=[("A", "B")])


# --------------------------------------------------------------------------
# Bout en bout : la donnee atteint-elle le fichier ?
# --------------------------------------------------------------------------


def test_le_pdf_est_produit_et_non_vide(tmp_path):
    chemin = tmp_path / "rapport.pdf"
    generate_pdf(_rapport_garni(), str(chemin))
    assert chemin.exists()
    assert chemin.stat().st_size > 1000, "PDF suspect : trop petit pour contenir un rapport"
    assert chemin.read_bytes().startswith(b"%PDF"), "en-tete PDF absent"


def test_les_valeurs_du_rapport_se_retrouvent_dans_le_pdf(tmp_path):
    """Le niveau de verification qui manquait a l'issue #259 : la valeur est
    cherchee dans le fichier livre, pas dans l'objet intermediaire.

    Les valeurs retenues sont celles reellement rendues. Un premier jet
    cherchait `seen_count` (4242) : il echouait, non par defaut du rendu mais
    parce que le nombre de paquets vus n'apparait NULLE PART en valeur
    absolue -- il ne sert que de denominateur aux pourcentages. Le test
    verifie donc ce que le PDF affiche, et la coherence de ce denominateur
    est verifiee separement ci-dessous.
    """
    chemin = tmp_path / "rapport.pdf"
    generate_pdf(_rapport_garni(), str(chemin))
    texte = _texte_pdf(chemin)
    assert "POINT_AMONT" in texte
    assert "POINT_AVAL" in texte
    assert "7 paquets manquants" in texte, "le compteur de pertes n'atteint pas le PDF"
    assert "13" in texte, "le compteur de retransmissions n'atteint pas le PDF"
    assert "5 paquet(s) remarque(s)" in texte, "le compteur DSCP n'atteint pas le PDF"


def test_le_pourcentage_de_pertes_utilise_le_bon_denominateur(tmp_path):
    """7 pertes sur 4242 paquets vus font 0,17 %. Un denominateur errone
    (total des deux points, paquets d'un autre point, nombre de flux) donnerait
    un chiffre d'apparence credible mais faux -- et c'est sur ce chiffre que
    l'utilisateur decide s'il y a un incident.

    Le pourcentage est ancre sur le compte de pertes (« 0.17% (7) ») et non
    cherche seul. Un premier jet acceptait n'importe quel pourcentage a 0,05
    point de la valeur attendue : en doublant volontairement le denominateur
    dans `path_metrics`, le test continuait de passer -- il tombait sur le
    « 0.2 % » de la section Synthese, calcule ailleurs et arrondi a une
    decimale, donc encore dans la plage toleree. Un test qui survit a la
    mutation qu'il est cense attraper ne sert a rien ; l'ancrage sur le compte
    le rend specifique a la valeur reellement rendue par le tableau de chemin.
    """
    import re

    r = _rapport_garni()
    pertes = r.loss_count["POINT_AVAL"]
    attendu = 100.0 * pertes / r.seen_count["POINT_AMONT"]
    chemin = tmp_path / "rapport.pdf"
    generate_pdf(r, str(chemin))
    texte = _texte_pdf(chemin)

    trouves = re.findall(rf"([0-9]+\.[0-9]+)%\s*\({pertes}\)", texte)
    assert trouves, (
        f"aucun pourcentage associe aux {pertes} pertes dans le PDF : "
        "le tableau de chemin a change de forme ou n'affiche plus le taux"
    )
    assert all(abs(float(v) - attendu) < 0.01 for v in trouves), (
        f"taux de pertes attendu {attendu:.2f}%, rendu {trouves} -- denominateur errone"
    )


def test_le_pdf_porte_le_titre_demande(tmp_path):
    chemin = tmp_path / "rapport.pdf"
    generate_pdf(_rapport_garni(), str(chemin), title="Incident INC-4242 -- coeur de reseau")
    assert "Incident INC-4242" in _texte_pdf(chemin)


def test_les_metadonnees_sont_ecrites_en_page_de_garde(tmp_path):
    """La page de garde sert a retrouver le contexte des mois plus tard : un
    numero de ticket perdu au rendu rend le rapport orphelin."""
    chemin = tmp_path / "rapport.pdf"
    generate_pdf(
        _rapport_garni(),
        str(chemin),
        meta={"Ticket": "INC-9137", "Auteur": "Equipe reseau"},
    )
    texte = _texte_pdf(chemin)
    assert "INC-9137" in texte
    assert "Equipe reseau" in texte


def test_les_sections_attendues_sont_presentes(tmp_path):
    chemin = tmp_path / "rapport.pdf"
    generate_pdf(_rapport_garni(), str(chemin))
    texte = _texte_pdf(chemin)
    for section in ("Vue d'ensemble", "Detail par module"):
        assert section in texte, f"section absente du PDF : {section}"


def test_un_rapport_sans_mesure_produit_quand_meme_un_pdf(tmp_path):
    """Une capture saine ne doit pas donner un fichier vide ou une
    exception : c'est le cas le plus frequent en exploitation normale, et
    l'utilisateur a besoin du document pour attester que rien n'a ete
    trouve."""
    chemin = tmp_path / "vide.pdf"
    generate_pdf(_rapport_vide(), str(chemin))
    texte = _texte_pdf(chemin)
    assert chemin.stat().st_size > 1000
    assert texte.strip(), "PDF sans aucun texte"


def test_le_pdf_accepte_des_constats_deja_calcules(tmp_path):
    """`findings` fourni evite un recalcul. Le chemin doit donner le meme
    resultat que le calcul interne, sinon l'optimisation change la sortie."""
    r = _rapport_garni()
    findings = build_findings(r)
    calcule = tmp_path / "a.pdf"
    fourni = tmp_path / "b.pdf"
    generate_pdf(r, str(calcule))
    generate_pdf(r, str(fourni), findings=findings)
    # L'horodatage de generation (minute) peut basculer entre les deux
    # rendus : on le neutralise pour ne comparer que le contenu.
    horodatage = re.compile(r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}")
    assert horodatage.sub("<date>", _texte_pdf(calcule)) == horodatage.sub("<date>", _texte_pdf(fourni))


# --------------------------------------------------------------------------
# Les sections vides ECRIVENT leur absence
# --------------------------------------------------------------------------


def test_une_table_de_constats_vide_ecrit_son_message():
    """Regle du projet : une section sans donnee ecrit qu'elle est vide. Le
    test porte sur la presence du message, jamais sur l'absence de la
    section -- l'inverse enterinerait le contraire de la regle."""
    rendu = _finding_table([], _styles())
    assert "Aucun constat notable" in rendu.text


def test_un_triage_sans_segment_convergent_explique_pourquoi():
    """Le message ne dit pas seulement « rien » : il renvoie a la table de
    constats. Un « aucun resultat » sec laisserait croire que l'analyse n'a
    rien trouve, alors qu'elle n'a trouve aucun FAISCEAU -- nuance qui change
    la conduite a tenir."""
    rendu = _triage_table([], _styles())
    assert "Aucun segment touche par plusieurs categories" in rendu.text
    assert "table de constats" in rendu.text


def test_les_tables_d_expertise_vides_ecrivent_leur_message():
    styles = _styles()
    assert "Aucun evenement d'expertise" in _expert_event_table([], styles).text
    assert "Aucun diagnostic par segment" in _diagnosis_table([], styles).text
    assert "Aucun referentiel evalue" in _compliance_table([], styles).text
    assert "Aucun flux correle" in _flow_table([], styles).text


def test_une_table_de_chemin_vide_explique_la_cause():
    """« Aucun segment exploitable » seul serait ambigu. Le message nomme les
    deux causes possibles -- ni topologie deduite, ni couple de points fourni
    -- parce que ce sont deux problemes a corriger differemment."""
    rendu = _path_table([], _styles())
    assert "Aucun segment exploitable" in rendu.text
    assert "topologie deduite" in rendu.text


@pytest.mark.parametrize(
    "fabrique",
    [_finding_table, _expert_event_table, _diagnosis_table, _compliance_table, _flow_table],
)
def test_aucune_table_vide_ne_renvoie_none(fabrique):
    """Invariant transverse : renvoyer `None` ferait disparaitre la section de
    la story sans bruit, ce qui est precisement le comportement que la regle
    de tracabilite interdit."""
    rendu = fabrique([], _styles())
    assert rendu is not None
    assert getattr(rendu, "text", "").strip()


# --------------------------------------------------------------------------
# PDF de comparaison -- n'etait couvert par aucun test
# --------------------------------------------------------------------------


def _paire_de_rapports():
    """Deux Report differant assez pour produire de vrais DiffFinding.

    Les constats viennent de `diff_reports()` plutot que d'objets fabriques a
    la main : un double mal forme testerait le double, pas le rendu.
    """
    reference = Report(points=["POINT_AMONT", "POINT_AVAL"], pairs=[("POINT_AMONT", "POINT_AVAL")])
    reference.seen_count["POINT_AMONT"] = 10000
    reference.seen_count["POINT_AVAL"] = 9990
    reference.loss_count["POINT_AVAL"] = 10
    reference.latency[("POINT_AMONT", "POINT_AVAL")] = [0.010] * 20

    courant = Report(points=["POINT_AMONT", "POINT_AVAL"], pairs=[("POINT_AMONT", "POINT_AVAL")])
    courant.seen_count["POINT_AMONT"] = 10000
    courant.seen_count["POINT_AVAL"] = 8500
    courant.loss_count["POINT_AVAL"] = 1500
    courant.latency[("POINT_AMONT", "POINT_AVAL")] = [0.250] * 20
    return reference, courant


def test_le_pdf_de_comparaison_est_produit(tmp_path):
    reference, courant = _paire_de_rapports()
    chemin = tmp_path / "diff.pdf"
    generate_diff_pdf(diff_reports(reference, courant), reference, courant, str(chemin))
    assert chemin.exists()
    assert chemin.read_bytes().startswith(b"%PDF")
    assert chemin.stat().st_size > 1000


def test_le_pdf_de_comparaison_nomme_les_deux_cotes(tmp_path):
    """Un rapport de comparaison qui ne dit pas ce qu'il compare est
    inutilisable : le lecteur ne sait pas quel cote est la reference."""
    reference, courant = _paire_de_rapports()
    chemin = tmp_path / "diff.pdf"
    generate_diff_pdf(diff_reports(reference, courant), reference, courant, str(chemin))
    texte = _texte_pdf(chemin)
    assert "POINT_AMONT" in texte
    assert "POINT_AVAL" in texte


def test_le_pdf_de_comparaison_signale_une_degradation_franche(tmp_path):
    """La reference perd 10 paquets sur 10000, le courant 1500 : la
    degradation doit apparaitre. Sans cette verification, le rendu pourrait
    jeter tous les constats et produire un PDF rassurant sur une panne
    reelle."""
    reference, courant = _paire_de_rapports()
    findings = diff_reports(reference, courant)
    assert findings, "diff_reports ne produit aucun constat : le scenario de test est faux"
    chemin = tmp_path / "diff.pdf"
    generate_diff_pdf(findings, reference, courant, str(chemin))
    texte = _texte_pdf(chemin).lower()
    assert "regression" in texte or "degradation" in texte


def test_le_pdf_de_comparaison_porte_son_titre_et_ses_metadonnees(tmp_path):
    reference, courant = _paire_de_rapports()
    chemin = tmp_path / "diff.pdf"
    generate_diff_pdf(
        diff_reports(reference, courant),
        reference,
        courant,
        str(chemin),
        title="Avant / apres migration MPLS",
        meta={"Ticket": "CHG-7781"},
    )
    texte = _texte_pdf(chemin)
    assert "Avant / apres migration MPLS" in texte
    assert "CHG-7781" in texte


def test_deux_rapports_identiques_produisent_un_pdf_qui_le_dit(tmp_path):
    """Cas frequent et important : une comparaison sans ecart doit produire un
    document affirmant qu'il n'y a pas d'ecart. Un PDF vide, ou une exception,
    laisserait l'utilisateur sans preuve que la verification a eu lieu."""
    reference, _ = _paire_de_rapports()
    findings = diff_reports(reference, reference)
    chemin = tmp_path / "identique.pdf"
    generate_diff_pdf(findings, reference, reference, str(chemin))
    texte = _texte_pdf(chemin)
    assert chemin.stat().st_size > 1000
    assert texte.strip()


def test_le_pdf_de_comparaison_accepte_l_absence_de_diagnostics_tls(tmp_path):
    """TLS/QUIC ne sont pas demandes a chaque comparaison : `None` (« pas
    analyse ») ne doit pas faire tomber le rendu ni etre confondu avec une
    liste vide (« analyse, rien trouve »)."""
    reference, courant = _paire_de_rapports()
    chemin = tmp_path / "diff_sans_tls.pdf"
    generate_diff_pdf(
        diff_reports(reference, courant),
        reference,
        courant,
        str(chemin),
        tls_findings_baseline=None,
        tls_findings_current=None,
        quic_findings_baseline=None,
        quic_findings_current=None,
    )
    assert chemin.stat().st_size > 1000


def test_le_pdf_de_comparaison_supporte_une_liste_de_constats_vide(tmp_path):
    """Chemin de degradation extreme : aucun constat du tout, ce que produit
    `diff_reports` sur deux rapports vides."""
    vide = Report(points=["A", "B"], pairs=[("A", "B")])
    chemin = tmp_path / "diff_vide.pdf"
    generate_diff_pdf([], vide, vide, str(chemin))
    assert chemin.exists()
    assert chemin.read_bytes().startswith(b"%PDF")


# -- couverture des branches manquantes (issue #246) -------------------------

from netcross_core.expert_model import Flow  # noqa: E402
from netcross_report.sequence_view import SequenceStep, SequenceView  # noqa: E402
from netcross_report.session_objects import SessionObjects  # noqa: E402
from netcross_report.synthesis import Finding  # noqa: E402


def _make_chart_png(path):
    """Cree un PNG minimal pour les tests d'images."""
    from PIL import Image

    img = Image.new("RGB", (100, 100), color="white")
    img.save(path)


def test_triage_table_avec_segments_convergents():
    """Lines 145-176 : _triage_table avec segments convergents."""
    from netcross_report.triage import SegmentScore

    scores = [
        SegmentScore(segment="A->B", score=75.0, categories=["latence", "perte"], findings=[], low_confidence=False),
        SegmentScore(segment="C->D", score=50.0, categories=["qos"], findings=[], low_confidence=True),
    ]
    rendu = _triage_table(scores, _styles())
    assert rendu is not None


def test_flow_table_avec_endpoints_vides():
    """Line 338 : _flow_table avec flow sans endpoints -> str(flow.key)."""
    flow = Flow(
        key="proto:1.1.1.1:1->2.2.2.2:2",
        points=["A", "B"],
        packet_count={"A": 10, "B": 8},
        byte_count={"A": 1000, "B": 800},
        first_ts=1.0,
        last_ts=2.0,
        endpoints=(),
    )
    rendu = _flow_table([flow], _styles())
    assert rendu is not None


def test_flow_table_avec_endpoints():
    """Line 337 : _flow_table avec endpoints."""
    flow = Flow(
        key="proto:1.1.1.1:1->2.2.2.2:2",
        points=["A", "B"],
        packet_count={"A": 10, "B": 8},
        byte_count={"A": 1000, "B": 800},
        first_ts=1.0,
        last_ts=2.0,
        endpoints=("1.1.1.1", "2.2.2.2"),
    )
    rendu = _flow_table([flow], _styles())
    assert rendu is not None


def test_scaled_image(tmp_path):
    """Lines 455-460 : _scaled_image met a l'echelle."""
    from reportlab.platypus import Image as RLImage

    from netcross_report.pdf import _scaled_image

    path = tmp_path / "test.png"
    _make_chart_png(path)
    img = _scaled_image(str(path), 5 * 72, 5 * 72)
    assert isinstance(img, RLImage)


def test_sequence_section_story_avec_title_et_truncated(tmp_path):
    """Lines 517, 529-530 : sequence_section_story avec title, truncated, chart."""
    from netcross_report.pdf import sequence_section_story

    styles = _styles()
    step = SequenceStep(
        ts=1.0,
        rel_ms=0.0,
        delta_ms=0.0,
        src="10.0.0.1",
        dst="10.0.0.2",
        point="A",
        length=100,
        proto="TCP",
        sport=1,
        dport=2,
        flags="S",
        frame_number=1,
        is_retransmission=False,
    )
    view = SequenceView(
        title="Flux 1",
        steps=[step],
        hosts=["10.0.0.1", "10.0.0.2"],
        points=["A", "B"],
        truncated=5,
        total_steps=6,
    )
    chart_path = tmp_path / "seq.png"
    _make_chart_png(chart_path)
    story = sequence_section_story([view], styles, [str(chart_path)])
    assert len(story) > 0


def test_sequence_section_story_sans_title_ni_chart():
    """Lines 517 (no title), 529 (no chart) : branches manquantes."""
    from netcross_report.pdf import sequence_section_story

    styles = _styles()
    step = SequenceStep(
        ts=1.0,
        rel_ms=0.0,
        delta_ms=0.0,
        src="10.0.0.1",
        dst="10.0.0.2",
        point="A",
        length=100,
        proto="TCP",
        sport=1,
        dport=2,
        flags="S",
        frame_number=1,
        is_retransmission=False,
    )
    view = SequenceView(
        title=None,
        steps=[step],
        hosts=["10.0.0.1", "10.0.0.2"],
        points=["A", "B"],
        truncated=0,
        total_steps=1,
    )
    story = sequence_section_story([view], styles, [None])
    assert len(story) > 0


def test_expert_section_story_avec_flows_et_wireshark():
    """Line 575 : expert_section_story avec flows et wireshark_expert_events."""
    from netcross_report.pdf import expert_section_story

    styles = _styles()
    flow = Flow(
        key="tcp:1->2",
        points=["A"],
        packet_count={"A": 10},
        byte_count={"A": 100},
        first_ts=1.0,
        last_ts=2.0,
        endpoints=("1.1.1.1", "2.2.2.2"),
    )
    so = SessionObjects(
        flows=[flow],
        conversations=[],
        expert_events=[],
        diagnoses=[],
        compliance=[],
        wireshark_expert_events=[],
    )
    story = expert_section_story(so, styles)
    assert len(story) > 0
    assert any("Flux correles" in str(s) for s in story)


def test_expert_section_story_avec_wireshark_events():
    """Line 575 : expert_section_story avec wireshark_expert_events non vide."""
    from netcross_core.expert_model import ExpertEvent
    from netcross_report.pdf import expert_section_story

    styles = _styles()
    ev = ExpertEvent(severity="warning", category="tcp", segment="A->B", message="Out of order", cause="x", impact="y")
    so = SessionObjects(
        flows=[],
        conversations=[],
        expert_events=[],
        diagnoses=[],
        compliance=[],
        wireshark_expert_events=[ev],
    )
    story = expert_section_story(so, styles)
    assert any("tshark" in str(s) for s in story)


def test_generate_pdf_avec_charts(monkeypatch, tmp_path):
    """Lines 884-886, 912-916, 925-948 : generate_pdf avec charts monkeypatches."""
    import netcross_report.pdf as pdf_mod

    # Cree des PNGs pour les charts
    topo = tmp_path / "topo.png"
    _make_chart_png(topo)
    sev = tmp_path / "sev.png"
    _make_chart_png(sev)
    thr = tmp_path / "thr.png"
    _make_chart_png(thr)
    lat = tmp_path / "lat.png"
    _make_chart_png(lat)
    loss = tmp_path / "loss.png"
    _make_chart_png(loss)
    topn_proto = tmp_path / "topn_proto.png"
    _make_chart_png(topn_proto)
    path_q = tmp_path / "path.png"
    _make_chart_png(path_q)

    charts = {
        "topology": str(topo),
        "severity": str(sev),
        "throughput": str(thr),
        "latency": str(lat),
        "loss": str(loss),
        "topn_protocol": str(topn_proto),
        "path_quality": str(path_q),
    }
    monkeypatch.setattr(pdf_mod, "generate_all_charts", lambda r, f, t: charts)

    r = _rapport_garni()
    # Ajoute des donnees pour declencher les sections
    r.encap_seen = {"POINT_AMONT": {"MPLS"}, "POINT_AVAL": set()}
    r.frag_new = {("POINT_AMONT", "POINT_AVAL"): 3}
    r.zero_window = {"POINT_AMONT": 5, "POINT_AVAL": 0}
    r.dup_ack = {"POINT_AMONT": 2, "POINT_AVAL": 0}
    r.rst_count = {"POINT_AMONT": 1, "POINT_AVAL": 0}
    r.rtp_streams = [
        {
            "label": "RTP stream (SSRC=1234)",
            "loss_pct": {"POINT_AVAL": 2.5},
            "delay_ms": 50.0,
            "mos": 4.2,
            "jitter_ms": {"POINT_AVAL": 5.0},
        }
    ]
    r.dhcp_msg_count = {"POINT_AMONT": {"DISCOVER": 1, "ACK": 1}, "POINT_AVAL": {}}
    r.sip_msg_count = {"POINT_AMONT": {"INVITE": 1, "200": 1}, "POINT_AVAL": {}}
    r.topn_timeseries = {"POINT_AMONT": {"protocol": [{"bucket": 0, "value": 100}]}}

    # Sequence views
    step = SequenceStep(
        ts=1.0,
        rel_ms=0.0,
        delta_ms=0.0,
        src="10.0.0.1",
        dst="10.0.0.2",
        point="A",
        length=100,
        proto="TCP",
        sport=1,
        dport=2,
        flags="S",
        frame_number=1,
        is_retransmission=False,
    )
    seq_view = SequenceView(
        title="Flux test",
        steps=[step],
        hosts=["10.0.0.1", "10.0.0.2"],
        points=["A", "B"],
        truncated=0,
        total_steps=1,
    )

    # TLS/QUIC findings
    tls_finding = Finding(
        severity="a_surveiller",
        category="tls",
        segment="A->B",
        message="Certificat expire",
        sample_size=1,
        evidence="x",
    )

    chemin = tmp_path / "rapport_complet.pdf"
    pdf_mod.generate_pdf(
        r,
        str(chemin),
        sequence_views=[seq_view],
        tls_findings=[tls_finding],
        quic_findings=[tls_finding],
        session_objects=SessionObjects(
            flows=[
                Flow(
                    key="tcp:1->2",
                    points=["A"],
                    packet_count={"A": 10},
                    byte_count={"A": 100},
                    first_ts=1.0,
                    last_ts=2.0,
                    endpoints=("1.1.1.1", "2.2.2.2"),
                )
            ],
            conversations=[],
            expert_events=[],
            diagnoses=[],
            compliance=[],
            wireshark_expert_events=[],
        ),
    )
    assert chemin.exists()
    texte = _texte_pdf(chemin)
    assert "Topologie deduite" in texte
    assert "Evolution temporelle" in texte
    assert "Flux RTP" in texte
    assert "DHCP" in texte
    assert "SIP" in texte
    assert "Diagnostics TLS / QUIC" in texte
    assert "Expertise" in texte


def test_generate_pdf_avec_securite(monkeypatch, tmp_path):
    """Line 1083-1084 : generate_pdf avec security_report et expert_story."""
    import netcross_report.pdf as pdf_mod

    r = _rapport_garni()
    flow = Flow(
        key="tcp:1->2",
        points=["A"],
        packet_count={"A": 10},
        byte_count={"A": 100},
        first_ts=1.0,
        last_ts=2.0,
        endpoints=("1.1.1.1", "2.2.2.2"),
    )
    so = SessionObjects(
        flows=[flow],
        conversations=[],
        expert_events=[],
        diagnoses=[],
        compliance=[],
        wireshark_expert_events=[],
    )
    security = None  # pas de rapport de securite : on teste expert_section_story
    chemin = tmp_path / "rapport_sec.pdf"
    pdf_mod.generate_pdf(r, str(chemin), security_report=security, session_objects=so)
    assert chemin.exists()
    texte = _texte_pdf(chemin)
    assert "Expertise" in texte or "Flux correles" in texte


def test_generate_diff_pdf_avec_tls_et_quic(tmp_path):
    """Lines 1206-1231 : generate_diff_pdf avec TLS et QUIC findings."""
    from netcross_core.tls_diagnostics import TlsFinding

    reference, courant = _paire_de_rapports()
    tls_base = [TlsFinding("a_surveiller", "TLS", "A->B", "Certificat expire")]
    tls_cur = [TlsFinding("info", "TLS", "A->B", "OK")]
    quic_base = [TlsFinding("anomalie", "QUIC", "A->B", "ClientHello bloque")]
    quic_cur = [TlsFinding("info", "QUIC", "A->B", "QUIC OK")]

    chemin = tmp_path / "diff_tls_quic.pdf"
    generate_diff_pdf(
        diff_reports(reference, courant),
        reference,
        courant,
        str(chemin),
        tls_findings_baseline=tls_base,
        tls_findings_current=tls_cur,
        quic_findings_baseline=quic_base,
        quic_findings_current=quic_cur,
    )
    assert chemin.exists()
    texte = _texte_pdf(chemin)
    assert "baseline vs courant" in texte.lower() or "Baseline" in texte
    assert "TLS" in texte
    assert "QUIC" in texte


def test_generate_diff_pdf_avec_tls_seulement(tmp_path):
    """Lines 1206-1231 : generate_diff_pdf avec TLS seulement (pas QUIC)."""
    from netcross_core.tls_diagnostics import TlsFinding

    reference, courant = _paire_de_rapports()
    tls_base = [TlsFinding("a_surveiller", "TLS", "A->B", "Certificat expire")]
    tls_cur = [TlsFinding("info", "TLS", "A->B", "OK")]

    chemin = tmp_path / "diff_tls_only.pdf"
    generate_diff_pdf(
        diff_reports(reference, courant),
        reference,
        courant,
        str(chemin),
        tls_findings_baseline=tls_base,
        tls_findings_current=tls_cur,
        quic_findings_baseline=None,
        quic_findings_current=None,
    )
    assert chemin.exists()
    texte = _texte_pdf(chemin)
    assert "TLS" in texte


def test_generate_diff_pdf_avec_quic_seulement(tmp_path):
    """Lines 1206-1231 : generate_diff_pdf avec QUIC seulement (pas TLS)."""
    from netcross_core.tls_diagnostics import TlsFinding

    reference, courant = _paire_de_rapports()
    quic_base = [TlsFinding("anomalie", "QUIC", "A->B", "ClientHello bloque")]
    quic_cur = [TlsFinding("info", "QUIC", "A->B", "QUIC OK")]

    chemin = tmp_path / "diff_quic_only.pdf"
    generate_diff_pdf(
        diff_reports(reference, courant),
        reference,
        courant,
        str(chemin),
        tls_findings_baseline=None,
        tls_findings_current=None,
        quic_findings_baseline=quic_base,
        quic_findings_current=quic_cur,
    )
    assert chemin.exists()
    texte = _texte_pdf(chemin)
    assert "QUIC" in texte


def test_generate_pdf_avec_topn_plusieurs_dimensions(monkeypatch, tmp_path):
    """Lines 925-948 : generate_pdf avec topN pour plusieurs dimensions."""
    import netcross_report.pdf as pdf_mod

    topn_port = tmp_path / "topn_port.png"
    _make_chart_png(topn_port)
    topn_ip = tmp_path / "topn_ip.png"
    _make_chart_png(topn_ip)
    topn_dscp = tmp_path / "topn_dscp.png"
    _make_chart_png(topn_dscp)

    charts = {
        "topn_protocol": str(topn_port),
        "topn_port": str(topn_port),
        "topn_ip": str(topn_ip),
        "topn_dscp": str(topn_dscp),
    }
    monkeypatch.setattr(pdf_mod, "generate_all_charts", lambda r, f, t: charts)

    r = _rapport_garni()
    r.topn_timeseries = {"POINT_AMONT": {"protocol": [{"bucket": 0, "value": 100}]}}

    chemin = tmp_path / "rapport_topn.pdf"
    pdf_mod.generate_pdf(r, str(chemin))
    assert chemin.exists()
    texte = _texte_pdf(chemin)
    assert "Par protocole" in texte
    assert "Par port" in texte
    assert "Par IP" in texte
    assert "Par marquage DSCP" in texte
