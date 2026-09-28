"""
netcross_report.triage.rank_segments -- module duck-type, on utilise
des objets minimalistes (namedtuple) exposant juste .severity/.category
/.segment/.message, comme le fait le module lui-meme avec
synthesis.Finding OU baseline_diff.DiffFinding indifferemment.
"""

from collections import namedtuple

from netcross_core.baseline_diff import DiffFinding
from netcross_core.expert_model import EvidenceLink, PacketEvidence
from netcross_report.triage import (
    DEFAULT_SEVERITY_WEIGHTS,
    HEALTH_LABELS,
    LOW_SAMPLE_THRESHOLD,
    format_health_line,
    health_label,
    health_score,
    print_triage,
    rank_segments,
)

F = namedtuple("F", ["severity", "category", "segment", "message"])
FS = namedtuple("FS", ["severity", "category", "segment", "message", "sample_size"])
FEv = namedtuple("FEv", ["severity", "category", "segment", "message", "evidence"])
Ev = namedtuple("Ev", ["point", "text"])


def test_rank_segments_score_simple():
    findings = [F("anomalie", "Pertes", "B", "20% de pertes")]
    ranked = rank_segments(findings)
    assert len(ranked) == 1
    assert ranked[0].segment == "B"
    assert ranked[0].score == DEFAULT_SEVERITY_WEIGHTS["anomalie"]


def test_rank_segments_convergence_bonus_categories_distinctes():
    findings = [
        F("anomalie", "TCP", "B", "RST localises"),
        F("anomalie", "Fragmentation", "B", "MTU cassee"),
    ]
    ranked = rank_segments(findings, convergence_bonus=1.5)
    assert ranked[0].score == 3.0 + 3.0 + 1.5  # 2 anomalies + bonus (2 categories - 1)
    assert ranked[0].convergent is True


def test_rank_segments_meme_categorie_repetee_pas_de_bonus():
    findings = [
        F("anomalie", "Pertes", "B", "pertes 1"),
        F("anomalie", "Pertes", "B", "pertes 2"),
    ]
    ranked = rank_segments(findings)
    assert ranked[0].score == 6.0  # 2 * 3.0, aucun bonus (une seule categorie)
    assert ranked[0].convergent is False


def test_rank_segments_severites_a_poids_nul_exclues_par_defaut():
    findings = [F("info", "Pertes", "A", "0 pertes")]
    ranked = rank_segments(findings)
    assert ranked == []  # score total 0.0 <= min_score par defaut


def test_rank_segments_min_score_personnalise_inclut_le_zero():
    findings = [F("info", "Pertes", "A", "contexte")]
    ranked = rank_segments(findings, min_score=-1.0)
    assert len(ranked) == 1


def test_rank_segments_tri_par_score_decroissant():
    findings = [
        F("a_surveiller", "TCP", "A", "petit souci"),
        F("regression", "Pertes", "B", "grosse regression"),
    ]
    ranked = rank_segments(findings)
    assert [s.segment for s in ranked] == ["B", "A"]


def test_rank_segments_tri_stable_par_segment_a_score_egal():
    findings = [F("anomalie", "X", "Z", "m"), F("anomalie", "X", "Y", "m")]
    ranked = rank_segments(findings)
    assert [s.segment for s in ranked] == ["Y", "Z"]


def test_rank_segments_poids_personnalises():
    findings = [F("a_surveiller", "Pertes", "A", "suspect")]
    ranked = rank_segments(findings, severity_weights={"a_surveiller": 5.0})
    assert ranked[0].score == 5.0


def test_rank_segments_findings_du_segment_tries_par_severite():
    findings = [
        F("info", "TCP", "A", "contexte"),
        F("anomalie", "Pertes", "A", "grave"),
    ]
    ranked = rank_segments(findings, min_score=-1.0)
    assert ranked[0].findings[0].severity == "anomalie"


def test_rank_segments_regroupe_par_segment_distinct():
    findings = [F("anomalie", "Pertes", "A", "x"), F("anomalie", "Pertes", "B", "y")]
    ranked = rank_segments(findings)
    assert {s.segment for s in ranked} == {"A", "B"}


def test_rank_segments_vide_renvoie_liste_vide():
    assert rank_segments([]) == []


def test_print_triage_ne_leve_pas_sur_liste_vide(capsys):
    print_triage([])
    out = capsys.readouterr().out
    assert "Aucun segment" in out


def test_print_triage_affiche_le_top_n(capsys):
    findings = [F("anomalie", "Pertes", f"P{i}", "m") for i in range(10)]
    ranked = rank_segments(findings)
    print_triage(ranked, top_n=3)
    out = capsys.readouterr().out
    assert "top 3" in out
    assert "autre(s) segment(s)" in out


# -- score de confiance (sample_size) --


def test_finding_sans_sample_size_pas_de_ponderation_amortie():
    """F (namedtuple sans le champ sample_size) doit se comporter
    exactement comme avant -- getattr(..., None) le traite comme un
    echantillon de confiance inconnue, jamais comme un echantillon
    faible."""
    findings = [F("anomalie", "Pertes", "A", "x")]
    ranked = rank_segments(findings)
    assert ranked[0].score == DEFAULT_SEVERITY_WEIGHTS["anomalie"]
    assert ranked[0].low_confidence is False


def test_sample_size_grand_pas_de_ponderation_amortie():
    findings = [FS("anomalie", "Pertes", "A", "x", LOW_SAMPLE_THRESHOLD)]
    ranked = rank_segments(findings)
    assert ranked[0].score == DEFAULT_SEVERITY_WEIGHTS["anomalie"]
    assert ranked[0].low_confidence is False


def test_sample_size_faible_ponderation_amortie_et_marquage():
    findings = [FS("anomalie", "Pertes", "A", "x", 1)]
    ranked = rank_segments(findings)
    assert ranked[0].score == DEFAULT_SEVERITY_WEIGHTS["anomalie"] * 0.5
    assert ranked[0].low_confidence is True


def test_sample_size_faible_reste_visible_pas_exclu():
    """Le finding a echantillon faible reste dans la liste des findings du
    segment -- amorti, pas retire."""
    findings = [FS("anomalie", "Pertes", "A", "x", 1)]
    ranked = rank_segments(findings)
    assert len(ranked[0].findings) == 1


def test_low_confidence_faux_si_un_seul_finding_actionable_est_fiable():
    """Un segment avec 2 findings actionables (poids > 0) dont un seul a
    un petit echantillon n'est PAS marque low_confidence : il suffit
    qu'un des constats repose sur une base solide."""
    findings = [
        FS("anomalie", "Pertes", "A", "petit echantillon", 1),
        FS("a_surveiller", "TCP", "A", "gros echantillon", 500),
    ]
    ranked = rank_segments(findings)
    assert ranked[0].low_confidence is False


def test_low_confidence_ignore_les_findings_non_actionables():
    """Un finding \"info\"/\"stable\" (poids nul) a petit echantillon ne
    doit pas a lui seul empecher/forcer le marquage -- seuls les
    findings a poids > 0 comptent."""
    findings = [
        FS("info", "DNS", "A", "contexte", 1),
        FS("anomalie", "Pertes", "A", "gros echantillon", 500),
    ]
    ranked = rank_segments(findings)
    assert ranked[0].low_confidence is False


def test_print_triage_affiche_le_marqueur_echantillon_faible(capsys):
    findings = [FS("anomalie", "Pertes", "A", "x", 1)]
    ranked = rank_segments(findings)
    print_triage(ranked)
    out = capsys.readouterr().out
    assert "ECHANTILLON FAIBLE" in out


def test_print_triage_pas_de_marqueur_si_confiance_normale(capsys):
    findings = [F("anomalie", "Pertes", "A", "x")]
    ranked = rank_segments(findings)
    print_triage(ranked)
    out = capsys.readouterr().out
    assert "ECHANTILLON FAIBLE" not in out


# -- preuves (evidence, Session 32) --


def test_print_triage_affiche_les_preuves(capsys):
    findings = [FEv("anomalie", "PMTUD", "A -> B", "noir PMTUD", [Ev("A -> B", "seq=123 retransmis 4x")])]
    ranked = rank_segments(findings)
    print_triage(ranked)
    out = capsys.readouterr().out
    assert "seq=123 retransmis 4x" in out


def test_print_triage_namedtuple_sans_evidence_ne_plante_pas(capsys):
    """F (namedtuple sans le champ evidence) doit se comporter exactement
    comme avant -- getattr(..., None) or () evite l'AttributeError, meme
    prudence duck-type que pour sample_size."""
    findings = [F("anomalie", "Pertes", "A", "x")]
    ranked = rank_segments(findings)
    print_triage(ranked)
    out = capsys.readouterr().out
    assert "x" in out


def test_print_triage_evidence_vide_n_affiche_aucune_ligne_de_preuve(capsys):
    findings = [FEv("anomalie", "Pertes", "A", "x", [])]
    ranked = rank_segments(findings)
    print_triage(ranked)
    out = capsys.readouterr().out
    assert "         - " not in out


def test_print_triage_affiche_les_preuves_d_un_diff_finding(capsys):
    """Session 33 : DiffFinding (netcross_core.baseline_diff) peut desormais
    porter une evidence -- print_triage() ne fait aucune distinction entre
    Finding et DiffFinding (duck-typing deja en place depuis la Session
    32), confirme ici avec le vrai DiffFinding plutot qu'un namedtuple."""
    df = DiffFinding(
        "regression",
        "PMTUD",
        "A -> B",
        "noir PMTUD nouveau",
        evidence=[Ev("A -> B", "seq=42 retransmis 3x")],
    )
    ranked = rank_segments([df])
    print_triage(ranked)
    out = capsys.readouterr().out
    assert "seq=42 retransmis 3x" in out


def test_print_triage_affiche_le_numero_de_trame_si_packet_present(capsys):
    """Session 35 : quand l'EvidenceLink porte un packet (PacketEvidence),
    print_triage() affiche son numero de trame entre parentheses a la
    suite du texte -- seule la categorie PMTUD le cable aujourd'hui (voir
    synthesis.py), mais print_triage() reste generique sur EvidenceLink."""
    findings = [
        FEv(
            "anomalie",
            "PMTUD",
            "A -> B",
            "noir PMTUD",
            [EvidenceLink("A -> B", "seq=123 retransmis 4x", packet=PacketEvidence("A -> B", 42))],
        )
    ]
    ranked = rank_segments(findings)
    print_triage(ranked)
    out = capsys.readouterr().out
    assert "seq=123 retransmis 4x (trame #42)" in out


def test_print_triage_namedtuple_ev_sans_packet_ne_plante_pas(capsys):
    """Ev (namedtuple sans le champ packet) doit se comporter exactement
    comme avant l'ajout de PacketEvidence -- meme prudence duck-type
    (getattr) que pour evidence/sample_size ci-dessus."""
    findings = [FEv("anomalie", "PMTUD", "A -> B", "noir PMTUD", [Ev("A -> B", "seq=123 retransmis 4x")])]
    ranked = rank_segments(findings)
    print_triage(ranked)
    out = capsys.readouterr().out
    assert "seq=123 retransmis 4x" in out
    assert "trame #" not in out


# -- score de sante synthetique (0-100) --


def test_health_score_ranked_vide_est_100_bon():
    assert health_score([]) == 100
    assert health_label(100) == "bon"


def test_health_score_toujours_borne_0_100():
    # Beaucoup de segments a fort score (anomalies convergentes) : le score
    # doit rester dans [0, 100], jamais negatif ni au-dela de 100.
    findings = [F("anomalie", "TCP", f"P{i}", "m") for i in range(50)] + [
        F("anomalie", "Fragmentation", f"P{i}", "m") for i in range(50)
    ]
    ranked = rank_segments(findings)
    score = health_score(ranked)
    assert 0 <= score <= 100


def test_health_score_decroit_avec_plus_de_findings():
    """Plus de preuve ponderee -> score plus bas (jamais l'inverse) --
    coeur de la formule de decroissance exponentielle."""
    ranked_1 = rank_segments([F("anomalie", "Pertes", "A", "x")])
    ranked_2 = rank_segments(
        [
            F("anomalie", "Pertes", "A", "x"),
            F("anomalie", "TCP", "A", "y"),
        ]
    )
    assert health_score(ranked_2) < health_score(ranked_1) < 100


def test_health_score_un_seul_anomalie_isolee_sort_de_bon():
    """Choix de calibration documente dans triage.py : une seule anomalie
    isolee (score de segment 3.0) fait deja sortir le score de la tranche
    "bon" (>= 85), sans pour autant l'ecraser."""
    ranked = rank_segments([F("anomalie", "Pertes", "A", "x")])
    score = health_score(ranked)
    assert score < 85
    assert score > 50


def test_health_score_generique_sur_vocabulaire_diff():
    """Meme duck-typing que rank_segments : fonctionne aussi sur un
    vocabulaire de DiffFinding (regression/a_verifier/amelioration/stable),
    pas seulement Finding."""
    findings = [F("regression", "Pertes", "A", "x")]
    ranked = rank_segments(findings)
    score = health_score(ranked)
    assert score == health_score(rank_segments([F("anomalie", "Pertes", "A", "x")]))  # meme poids


def test_health_label_seuils():
    assert health_label(100) == "bon"
    assert health_label(85) == "bon"
    assert health_label(84) == "a_surveiller"
    assert health_label(60) == "a_surveiller"
    assert health_label(59) == "degrade"
    assert health_label(35) == "degrade"
    assert health_label(34) == "critique"
    assert health_label(0) == "critique"


def test_health_labels_couvre_toutes_les_cles_de_health_label():
    for _, label in [(100, "bon"), (70, "a_surveiller"), (40, "degrade"), (10, "critique")]:
        assert label in HEALTH_LABELS


def test_format_health_line_contient_score_et_libelle():
    line = format_health_line(100)
    assert "100/100" in line
    assert HEALTH_LABELS["bon"] in line


# -- Issue #754 : couverture ligne 308-309 de triage.py (garde-fou) -------


def test_health_label_score_negatif_retourne_critique():
    """Lignes 308-309 : health_label retourne 'critique' pour un score
    negatif (garde-fou inatteignable en pratique car health_score() ne
    renvoie jamais de valeur negative, mais la fonction doit rester
    robuste a un appel direct avec un score negatif)."""
    assert health_label(-1) == "critique"
