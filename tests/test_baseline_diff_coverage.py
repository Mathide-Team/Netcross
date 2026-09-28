"""
Tests supplementaires pour netcross_core/baseline_diff.py -- issue #705 (suite de #665).

Couvrent les chemins que test_baseline_diff.py n'atteignait pas : latence qui
apparait de zero, temps de traitement serveur, changements de verdict de
saturation selon les mots-cles, flux RTP sans MOS et ecarts de MOS
negligeables, arcs de topologie ou paires dont un point n'est pas commun aux
deux runs, exemples d'erreur HTTP illisibles, echantillon vide de _p95 et
sortie texte de print_diff_report.

Chaque test verifie un comportement observable (severite, segment, message,
preuve, journalisation), pas seulement le passage par la ligne.
"""

import pytest
from loguru import logger

from netcross_core.baseline_diff import (
    DiffFinding,
    _http_error_evidence,
    _p95,
    diff_reports,
    print_diff_report,
)
from netcross_core.expert_model import PacketEvidence
from netcross_core.models import Report


@pytest.fixture
def journal():
    logger.enable("netcross_core")
    lignes: list[tuple[str, str]] = []
    sink = logger.add(lambda m: lignes.append((m.record["level"].name, m.record["message"])), level="TRACE")
    yield lignes
    logger.remove(sink)


def _par_categorie(findings, categorie):
    return [f for f in findings if f.category == categorie]


# -- _p95 --------------------------------------------------------------------


def test_p95_liste_vide_renvoie_none():
    assert _p95([]) is None


def test_p95_prend_l_echantillon_au_rang_arrondi():
    # 5 valeurs : rang = round(0.95 * 4) = 4, la plus grande
    assert _p95([50.0, 10.0, 40.0, 20.0, 30.0]) == 50.0
    # 21 valeurs (1..21) : rang = round(0.95 * 20) = 19, donc la 20e valeur
    assert _p95([float(i) for i in range(21, 0, -1)]) == 20.0
    # une seule valeur : le rang est borne a len - 1
    assert _p95([7.0]) == 7.0


def test_latence_regression_message_donne_moyenne_et_p95():
    baseline = Report(points=["A", "B"])
    baseline.latency[("A", "B")] = [10.0] * 5
    current = Report(points=["A", "B"])
    current.latency[("A", "B")] = [50.0] * 5
    latence = _par_categorie(diff_reports(baseline, current), "Latence")
    assert latence[0].message == "latence moyenne 10.0ms -> 50.0ms (+40.0ms), p95 10.0ms -> 50.0ms"


# -- latence : mesurable seulement apres ---------------------------------------


def test_latence_apparait_de_zero_signale_a_verifier():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.latency[("A", "B")] = [12.0, 14.0]
    latence = _par_categorie(diff_reports(baseline, current), "Latence")
    assert len(latence) == 1
    assert latence[0].severity == "a_verifier"
    assert latence[0].segment == "A -> B"
    assert latence[0].message == "aucun echantillon avant, latence mesurable apres (13.0ms)"
    assert latence[0].sample_size == 2


# -- exemples d'erreur HTTP illisibles ---------------------------------------


def test_http_error_evidence_ignore_un_exemple_sans_code_de_statut():
    textes, trames = _http_error_evidence(
        ["GET /a -> 404", "GET /b -> timeout", "GET /c -> 404"],
        4,
        [1, 2, 3],
    )
    assert textes == ["GET /a -> 404", "GET /c -> 404"]
    # les trames restent alignees sur les exemples conserves
    assert trames == [1, 3]


def test_http_error_evidence_journalise_l_exemple_illisible(journal):
    textes, trames = _http_error_evidence(["GET /b -> timeout"], 4)
    assert textes == []
    assert trames == []
    assert any(niveau == "ERROR" and "_http_error_evidence" in message for niveau, message in journal)


def test_http_4xx_exemple_illisible_ne_fait_pas_echouer_la_comparaison():
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    current.http_client_error_count["A"] = 3
    current.http_error_examples["A"] = ["GET /a -> 404", "GET /b -> ???", "GET /c -> 403"]
    current.http_error_frames["A"] = [10, 11, 12]
    findings = diff_reports(baseline, current)
    http4xx = [f for f in findings if f.category == "HTTP" and "4xx" in f.message]
    assert len(http4xx) == 1
    assert [e.text for e in http4xx[0].evidence] == ["GET /a -> 404", "GET /c -> 403"]
    assert [e.packet for e in http4xx[0].evidence] == [PacketEvidence("A", 10), PacketEvidence("A", 12)]


# -- temps de traitement serveur ---------------------------------------------


def _rapports_avec_temps_serveur(avant, apres):
    baseline = Report(points=["A"])
    baseline.server_think_time["A"] = avant
    current = Report(points=["A"])
    current.server_think_time["A"] = apres
    return baseline, current


def test_temps_de_traitement_serveur_en_hausse_est_une_regression():
    baseline, current = _rapports_avec_temps_serveur([20.0, 20.0], [60.0, 60.0, 60.0])
    serveur = _par_categorie(diff_reports(baseline, current), "Reseau/Serveur")
    assert len(serveur) == 1
    assert serveur[0].severity == "regression"
    assert serveur[0].segment == "A"
    assert serveur[0].message == "temps de traitement serveur moyen 20.0ms -> 60.0ms (+40.0ms)"
    assert (serveur[0].before, serveur[0].after) == (20.0, 60.0)
    # taille de l'echantillon COURANT, comme pour la latence
    assert serveur[0].sample_size == 3


def test_temps_de_traitement_serveur_en_baisse_est_une_amelioration():
    baseline, current = _rapports_avec_temps_serveur([80.0], [20.0])
    serveur = _par_categorie(diff_reports(baseline, current), "Reseau/Serveur")
    assert len(serveur) == 1
    assert serveur[0].severity == "amelioration"
    assert serveur[0].message == "temps de traitement serveur moyen 80.0ms -> 20.0ms (-60.0ms)"


@pytest.mark.parametrize(
    ("avant", "apres"),
    [
        pytest.param([100.0], [103.0], id="ecart_absolu_sous_le_seuil"),  # +3ms < 5ms
        pytest.param([1000.0], [1010.0], id="ecart_relatif_sous_le_seuil"),  # +10ms mais +1% < 20%
    ],
)
def test_temps_de_traitement_serveur_sous_les_seuils_n_est_pas_signale(avant, apres):
    baseline, current = _rapports_avec_temps_serveur(avant, apres)
    assert not _par_categorie(diff_reports(baseline, current), "Reseau/Serveur")


@pytest.mark.parametrize(
    ("avant", "apres"),
    [
        pytest.param([20.0], [], id="pas_d_echantillon_courant"),
        pytest.param([], [20.0], id="pas_d_echantillon_baseline"),
    ],
)
def test_temps_de_traitement_serveur_mesure_d_un_seul_cote_n_est_pas_compare(avant, apres):
    baseline, current = _rapports_avec_temps_serveur(avant, apres)
    assert not _par_categorie(diff_reports(baseline, current), "Reseau/Serveur")


def test_temps_de_traitement_serveur_respecte_latency_min_ms():
    baseline, current = _rapports_avec_temps_serveur([10.0], [16.0])  # +6ms, +60%
    assert _par_categorie(diff_reports(baseline, current), "Reseau/Serveur")
    assert not _par_categorie(diff_reports(baseline, current, latency_min_ms=10.0), "Reseau/Serveur")


def test_temps_de_traitement_serveur_nul_avant_est_une_regression_sans_division_par_zero():
    baseline, current = _rapports_avec_temps_serveur([0.0, 0.0], [12.0])
    serveur = _par_categorie(diff_reports(baseline, current), "Reseau/Serveur")
    assert len(serveur) == 1
    assert serveur[0].severity == "regression"
    assert serveur[0].before == 0.0


# -- paires dont un point n'est pas commun aux deux runs ---------------------


@pytest.mark.parametrize(
    "paire",
    [pytest.param(("A", "Z"), id="arrivee_absente"), pytest.param(("Z", "A"), id="depart_absent")],
)
def test_paire_dont_un_point_est_absent_du_courant_n_est_pas_comparee(paire):
    baseline = Report(points=["A", "B", "Z"])
    baseline.latency[paire] = [10.0] * 5
    current = Report(points=["A", "B"])
    findings = diff_reports(baseline, current)
    # seul le point manquant est signale : pas de "plus aucun echantillon" sur
    # un arc dont une extremite n'existe plus dans le run courant
    assert [f.category for f in findings] == ["Perimetre"]
    assert findings[0].segment == "Z"


# -- saturation : changement de verdict --------------------------------------


def _rapports_avec_verdict(avant, apres):
    baseline = Report(points=["A", "B"])
    baseline.latency[("A", "B")] = [10.0]  # la paire doit exister pour etre consideree (all_pairs)
    current = Report(points=["A", "B"])
    current.latency[("A", "B")] = [10.0]
    if avant is not None:
        baseline.saturation_verdict[("A", "B")] = avant
    if apres is not None:
        current.saturation_verdict[("A", "B")] = apres
    return baseline, current


@pytest.mark.parametrize(
    ("avant", "apres", "severite"),
    [
        pytest.param("saturation probable", "fluide", "amelioration", id="n_est_plus_sature"),
        pytest.param("limitation de debit", "fluide", "amelioration", id="mot_cle_limitation"),
        pytest.param("fluide", "debit nominal", "a_verifier", id="deux_verdicts_sains_differents"),
        pytest.param("saturation probable", "policing probable", "a_verifier", id="deux_verdicts_degrades_differents"),
    ],
)
def test_saturation_changement_de_verdict_selon_les_mots_cles(avant, apres, severite):
    baseline, current = _rapports_avec_verdict(avant, apres)
    sat = _par_categorie(diff_reports(baseline, current), "Saturation")
    assert len(sat) == 1
    assert sat[0].severity == severite
    assert sat[0].segment == "A -> B"
    assert sat[0].message == f'verdict change : "{avant}" -> "{apres}"'


@pytest.mark.parametrize(
    ("avant", "apres"),
    [
        pytest.param("saturation probable", "saturation probable", id="verdict_identique"),
        pytest.param(None, "saturation probable", id="pas_de_verdict_avant"),
        pytest.param("saturation probable", None, id="pas_de_verdict_apres"),
    ],
)
def test_saturation_sans_changement_de_verdict_n_est_pas_signalee(avant, apres):
    baseline, current = _rapports_avec_verdict(avant, apres)
    assert not _par_categorie(diff_reports(baseline, current), "Saturation")


# -- RTP / qualite voix ------------------------------------------------------


def test_rtp_flux_sans_mos_n_est_pas_apparie():
    baseline = Report(points=["A", "B"])
    baseline.rtp_streams = [
        {"label": "A -> B (SSRC=1)", "mos": None},
        {"label": "B -> A (SSRC=2)", "mos": 4.0},
    ]
    current = Report(points=["A", "B"])
    current.rtp_streams = [
        {"label": "A -> B (SSRC=9)", "mos": 1.5},  # regression si le flux baseline etait apparie
        {"label": "B -> A (SSRC=8)", "mos": 3.0},
    ]
    rtp = _par_categorie(diff_reports(baseline, current), "RTP/Voix")
    assert [f.segment for f in rtp] == ["B -> A"]
    assert rtp[0].severity == "regression"


def test_rtp_petit_ecart_de_mos_est_ignore():
    baseline = Report(points=["A", "B"])
    baseline.rtp_streams = [{"label": "A -> B (SSRC=1)", "mos": 4.0}]
    current = Report(points=["A", "B"])
    current.rtp_streams = [{"label": "A -> B (SSRC=1)", "mos": 3.9}]  # -0.1 < 0.2
    assert not _par_categorie(diff_reports(baseline, current), "RTP/Voix")


def test_rtp_mos_en_hausse_est_une_amelioration():
    baseline = Report(points=["A", "B"])
    baseline.rtp_streams = [{"label": "A -> B (SSRC=1)", "mos": 3.0}]
    current = Report(points=["A", "B"])
    current.rtp_streams = [{"label": "A -> B (SSRC=1)", "mos": 4.0, "sample_count": 120}]
    rtp = _par_categorie(diff_reports(baseline, current), "RTP/Voix")
    assert len(rtp) == 1
    assert rtp[0].severity == "amelioration"
    assert rtp[0].segment == "A -> B"
    assert rtp[0].message == "MOS 3.00 -> 4.00 (+1.00)"
    assert rtp[0].sample_size == 120


# -- topologie : arcs dont une extremite n'est pas commune -------------------


@pytest.mark.parametrize(
    "arc",
    [pytest.param(("A", "Z"), id="arrivee_absente"), pytest.param(("Z", "A"), id="depart_absent")],
)
def test_topologie_arc_disparu_dont_une_extremite_n_est_plus_commune_n_est_pas_signale(arc):
    baseline = Report(points=["A", "B", "Z"])
    baseline.topology_edges = [(arc[0], arc[1], {})]
    current = Report(points=["A", "B"])
    findings = diff_reports(baseline, current)
    assert not _par_categorie(findings, "Topologie")
    assert [f.segment for f in _par_categorie(findings, "Perimetre")] == ["Z"]


@pytest.mark.parametrize(
    "arc",
    [pytest.param(("A", "Z"), id="arrivee_nouvelle"), pytest.param(("Z", "A"), id="depart_nouveau")],
)
def test_topologie_nouvel_arc_dont_une_extremite_n_est_pas_commune_n_est_pas_signale(arc):
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B", "Z"])
    current.topology_edges = [(arc[0], arc[1], {})]
    findings = diff_reports(baseline, current)
    assert not _par_categorie(findings, "Topologie")
    assert [f.segment for f in _par_categorie(findings, "Perimetre")] == ["Z"]


# -- print_diff_report -------------------------------------------------------


def test_print_diff_report_sans_ecart(capsys):
    print_diff_report([])
    sortie = capsys.readouterr().out
    assert "COMPARAISON AVANT / APRES (baseline vs courant)" in sortie
    assert "Aucun ecart significatif detecte entre les deux runs." in sortie
    assert "regression(s)" not in sortie


def test_print_diff_report_groupe_par_severite_et_compte_les_constats(capsys):
    findings = [
        DiffFinding("regression", "Pertes", "B", "taux de pertes 0.0% -> 20.0% (0/100 -> 20/100)"),
        DiffFinding("regression", "TCP", "B", "RST injectes localement : 1 -> 9 (+8)"),
        DiffFinding("a_verifier", "Perimetre", "C", "point present dans le baseline mais absent du run courant"),
        DiffFinding("amelioration", "DNS", "global", "duree moyenne de resolution DNS 300.0ms -> 100.0ms (-200.0ms)"),
        DiffFinding("stable", "HTTP", "A", "aucun ecart"),
    ]
    print_diff_report(findings)
    sortie = capsys.readouterr().out
    # le decompte ne porte que sur les trois severites qui appellent une action
    assert "2 regression(s), 1 amelioration(s), 1 point(s) a verifier" in sortie
    # un seul titre par groupe, dans l'ordre d'affichage des constats
    for titre in ("-- REGRESSIONS", "-- A VERIFIER", "-- AMELIORATIONS", "-- STABLE --"):
        assert sortie.count(titre) == 1
    assert (
        sortie.index("-- REGRESSIONS")
        < sortie.index("-- A VERIFIER")
        < sortie.index("-- AMELIORATIONS")
        < sortie.index("-- STABLE --")
    )
    # chaque constat est imprime avec sa categorie, son segment et son message
    for f in findings:
        assert any(f.category in ligne and f.segment in ligne and f.message in ligne for ligne in sortie.splitlines())
