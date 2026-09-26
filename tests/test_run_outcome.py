"""
Tests de l'etat de resultat de la GUI (`netcross_gtk4/run_outcome.py`).

Deuxieme lot de l'issue #285. Ce qui est verifie ici n'est pas du rendu :
c'est la regle qui decide quelles donnees du dernier run la fenetre
conserve. Un champ oublie ne produit ni exception ni message -- il fait
afficher au run suivant des donnees restees du precedent, avec la meme
assurance qu'un resultat juste. C'est la classe de defaut la plus couteuse
a diagnostiquer, et la moins visible.
"""

import ast
import dataclasses
import pathlib

import pytest

from netcross_gtk4.run_outcome import (
    INDICATEUR_DOUBLONS_DIFF,
    RunOutcome,
    analysis_outcome,
    diff_outcome,
    diff_status_text,
)


class _Constat:
    """Double minimal : seul `severity` est lu par le comptage."""

    def __init__(self, severity):
        self.severity = severity


class _Rapport:
    """Double de rapport pour `format_duplicate_indicator`."""

    def __init__(self, duplicate_count=None, duplicates_excluded=False):
        self.duplicate_count = duplicate_count or {}
        self.duplicates_excluded = duplicates_excluded


# --------------------------------------------------------------------------
# L'invariant central : les deux modes couvrent le meme etat
# --------------------------------------------------------------------------


def test_les_deux_modes_renseignent_exactement_les_memes_champs():
    """C'est la raison d'etre du module.

    Avant l'extraction, `_on_analysis_done` et `_on_diff_done` reecrivaient
    chacune sa propre liste de quatorze attributs `last_*`. Rien ne
    garantissait qu'elles restent identiques : ajouter un champ a une seule
    des deux suffisait pour que l'utilisateur lance une analyse, puis une
    comparaison, et voie des donnees de l'analyse precedente.
    """
    analyse = analysis_outcome("single", _Rapport(), [], [], "texte")
    comparaison = diff_outcome([], _Rapport(), _Rapport(), "texte")
    assert set(analyse.etat()) == set(comparaison.etat())
    assert len(analyse.etat()) == 16


def test_l_analyse_efface_l_etat_de_comparaison():
    """Une analyse lancee apres une comparaison ne doit pas heriter de la
    baseline : les vues de comparaison se desactivent sur `None`, et un
    reste de baseline leur ferait afficher un ecart entre deux runs sans
    rapport."""
    o = analysis_outcome("single", _Rapport(), ["f"], ["c"], "texte")
    assert o.diff_findings is None
    assert o.baseline_report is None
    assert o.current_report is None
    assert o.diff_tls_findings_baseline is None
    assert o.diff_tls_findings_current is None
    assert o.diff_quic_findings_baseline is None
    assert o.diff_quic_findings_current is None


def test_la_comparaison_efface_l_etat_d_analyse_simple():
    """Symetrique : le tableau de bord et la vue statistiques s'appuient sur
    `report`, `flows` et `flow_objects`, et doivent se desactiver en mode
    comparaison plutot que d'afficher les chiffres du run precedent."""
    o = diff_outcome(["e"], _Rapport(), _Rapport(), "texte")
    assert o.report is None
    assert o.flows is None
    assert o.flow_objects is None
    assert o.findings is None
    assert o.tls_findings is None
    assert o.quic_findings is None
    assert o.wireshark_expert_events is None


def test_l_etat_est_prefixe_last_pour_la_fenetre():
    o = analysis_outcome("single", _Rapport(), [], [], "texte")
    assert all(nom.startswith("last_") for nom in o.etat())
    assert "last_wireshark_expert_events" in o.etat()


def test_aucun_champ_d_etat_n_a_de_valeur_par_defaut():
    """C'est ce qui empeche la derive : un champ ajoute sans etre renseigne
    par les DEUX constructeurs casse la construction immediatement, au lieu
    de fuiter silencieusement six mois plus tard."""
    with pytest.raises(TypeError):
        RunOutcome()  # type: ignore[call-arg]


def test_le_resultat_est_gele():
    """Une decision prise ne doit plus bouger au fil des appels de widgets :
    un bug de sequencement devient une exception plutot qu'un etat a moitie
    mis a jour."""
    o = analysis_outcome("single", _Rapport(), [], [], "texte")
    with pytest.raises(dataclasses.FrozenInstanceError):
        o.mode = "diff"  # type: ignore[misc]


# --------------------------------------------------------------------------
# Le garde-fou qui relit app.py
# --------------------------------------------------------------------------


def test_champs_etat_couvre_tous_les_last_de_app_py():
    """Verifie par analyse syntaxique que `RunOutcome` couvre bien tous les
    attributs `last_*` que `MainWindow` conserve.

    `app.py` n'est pas importable en CI (il fait `import gi`, PyGObject y
    est absent) : c'est justement le probleme que l'issue #285 attaque. Le
    fichier est donc lu comme du texte. C'est moins elegant qu'un import,
    mais cela verifie la seule chose qui compte -- qu'un nouveau `last_*`
    ajoute a la fenetre ne reste pas hors de la structure, ce qui ferait
    revenir exactement le defaut corrige ici.

    `last_stats_rows` est exclu volontairement : il est renseigne par
    `_refresh_stats()`, pas par la fin d'un run, et il est recalcule a
    chaque rafraichissement. L'exclusion est nommee plutot que deduite,
    pour qu'un futur ajout ne puisse pas s'y glisser en silence.
    """
    source = pathlib.Path(__file__).resolve().parents[1] / "src" / "netcross_gtk4" / "app.py"
    arbre = ast.parse(source.read_text(encoding="utf-8"))

    trouves = set()
    for noeud in ast.walk(arbre):
        if (
            isinstance(noeud, ast.Attribute)
            and noeud.attr.startswith("last_")
            and isinstance(noeud.value, ast.Name)
            and noeud.value.id == "self"
        ):
            trouves.add(noeud.attr)

    assert trouves, "aucun attribut last_* trouve : l'analyse de app.py a echoue, pas le code"

    hors_run = {"last_stats_rows"}
    attendus = set(RunOutcome.CHAMPS_ETAT)
    manquants = trouves - hors_run - {f"last_{n}" for n in attendus}
    assert not manquants, (
        f"attributs last_* de MainWindow absents de RunOutcome.CHAMPS_ETAT : {sorted(manquants)} "
        "-- ils ne seront pas reinitialises entre deux modes"
    )


def test_champs_etat_ne_declare_rien_d_inconnu_de_app_py():
    """Reciproque : un champ de `RunOutcome` que `MainWindow` n'utilise plus
    est du code mort qui donne une fausse impression de couverture."""
    source = pathlib.Path(__file__).resolve().parents[1] / "src" / "netcross_gtk4" / "app.py"
    texte = source.read_text(encoding="utf-8")
    inutilises = [nom for nom in RunOutcome.CHAMPS_ETAT if f"last_{nom}" not in texte]
    assert not inutilises, f"champs de RunOutcome inconnus de app.py : {inutilises}"


def test_le_garde_fou_de_completude_se_declenche_vraiment(monkeypatch):
    """`_verifier_completude()` tourne a l'import de `run_outcome`, donc une
    incoherence se manifeste au lancement de la GUI meme sur un poste ou les
    tests n'ont pas ete rejoues. Encore faut-il qu'il sache echouer : un
    garde-fou qui n'a jamais leve est un garde-fou dont on ignore s'il
    fonctionne.

    Les deux sens sont verifies -- un champ du dataclass oublie dans
    CHAMPS_ETAT, et un nom de CHAMPS_ETAT inconnu du dataclass -- parce que
    le message d'erreur les distingue et qu'un message qui designe le mauvais
    probleme coute plus de temps qu'une absence de message.
    """
    from netcross_gtk4 import run_outcome as module

    monkeypatch.setattr(RunOutcome, "CHAMPS_ETAT", ("mode", "report"))
    with pytest.raises(AssertionError) as erreur:
        module._verifier_completude()
    assert "absents de CHAMPS_ETAT" in str(erreur.value)
    assert "flows" in str(erreur.value)

    monkeypatch.setattr(RunOutcome, "CHAMPS_ETAT", (*RunOutcome.CHAMPS_ETAT, "champ_inexistant"))
    with pytest.raises(AssertionError) as erreur:
        module._verifier_completude()
    assert "inconnus du dataclass" in str(erreur.value)
    assert "champ_inexistant" in str(erreur.value)


# --------------------------------------------------------------------------
# Les textes annonces a l'utilisateur
# --------------------------------------------------------------------------


def test_le_resume_de_comparaison_compte_les_regressions():
    findings = [_Constat("regression"), _Constat("amelioration"), _Constat("regression")]
    assert diff_status_text(findings) == "Comparaison terminee -- 2 regressions detectees."


def test_le_resume_de_comparaison_annonce_l_absence_de_regression():
    """« Comparaison terminee » seul laisserait l'utilisateur se demander si
    le calcul a eu lieu. Dire « aucune regression » est un resultat."""
    assert diff_status_text([_Constat("amelioration")]) == "Comparaison terminee -- aucune regression."


def test_le_resume_de_comparaison_supporte_une_liste_vide():
    assert diff_status_text([]) == "Comparaison terminee -- aucune regression."


def test_le_resume_de_comparaison_ignore_un_constat_sans_severite():
    """Les constats viennent de `baseline_diff` : un objet sans `severity`
    ne doit pas faire tomber l'affichage du resume. `getattr` avec defaut
    plutot qu'un acces direct."""

    class _SansSeverite:
        pass

    assert diff_status_text([_SansSeverite(), _Constat("regression")]) == (
        "Comparaison terminee -- 1 regression detectee."
    )


def test_l_analyse_annonce_les_doublons_detectes():
    rapport = _Rapport({("A", "B"): 3})
    o = analysis_outcome("single", rapport, [], [], "texte")
    assert "3 paquet(s)" in o.duplicate_indicator
    assert "A ↔ B : 3" in o.duplicate_indicator


def test_l_analyse_annonce_explicitement_l_absence_de_doublon():
    o = analysis_outcome("single", _Rapport(), [], [], "texte")
    assert o.duplicate_indicator == "Doublons inter-captures : aucun détecté."


def test_la_comparaison_dit_que_les_doublons_sont_indisponibles():
    """La detection de doublons compare deux points d'une meme capture ; elle
    n'a pas de sens entre une baseline et un courant. Laisser la zone vide
    se lirait « aucun doublon », une affirmation que l'outil n'a pas
    verifiee -- c'est la difference entre « rien trouve » et « pas
    regarde »."""
    o = diff_outcome([], _Rapport(), _Rapport(), "texte")
    assert o.duplicate_indicator == INDICATEUR_DOUBLONS_DIFF
    assert "non disponible" in o.duplicate_indicator


def test_le_texte_du_rapport_est_transmis_tel_quel():
    """Aucune troncature : ce texte est le rapport complet affiche dans la
    page Resultats, qui possede son propre defilement."""
    texte = "ligne\n" * 5000
    assert analysis_outcome("single", _Rapport(), [], [], texte).result_text == texte
    assert diff_outcome([], _Rapport(), _Rapport(), texte).result_text == texte


def test_les_deux_modes_annoncent_un_avancement_non_vide():
    """La zone d'avancement passe de « Analyse en cours... » a un etat final.
    La laisser sur « en cours » ferait croire a un blocage."""
    for o in (
        analysis_outcome("single", _Rapport(), [], [], "t"),
        diff_outcome([], _Rapport(), _Rapport(), "t"),
    ):
        assert o.work_status.strip()
        assert "en cours" not in o.work_status
        assert o.status.strip()


def test_le_mode_est_conserve_tel_quel():
    """`on_export_csv` choisit le nom de fichier propose d'apres `last_mode`
    (`details_flux.csv` ou `ecarts.csv`) : une valeur alteree ici
    proposerait le mauvais export."""
    assert analysis_outcome("single", _Rapport(), [], [], "t").mode == "single"
    assert diff_outcome([], _Rapport(), _Rapport(), "t").mode == "diff"


def test_les_diagnostics_tls_quic_optionnels_restent_none_par_defaut():
    """TLS/QUIC ne sont pas demandes a chaque run : leur absence doit donner
    `None` (« pas demande ») et non une liste vide (« demande, rien
    trouve »). Les deux se presentent differemment dans les rapports."""
    o = analysis_outcome("single", _Rapport(), [], [], "t")
    assert o.tls_findings is None
    assert o.quic_findings is None
    d = diff_outcome([], _Rapport(), _Rapport(), "t")
    assert d.diff_tls_findings_baseline is None
    assert d.diff_quic_findings_current is None


def test_les_diagnostics_fournis_sont_conserves():
    o = analysis_outcome(
        "single",
        _Rapport(),
        [],
        [],
        "t",
        tls_findings=["tls"],
        quic_findings=["quic"],
        wireshark_expert_events=["expert"],
    )
    assert o.tls_findings == ["tls"]
    assert o.quic_findings == ["quic"]
    assert o.wireshark_expert_events == ["expert"]


def test_une_liste_vide_de_diagnostics_reste_une_liste_vide():
    """Distinction a ne pas ecraser : `[]` signifie « TLS analyse, aucun
    probleme » et doit se maintenir jusqu'aux rapports, la ou `None`
    signifie « TLS non analyse »."""
    o = analysis_outcome("single", _Rapport(), [], [], "t", tls_findings=[])
    assert o.tls_findings == []
    assert o.tls_findings is not None
