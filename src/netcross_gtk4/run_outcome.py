"""
netcross_gtk4.run_outcome -- etat de resultat et decisions d'affichage a la
fin d'une analyse ou d'une comparaison (issue #285, deuxieme lot).

## Le probleme que ce module resout

`MainWindow` conserve seize attributs `last_*` decrivant le dernier
run : le rapport, les flux (sous leurs deux formes, voir `flow_objects`),
les constats, les diagnostics TLS/QUIC, les evenements Expert Info, et
leurs equivalents en mode comparaison. Deux
methodes les reecrivaient chacune de son cote : `_on_analysis_done` et
`_on_diff_done`.

Elles devaient donc toucher **exactement le meme jeu de champs**, chacune
mettant a `None` ceux qui ne s'appliquent pas a son mode. Rien ne le
garantissait. Ajouter un quinzieme `last_*` a une seule des deux suffisait
a produire un defaut silencieux et desagreable a diagnostiquer :
l'utilisateur lance une analyse, puis une comparaison, et la comparaison
affiche des donnees restees de l'analyse precedente. Aucune exception,
aucun message -- juste un resultat faux, presente avec la meme assurance
qu'un resultat juste.

Les deux modes produisent desormais un `RunOutcome`, une structure gelee
dont **tous** les champs sont obligatoires. Un champ ajoute sans etre
renseigne par les deux constructeurs est une erreur a la construction, pas
une fuite d'etat six mois plus tard. La methode GTK ne fait plus que
l'appliquer.

## Ce qui reste dans la vue

L'application effective (`set_text`, `set_sensitive`, `spinner.stop()`,
changement de page) reste dans `app.py` : c'est du pilotage de widgets,
il n'y a rien a verifier la. Ce qui est sorti ici, c'est la decision --
quel etat retenir, quel texte annoncer -- et c'est la seule partie ou une
erreur change ce que l'utilisateur croit.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any

from netcross_core.correlate import build_flows
from netcross_core.i18n import N_, _, ngettext
from netcross_core.logging_config import get_logger
from netcross_gtk4.duplicate_view import format_duplicate_indicator

logger = get_logger(__name__)

#: Indicateur de doublons en mode comparaison. La detection de doublons
#: inter-captures compare deux points d'une meme capture ; elle n'a pas de
#: sens entre une baseline et un courant. Le message le dit au lieu de
#: laisser la zone vide : une zone vide se lit « aucun doublon », ce qui
#: serait une affirmation que l'outil n'a pas verifiee.
INDICATEUR_DOUBLONS_DIFF = N_("Doublons inter-captures : non disponible en mode comparaison.")


@dataclass(frozen=True)
class RunOutcome:
    """Etat complet retenu apres un run, plus les textes a afficher.

    Gele (`frozen=True`) : une fois la decision prise, elle ne se modifie
    plus au fil des appels de widgets. Un bug de sequencement devient une
    exception au lieu d'un etat a moitie mis a jour.

    Aucun champ n'a de valeur par defaut, volontairement. C'est ce qui
    empeche la derive decrite dans l'en-tete du module : le compilateur
    -- ici, la construction du dataclass -- refuse un champ oublie.
    """

    # --- etat du dernier run (miroir des attributs `last_*` de MainWindow) ---
    mode: str
    report: Any
    flows: Any
    # Issue #453 : les flux sous forme de list[Flow] (netcross_core.
    # expert_model), construite par build_flow_objects() depuis le dict brut
    # de correlate(). Les vues orientees objets -- dashboard analytique,
    # exploration statistique, selection de flux -- consomment cette forme ;
    # `flows` reste le dict brut pour les consommateurs qui lisent les Pkt
    # (detail CSV, cartographie, objets de session).
    flow_objects: Any
    findings: Any
    tls_findings: Any
    quic_findings: Any
    wireshark_expert_events: Any
    # issue #357 : SecurityReport du run simple (None : non demande ou diff)
    security_report: Any
    diff_findings: Any
    baseline_report: Any
    current_report: Any
    diff_tls_findings_baseline: Any
    diff_tls_findings_current: Any
    diff_quic_findings_baseline: Any
    diff_quic_findings_current: Any

    # --- textes destines a l'utilisateur ---
    work_status: str
    status: str
    duplicate_indicator: str
    result_text: str

    #: Champs d'etat, par opposition aux textes d'affichage. Utilise par
    #: `app.py` pour recopier l'etat sans enumerer quinze noms, et par
    #: les tests pour verifier qu'aucun `last_*` de `MainWindow` n'est
    #: oublie.
    CHAMPS_ETAT = (
        "mode",
        "report",
        "flows",
        "flow_objects",
        "findings",
        "tls_findings",
        "quic_findings",
        "wireshark_expert_events",
        "security_report",
        "diff_findings",
        "baseline_report",
        "current_report",
        "diff_tls_findings_baseline",
        "diff_tls_findings_current",
        "diff_quic_findings_baseline",
        "diff_quic_findings_current",
    )

    def etat(self) -> dict[str, Any]:
        """Les champs d'etat sous forme de dictionnaire `last_<nom>`.

        Permet a `MainWindow` de faire `setattr` en boucle : un champ
        ajoute a `RunOutcome` se propage alors a la fenetre sans qu'on ait
        a penser aux deux modes, ce qui est exactement l'oubli que ce
        module empeche.
        """
        logger.debug("RunOutcome.etat: mode={}, {} champ(s) d'état", self.mode, len(self.CHAMPS_ETAT))
        return {f"last_{nom}": getattr(self, nom) for nom in self.CHAMPS_ETAT}


def _verifier_completude() -> None:
    """Garde-fou interne : `CHAMPS_ETAT` doit couvrir tous les champs
    d'etat declares, ni plus ni moins.

    Verifie a l'import plutot que dans un test : ce module est importe par
    `app.py`, donc une incoherence se manifeste au lancement de la GUI, y
    compris sur un poste ou les tests n'ont pas ete rejoues.
    """
    logger.debug("_verifier_completude: {} champ(s) d'état déclarés", len(RunOutcome.CHAMPS_ETAT))
    textes = {"work_status", "status", "duplicate_indicator", "result_text"}
    declares = {f.name for f in fields(RunOutcome)} - textes
    if declares != set(RunOutcome.CHAMPS_ETAT):
        manquants = declares - set(RunOutcome.CHAMPS_ETAT)
        surnumeraires = set(RunOutcome.CHAMPS_ETAT) - declares
        raise AssertionError(
            "RunOutcome.CHAMPS_ETAT desynchronise des champs du dataclass "
            f"-- absents de CHAMPS_ETAT : {sorted(manquants)} ; "
            f"inconnus du dataclass : {sorted(surnumeraires)}"
        )


_verifier_completude()


def build_flow_objects(flows: Any) -> Any:
    """Construit la liste de `Flow` correspondant aux flux d'un run.

    Issue #453 : les deux threads d'analyse (fichier via le pipeline,
    capture en direct via `_join_live_and_analyze`) transmettent le dict
    brut retourne par `correlate()`, et c'est ce dict qui est stocke dans
    `last_flows` -- voulu, car le detail CSV, la cartographie et les objets
    de session lisent les paquets qu'il porte. Mais les vues orientees
    objets (dashboard, statistiques, selection de flux) attendent une
    `list[Flow]` avec `.endpoints`, `.points`, `.packet_count`... Les deux
    formes coexistent donc : cette fonction derive la seconde de la
    premiere, au seul endroit par lequel les deux chemins passent --
    `_on_analysis_done` appele `analysis_outcome`, jamais l'inverse.

    Tolere une entree deja convertie (une liste de `Flow`, y compris
    vide) : les tests et les futurs appelants n'ont pas a connaitre la
    forme interne. `None` reste `None` -- c'est l'etat "pas de run",
    pas un run sans flux.
    """
    if flows is None:
        logger.debug("build_flow_objects: aucun flux (run absent)")
        return None
    if isinstance(flows, dict):
        flow_objects = build_flows(flows)
        logger.debug("build_flow_objects: {} flux -> {} Flow", len(flows), len(flow_objects))
        return flow_objects
    if isinstance(flows, list):
        return flows
    return list(flows)


def analysis_outcome(
    mode: str,
    report: Any,
    flows: Any,
    findings: Any,
    text: str,
    tls_findings: Any = None,
    quic_findings: Any = None,
    wireshark_expert_events: Any = None,
    security_report: Any = None,
) -> RunOutcome:
    """Etat retenu apres une analyse simple.

    Les champs de comparaison sont explicitement mis a `None` : l'analyse
    qui suit une comparaison ne doit pas heriter de la baseline
    precedente.
    """
    logger.debug("analysis_outcome: mode={} texte={} caractère(s)", mode, len(text))
    return RunOutcome(
        mode=mode,
        report=report,
        flows=flows,
        flow_objects=build_flow_objects(flows),
        findings=findings,
        tls_findings=tls_findings,
        quic_findings=quic_findings,
        wireshark_expert_events=wireshark_expert_events,
        security_report=security_report,
        diff_findings=None,
        baseline_report=None,
        current_report=None,
        diff_tls_findings_baseline=None,
        diff_tls_findings_current=None,
        diff_quic_findings_baseline=None,
        diff_quic_findings_current=None,
        work_status=_("Analyse terminee."),
        status=_("Analyse terminee."),
        duplicate_indicator=format_duplicate_indicator(report),
        result_text=text,
    )


def diff_status_text(findings: Any) -> str:
    """Resume d'une comparaison, avec le nombre de regressions.

    Le cas « aucune regression » a son propre message et n'est pas
    silencieux : « Comparaison terminee » seul laisserait l'utilisateur se
    demander si le calcul a eu lieu. Dire « aucune regression » est un
    resultat.
    """
    regressions = sum(1 for f in findings if getattr(f, "severity", None) == "regression")
    logger.debug("diff_status_text: {} régression(s)", regressions)
    if regressions:
        return ngettext(
            "Comparaison terminee -- {n} regression detectee.",
            "Comparaison terminee -- {n} regressions detectees.",
            regressions,
        ).format(n=regressions)
    return _("Comparaison terminee -- aucune regression.")


def diff_outcome(
    findings: Any,
    baseline_report: Any,
    current_report: Any,
    text: str,
    tls_findings_baseline: Any = None,
    tls_findings_current: Any = None,
    quic_findings_baseline: Any = None,
    quic_findings_current: Any = None,
) -> RunOutcome:
    """Etat retenu apres une comparaison baseline/courant.

    `report` et `flows` sont mis a `None` : le tableau de bord et la vue
    statistiques s'appuient dessus et doivent se desactiver en mode
    comparaison plutot que d'afficher les chiffres du run precedent.
    """
    logger.debug("diff_outcome: {} constat(s)", len(findings or []))
    return RunOutcome(
        mode="diff",
        report=None,
        flows=None,
        flow_objects=None,
        findings=None,
        tls_findings=None,
        quic_findings=None,
        wireshark_expert_events=None,
        security_report=None,
        diff_findings=findings,
        baseline_report=baseline_report,
        current_report=current_report,
        diff_tls_findings_baseline=tls_findings_baseline,
        diff_tls_findings_current=tls_findings_current,
        diff_quic_findings_baseline=quic_findings_baseline,
        diff_quic_findings_current=quic_findings_current,
        work_status=_("Comparaison terminee."),
        status=diff_status_text(findings),
        duplicate_indicator=_(INDICATEUR_DOUBLONS_DIFF),
        result_text=text,
    )
