"""
netcross_gtk4.panel_state -- decisions de visibilite, de sensibilite et de
selection des panneaux de la GUI (issue #285, troisieme lot).

Ces regles etaient dispersees dans `MainWindow`, melangees aux appels de
widgets qui les appliquent. Elles ne touchent pourtant aucun objet GTK :
ce sont des reponses a des questions ordinaires -- « le panneau de
comparaison doit-il etre visible ? », « le bouton Lancer doit-il etre
actif ? », « ce clic sur une ligne du tableau de bord correspond a quelle
vue ? ».

C'est la partie ou une erreur est la plus desagreable pour
l'utilisateur : un panneau visible dans le mauvais mode, une option qui
reste cochee alors qu'elle est incompatible, un bouton grise sans qu'on
sache pourquoi. Rien ne leve d'exception, l'interface a simplement l'air
cassee.

Trois familles :

- `panel_visibility()` : quels panneaux et quelles options pour un couple
  de modes donne, y compris les cases a **forcer** a l'etat inactif parce
  qu'elles sont incompatibles avec le mode choisi.
- `run_button_state()` : le bouton Lancer est-il actif, **et pourquoi pas**.
  L'ancien code repondait seulement oui/non ; la raison est desormais
  produite avec la decision, pour pouvoir l'afficher plutot que de laisser
  l'utilisateur deviner (regle de tracabilite du projet : ne pas taire une
  information disponible).
- `apply_dashboard_selection()` : le clic sur une ligne du tableau de bord,
  avec **rejet explicite** d'un type de vue inconnu la ou l'ancien code
  ne faisait rien du tout.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from netcross_core.logging_config import get_logger
from netcross_gtk4.dashboard_context import (
    select_bucket,
    select_endpoint,
    select_event,
    select_flow,
    select_point,
    select_protocol,
)

logger = get_logger(__name__)

#: Nombre minimal de points de capture pour lancer une analyse croisee.
#: Deux, par definition : l'outil compare ce que plusieurs points ont vu du
#: meme trafic. Nomme plutot que repete en `>= 2` a quatre endroits, ou la
#: raison du seuil disparait.
POINTS_MINIMUM = 2

LABEL_LANCER_ANALYSE = "Lancer l'analyse"
LABEL_DEMARRER_CAPTURE = "Demarrer la capture"


@dataclass(frozen=True)
class PanelVisibility:
    """Etat visible de la page de configuration pour un couple de modes.

    Gele : la decision est prise en une fois a partir des deux cases a
    cocher, puis appliquee. C'est ce que documentait deja
    `_sync_panel_visibility` en se decrivant comme « point unique qui
    decide » -- la structure rend cette intention verifiable.
    """

    single_panel: bool
    live_panel: bool
    live_extra: bool
    diff_panels: bool
    single_options: bool
    diff_options: bool

    #: Sensibilite (l'option existe mais n'est pas utilisable dans ce mode)
    tls_sensitive: bool
    quic_sensitive: bool
    parallel_sensitive: bool
    duplicate_detect_sensitive: bool
    duplicate_threshold_sensitive: bool
    duplicate_exclude_sensitive: bool

    #: Cases a forcer a l'etat inactif, parce qu'elles sont incompatibles
    #: avec le mode et qu'une case cochee mais grisee serait un mensonge :
    #: l'utilisateur croirait l'option active.
    force_tls_off: bool
    force_quic_off: bool
    force_duplicate_detect_off: bool
    force_duplicate_exclude_off: bool


def panel_visibility(
    diff_mode: bool,
    live_mode: bool,
    detect_duplicates_active: bool,
) -> PanelVisibility:
    """Decide l'etat de la page de configuration.

    `diff_mode` et `live_mode` proviennent de deux cases a cocher
    independantes ; les faire converger ici est justement ce qui empeche
    qu'elles divergent.

    Le mode live a **priorite** sur le mode comparaison si les deux etaient
    actifs. Cet etat est normalement inatteignable -- chaque bascule decoche
    et grise l'autre case (`_on_diff_toggled` / `_on_live_toggled`) -- mais
    la fonction doit quand meme repondre quelque chose de coherent. La
    priorite retenue est celle de `on_run_analysis`, qui teste `live_check`
    en premier et s'arrete la : ainsi le panneau affiche correspond a ce qui
    serait reellement execute. L'ancien code, lui, affichait le panneau live
    ET les panneaux de comparaison, dont l'un aurait ete rempli pour rien.

    Deux regles valent d'etre explicitees, car elles ne se devinent pas :

    - **TLS/QUIC restent visibles en capture live mais deviennent
      insensibles.** Ces diagnostics relisent les fichiers passes a
      `--capture`, et une capture live n'en produit pas. Les masquer
      laisserait croire que l'outil n'en est pas capable ; les griser dit
      « pas dans ce mode ».
    - **Le triage reste pertinent en live**, contrairement a TLS/QUIC :
      `single_options` ne depend donc que de `diff_mode`, pas de
      `live_mode`.

    Les seuils de doublons ne sont sensibles que si la detection elle-meme
    est active : un seuil reglable alors que rien ne le consomme est une
    invitation a perdre du temps.
    """
    # Priorite au live, cf. docstring : l'affichage doit designer le mode
    # qui serait reellement execute.
    logger.debug(
        "panel_visibility: diff={} live={} doublons={}",
        diff_mode,
        live_mode,
        detect_duplicates_active,
    )
    diff_effectif = diff_mode and not live_mode
    duplicate_controls = not diff_mode
    return PanelVisibility(
        single_panel=not diff_mode and not live_mode,
        live_panel=live_mode,
        live_extra=live_mode,
        diff_panels=diff_effectif,
        single_options=not diff_mode,
        diff_options=diff_mode,
        tls_sensitive=not live_mode,
        quic_sensitive=not live_mode,
        parallel_sensitive=not live_mode,
        duplicate_detect_sensitive=duplicate_controls,
        duplicate_threshold_sensitive=duplicate_controls and detect_duplicates_active,
        duplicate_exclude_sensitive=duplicate_controls and detect_duplicates_active,
        force_tls_off=live_mode,
        force_quic_off=live_mode,
        force_duplicate_detect_off=diff_mode,
        force_duplicate_exclude_off=diff_mode,
    )


@dataclass(frozen=True)
class RunButtonState:
    """Etat du bouton Lancer, avec la raison quand il est inactif."""

    enabled: bool
    #: Explication destinee a l'utilisateur, ou `None` quand le bouton est
    #: actif. Presente parce qu'un bouton grise sans explication oblige a
    #: deviner -- et la raison est connue au moment de la decision, donc la
    #: taire serait un choix, pas une limite technique.
    raison: str | None
    label: str


def run_button_state(
    *,
    live_capturing: bool,
    diff_mode: bool,
    live_mode: bool,
    single_rows: int,
    baseline_rows: int,
    current_rows: int,
    live_points: int,
    label_actuel: str,
) -> RunButtonState:
    """Decide si l'analyse peut etre lancee, et sous quel intitule.

    Pendant une capture en cours, l'etat du bouton est pilote par
    `_begin_live_capture` / `_end_live_capture` : la decision est donc
    rendue telle quelle (`enabled=True`, label inchange) plutot que
    recalculee, sinon un simple changement de case a cocher arreterait
    d'etre coherent avec une capture en cours. La raison le dit
    explicitement au lieu de retourner un etat muet.

    `live_points` est le nombre de points **apres eclatement** : une seule
    ligne « eth0, eth1 » en produit deux (Job 48). Compter les lignes
    refuserait a tort une configuration valide sur une machine a deux
    interfaces.
    """
    logger.debug(
        "run_button_state: capture={} diff={} live={} lignes={} base={} courant={} points_live={}",
        live_capturing,
        diff_mode,
        live_mode,
        single_rows,
        baseline_rows,
        current_rows,
        live_points,
    )
    if live_capturing:
        return RunButtonState(
            enabled=True,
            raison="capture en cours : bouton pilote par le cycle de capture",
            label=label_actuel,
        )

    label = LABEL_DEMARRER_CAPTURE if live_mode else LABEL_LANCER_ANALYSE

    if diff_mode:
        if baseline_rows < POINTS_MINIMUM or current_rows < POINTS_MINIMUM:
            return RunButtonState(
                enabled=False,
                raison=(
                    f"comparaison : {POINTS_MINIMUM} points minimum de chaque cote "
                    f"(reference : {baseline_rows}, courant : {current_rows})"
                ),
                label=label,
            )
        return RunButtonState(enabled=True, raison=None, label=label)

    if live_mode:
        if live_points < POINTS_MINIMUM:
            return RunButtonState(
                enabled=False,
                raison=(
                    f"capture live : {POINTS_MINIMUM} points minimum apres eclatement "
                    f"des interfaces ({live_points} pour l'instant)"
                ),
                label=label,
            )
        return RunButtonState(enabled=True, raison=None, label=label)

    if single_rows < POINTS_MINIMUM:
        return RunButtonState(
            enabled=False,
            raison=(f"analyse croisee : {POINTS_MINIMUM} captures minimum ({single_rows} pour l'instant)"),
            label=label,
        )
    return RunButtonState(enabled=True, raison=None, label=label)


def selected_protocol(index: int, n_items: int, lire: Callable[[int], str]) -> str | None:
    """Protocole choisi dans la liste deroulante de la cartographie.

    L'index 0 est l'entree « tous les protocoles » : il doit donner `None`
    (aucun filtre) et non le libelle de cette entree, qui filtrerait sur un
    protocole nomme « Tous ». D'ou le `0 < index` et non `0 <= index`.

    Un index hors bornes donne aussi `None` : GTK renvoie
    `Gtk.INVALID_LIST_POSITION` (un tres grand entier) quand rien n'est
    selectionne, et une lecture directe leverait.
    """
    if n_items <= 0:
        return None
    if not 0 < index < n_items:
        return None
    return lire(index)


def comm_map_filters(
    protocole: str | None,
    top_n: int,
    only_anomalies: bool,
) -> dict[str, Any]:
    """Filtres de la cartographie, sous la forme attendue par le rendu.

    `protocols` vaut `None` plutot que `[]` quand aucun protocole n'est
    choisi : en aval, `None` signifie « pas de filtre » tandis qu'une liste
    vide signifierait « filtrer sur aucun protocole », c'est-a-dire une
    carte vide. La confusion produirait un ecran blanc sans message.
    """
    return {
        "protocols": [protocole] if protocole else None,
        "top_n": int(top_n),
        "only_anomalies": bool(only_anomalies),
    }


#: Types de vue du tableau de bord acceptes par `apply_dashboard_selection`,
#: tels que produits par la construction des sections. « Segments » utilise
#: le type `point` et non `segment` : c'est volontaire (la selection porte
#: sur un point de capture), mais c'est exactement le genre d'ecart qui
#: justifie de valider le type au lieu de l'ignorer en silence.
TYPES_DE_VUE = ("bucket", "point", "flow", "endpoint", "protocol", "event")


class UnknownViewTypeError(ValueError):
    """Type de vue non reconnu lors d'une selection au tableau de bord."""


def apply_dashboard_selection(
    kind: str,
    selection: Any,
    key: Any,
    *,
    flow_par_cle: Callable[[Any], Any] | None = None,
    evenements: Sequence[Any] | None = None,
) -> Any:
    """Applique un clic sur une ligne du tableau de bord.

    Un `kind` inconnu leve `UnknownViewTypeError`. L'ancien code enchainait des
    `elif` sans branche finale : un type mal orthographie traversait la
    cascade, la selection repartait inchangee et l'interface se
    rafraichissait a l'identique. Concretement, les clics sur une vue
    entiere ne faisaient rien, sans message ni trace -- un defaut qu'aucun
    test ne pouvait attraper et que l'utilisateur ne peut que subir. Mieux
    vaut une erreur bruyante au developpement qu'une vue morte en
    production.

    `flow` est le seul type qui doit resoudre sa cle en objet avant de
    selectionner : une cle qui ne correspond a aucun flux laisse la
    selection inchangee, ce qui est le comportement d'origine et reste
    correct (le flux a pu disparaitre entre l'affichage et le clic).
    """
    logger.debug("apply_dashboard_selection: kind={} key={}", kind, key)
    if kind == "flow":
        if flow_par_cle is None:
            logger.warning("apply_dashboard_selection: sélection flow sans résolveur de clé")
            raise UnknownViewTypeError("selection de type 'flow' sans resolveur de cle")
        flow = flow_par_cle(key)
        if flow is None:
            logger.debug("apply_dashboard_selection: flux introuvable pour la clé {}, sélection inchangée", key)
            return selection
        return select_flow(selection, flow)
    if kind == "endpoint":
        return select_endpoint(selection, key)
    if kind == "protocol":
        return select_protocol(selection, key)
    if kind == "point":
        return select_point(selection, key)
    if kind == "bucket":
        return select_bucket(selection, key)
    if kind == "event":
        return select_event(selection, key, list(evenements or []))
    logger.warning("apply_dashboard_selection: type de vue inconnu {!r}", kind)
    raise UnknownViewTypeError(f"type de vue inconnu : {kind!r} (attendus : {', '.join(TYPES_DE_VUE)})")
