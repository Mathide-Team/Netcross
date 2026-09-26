"""
Decisions du panneau de filtres BPF de la capture live, sorties de
``netcross_gtk4/app.py`` (issue #285, quatrieme lot).

``LiveCaptureRow`` melait deux choses : les regles qui decident ce que le
menu deroulant annonce, quand il doit se desolidariser du champ texte, si un
filtre peut etre enregistre et ou une ligne se deplace dans la liste -- et
les appels de widgets qui appliquent ces regles. Aucune de ces regles ne
touche un objet GTK.

Elles sont pourtant celles qui decident ce que l'utilisateur CROIT capturer.
Un menu annoncant « DNS » alors que le champ contient autre chose, ou un
filtre enregistre sous un nom qui en ecrase un autre, ne provoque aucune
erreur : la capture tourne, et c'est en relisant les resultats -- parfois
beaucoup plus tard -- que l'ecart se voit. C'est le pire moment.

## Convention d'indice

Le menu deroulant a un element de titre en position 0 (« choisir un
filtre... »), donc le i-eme filtre est a l'indice ``i + 1``. Ce decalage
d'une unite est la source d'erreur naturelle de tout ce fichier : il est
donc nomme une fois (``DECALAGE_TITRE``) et les conversions passent par des
fonctions, plutot que d'etre reecrit en ``index - 1`` a six endroits.
"""

from __future__ import annotations

from dataclasses import dataclass

from netcross_core.bpf_filters import BPFFilter
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

# Position du titre dans le menu deroulant : le i-eme filtre est donc a
# l'indice i + 1. Nomme une fois plutot que reecrit en "index - 1".
DECALAGE_TITRE = 1

TITRE_MENU_FILTRES = "Choisir un filtre..."
INDICE_AUCUNE_SELECTION = 0

# Messages de refus d'enregistrement. Ils sont affiches tels quels a
# l'utilisateur, donc verifies par les tests : un message change par
# inadvertance est une regression fonctionnelle, pas un detail de forme.
MSG_EXPRESSION_VIDE = "Le champ filtre BPF est vide : rien a enregistrer."
MSG_NOM_MANQUANT = "Donnez un nom au filtre."
MSG_SAUVEGARDE_INDISPONIBLE = "Sauvegarde des filtres indisponible."


def filtre_a_l_indice(index, filtres):
    """Le filtre designe par `index` dans le menu, ou ``None``.

    ``None`` couvre trois cas volontairement confondus ici -- le titre
    (indice 0), un indice negatif et un indice au-dela de la liste : dans les
    trois, il n'y a pas de filtre a annoncer, et l'appelant fait la meme
    chose. Les distinguer obligerait chaque appelant a les redistinguer.

    Un indice hors bornes n'est pas theorique : GTK renvoie
    ``Gtk.INVALID_LIST_POSITION`` (un tres grand entier) quand rien n'est
    selectionne, et le menu est reconstruit a chaque rafraichissement de la
    liste des filtres, donc l'indice memorise peut designer une position qui
    n'existe plus.
    """
    if index is None:
        return None
    position = index - DECALAGE_TITRE
    if position < 0 or position >= len(filtres):
        return None
    return filtres[position]


def infobulle_du_menu(index, filtres, indice_hint=None):
    """Texte d'infobulle du menu deroulant pour l'indice selectionne.

    Sur un filtre : sa description, ou son nom a defaut. Une description
    vide donnant une infobulle vide, l'utilisateur ne saurait pas si le
    filtre est sans description ou si l'infobulle est cassee -- le nom est
    toujours present, donc toujours affichable.

    Sur le titre ou un indice invalide : le texte d'invite passe par
    `indice_hint` plutot que code ici, parce qu'il appartient a la
    presentation.
    """
    flt = filtre_a_l_indice(index, filtres)
    if flt is None:
        return indice_hint
    return flt.description or flt.name


def selection_apres_choix(index, filtres):
    """(indice_a_appliquer, expression_a_ecrire) apres un choix dans le menu.

    ``(None, None)`` si l'indice ne designe pas un filtre : le titre n'est
    pas un choix, et le selectionner ne doit RIEN ecrire dans le champ --
    ecrire une chaine vide effacerait un filtre tape a la main, ce qui
    transformerait un clic malencontreux en perte de saisie.
    """
    flt = filtre_a_l_indice(index, filtres)
    if flt is None:
        logger.debug("selection_apres_choix: index={} -> titre ou hors bornes, rien à écrire", index)
        return None, None
    logger.debug("selection_apres_choix: index={} -> filtre {}", index, flt.name)
    return index, flt.expression


def doit_desolidariser_le_menu(index, filtres, texte_du_champ):
    """Le menu doit-il revenir sur le titre parce que le champ a ete edite ?

    Vrai seulement si un filtre est annonce ET que le texte du champ ne
    correspond plus a son expression. Laisser le menu annoncer « DNS » alors
    que le champ contient autre chose est le defaut que cette regle empeche :
    la capture tournerait avec l'expression du champ, et l'utilisateur
    croirait capturer du DNS.

    La comparaison ignore les espaces de bord uniquement. Normaliser
    davantage (casse, espaces internes) serait faux : `port 53` et `port  53`
    sont equivalents pour BPF, mais `tcp port 53` et `port 53` ne le sont
    pas, et une normalisation trop large finirait par confondre deux filtres
    reellement differents.
    """
    flt = filtre_a_l_indice(index, filtres)
    if flt is None:
        return False
    return (texte_du_champ or "").strip() != flt.expression


@dataclass(frozen=True)
class DemandeSauvegarde:
    """Resultat de la validation d'une demande d'enregistrement de filtre.

    `message` est non vide exactement quand `filtre` est ``None`` : un refus
    silencieux laisserait l'utilisateur cliquer sans comprendre, et un
    message affiche en cas de succes ferait croire a un probleme. L'invariant
    est verifie par un test plutot que seulement documente.
    """

    filtre: BPFFilter | None
    message: str

    @property
    def acceptee(self) -> bool:
        return self.filtre is not None


def valider_sauvegarde(expression, nom, description="", *, sauvegarde_possible=True):
    """Valide une demande d'enregistrement de filtre.

    L'ordre des controles est celui du plus probable au moins probable, et il
    est significatif : un champ filtre vide est l'oubli courant, alors que
    l'absence de mecanisme de sauvegarde est un defaut de configuration. Les
    signaler dans l'autre sens ferait croire a une panne de l'outil la ou il
    ne manque qu'une saisie.

    `sauvegarde_possible` reflete l'absence de rappel de sauvegarde cote
    panneau (`_on_save_filter is None`). C'est un etat anormal, mais il ne
    doit pas passer pour un succes : sans ce controle, le filtre semblerait
    enregistre et disparaitrait a la fermeture.
    """
    expression = (expression or "").strip()
    nom = (nom or "").strip()
    if not expression:
        logger.debug("valider_sauvegarde: refus, expression vide")
        return DemandeSauvegarde(None, MSG_EXPRESSION_VIDE)
    if not nom:
        logger.debug("valider_sauvegarde: refus, nom manquant")
        return DemandeSauvegarde(None, MSG_NOM_MANQUANT)
    if not sauvegarde_possible:
        logger.debug("valider_sauvegarde: refus, sauvegarde indisponible")
        return DemandeSauvegarde(None, MSG_SAUVEGARDE_INDISPONIBLE)
    logger.debug("valider_sauvegarde: acceptée, nom={} expression={}", nom, expression)
    return DemandeSauvegarde(BPFFilter(nom, expression, (description or "").strip()), "")


def indice_du_filtre_nomme(nom, filtres):
    """Indice de menu du filtre portant ce nom, ou ``None``.

    Comparaison insensible a la casse (`casefold`), alignee sur
    `netcross_core.bpf_filters`, qui traite deja « DNS » et « dns » comme un
    seul filtre. Utiliser une comparaison sensible a la casse ici
    repositionnerait le menu sur le titre apres un enregistrement reussi :
    l'utilisateur verrait son filtre sauvegarde mais non selectionne, et le
    choisirait a nouveau sans savoir s'il vient d'en creer un doublon.
    """
    if not nom:
        return None
    cible = nom.casefold()
    for position, flt in enumerate(filtres):
        if flt.name.casefold() == cible:
            logger.debug("indice_du_filtre_nomme: {} -> indice {}", nom, position + DECALAGE_TITRE)
            return position + DECALAGE_TITRE
    return None


def noms_du_menu(filtres, titre=TITRE_MENU_FILTRES):
    """Libelles du menu deroulant : le titre, puis un nom par filtre.

    Le titre est toujours present, meme sans aucun filtre : un menu vide
    n'aurait rien a afficher et paraitrait casse, alors que « choisir un
    filtre... » sur une liste vide dit au moins que la fonction existe.
    """
    logger.debug("noms_du_menu: {} filtre(s)", len(filtres))
    return [titre, *[flt.name for flt in filtres]]


def indice_apres_deplacement(index, nombre_de_lignes, vers_le_haut):
    """Nouvelle position d'une ligne deplacee, ou ``None`` si elle ne bouge pas.

    ``None`` -- et non la position inchangee -- pour que l'appelant puisse ne
    rien faire du tout : retirer puis reinserer une ligne a sa propre place
    fait clignoter la selection sans rien changer.

    L'ancien code etait dissymetrique : monter etait garde par ``if idx > 0``,
    descendre ne l'etait pas et inserait a ``idx + 1`` meme sur la derniere
    ligne. GTK appendant silencieusement quand la position depasse la
    longueur, la ligne restait en place -- donc aucun degat visible, mais la
    borne n'etait respectee que par accident. Une borne tenue par le hasard
    est une borne qui cassera le jour ou le conteneur changera de
    comportement, et c'est l'ordre des points de capture qui en depend
    (cf. lot 5).
    """
    if index is None or index < 0 or index >= nombre_de_lignes:
        return None
    logger.debug(
        "indice_apres_deplacement: index={} lignes={} vers_le_haut={}",
        index,
        nombre_de_lignes,
        vers_le_haut,
    )
    cible = index - 1 if vers_le_haut else index + 1
    if cible < 0 or cible >= nombre_de_lignes:
        return None
    return cible
