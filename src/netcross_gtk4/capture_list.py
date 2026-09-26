"""
Enumeration, ordre et retrait des lignes des panneaux de captures, sortis de
``netcross_gtk4/app.py`` (issue #285, cinquieme lot).

L'ordre des lignes n'est pas cosmetique : quand la deduction automatique de
topologie est desactivee, il EST le chemin physique du reseau (point 1 en
amont, point N en aval). Une ligne mal enumeree, un deplacement qui saute une
borne ou un nom par defaut en double changent donc le resultat de l'analyse
sans lever d'erreur.

Les fonctions ci-dessous ne touchent aucun objet GTK par leur type : elles
recoivent le ``Gtk.ListBox`` ou la ligne et n'en appellent que les methodes
(``get_row_at_index``, ``get_child``, ``get_parent``, ``get_index``,
``remove``, ``insert``, ``select_row``). Des objets factices suffisent donc a
les tester, sans PyGObject ni serveur graphique.

## Ce que ce lot a corrige

- Retirer une capture ne prevenait pas la fenetre : le bouton Lancer restait
  dans l'etat calcule AVANT le retrait (actif avec une seule capture en mode
  comparaison, par exemple). ``retirer_ligne`` rappelle desormais
  ``on_change``, comme l'ajout le faisait deja.
- Les lignes de capture live montaient avec une borne mais descendaient
  sans, contrairement aux lignes de fichiers corrigees au lot 4 : les deux
  passent maintenant par ``deplacer_ligne``.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from typing import Any, Protocol

from netcross_core.logging_config import get_logger
from netcross_gtk4.bpf_panel import indice_apres_deplacement

logger = get_logger(__name__)

PREFIXE_POINT = "POINT"


class _RowSource(Protocol):
    def get_row_at_index(self, index: int) -> Any: ...


def nombre_de_lignes(listbox: _RowSource) -> int:
    """Nombre de lignes d'un ``Gtk.ListBox`` : GTK n'expose pas de compteur,
    on avance jusqu'a ce que ``get_row_at_index`` renvoie ``None``."""
    nombre = 0
    while listbox.get_row_at_index(nombre) is not None:
        nombre += 1
    return nombre


def lignes(listbox: _RowSource) -> list[Any]:
    """Contenus des lignes (``row.get_child()``) dans l'ordre visuel."""
    contenus = []
    i = 0
    while (row := listbox.get_row_at_index(i)) is not None:
        contenus.append(row.get_child())
        i += 1
    return contenus


def nom_de_point(nom: str, index: int) -> str:
    """Nom saisi, ou ``POINT<n>`` (n a partir de 1) si le champ est vide."""
    return nom or f"{PREFIXE_POINT}{index + 1}"


def nom_par_defaut_fichier(chemin: str) -> str:
    """Nom propose pour une capture ajoutee : nom du fichier sans extension,
    en majuscules (``/tmp/lan-a.pcapng`` -> ``LAN-A``)."""
    logger.debug("nom_par_defaut_fichier: {}", chemin)
    return os.path.splitext(os.path.basename(chemin))[0].upper()


def nom_par_defaut_live(lignes_existantes: int) -> str:
    """Nom propose pour un nouveau point live : le suivant dans la liste."""
    logger.debug("nom_par_defaut_live: {} ligne(s) existante(s)", lignes_existantes)
    return nom_de_point("", lignes_existantes)


def captures_fichiers(contenus: Sequence[Any]) -> list[tuple[str, str]]:
    """(nom, chemin) de chaque ligne de fichier, dans l'ordre visuel."""
    logger.debug("captures_fichiers: {} ligne(s)", len(contenus))
    return [(nom_de_point(row.label, i), row.path) for i, row in enumerate(contenus)]


def captures_live(contenus: Sequence[Any]) -> list[tuple[str, str, str | None]]:
    """(nom, texte du champ interface, filtre BPF ou ``None``) de chaque
    ligne live, dans l'ordre visuel. Le champ interface peut en porter
    plusieurs : voir ``live_capture_points.expand_live_points``."""
    logger.debug("captures_live: {} ligne(s)", len(contenus))
    return [(nom_de_point(row.label, i), row.interface, row.bpf_filter) for i, row in enumerate(contenus)]


def deplacer_ligne(row: Any, *, vers_le_haut: bool) -> bool:
    """Deplace ``row`` (un ``Gtk.ListBoxRow``) d'un cran dans sa liste et la
    selectionne. Au bord, ne fait rien -- pas de retrait/reinsertion a la
    meme place, qui ferait clignoter la selection. Renvoie ``True`` si la
    ligne a bouge."""
    listbox = row.get_parent()
    if listbox is None:
        return False
    cible = indice_apres_deplacement(row.get_index(), nombre_de_lignes(listbox), vers_le_haut)
    if cible is None:
        logger.debug("deplacer_ligne: au bord, aucun déplacement")
        return False
    logger.debug("deplacer_ligne: {} -> {}", row.get_index(), cible)
    listbox.remove(row)
    listbox.insert(row, cible)
    listbox.select_row(row)
    return True


def retirer_ligne(row: Any, on_change: Callable[[], Any] | None = None) -> bool:
    """Retire ``row`` de sa liste puis previent ``on_change`` : l'etat du
    bouton Lancer depend du nombre de lignes. Renvoie ``True`` si la ligne
    a ete retiree."""
    listbox = row.get_parent()
    if listbox is None:
        return False
    logger.debug("retirer_ligne: retrait d'une ligne, on_change={}", on_change is not None)
    listbox.remove(row)
    if on_change is not None:
        on_change()
    return True


__all__ = [
    "PREFIXE_POINT",
    "captures_fichiers",
    "captures_live",
    "deplacer_ligne",
    "lignes",
    "nom_de_point",
    "nom_par_defaut_fichier",
    "nom_par_defaut_live",
    "nombre_de_lignes",
    "retirer_ligne",
]
