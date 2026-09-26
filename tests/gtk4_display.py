"""Garde commune des tests GTK4 : pygobject, GTK4 ET un affichage réel.

Les tests pilotés via pygobject (#357, #363, lots de #421) doivent être
sautés proprement là où GTK4 ou un affichage manquent -- en particulier en
CI sans libgtk-4 (principe de #285/#421 : aucun test n'exige GTK4 en CI).

``Gtk.init_check()`` seul ne suffit PAS : sous GTK 4.22 il renvoie ``True``
même sans ``DISPLAY`` ni ``WAYLAND_DISPLAY``, alors qu'aucun
``Gdk.Display`` n'existe. La création du premier widget échoue alors sur
``gtk_icon_theme_get_for_display: assertion 'GDK_IS_DISPLAY (display)'``
puis provoque une **erreur de segmentation qui tue tout le processus
pytest** -- toute la suite, pas seulement le test GTK (constaté sur un
poste avec pygobject installé et sans serveur graphique : SSH, conteneur).
Le seul critère fiable est ``Gdk.Display.get_default() is not None``.

Usage, en tête de module, avant tout import de ``netcross_gtk4`` :

    from gtk4_display import exiger_gtk4_avec_affichage

    Gtk = exiger_gtk4_avec_affichage()
"""

from __future__ import annotations

import pytest

MOTIF_PYGOBJECT_ABSENT = "pygobject absent"
MOTIF_GTK4_ABSENT = "GTK4 absent"
MOTIF_SANS_AFFICHAGE = "pas d'affichage pour GTK4"


def exiger_gtk4_avec_affichage():
    """Renvoie le module ``Gtk`` (4.0) prêt à l'emploi, ou saute le module
    de test appelant (``allow_module_level``) si pygobject, GTK4 ou un
    affichage manquent. Les motifs de saut sont stables : le job CI GTK4
    (Xvfb) échoue s'il les rencontre."""
    gi = pytest.importorskip("gi", reason=MOTIF_PYGOBJECT_ABSENT)
    try:
        gi.require_version("Gtk", "4.0")
        gi.require_version("Gdk", "4.0")
        from gi.repository import Gdk, Gtk
    except (ValueError, ImportError):
        pytest.skip(MOTIF_GTK4_ABSENT, allow_module_level=True)
    if not Gtk.init_check() or Gdk.Display.get_default() is None:
        pytest.skip(MOTIF_SANS_AFFICHAGE, allow_module_level=True)
    return Gtk
