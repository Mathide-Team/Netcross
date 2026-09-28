"""Tests GUI complementaires du panneau d'annotations (#683).

`tests/test_gui_annotations_panel.py` couvre l'ajout, la relecture, la
saisie invalide, le menu contextuel (via `context_actions`) et `clear`.
Ce fichier ajoute :

- les gardes sans capture chargee (`selected_point`, `submit`, `remove`) ;
- `prefill` avec un point inconnu ;
- l'echec d'ecriture d'une suppression (`remove` -> message d'erreur) ;
- `context_actions` pour un point qui n'est plus inscriptible ;
- le gestionnaire de clic droit `_on_right_click`, appele directement avec
  une doublure de geste et `Gtk.Popover.popup` doublee : un vrai popup exige
  un gestionnaire de fenetres (absent sous Xvfb), comme `present()` dans
  `test_app_gtk4_lot10.py`.

Ignore si GTK4/pygobject ou un affichage manquent (CI sans libgtk-4).
"""

from unittest import mock

import pytest
from gtk4_display import exiger_gtk4_avec_affichage

from netcross_core.forensic import read_annotations

Gtk = exiger_gtk4_avec_affichage()

from netcross_gtk4.annotations_panel import AnnotationsPanel  # noqa: E402
from netcross_gtk4.annotations_view import AnnotationStore  # noqa: E402


@pytest.fixture
def captures(tmp_path):
    paths = []
    for name in ("client", "serveur"):
        p = tmp_path / f"{name}.pcap"
        p.write_bytes(b"")
        paths.append((name, str(p)))
    return paths


@pytest.fixture
def panneau(captures):
    """Panneau charge, avec une annotation (client, trame 5, « perte »)."""
    panel = AnnotationsPanel()
    panel.load(captures)
    panel.frame_entry.set_text("5")
    panel.tag_entry.set_text("perte")
    assert panel.submit()
    return panel


@pytest.fixture
def popovers(monkeypatch):
    """Remplace `Gtk.Popover.popup` par un enregistreur ; deparente les
    popovers a la fin (sinon GTK signale des enfants restants)."""
    ouverts = []
    monkeypatch.setattr(Gtk.Popover, "popup", lambda self: ouverts.append(self))
    yield ouverts
    for popover in ouverts:
        popover.emit("closed")  # le panneau se deparente sur ce signal


class _Geste:
    """Doublure de Gtk.GestureClick : note l'etat demande."""

    def __init__(self):
        self.etat = None

    def set_state(self, etat):
        self.etat = etat


def _boutons(popover):
    boites = popover.get_child()
    out = {}
    enfant = boites.get_first_child()
    while enfant is not None:
        out[enfant.get_label()] = enfant
        enfant = enfant.get_next_sibling()
    return out


# -- gardes sans capture chargee -------------------------------------------------------


def test_selected_point_sans_capture_renvoie_none():
    assert AnnotationsPanel().selected_point() is None


def test_selected_point_apres_chargement(captures):
    panel = AnnotationsPanel()
    panel.load(captures)
    assert panel.selected_point() == "client"
    panel.point_drop.set_selected(1)
    assert panel.selected_point() == "serveur"


def test_submit_sans_capture_renvoie_false():
    panel = AnnotationsPanel()
    panel.frame_entry.set_text("1")
    panel.tag_entry.set_text("x")
    assert panel.submit() is False


def test_remove_sans_capture_ne_fait_rien():
    panel = AnnotationsPanel()
    panel.remove("client", 5, "perte")  # ne leve pas
    assert panel.store is None


# -- prefill ------------------------------------------------------------------------------


def test_prefill_point_inconnu_garde_la_selection(captures):
    panel = AnnotationsPanel()
    panel.load(captures)
    panel.point_drop.set_selected(1)

    panel.prefill("inconnu", 7)

    assert panel.selected_point() == "serveur"
    assert panel.frame_entry.get_text() == "7"
    assert panel.tag_entry.get_text() == ""


def test_prefill_sans_trame_vide_le_champ_trame(captures):
    panel = AnnotationsPanel()
    panel.load(captures)
    panel.frame_entry.set_text("9")

    panel.prefill("serveur", None)

    assert panel.selected_point() == "serveur"
    assert panel.frame_entry.get_text() == ""


# -- remove : echec d'ecriture -----------------------------------------------------------------


@pytest.mark.parametrize("erreur", [OSError("disque plein"), ValueError("annotation introuvable")])
def test_remove_echec_affiche_une_erreur_et_garde_la_ligne(panneau, captures, erreur):
    with mock.patch.object(AnnotationStore, "remove", side_effect=erreur):
        panneau.remove("client", 5, "perte")

    assert f"Suppression impossible : {erreur}" in panneau.status_label.get_text()
    assert [a.tag for a in read_annotations(captures[0][1])] == ["perte"]
    assert len(panneau.visible_rows()) == 1


# -- context_actions -------------------------------------------------------------------------------


def test_context_actions_point_inconnu_sans_action(panneau):
    assert panneau.context_actions(("inconnu", 1, "x")) == []


# -- _on_right_click ---------------------------------------------------------------------------------


def test_clic_droit_sans_capture_ne_montre_rien(popovers):
    panel = AnnotationsPanel()
    geste = _Geste()

    panel._on_right_click(geste, 1, 10.0, 10.0)

    assert popovers == []
    assert geste.etat is None


def test_clic_droit_point_inconnu_ne_montre_rien(panneau, monkeypatch, popovers):
    ligne = Gtk.ListBoxRow()
    ligne.annotation = ("inconnu", 1, "x")
    monkeypatch.setattr(panneau.list_box, "get_row_at_y", lambda _y: ligne)
    geste = _Geste()

    panneau._on_right_click(geste, 1, 10.0, 10.0)

    assert popovers == []
    assert geste.etat is None


def test_clic_droit_zone_vide_propose_d_ajouter(panneau, monkeypatch, popovers):
    monkeypatch.setattr(panneau.list_box, "get_row_at_y", lambda _y: None)
    geste = _Geste()

    panneau._on_right_click(geste, 1, 10.0, 12.0)

    assert geste.etat == Gtk.EventSequenceState.CLAIMED
    assert len(popovers) == 1
    boutons = _boutons(popovers[0])
    assert list(boutons) == ["Ajouter une etiquette"]

    panneau.point_drop.set_selected(0)
    boutons["Ajouter une etiquette"].emit("clicked")
    assert panneau.frame_entry.get_text() == ""  # formulaire prepare, focus sur la trame


def test_clic_droit_sur_une_annotation_propose_ajout_et_suppression(panneau, captures, monkeypatch, popovers):
    ligne = next(
        enfant
        for enfant in _enfants(panneau.list_box)
        if isinstance(enfant, Gtk.ListBoxRow) and hasattr(enfant, "annotation")
    )
    monkeypatch.setattr(panneau.list_box, "get_row_at_y", lambda _y: ligne)
    geste = _Geste()

    panneau._on_right_click(geste, 1, 10.0, 12.0)

    assert geste.etat == Gtk.EventSequenceState.CLAIMED
    boutons = _boutons(popovers[0])
    assert list(boutons) == ["Ajouter une etiquette sur cette trame", "Supprimer cette etiquette"]

    boutons["Ajouter une etiquette sur cette trame"].emit("clicked")
    assert panneau.frame_entry.get_text() == "5"

    boutons["Supprimer cette etiquette"].emit("clicked")
    assert read_annotations(captures[0][1]) == []


def _enfants(widget):
    enfant = widget.get_first_child()
    while enfant is not None:
        yield enfant
        enfant = enfant.get_next_sibling()
