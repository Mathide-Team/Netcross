"""Test GUI (pygobject) du panneau d'annotations (issue #363).

Ignore si GTK4/pygobject ou un affichage manquent (CI sans libgtk-4) ;
la logique est couverte sans GTK par test_annotations_store.py.
"""

import pytest
from gtk4_display import exiger_gtk4_avec_affichage

from netcross_core.forensic import read_annotations

Gtk = exiger_gtk4_avec_affichage()

from netcross_gtk4.annotations_panel import AnnotationsPanel  # noqa: E402


def _labels(panel):
    out = []
    child = panel.list_box.get_first_child()
    while child is not None:
        label = child.get_child() if isinstance(child, Gtk.ListBoxRow) else child
        out.append(label.get_text())
        child = child.get_next_sibling()
    return out


@pytest.fixture
def captures(tmp_path):
    paths = []
    for name in ("client", "serveur"):
        p = tmp_path / f"{name}.pcap"
        p.write_bytes(b"")
        paths.append((name, str(p)))
    return paths


def test_ajout_puis_relecture_depuis_le_sidecar(captures):
    panel = AnnotationsPanel()
    panel.load(captures)
    panel.point_drop.set_selected(1)
    panel.frame_entry.set_text("42")
    panel.tag_entry.set_text("rst-suspect")
    panel.comment_entry.set_text("reset apres SYN")
    assert panel.submit()
    assert [a.tag for a in read_annotations(captures[1][1])] == ["rst-suspect"]

    relu = AnnotationsPanel()
    relu.load(captures)
    assert _labels(relu) == ["serveur [rst-suspect] trame #42 -- reset apres SYN"]


def test_saisie_invalide_affiche_une_erreur(captures):
    panel = AnnotationsPanel()
    panel.load(captures)
    panel.frame_entry.set_text("abc")
    panel.tag_entry.set_text("x")
    assert not panel.submit()
    assert "non enregistree" in panel.status_label.get_text()
    assert read_annotations(captures[0][1]) == []


def test_menu_contextuel_et_filtre(captures):
    panel = AnnotationsPanel()
    panel.load(captures)
    assert [label for label, _cb in panel.context_actions(None)] == ["Ajouter une etiquette"]
    for frame, tag in ((5, "perte"), (6, "retrans")):
        panel.frame_entry.set_text(str(frame))
        panel.tag_entry.set_text(tag)
        assert panel.submit()

    actions = dict(panel.context_actions(("client", 5, "perte")))
    assert list(actions) == ["Ajouter une etiquette sur cette trame", "Supprimer cette etiquette"]
    actions["Ajouter une etiquette sur cette trame"]()
    assert panel.frame_entry.get_text() == "5"
    panel.tag_entry.set_text("a-revoir")
    assert panel.submit()

    panel.toggle_tag("perte", True)
    assert [a.tag for _p, a in panel.visible_rows()] == ["perte"]
    panel.toggle_tag("perte", False)
    assert len(panel.visible_rows()) == 3

    actions["Supprimer cette etiquette"]()
    assert sorted(a.tag for a in read_annotations(captures[0][1])) == ["a-revoir", "retrans"]


def test_clear_desactive_le_formulaire(captures):
    panel = AnnotationsPanel()
    panel.load(captures)
    panel.clear()
    assert not panel.add_btn.get_sensitive()
    assert panel.context_actions(None) == []
