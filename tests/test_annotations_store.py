"""AnnotationStore : persistance GUI des annotations par capture (issue #363).

Logique sans GTK du panneau `netcross_gtk4.annotations_panel` : chargement
des sidecars, ajout/suppression persistes, filtre par etiquette,
point en lecture seule si son sidecar est illisible.
"""

import json
import pathlib

import pytest

from netcross_core.forensic import annotations_sidecar_path, read_annotations
from netcross_gtk4.annotations_view import AnnotationStore, parse_frame_number

APP = pathlib.Path(__file__).resolve().parents[1] / "src" / "netcross_gtk4" / "app.py"


def _captures(tmp_path):
    a = tmp_path / "client.pcap"
    b = tmp_path / "serveur.pcap"
    a.write_bytes(b"")
    b.write_bytes(b"")
    return [("client", str(a)), ("serveur", str(b))]


def test_ajout_persiste_dans_le_sidecar_de_la_bonne_capture(tmp_path):
    caps = _captures(tmp_path)
    store = AnnotationStore.load(caps)
    store.add("serveur", 42, " rst-suspect ", "  reset apres SYN  ")
    assert read_annotations(caps[0][1]) == []
    (ann,) = read_annotations(caps[1][1])
    assert (ann.frame_number, ann.tag, ann.comment) == (42, "rst-suspect", "reset apres SYN")
    # relu par une nouvelle session
    assert [(p, a.tag) for p, a in AnnotationStore.load(caps).rows()] == [("serveur", "rst-suspect")]


def test_doublon_trame_tag_met_a_jour_le_commentaire(tmp_path):
    caps = _captures(tmp_path)
    store = AnnotationStore.load(caps)
    store.add("client", 3, "x", "v1")
    store.add("client", 3, "x", "v2")
    assert [a.comment for a in read_annotations(caps[0][1])] == ["v2"]


def test_suppression_persiste(tmp_path):
    caps = _captures(tmp_path)
    store = AnnotationStore.load(caps)
    store.add("client", 3, "a")
    store.add("client", 4, "b")
    store.remove("client", 3, "a")
    assert [(a.frame_number, a.tag) for a in read_annotations(caps[0][1])] == [(4, "b")]


def test_filtre_par_tag_et_ordre(tmp_path):
    caps = _captures(tmp_path)
    store = AnnotationStore.load(caps)
    store.add("serveur", 9, "perte")
    store.add("client", 7, "retrans")
    store.add("client", 2, "perte")
    assert store.tags() == ["perte", "retrans"]
    assert [(p, a.frame_number) for p, a in store.rows()] == [("client", 2), ("client", 7), ("serveur", 9)]
    assert [(p, a.frame_number) for p, a in store.rows({"perte"})] == [("client", 2), ("serveur", 9)]


def test_tag_vide_refuse_sans_ecriture(tmp_path):
    caps = _captures(tmp_path)
    store = AnnotationStore.load(caps)
    with pytest.raises(ValueError):
        store.add("client", 1, "   ")
    assert not pathlib.Path(annotations_sidecar_path(caps[0][1])).exists()


@pytest.mark.parametrize("contenu", ["{pas du json", json.dumps([{"tag": "sans trame"}]), json.dumps(3)])
def test_sidecar_illisible_point_en_lecture_seule(tmp_path, contenu):
    caps = _captures(tmp_path)
    side = pathlib.Path(annotations_sidecar_path(caps[0][1]))
    side.write_text(contenu, encoding="utf-8")
    store = AnnotationStore.load(caps)
    assert "client" in store.errors
    assert store.writable_labels() == ["serveur"]
    with pytest.raises(ValueError, match="lecture seule"):
        store.add("client", 1, "x")
    assert side.read_text(encoding="utf-8") == contenu  # jamais ecrase
    store.add("serveur", 1, "x")  # les autres points restent annotables


def test_point_inconnu_leve_keyerror_sans_rien_ecrire(tmp_path):
    """Annoter ou retirer une annotation d'un point qui n'est pas dans les
    captures leve KeyError (`_path`), sans rien persister (#746)."""
    caps = _captures(tmp_path)
    store = AnnotationStore.load(caps)
    with pytest.raises(KeyError, match="point inconnu : fantome"):
        store.add("fantome", 1, "x")
    with pytest.raises(KeyError, match="point inconnu : fantome"):
        store.remove("fantome", 1, "x")
    assert "fantome" not in store.by_label
    assert all(read_annotations(path) == [] for _label, path in caps)


@pytest.mark.parametrize(("texte", "attendu"), [("12", 12), (" #7 ", 7)])
def test_parse_frame_number(texte, attendu):
    assert parse_frame_number(texte) == attendu


@pytest.mark.parametrize("texte", ["", "abc", "0", "-3", "1.5"])
def test_parse_frame_number_invalide(texte):
    with pytest.raises(ValueError):
        parse_frame_number(texte)


def test_app_raccorde_le_panneau_aux_analyses():
    """Verifiable sans GTK : l'ancien formulaire (inutilisable, expander
    desactive tant qu'aucune annotation n'existait) est remplace par le
    panneau, charge a la fin d'une analyse de fichiers."""
    src = APP.read_text(encoding="utf-8")
    assert "AnnotationsPanel()" in src
    assert "self.annotations_panel.load(self._annotation_captures)" in src
    assert "self.annotations_panel.clear()" in src
    assert "annotations_expander.set_sensitive(False)" not in src
