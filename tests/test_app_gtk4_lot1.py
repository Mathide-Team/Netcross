"""Tests GTK4 de CaptureRow et du debut de LiveCaptureRow (issue #422,
lot 1/N de #421), pilotes via pygobject.

Ignore si GTK4/pygobject ou un affichage manquent (CI sans libgtk-4) ; voir
tests/test_gui_security_window.py pour le meme garde-fou (issue #357).

Perimetre (lignes 135-309 de netcross_gtk4/app.py) :
- CaptureRow : __init__, _on_up, _on_down, _deplacer, _on_remove, label
- LiveCaptureRow : __init__, set_filters

MainWindow n'est volontairement pas instanciee dans ce lot (hors perimetre
de #422).
"""

import pytest

gi = pytest.importorskip("gi", reason="pygobject absent")
try:
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk
except (ValueError, ImportError):
    pytest.skip("GTK4 absent", allow_module_level=True)
if not Gtk.init_check():
    pytest.skip("pas d'affichage pour GTK4", allow_module_level=True)

from netcross_core.bpf_filters import PREDEFINED_BPF_FILTERS  # noqa: E402
from netcross_gtk4.app import (  # noqa: E402
    _FILTER_PICKER_TITLE,
    CaptureRow,
    LiveCaptureRow,
)
from netcross_gtk4.bpf_panel import noms_du_menu  # noqa: E402

# --------------------------------------------------------------------------
# CaptureRow : construction
# --------------------------------------------------------------------------


def test_capture_row_construction_stocke_le_path_et_le_label_par_defaut():
    row = CaptureRow("/tmp/captures/lan-a.pcapng", "LAN")
    assert row.path == "/tmp/captures/lan-a.pcapng"
    assert row.label == "LAN"


def test_capture_row_affiche_le_nom_de_fichier_sans_le_chemin_complet():
    row = CaptureRow("/tmp/captures/lan-a.pcapng", "LAN")
    # label_entry est le premier enfant du Box ; le libelle du fichier
    # (un Gtk.Label) est le suivant.
    path_label = row.label_entry.get_next_sibling()
    assert path_label.get_text() == "lan-a.pcapng"
    assert "/tmp/captures/lan-a.pcapng" not in path_label.get_text()


def test_capture_row_label_reflete_le_champ_edite_et_strip():
    row = CaptureRow("/tmp/x.pcap", "LAN")
    row.label_entry.set_text("  WAN  ")
    assert row.label == "WAN"


# --------------------------------------------------------------------------
# CaptureRow : reordonnancement (_on_up / _on_down / _deplacer)
# --------------------------------------------------------------------------


def _index_de(row):
    """Position de `row` dans le Gtk.ListBox qui le contient, via le
    Gtk.ListBoxRow implicite cree par GTK4 lors de l'append (voir le
    contrat get_parent()/deplacer_ligne de netcross_gtk4.capture_list)."""
    return row.get_parent().get_index()


def test_capture_row_on_up_et_on_down_avec_plusieurs_lignes():
    listbox = Gtk.ListBox()
    rows = [CaptureRow(f"/tmp/{nom}.pcap", nom) for nom in ("A", "B", "C")]
    for row in rows:
        listbox.append(row)
    assert [_index_de(r) for r in rows] == [0, 1, 2]

    # Monter la ligne du milieu (B) : echange avec A.
    rows[1]._on_up(None)
    assert _index_de(rows[1]) == 0
    assert _index_de(rows[0]) == 1
    assert _index_de(rows[2]) == 2

    # La redescendre : retour a la position initiale.
    rows[1]._on_down(None)
    assert _index_de(rows[1]) == 1
    assert _index_de(rows[0]) == 0
    assert _index_de(rows[2]) == 2


def test_capture_row_on_up_deja_en_haut_ne_deplace_rien():
    listbox = Gtk.ListBox()
    rows = [CaptureRow(f"/tmp/{nom}.pcap", nom) for nom in ("A", "B")]
    for row in rows:
        listbox.append(row)

    rows[0]._on_up(None)

    assert _index_de(rows[0]) == 0
    assert _index_de(rows[1]) == 1


def test_capture_row_on_down_deja_en_bas_ne_deplace_rien():
    listbox = Gtk.ListBox()
    rows = [CaptureRow(f"/tmp/{nom}.pcap", nom) for nom in ("A", "B")]
    for row in rows:
        listbox.append(row)

    rows[-1]._on_down(None)

    assert _index_de(rows[0]) == 0
    assert _index_de(rows[1]) == 1


# --------------------------------------------------------------------------
# CaptureRow : suppression (_on_remove)
# --------------------------------------------------------------------------


def test_capture_row_on_remove_retire_la_ligne_et_previent():
    listbox = Gtk.ListBox()
    appels = []
    row = CaptureRow("/tmp/x.pcap", "X", on_change=lambda: appels.append(True))
    listbox.append(row)
    assert listbox.get_row_at_index(0) is not None

    row._on_remove(None)

    assert listbox.get_row_at_index(0) is None
    assert appels == [True]


# --------------------------------------------------------------------------
# LiveCaptureRow : __init__
# --------------------------------------------------------------------------


def test_live_capture_row_construction_initialise_les_champs_passes():
    row = LiveCaptureRow("LAN", interface="eth0", bpf_filter="tcp port 80")
    assert row.label == "LAN"
    assert row.interface == "eth0"
    assert row.bpf_filter == "tcp port 80"


def test_live_capture_row_on_change_connecte_au_signal_changed_de_interface():
    appels = []
    row = LiveCaptureRow("LAN", on_change=lambda: appels.append(True))

    row.interface_entry.set_text("eth1")

    assert appels == [True]
    assert row.interface == "eth1"


def test_live_capture_row_sans_on_change_ne_leve_pas():
    # on_change est optionnel : aucun callback n'est connecte, mais editer
    # le champ ne doit pas lever d'exception pour autant.
    row = LiveCaptureRow("LAN")
    row.interface_entry.set_text("eth2")
    assert row.interface == "eth2"


# --------------------------------------------------------------------------
# LiveCaptureRow : set_filters
# --------------------------------------------------------------------------


def test_live_capture_row_set_filters_peuple_le_menu_avec_les_bons_noms():
    row = LiveCaptureRow("LAN")
    filtres = list(PREDEFINED_BPF_FILTERS[:3])

    row.set_filters(filtres)

    modele = row.filter_dropdown.get_model()
    noms = [modele.get_string(i) for i in range(modele.get_n_items())]
    assert noms == noms_du_menu(filtres, _FILTER_PICKER_TITLE)


def test_live_capture_row_set_filters_reselectionne_le_titre():
    row = LiveCaptureRow("LAN")
    filtres = list(PREDEFINED_BPF_FILTERS[:2])

    row.set_filters(filtres)

    # Apres l'appel, la selection revient sur le titre (indice 0), meme si
    # une liste non vide de filtres a ete fournie.
    assert row.filter_dropdown.get_selected() == 0


def test_live_capture_row_set_filters_avec_liste_vide():
    row = LiveCaptureRow("LAN")

    row.set_filters([])

    modele = row.filter_dropdown.get_model()
    noms = [modele.get_string(i) for i in range(modele.get_n_items())]
    assert noms == [_FILTER_PICKER_TITLE]
    assert row.filter_dropdown.get_selected() == 0
