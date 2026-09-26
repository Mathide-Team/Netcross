"""Couverture GTK4 de app.py, lot 2 (issue #423, sous-issue de #421).

Portee : LiveCaptureRow (menu de filtres BPF, popover de sauvegarde,
up/down/remove, properties) et CaptureListPanel (selecteur de fichiers).
Meme garde que tests/test_gui_security_window.py : ignore proprement si
GTK4/pygobject ou un affichage manquent (CI sans libgtk-4) -- aucun test
de ce fichier ne doit exiger GTK4 en CI.
"""

import pytest

gi = pytest.importorskip("gi", reason="pygobject absent")
try:
    gi.require_version("Gtk", "4.0")
    from gi.repository import GLib, Gtk
except (ValueError, ImportError):
    pytest.skip("GTK4 absent", allow_module_level=True)
if not Gtk.init_check():
    pytest.skip("pas d'affichage pour GTK4", allow_module_level=True)

from netcross_core.models import BPFFilter  # noqa: E402
from netcross_gtk4 import app as app_module  # noqa: E402
from netcross_gtk4.app import CaptureListPanel, LiveCaptureRow  # noqa: E402
from netcross_gtk4.bpf_panel import (  # noqa: E402
    MSG_EXPRESSION_VIDE,
    MSG_NOM_MANQUANT,
    MSG_SAUVEGARDE_INDISPONIBLE,
    infobulle_du_menu,
)

HTTP = BPFFilter("HTTP", "tcp port 80", "Trafic HTTP en clair.")
DNS = BPFFilter("DNS", "port 53", "Requetes et reponses DNS.")


def _make_row(**kwargs):
    return LiveCaptureRow("A", **kwargs)


# ================= _select_filter_index / infobulle =================


def test_select_filter_index_positionne_le_dropdown_et_l_infobulle():
    row = _make_row(filters=[HTTP, DNS])

    row._select_filter_index(2)  # DECALAGE_TITRE=1 -> DNS est a l'indice 2
    assert row.filter_dropdown.get_selected() == 2
    assert row.filter_dropdown.get_tooltip_text() == infobulle_du_menu(2, row._filters, app_module._FILTER_PICKER_HINT)
    assert row.filter_dropdown.get_tooltip_text() == DNS.description

    row._select_filter_index(0)
    assert row.filter_dropdown.get_selected() == 0
    assert row.filter_dropdown.get_tooltip_text() == app_module._FILTER_PICKER_HINT


# ================= _on_filter_picked =================


def test_on_filter_picked_remplit_le_champ():
    row = _make_row(filters=[HTTP, DNS])
    row.filter_dropdown.set_selected(1)  # HTTP
    assert row.filter_entry.get_text() == HTTP.expression
    assert row.filter_dropdown.get_selected() == 1


def test_on_filter_picked_titre_ne_vide_pas_le_champ():
    row = _make_row(filters=[HTTP])
    row.filter_dropdown.set_selected(1)
    assert row.filter_entry.get_text() == HTTP.expression

    row.filter_dropdown.set_selected(0)  # retour au titre
    assert row.filter_entry.get_text() == HTTP.expression  # inchange


def test_syncing_dropdown_evite_la_boucle_de_retroaction():
    """Sans le garde _syncing_dropdown, positionner le dropdown depuis
    _select_filter_index declencherait la notification GTK -> _on_filter_picked,
    qui ecrirait l'expression du filtre survole dans le champ -- ecrasant une
    saisie manuelle en cours a chaque fois que le menu se met a jour lui-meme
    (ex: set_filters() apres l'enregistrement d'un nouveau filtre)."""
    row = _make_row(filters=[HTTP])
    row.filter_entry.set_text("saisie manuelle en cours")

    row._select_filter_index(1)  # le menu se met a jour lui-meme sur HTTP

    assert row.filter_dropdown.get_selected() == 1
    assert row.filter_entry.get_text() == "saisie manuelle en cours"  # jamais ecrase


# ================= _on_filter_text_changed =================


def test_filter_text_changed_desolidarise_le_menu():
    row = _make_row(filters=[HTTP])
    row.filter_dropdown.set_selected(1)
    assert row.filter_dropdown.get_selected() == 1

    row.filter_entry.set_text("tcp port 8080")  # edite a la main
    assert row.filter_dropdown.get_selected() == 0


def test_filter_text_changed_meme_expression_ne_desolidarise_pas():
    row = _make_row(filters=[HTTP])
    row.filter_dropdown.set_selected(1)  # HTTP selectionne, champ = "tcp port 80"
    assert row.filter_dropdown.get_selected() == 1
    # Appel direct du handler plutot que filter_entry.set_text(...) : set_text()
    # emet "changed" deux fois (suppression puis insertion), et l'etat
    # intermediaire vide desolidariserait le menu avant meme l'ecriture du
    # texte final, quel qu'il soit -- artefact de GtkEditable sans rapport
    # avec la regle testee ici (meme expression -> pas de desolidarisation).
    row._on_filter_text_changed(row.filter_entry)
    assert row.filter_dropdown.get_selected() == 1


# ================= popover de sauvegarde =================


def test_save_filter_nominal():
    saved = []
    row = _make_row(on_save_filter=lambda flt: saved.append(flt))
    row._build_save_popover()
    row.filter_entry.set_text("tcp port 999")
    row._save_name_entry.set_text("MonFiltre")
    row._save_desc_entry.set_text("une description")

    row._on_save_filter_clicked(None)

    assert saved == [BPFFilter("MonFiltre", "tcp port 999", "une description")]
    assert row._save_status.get_text() == ""
    assert row._save_name_entry.get_text() == ""
    assert row._save_desc_entry.get_text() == ""


def test_save_filter_expression_vide():
    row = _make_row(on_save_filter=lambda flt: None)
    row._build_save_popover()
    row.filter_entry.set_text("")
    row._save_name_entry.set_text("MonFiltre")

    row._on_save_filter_clicked(None)

    assert row._save_status.get_text() == MSG_EXPRESSION_VIDE


def test_save_filter_nom_manquant():
    row = _make_row(on_save_filter=lambda flt: None)
    row._build_save_popover()
    row.filter_entry.set_text("tcp port 999")
    row._save_name_entry.set_text("")

    row._on_save_filter_clicked(None)

    assert row._save_status.get_text() == MSG_NOM_MANQUANT


def test_save_filter_sauvegarde_indisponible():
    row = _make_row(on_save_filter=None)
    row._build_save_popover()
    row.filter_entry.set_text("tcp port 999")
    row._save_name_entry.set_text("MonFiltre")

    row._on_save_filter_clicked(None)

    assert row._save_status.get_text() == MSG_SAUVEGARDE_INDISPONIBLE


def test_save_filter_erreur_de_sauvegarde():
    """on_save_filter peut lever OSError/ValueError (fichier illisible, nom
    reserve...) : l'erreur doit s'afficher dans le popover, pas remonter."""

    def _on_save(flt):
        raise OSError("permission refusee")

    row = _make_row(on_save_filter=_on_save)
    row._build_save_popover()
    row.filter_entry.set_text("tcp port 999")
    row._save_name_entry.set_text("MonFiltre")

    row._on_save_filter_clicked(None)  # ne doit pas lever

    assert row._save_status.get_text() == "permission refusee"
    # champs non vides : l'echec ne doit pas effacer la saisie en cours
    assert row._save_name_entry.get_text() == "MonFiltre"


def test_save_filter_repositionne_sur_le_filtre_enregistre():
    """Apres un enregistrement reussi, la ligne se repositionne sur le
    filtre qu'elle vient de sauvegarder (via indice_du_filtre_nomme)."""
    nouveau = BPFFilter("MonFiltre", "tcp port 999", "")

    def _on_save(flt):
        row.set_filters([HTTP, nouveau])

    row = _make_row(filters=[HTTP], on_save_filter=_on_save)
    row._build_save_popover()
    row.filter_entry.set_text("tcp port 999")
    row._save_name_entry.set_text("MonFiltre")

    row._on_save_filter_clicked(None)

    assert row.filter_dropdown.get_selected() == 2  # HTTP=1, MonFiltre=2


# ================= up / down / remove =================


def _listbox_with_rows(n):
    listbox = Gtk.ListBox()
    rows = []
    for i in range(n):
        row = LiveCaptureRow(f"P{i}")
        listbox.append(row)
        rows.append(row)
    return listbox, rows


def test_up_down_remove_live_capture_row():
    listbox, rows = _listbox_with_rows(3)

    rows[1]._on_down(None)
    assert [listbox.get_row_at_index(i).get_child() for i in range(3)] == [rows[0], rows[2], rows[1]]

    rows[1]._on_up(None)  # rows[1] est maintenant en derniere position
    assert [listbox.get_row_at_index(i).get_child() for i in range(3)] == [rows[0], rows[1], rows[2]]

    changed = []
    rows[0]._on_change = lambda: changed.append(True)
    rows[0]._on_remove(None)
    assert changed == [True]
    remaining = [listbox.get_row_at_index(i).get_child() for i in range(2)]
    assert rows[0] not in remaining


def test_up_au_bord_ne_bouge_pas():
    listbox, rows = _listbox_with_rows(2)
    rows[0]._on_up(None)
    assert [listbox.get_row_at_index(i).get_child() for i in range(2)] == rows


def test_down_au_bord_ne_bouge_pas():
    listbox, rows = _listbox_with_rows(2)
    rows[1]._on_down(None)
    assert [listbox.get_row_at_index(i).get_child() for i in range(2)] == rows


# ================= properties =================


def test_properties_label_interface_bpf_filter_strippees():
    row = _make_row(interface=" eth0 ", bpf_filter=" tcp port 80 ")
    row.label_entry.set_text("  LAN  ")
    assert row.label == "LAN"
    assert row.interface == "eth0"
    assert row.bpf_filter == "tcp port 80"


def test_bpf_filter_vide_est_none():
    row = _make_row(bpf_filter="   ")
    assert row.bpf_filter is None


# ================= CaptureListPanel._on_add_clicked =================


def test_on_add_clicked_ouvre_un_file_dialog(monkeypatch):
    panel = CaptureListPanel("Points de capture")
    appels = []

    def _fake_open_multiple(dialog_self, parent, cancellable, callback):
        appels.append((dialog_self, parent, cancellable, callback))

    monkeypatch.setattr(Gtk.FileDialog, "open_multiple", _fake_open_multiple)

    panel._on_add_clicked(None)

    assert len(appels) == 1
    dialog, _parent, cancellable, callback = appels[0]
    assert isinstance(dialog, Gtk.FileDialog)
    assert cancellable is None
    assert callback == panel._on_files_chosen
    filtres = dialog.get_filters()
    assert filtres.get_n_items() == 1
    assert filtres.get_item(0).get_name() == "Captures Wireshark (*.pcap, *.pcapng)"


# ================= CaptureListPanel._on_files_chosen =================


class _FakeGFile:
    def __init__(self, path):
        self._path = path

    def get_path(self):
        return self._path


class _FakeFiles:
    def __init__(self, paths):
        self._items = [_FakeGFile(p) for p in paths]

    def get_n_items(self):
        return len(self._items)

    def get_item(self, index):
        return self._items[index]


def test_on_files_chosen_succes_ajoute_les_lignes(monkeypatch):
    panel = CaptureListPanel("Points de capture")
    ajoutees = []
    monkeypatch.setattr(panel, "add_row", lambda path, default_label=None: ajoutees.append(path))

    dialog = Gtk.FileDialog()
    fake_files = _FakeFiles(["/tmp/lan-a.pcapng", "/tmp/wan-b.pcap"])
    monkeypatch.setattr(dialog, "open_multiple_finish", lambda result: fake_files)

    panel._on_files_chosen(dialog, None)

    assert ajoutees == ["/tmp/lan-a.pcapng", "/tmp/wan-b.pcap"]


def test_on_files_chosen_annulation_ne_leve_pas_et_n_ajoute_rien(monkeypatch):
    panel = CaptureListPanel("Points de capture")
    ajoutees = []
    monkeypatch.setattr(panel, "add_row", lambda path, default_label=None: ajoutees.append(path))

    dialog = Gtk.FileDialog()

    def _raise(result):
        raise GLib.Error("Dismissed by user")

    monkeypatch.setattr(dialog, "open_multiple_finish", _raise)

    panel._on_files_chosen(dialog, None)  # ne doit pas lever

    assert ajoutees == []
