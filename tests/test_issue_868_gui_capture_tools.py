"""Issues #868, #869, #870, #886, #887 : fenêtre « Outils de capture » de
la GUI, mêmes fichiers et mêmes refus que la CLI."""

from __future__ import annotations

import shutil

import pytest
from pcap_builders import read_pcap, synthetic_packets, write_pcap

from netcross_core import capture_tools

outils = pytest.mark.skipif(
    any(shutil.which(t) is None for t in ("tshark", "editcap", "mergecap", "reordercap")),
    reason="outils Wireshark absents",
)
A = synthetic_packets(6, start_us=1_700_000_000_000_000)
B = synthetic_packets(4, start_us=1_700_000_000_050_000)


def _gtk():
    from gtk4_display import exiger_gtk4_avec_affichage

    return exiger_gtk4_avec_affichage()


@pytest.fixture
def win(tmp_path):
    _gtk()
    from netcross_gtk4.capture_tools_window import CaptureToolsWindow

    write_pcap(tmp_path / "a.pcap", A)
    write_pcap(tmp_path / "b.pcap", B)
    # thread remplace par un appel direct : _done est poste via GLib.idle_add
    return CaptureToolsWindow(start_thread=lambda fn: fn())


@outils
def test_fusion(win, tmp_path):
    win.set_merge_files([str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap")])
    win.merge_output.set_path(str(tmp_path / "gui.pcap"))
    msg = win.run_merge()
    capture_tools.merge([str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap")], str(tmp_path / "cli.pcap"))
    assert msg == f"2 fichier(s) fusionne(s) dans {tmp_path / 'gui.pcap'}."
    assert read_pcap(tmp_path / "gui.pcap")[1] == read_pcap(tmp_path / "cli.pcap")[1]


def test_fusion_sans_fichier(win):
    with pytest.raises(ValueError, match="au moins une capture"):
        win.run_merge()


@outils
def test_decoupage(win, tmp_path):
    win.split_source.set_path(str(tmp_path / "a.pcap"))
    win.split_mode.set_selected(1)  # count
    win.split_value.set_text("4")
    win.split_output.set_path(str(tmp_path / "seg"))
    assert win.split_spec() == "count:4"
    assert win.run_split() == f"2 segment(s) dans {tmp_path / 'seg'}."


@pytest.mark.parametrize(("mode", "valeur"), [(0, "0"), (1, "x"), (2, "10MiB")])
def test_decoupage_refus_comme_la_cli(win, mode, valeur):
    win.split_mode.set_selected(mode)
    win.split_value.set_text(valeur)
    with pytest.raises(ValueError, match="Format invalide pour --split"):
        win.run_split()


@outils
def test_conversion_et_export_et_recalage(win, tmp_path):
    win.convert_source.set_path(str(tmp_path / "a.pcap"))
    win.convert_format.set_selected(capture_tools.CONVERT_FORMATS.index("csv"))
    win.convert_output.set_path(str(tmp_path / "a.csv"))
    assert win.run_convert() == f"Converti {tmp_path / 'a.pcap'} -> {tmp_path / 'a.csv'} (format: csv)."
    capture_tools.convert(str(tmp_path / "a.pcap"), str(tmp_path / "cli.csv"), "csv")
    assert (tmp_path / "a.csv").read_bytes() == (tmp_path / "cli.csv").read_bytes()

    win.export_source.set_path(str(tmp_path / "a.pcap"))
    win.export_filter.set_text("frame.number <= 2")
    win.export_output.set_path(str(tmp_path / "e.pcap"))
    win.run_export()
    assert len(read_pcap(tmp_path / "e.pcap")[1]) == 2

    win.adjust_source.set_path(str(tmp_path / "a.pcap"))
    win.adjust_mode.set_selected(1)  # normaliser
    win.adjust_output.set_path(str(tmp_path / "n.pcap"))
    win.run_adjust()
    assert read_pcap(tmp_path / "n.pcap")[1][0][0] == 0
    win.adjust_mode.set_selected(2)
    with pytest.raises(ValueError, match="capture de reference"):
        win.run_adjust()


def test_saisies_invalides(win, tmp_path):
    win.export_source.set_path(str(tmp_path / "a.pcap"))
    win.export_output.set_path(str(tmp_path / "e.pcap"))
    win.export_start.set_text("demain")
    with pytest.raises(ValueError, match="debut : nombre attendu"):
        win.run_export()


def test_erreur_affichee_sans_planter(win):
    win._launch(win.run_merge)
    from gi.repository import GLib

    ctx = GLib.MainContext.default()
    while ctx.pending():
        ctx.iteration(False)
    assert win.status_label.get_text() == "Erreur : ajoutez au moins une capture a fusionner"
    assert not win.running and all(b.get_sensitive() for b in win.buttons)


def test_bouton_de_la_fenetre_principale():
    gtk = _gtk()
    from netcross_gtk4.app import MainWindow

    app = gtk.Application(application_id="org.netcross.test868")
    app.register(None)
    window = MainWindow(app)
    assert window.capture_tools_btn.get_label() == "Outils de capture"
    outils_win = window.open_capture_tools()
    assert window.open_capture_tools() is outils_win
    outils_win.close()
    assert window.capture_tools_window is None
