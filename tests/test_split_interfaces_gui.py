"""Issue #474 lot 2 : capture unique et --split-interfaces dans la GUI.

Partie 1 : pipeline (pur Python). Partie 2 : case de MainWindow, ignorée
sans GTK4 ou sans affichage (même garde que test_gui_reglages_fins).
"""

from __future__ import annotations

import os

import pytest

import netcross_gtk4.analysis_pipeline as pipeline_mod
from netcross_gtk4.analysis_pipeline import AnalysisOptions, expand_split_interfaces, run_analysis_pipeline
from pcap_parser.capture import InterfaceSlice
from pcap_parser.ek_source import TsharkError
from tests.conftest import make_pkt


def _faux_split(noms, echec=None):
    appels = []

    def split(path, output_dir):
        appels.append((path, output_dir))
        if echec is not None:
            raise echec
        if len(noms) <= 1:
            return [InterfaceSlice(section=0, interface_id=0, name=noms[0], packets=1, path=path)]
        os.makedirs(output_dir, exist_ok=True)
        tranches = []
        for i, nom in enumerate(noms):
            cible = os.path.join(output_dir, f"{nom}.pcapng")
            with open(cible, "wb") as fh:
                fh.write(b"x")
            tranches.append(InterfaceSlice(section=0, interface_id=i, name=nom, packets=1, path=cible))
        return tranches

    return split, appels


def test_options_split_interfaces_desactive_par_defaut():
    assert AnalysisOptions().split_interfaces is False


def test_expand_un_point_par_interface(monkeypatch, tmp_path):
    import pcap_parser.capture as capture_mod

    split, _appels = _faux_split(["eth0", "eth1"])
    monkeypatch.setattr(capture_mod, "split_by_interface", split)
    journal = []
    points = expand_split_interfaces([("SW", "/x/sw.pcapng")], str(tmp_path), journal.append)
    assert [label for label, _ in points] == ["SW:eth0", "SW:eth1"]
    assert all(os.path.exists(path) for _, path in points)
    assert "2 captures" in journal[0]


def test_expand_une_seule_capture_ou_echec_garde_le_fichier(monkeypatch, tmp_path):
    import pcap_parser.capture as capture_mod

    split, _ = _faux_split(["eth0"])
    monkeypatch.setattr(capture_mod, "split_by_interface", split)
    assert expand_split_interfaces([("LAN", "/x/lan.pcap")], str(tmp_path), lambda _m: None) == [("LAN", "/x/lan.pcap")]
    split, _ = _faux_split(["eth0"], echec=TsharkError("illisible"))
    monkeypatch.setattr(capture_mod, "split_by_interface", split)
    journal = []
    assert expand_split_interfaces([("LAN", "/x/lan.pcap")], str(tmp_path), journal.append) == [("LAN", "/x/lan.pcap")]
    assert "impossible" in journal[0]


def test_pipeline_split_interfaces_analyse_les_points_separes(monkeypatch):
    import pcap_parser.capture as capture_mod

    split, _ = _faux_split(["eth0", "eth1"])
    monkeypatch.setattr(capture_mod, "split_by_interface", split)
    lus = []

    def faux_parse(label, path):
        lus.append(label)
        return [make_pkt(point=label, sport=1, ts=1000.0 + len(lus) * 0.001)]

    monkeypatch.setattr(pipeline_mod, "parse_capture", faux_parse)
    result = run_analysis_pipeline([("SW", "/x/sw.pcapng")], AnalysisOptions(parallel=False, split_interfaces=True))
    assert lus == ["SW:eth0", "SW:eth1"]
    assert result.report.points == ["SW:eth0", "SW:eth1"]
    assert "Capture unique" not in result.text


def test_pipeline_capture_unique_sans_sections_multi_points(monkeypatch):
    monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: [make_pkt(point=label, sport=1)])
    result = run_analysis_pipeline([("LAN", "/x/lan.pcap")], AnalysisOptions(parallel=False))
    assert "Capture unique : sections multi-points omises" in result.text
    assert "Topologie deduite" not in result.text


# --- Partie 2 : case de la GUI -------------------------------------------


@pytest.fixture(scope="module")
def window():
    from gtk4_display import exiger_gtk4_avec_affichage

    gtk = exiger_gtk4_avec_affichage()
    from netcross_gtk4.app import MainWindow

    app = gtk.Application(application_id="org.netcross.test474lot2")
    app.register(None)
    return MainWindow(app)


def test_case_split_interfaces_transmise_au_pipeline(window, monkeypatch):
    assert window.split_interfaces_check.get_active() is False
    vu = {}

    def faux_pipeline(_captures, options, on_progress=None):
        vu["options"] = options
        raise RuntimeError("arret du test")

    monkeypatch.setattr(pipeline_mod, "run_analysis_pipeline", faux_pipeline)
    window._run_analysis_thread(
        [],
        1000.0,
        8000,
        False,
        False,
        True,
        False,
        5,
        False,
        False,
        False,
        False,
        25,
        False,
        False,
        2.0,
        split_interfaces=True,
    )
    assert vu["options"].split_interfaces is True
