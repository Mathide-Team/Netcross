"""Issue #676 : comparaison d'un baseline enregistre avec un courant capture
en direct dans la GUI (equivalent de --live-current). Partie sans GTK :
pipeline de comparaison avec des paquets deja captures."""

from __future__ import annotations

import pytest
from conftest import make_pkt

import netcross_core.analysis as analysis_mod
from netcross_gtk4.diff_pipeline import DiffOptions, run_diff_pipeline


@pytest.fixture
def baseline(monkeypatch):
    lus = []

    def faux_parse(label, path):
        lus.append(path)
        return [make_pkt(point=label, src="10.0.0.1", dst="10.0.0.2", ts=1000.0 + (label == "B") * 0.001)]

    monkeypatch.setattr("netcross_gtk4.analysis_pipeline.parse_capture", faux_parse)
    return lus


def _courant():
    return [
        make_pkt(point="B", src="10.0.0.1", dst="10.0.0.2", ts=2000.001),
        make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", ts=2000.0),
    ]


def test_courant_en_direct_ne_relit_aucun_fichier_courant(baseline):
    journal = []
    result = run_diff_pipeline(
        [("A", "/base/a.pcap"), ("B", "/base/b.pcap")],
        [("X", "/jamais/lu.pcap")],
        DiffOptions(parallel=False),
        on_progress=journal.append,
        current_packets=_courant(),
    )
    assert baseline == ["/base/a.pcap", "/base/b.pcap"]
    assert result.current_report is not None
    assert any("CAPTURE EN DIRECT : 2 paquet(s)" in ligne for ligne in journal)
    assert not any("CHARGEMENT DU RUN COURANT" in ligne for ligne in journal)


def test_ordre_des_points_du_courant_en_direct(baseline, monkeypatch):
    # import local dans run_diff_pipeline : l'espion sur le module suffit
    ordres = []
    original = analysis_mod.analyse

    def espion(flows, points_order, *a, **k):
        ordres.append(points_order)
        return original(flows, points_order, *a, **k)

    monkeypatch.setattr(analysis_mod, "analyse", espion)
    options = DiffOptions(parallel=False, auto_topology=False)
    run_diff_pipeline([("A", "a"), ("B", "b")], [], options, current_packets=_courant(), current_points=["A", "B"])
    run_diff_pipeline([("A", "a"), ("B", "b")], [], options, current_packets=_courant())
    run_diff_pipeline([("A", "a"), ("B", "b")], [], DiffOptions(parallel=False), current_packets=_courant())
    # [baseline, courant] par appel
    assert ordres[1] == ["A", "B"]
    assert ordres[3] == ["B", "A"]  # sans ordre fourni : ordre d'apparition des paquets
    assert ordres[5] is None  # topologie automatique


@pytest.mark.parametrize("option", ["tls", "quic"])
def test_tls_quic_refuses_avec_un_courant_en_direct(baseline, option):
    with pytest.raises(ValueError, match="courant capture en direct"):
        run_diff_pipeline(
            [("A", "a"), ("B", "b")], [], DiffOptions(parallel=False, **{option: True}), current_packets=_courant()
        )
    assert baseline == []  # refus avant toute lecture
