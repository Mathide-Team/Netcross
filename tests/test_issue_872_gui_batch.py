"""Issue #872 (GUI) : fenêtre « Analyse d'un dossier », équivalent de
``cross_capture_batch_cli.py``. Même moteur (``batch_runner``) que la CLI :
mêmes groupes, mêmes rapports, mêmes refus."""

from __future__ import annotations

import dataclasses
import os

import pytest
from conftest import make_pkt

from netcross_report import batch_runner as runner

T0 = 1_700_000_000.0


def _flux(t0, n=20, src="10.0.0.5", dst="10.0.0.9"):
    return [make_pkt(point="x", ts=t0 + i, src=src, dst=dst) for i in range(n)]


CONTENU = {
    "amont": _flux(T0),
    "aval": _flux(T0 + 0.003, 18),
    "autre": _flux(T0 + 86400, 5, src="192.168.1.1", dst="192.168.1.2"),
    "casse": None,
}


@pytest.fixture(autouse=True)
def faux_parse(monkeypatch):
    def _parse(label, path, raise_on_error=False):
        pk = CONTENU[os.path.basename(path).split(".")[0]]
        if pk is None:
            raise RuntimeError("tshark: The file appears to be damaged or corrupt.")
        return [dataclasses.replace(p, point=label) for p in pk]

    monkeypatch.setattr(runner, "parse_capture", _parse)


@pytest.fixture
def win(tmp_path):
    from gtk4_display import exiger_gtk4_avec_affichage

    exiger_gtk4_avec_affichage()
    from netcross_gtk4.batch_window import BatchWindow

    entree = tmp_path / "captures"
    entree.mkdir()
    for nom in ("amont.pcap", "aval.pcapng", "autre.pcap", "casse.pcap", "notes.txt"):
        (entree / nom).write_bytes(b"\0")
    w = BatchWindow(start_thread=lambda fn: fn())
    w.input_dir.set_path(str(entree))
    w.output_dir.set_path(str(tmp_path / "sortie"))
    return w


def test_lot_identique_a_la_cli(win, tmp_path):
    lignes: list[str] = []
    msg = win.run_batch_now(lignes.append)
    assert msg.startswith("4 capture(s) : 1 groupe(s), 1 isolee(s), 1 echec(s).")
    res = win.result
    assert [g.labels for g in res.plan.groups] == [["amont", "aval"]]
    assert any("inventaire casse : ECHEC" in ligne for ligne in lignes)
    assert (tmp_path / "sortie" / "index.txt").read_text(encoding="utf-8") == res.index
    assert (tmp_path / "sortie" / "rapport-groupe-1.txt").is_file()
    # meme lot par le moteur de la CLI : meme index (hors chemins de sortie)
    captures, ignored = runner.list_captures(str(tmp_path / "captures"))
    cli = runner.run_batch(
        captures, ignored, str(tmp_path / "cli"), runner.BatchOptions(), str(tmp_path / "captures"), lambda _m: None
    )
    assert [g.labels for g in cli.plan.groups] == [g.labels for g in res.plan.groups]
    assert cli.index == res.index
    assert [os.path.basename(p) for p in res.ignored] == ["notes.txt"]


def test_reglages_transmis(win):
    win.recursive.set_active(True)
    win.group.set_active(False)
    win.group_window.set_value(5)
    win.min_overlap.set_value(0.8)
    win.min_common_ips.set_value(3)
    win.jobs.set_value(2)
    win.skip_existing.set_active(True)
    win.security_report.set_active(True)
    assert win.options() == runner.BatchOptions(
        recursive=True,
        group=False,
        group_window=5.0,
        min_overlap=0.8,
        min_common_ips=3,
        jobs=2,
        skip_existing=True,
        security_report=True,
    )


def test_valeurs_par_defaut_de_la_cli(win):
    assert win.options() == runner.BatchOptions()


def test_sans_regroupement(win):
    win.group.set_active(False)
    win.run_batch_now(lambda _m: None)
    assert win.result.plan.groups == []


def test_dossier_introuvable(win, tmp_path):
    win.input_dir.set_path(str(tmp_path / "absent"))
    with pytest.raises(ValueError, match="--input : dossier introuvable"):
        win.run_batch_now(lambda _m: None)


def test_sortie_obligatoire(win):
    win.output_dir.set_path(None)
    with pytest.raises(ValueError, match="--output"):
        win.run_batch_now(lambda _m: None)


def test_dossier_sans_capture(win, tmp_path):
    vide = tmp_path / "vide"
    vide.mkdir()
    win.input_dir.set_path(str(vide))
    with pytest.raises(ValueError, match="Aucune capture"):
        win.run_batch_now(lambda _m: None)


def test_bouton_affiche_avancement_et_resultat(win):
    from gi.repository import GLib

    win.launch()
    ctx = GLib.MainContext.default()
    while ctx.pending():
        ctx.iteration(False)
    assert not win.running
    assert win.status_label.get_text().startswith("4 capture(s)")
    assert "Inventaire de 4 capture(s)..." in win.progress_text()


def test_bouton_erreur(win, tmp_path):
    from gi.repository import GLib

    win.input_dir.set_path(str(tmp_path / "absent"))
    win.launch()
    ctx = GLib.MainContext.default()
    while ctx.pending():
        ctx.iteration(False)
    assert win.status_label.get_text().startswith("Erreur : --input : dossier introuvable")
