"""Issue #675 : resume NetFlow v5 dans la GUI (equivalent de --netflow /
--netflow-top / JSON de --json-report). Module sans GTK et panneau."""

from __future__ import annotations

import json

import pytest
from test_netflow_cli import _export

from netcross_core.netflow import iter_netflow_v5_file, summarize_flow_records
from netcross_core.netflow.summary import format_flow_summary
from netcross_gtk4.netflow_view import NetflowFileError, summarize_files, write_netflow_json


def test_meme_resume_que_la_cli(tmp_path):
    path = str(_export(tmp_path))
    summary, lines = summarize_files([("R1", path)], top=3)
    attendu = summarize_flow_records(iter_netflow_v5_file(path, exporter="R1"), top=3)
    assert summary == attendu
    assert lines == format_flow_summary(attendu)


def test_plusieurs_exportateurs(tmp_path):
    a = str(_export(tmp_path, "r1.nf5"))
    b = str(_export(tmp_path, "r2.nf5"))
    summary, _ = summarize_files([("R1", a), ("R2", b)])
    assert sorted(e["exporter"] for e in summary["exporters"]) == ["R1", "R2"]
    assert summary["totals"]["flows"] == 8


def test_sans_fichier_ou_top_invalide(tmp_path):
    with pytest.raises(NetflowFileError, match="au moins un export"):
        summarize_files([])
    with pytest.raises(NetflowFileError, match=">= 1"):
        summarize_files([("R1", str(_export(tmp_path)))], top=0)


def test_fichier_illisible_ou_tronque(tmp_path):
    with pytest.raises(NetflowFileError, match=r"absent\.nf5"):
        summarize_files([(None, str(tmp_path / "absent.nf5"))])
    tronque = tmp_path / "t.nf5"
    tronque.write_bytes(_export(tmp_path).read_bytes()[:-10])
    with pytest.raises(NetflowFileError, match=r"t\.nf5"):
        summarize_files([("R1", str(tronque))])


def test_json_identique_a_la_cli(tmp_path):
    summary, _ = summarize_files([("R1", str(_export(tmp_path)))])
    cible = write_netflow_json(tmp_path / "n.json", summary)
    assert json.loads(cible.read_text(encoding="utf-8")) == {"netflow": json.loads(json.dumps(summary))}


# -- panneau GTK (ignore sans GTK4 ni affichage) --


@pytest.fixture()
def panel():
    from gtk4_display import exiger_gtk4_avec_affichage

    exiger_gtk4_avec_affichage()
    from netcross_gtk4.netflow_panel import NetflowPanel

    return NetflowPanel(start_thread=lambda fn: fn())


def _pump():
    from gi.repository import GLib

    ctx = GLib.MainContext.default()
    while ctx.iteration(False):
        pass


def _texte(panel):
    buf = panel.text_view.get_buffer()
    return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)


def test_panneau_vide(panel):
    from netcross_gtk4.netflow_panel import EMPTY_MESSAGE

    assert panel.files_label.get_text() == EMPTY_MESSAGE
    assert not panel.summarize_btn.get_sensitive()
    assert not panel.json_btn.get_sensitive()
    assert panel.start_summary() is False


def test_panneau_resume_et_export(panel, tmp_path):
    path = str(_export(tmp_path, "routeur1.nf5"))
    panel.add_files([path, path])  # doublon ignore
    assert panel.files == [("routeur1", path)]
    assert "routeur1=routeur1.nf5" in panel.files_label.get_text()
    panel.top_spin.set_value(2)

    assert panel.start_summary()
    _pump()

    _summary, lignes = summarize_files([("routeur1", path)], top=2)
    assert _texte(panel) == "\n".join(lignes)
    assert panel.json_btn.get_sensitive()
    cible = tmp_path / "n.json"
    panel.export_to(cible)
    assert "netflow" in json.loads(cible.read_text(encoding="utf-8"))
    assert str(cible) in panel.status_label.get_text()


def test_panneau_erreur_de_lecture(panel, tmp_path):
    panel.add_files([str(tmp_path / "absent.nf5")])
    assert panel.start_summary()
    _pump()
    assert panel.status_label.get_text().startswith("NetFlow : ")
    assert not panel.json_btn.get_sensitive()
    assert panel.summarize_btn.get_sensitive()


def test_panneau_vider(panel, tmp_path):
    panel.add_files([str(_export(tmp_path))])
    panel.start_summary()
    _pump()
    panel.clear_files()
    assert panel.files == []
    assert _texte(panel) == ""
    assert not panel.json_btn.get_sensitive()


def test_panneau_pendant_la_lecture(tmp_path):
    from gtk4_display import exiger_gtk4_avec_affichage

    exiger_gtk4_avec_affichage()
    from netcross_gtk4.netflow_panel import NetflowPanel

    en_attente = []
    panel = NetflowPanel(start_thread=en_attente.append)
    panel.add_files([str(_export(tmp_path))])
    assert panel.start_summary()
    assert not panel.add_btn.get_sensitive()
    assert not panel.summarize_btn.get_sensitive()
    assert panel.start_summary() is False


def test_panneau_dans_la_fenetre():
    from gtk4_display import exiger_gtk4_avec_affichage

    gtk = exiger_gtk4_avec_affichage()
    from netcross_gtk4.app import MainWindow
    from netcross_gtk4.netflow_panel import NetflowPanel

    app = gtk.Application(application_id="org.netcross.test675netflow")
    app.register(None)
    window = MainWindow(app)
    assert isinstance(window.netflow_panel, NetflowPanel)
    assert window.netflow_expander.get_child() is window.netflow_panel
