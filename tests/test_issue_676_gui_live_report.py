"""Issue #676 : rapport HTML rafraichi en continu pendant une capture en
direct de la GUI (equivalent de --live-report, --live-report-interval et
--live-report-serve). Module sans GTK : testable sans affichage."""

from __future__ import annotations

import json
import urllib.request

import pytest
from conftest import make_pkt

from netcross_gtk4.live_report_session import LiveReportError, start_live_report


def _render(snapshot, journal, interval):
    return f"<html>{snapshot.get('points', '')}</html>"


def test_rapport_publie_dans_le_repertoire_demande(tmp_path):
    session, messages = start_live_report(["LAN", "DC"], str(tmp_path / "live"), interval=60, render=_render)
    try:
        session.add(make_pkt(point="LAN", sport=1))
        session.point_stopped("LAN")
        session.point_stopped("DC", error="interface absente")
    finally:
        fin = session.stop()
    assert session.html_path == tmp_path / "live" / "index.html"
    assert session.html_path.exists()
    assert any("rafraichi toutes les 60 s" in m for m in messages)
    assert any("derniere publication" in m for m in fin)
    snapshot = json.loads((tmp_path / "live" / "live.json").read_text(encoding="utf-8"))
    assert set(snapshot["points"]) >= {"LAN", "DC"}
    journal = (tmp_path / "live" / "live.jsonl").read_text(encoding="utf-8")
    assert "point_erreur" in journal and "interface absente" in journal
    assert "point_arrete" in journal


def test_repertoire_vide_donne_un_repertoire_temporaire(tmp_path):
    cible = tmp_path / "tmp-live"
    session, _ = start_live_report(["A"], "", interval=60, render=_render, mkdtemp=lambda prefix: str(cible))
    session.stop()
    assert session.html_path.parent == cible


def test_page_servie_en_local(tmp_path):
    session, messages = start_live_report(["A"], str(tmp_path), interval=60, serve_port=0, render=_render)
    try:
        assert session.url is not None and session.url.startswith("http://127.0.0.1:")
        assert any(session.url in m for m in messages)
        with urllib.request.urlopen(session.url + "index.html", timeout=5) as rep:
            assert rep.status == 200
    finally:
        session.stop()
    assert session.server is not None


def test_sans_port_pas_de_serveur(tmp_path):
    session, _ = start_live_report(["A"], str(tmp_path), interval=60, render=_render)
    session.stop()
    assert session.url is None


def test_port_occupe_refuse(tmp_path):
    def occupe(addr, handler):
        raise OSError("Address already in use")

    with pytest.raises(LiveReportError, match="port 8765"):
        start_live_report(["A"], str(tmp_path), interval=60, serve_port=8765, render=_render, server_factory=occupe)


@pytest.mark.parametrize(("interval", "port", "fragment"), [(0.5, None, "trop court"), (5, 70000, "port invalide")])
def test_reglages_invalides_refuses(tmp_path, interval, port, fragment):
    with pytest.raises(LiveReportError, match=fragment):
        start_live_report(["A"], str(tmp_path), interval=interval, serve_port=port, render=_render)


def test_fichier_a_la_place_du_repertoire_refuse(tmp_path):
    fichier = tmp_path / "pas-un-dossier"
    fichier.write_text("x")
    with pytest.raises(LiveReportError, match="n'est pas un repertoire"):
        start_live_report(["A"], str(fichier), interval=60, render=_render)


def test_repertoire_impossible_a_creer(tmp_path):
    def refuse(prefix):
        raise OSError("disque plein")

    with pytest.raises(LiveReportError, match="disque plein"):
        start_live_report(["A"], None, interval=60, render=_render, mkdtemp=refuse)


def test_echecs_de_publication_signales(tmp_path):
    session, _ = start_live_report(["A"], str(tmp_path), interval=60, render=_render)
    session.reporter.failures = 2
    fin = session.stop()
    assert any("2 publication(s) impossible(s)" in m for m in fin)


def test_rendu_par_defaut_page_netcross(tmp_path):
    session, _ = start_live_report(["A"], str(tmp_path), interval=60)
    session.stop()
    assert "<html" in session.html_path.read_text(encoding="utf-8").lower()
