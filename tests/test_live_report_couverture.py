"""tests/test_live_report_couverture.py -- couverture >= 98 % de netcross_core/live_report.py (issue #732).

Complete tests/test_live_report.py sur ce qu'il ne prenait pas : chemin
d'erreur de `_atomic_write` (nettoyage du temporaire puis relance),
ecrivain sans page HTML, thread de publication periodique de
`LiveReporter` et `stop()` sans `start()`.
"""

from __future__ import annotations

import threading

import pytest
from conftest import make_pkt

from netcross_core import live_report
from netcross_core.live_report import LiveAggregator, LiveReporter, LiveReportWriter


class _EcrivainEspion:
    """Ecrivain factice : memorise les instantanes publies, signale le deuxieme."""

    def __init__(self, interval: float) -> None:
        self.interval = interval
        self.snapshots: list[dict] = []
        self.deuxieme_releve = threading.Event()

    def publish(self, snapshot: dict, journal: dict) -> None:
        self.snapshots.append(snapshot)
        if len(self.snapshots) >= 2:
            self.deuxieme_releve.set()


# -- _atomic_write ------------------------------------------------------------


def test_atomic_write_ecrit_le_fichier_en_0644_sans_residu(tmp_path):
    cible = tmp_path / "live.json"
    live_report._atomic_write(cible, "bonjour")
    assert cible.read_text(encoding="utf-8") == "bonjour"
    assert cible.stat().st_mode & 0o777 == 0o644
    assert [p.name for p in tmp_path.iterdir()] == ["live.json"]


@pytest.mark.parametrize("erreur", [OSError("disque plein"), KeyboardInterrupt()])
def test_atomic_write_nettoie_le_temporaire_et_relance(tmp_path, monkeypatch, erreur):
    """Echec au remplacement : cible intacte, temporaire supprime, erreur relancee (meme BaseException)."""
    cible = tmp_path / "live.json"
    cible.write_text("ancien contenu", encoding="utf-8")

    def replace_en_echec(_src, _dst):
        raise erreur

    monkeypatch.setattr(live_report.os, "replace", replace_en_echec)
    with pytest.raises(type(erreur)):
        live_report._atomic_write(cible, "nouveau contenu")
    monkeypatch.undo()
    assert cible.read_text(encoding="utf-8") == "ancien contenu"
    assert [p.name for p in tmp_path.iterdir()] == ["live.json"]


def test_atomic_write_relance_l_erreur_d_origine_meme_si_le_nettoyage_echoue(tmp_path, monkeypatch):
    def replace_en_echec(_src, _dst):
        raise OSError("disque plein")

    def unlink_en_echec(_path):
        raise OSError("temporaire deja disparu")

    monkeypatch.setattr(live_report.os, "replace", replace_en_echec)
    monkeypatch.setattr(live_report.os, "unlink", unlink_en_echec)
    with pytest.raises(OSError, match="disque plein"):
        live_report._atomic_write(tmp_path / "live.json", "x")


# -- LiveReportWriter ---------------------------------------------------------


def test_ecrivain_sans_page_ne_publie_que_le_json_et_le_journal(tmp_path):
    """Sans `render_html`, aucune page n'est ecrite : seuls live.json et live.jsonl existent."""
    writer = LiveReportWriter(tmp_path / "live")
    agg = LiveAggregator(started_at=0.0)
    agg.add(make_pkt(point="A"))
    writer.publish(*agg.tick(now=1.0))
    assert sorted(p.name for p in writer.out_dir.iterdir()) == ["live.json", "live.jsonl"]
    assert not writer.html_path.exists()


# -- LiveReporter -------------------------------------------------------------


def test_le_thread_publie_a_chaque_intervalle_puis_un_releve_final():
    writer = _EcrivainEspion(interval=0.01)
    reporter = LiveReporter(writer)
    reporter.start()
    try:
        assert writer.deuxieme_releve.wait(timeout=5), "le thread de publication n'a jamais publie"
    finally:
        reporter.stop()
    # releve initial (start) + au moins un releve du thread + releve final (stop)
    assert len(writer.snapshots) >= 3
    assert [s["final"] for s in writer.snapshots].count(True) == 1
    assert writer.snapshots[-1]["final"] is True


def test_stop_sans_start_publie_uniquement_le_releve_final():
    writer = _EcrivainEspion(interval=1)
    reporter = LiveReporter(writer)
    reporter.stop()
    assert len(writer.snapshots) == 1
    assert writer.snapshots[0]["final"] is True
