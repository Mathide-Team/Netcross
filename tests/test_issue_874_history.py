"""Issue #874 : historique des comparaisons et consultation filtrée en GUI
et en API (équivalents de ``--history-db``/``--history-label`` de
``cross_capture_diff_cli.py`` et de ``netcross-history``)."""

from __future__ import annotations

import contextlib
import io
from unittest.mock import patch

import pytest

from netcross_core.models import Report
from netcross_report.history import list_history, print_history, record_diff_run, record_run
from tests.conftest import make_pkt


def _reports():
    base = Report(points=["A", "B"], pairs=[("A", "B")])
    cur = Report(points=["A", "B"], pairs=[("A", "B")])
    return base, cur


def _texte_cli(db, **filtres):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_history(list_history(db, **filtres))
    return buf.getvalue()


# -- API -----------------------------------------------------------------------

pytest.importorskip("fastapi", reason="extra [api] non installé")
pytest.importorskip("multipart", reason="python-multipart non installé")
from fastapi.testclient import TestClient  # noqa: E402

from netcross_api import history_routes  # noqa: E402
from netcross_api.app import _comparisons, app  # noqa: E402

client = TestClient(app)


def _pkts(label, path):
    return [
        make_pkt(src="192.168.1.1", dst="192.168.1.2", dport=80, ts=1000.0),
        make_pkt(src="192.168.1.2", dst="192.168.1.1", dport=50000, ts=1001.0),
    ]


def _compare(**data):
    with (
        patch("netcross_api.app.parse_capture", side_effect=_pkts),
        patch("netcross_api.app.scan_capture_exploits", return_value=[]),
    ):
        return client.post(
            "/comparisons?wait=true",
            files=[
                ("baseline_files", ("b.pcap", b"\xd4\xc3\xb2\xa1" + bytes(100), "application/octet-stream")),
                ("current_files", ("c.pcap", b"\xd4\xc3\xb2\xa1" + bytes(100), "application/octet-stream")),
            ],
            data={"baseline_labels": "A", "current_labels": "A", **data},
        )


@pytest.fixture(autouse=True)
def _propre():
    _comparisons.clear()
    yield
    _comparisons.clear()


def test_api_comparaison_enregistree(tmp_path, monkeypatch):
    db = tmp_path / "h.db"
    monkeypatch.setenv(history_routes.HISTORY_DB_ENV, str(db))
    rep = _compare(history="true", history_label="Site-A")
    assert rep.status_code == 201, rep.text
    assert rep.json()["history_id"] == 1
    (entree,) = list_history(db)
    assert (entree.run_type, entree.label) == ("diff", "Site-A")
    assert set(entree.points) == {"baseline", "current"}


def test_api_sans_history_rien_n_est_ecrit(tmp_path, monkeypatch):
    db = tmp_path / "h.db"
    monkeypatch.setenv(history_routes.HISTORY_DB_ENV, str(db))
    rep = _compare()
    assert rep.status_code == 201
    assert "history_id" not in rep.json()
    assert not db.exists()


def test_api_history_refuse_sans_base(monkeypatch):
    monkeypatch.delenv(history_routes.HISTORY_DB_ENV, raising=False)
    rep = _compare(history="true")
    assert rep.status_code == 400
    assert "NETCROSS_HISTORY_DB" in rep.json()["detail"]


def test_api_label_sans_history_refuse(monkeypatch, tmp_path):
    monkeypatch.setenv(history_routes.HISTORY_DB_ENV, str(tmp_path / "h.db"))
    rep = _compare(history_label="Site-A")
    assert rep.status_code == 400
    assert "history_label necessite history=true" in rep.json()["detail"]


def test_api_base_illisible_garde_la_comparaison(monkeypatch, tmp_path):
    db = tmp_path / "pas-une-base.db"
    db.write_text("ceci n'est pas sqlite" * 50)
    monkeypatch.setenv(history_routes.HISTORY_DB_ENV, str(db))
    rep = _compare(history="true")
    assert rep.status_code == 201
    assert "history_error" in rep.json()
    assert "health_score" in rep.json()


def test_api_get_history_filtres(monkeypatch, tmp_path):
    db = tmp_path / "h.db"
    base, cur = _reports()
    record_run(base, db, findings=[], label="Site-A")
    record_diff_run([], base, cur, db, label="Site-A")
    record_diff_run([], base, cur, db, label="Site-B")
    monkeypatch.setenv(history_routes.HISTORY_DB_ENV, str(db))
    tous = client.get("/history").json()["entries"]
    assert [e["id"] for e in tous] == [3, 2, 1]
    diff_a = client.get("/history", params={"run_type": "diff", "label": "Site-A"}).json()["entries"]
    assert [e["id"] for e in diff_a] == [2]
    assert [e["id"] for e in client.get("/history", params={"limit": 1}).json()["entries"]] == [3]
    assert client.get("/history", params={"run_type": "autre"}).status_code == 400
    assert client.get("/history", params={"limit": 0}).status_code == 422


def test_api_get_history_non_configure(monkeypatch):
    monkeypatch.delenv(history_routes.HISTORY_DB_ENV, raising=False)
    assert client.get("/history").status_code == 503


# -- GUI -----------------------------------------------------------------------


def _gtk():
    from gtk4_display import exiger_gtk4_avec_affichage

    return exiger_gtk4_avec_affichage()


def test_gui_record_diff_history_comme_la_cli(tmp_path):
    from netcross_gtk4.report_exports import HistorySettings, record_diff_history

    base, cur = _reports()
    msg = record_diff_history([], base, cur, HistorySettings(str(tmp_path / "g.db"), "Site-A"), redact=True)
    assert msg == f"Resume de ce diff enregistre dans l'historique {tmp_path / 'g.db'} (etiquette: Site-A)."
    (entree,) = list_history(tmp_path / "g.db")
    assert entree.run_type == "diff" and entree.meta == {"Anonymisation": "adresses IP/MAC anonymisees (--redact)"}


def test_gui_fenetre_historique_filtres(tmp_path):
    _gtk()
    from netcross_gtk4.history_window import HistoryWindow

    db = tmp_path / "h.db"
    base, cur = _reports()
    record_run(base, db, findings=[], label="Site-A")
    record_diff_run([], base, cur, db, label="Site-A")
    record_diff_run([], base, cur, db, label="Site-B")
    win = HistoryWindow(db_path=str(db))
    win.limit_spin.set_value(0)
    assert win.show_history() == _texte_cli(db)
    win.run_type_dropdown.set_selected(2)
    win.label_entry.set_text("Site-A")
    assert win.show_history() == _texte_cli(db, run_type="diff", label="Site-A")
    win.run_type_dropdown.set_selected(1)
    win.label_entry.set_text("")
    win.limit_spin.set_value(1)
    assert win.show_history() == _texte_cli(db, run_type="analyse", limit=1)


def test_gui_fenetre_sans_base_et_base_illisible(tmp_path):
    _gtk()
    from netcross_gtk4.history_window import HistoryWindow

    assert HistoryWindow().show_history() == "Choisissez une base d'historique."
    db = tmp_path / "x.db"
    db.write_text("pas sqlite" * 100)
    assert "netcross" in HistoryWindow(db_path=str(db)).show_history().lower()


def test_gui_comparaison_enregistree_depuis_la_fenetre(tmp_path):
    gtk = _gtk()
    from netcross_gtk4.app import MainWindow
    from netcross_gtk4.diff_pipeline import DiffResult
    from netcross_gtk4.report_exports import HistorySettings

    app = gtk.Application(application_id="org.netcross.test874")
    app.register(None)
    window = MainWindow(app)
    base, cur = _reports()
    result = DiffResult(findings=[], baseline_report=base, current_report=cur, text="")
    msg = window._record_diff_history(result, HistorySettings(str(tmp_path / "w.db"), None), False)
    assert msg.startswith("Resume de ce diff enregistre")
    assert list_history(tmp_path / "w.db")[0].run_type == "diff"
    bad = tmp_path / "bad.db"
    bad.write_text("pas sqlite" * 100)
    assert window._record_diff_history(result, HistorySettings(str(bad), None), False).startswith(
        "Historique non enregistre"
    )
    window.history_option.set_path(str(tmp_path / "w.db"))
    hist = window.open_history()
    assert hist.db_option.path == str(tmp_path / "w.db")
    assert window.open_history() is hist
    assert window.history_btn.get_label() == "Historique des runs"
