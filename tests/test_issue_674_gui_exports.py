"""Issue #674 : diagramme de sequence, export SIEM, historique et ticket de
support dans la GUI. Partie sans GTK, puis panneau et fenetre."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from conftest import make_pkt

import netcross_gtk4.analysis_pipeline as pipeline_mod
from netcross_core.support import ConsentRequiredError
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline
from netcross_gtk4.report_exports import (
    HistorySettings,
    ReportContext,
    export_siem,
    history_text,
    record_history,
    sequence_views,
    write_support_ticket,
)
from netcross_report.siem_export import observed_bounds, write_siem

CAPTURES = [("A", "a.pcap"), ("B", "b.pcap")]


@pytest.fixture
def _paquets(monkeypatch):
    pkts = [
        make_pkt(point=p, src="10.0.0.5", dst="10.0.0.9", sport=1, ts=1000.0 + i * 0.1 + (0.001 if p == "B" else 0))
        for i in range(5)
        for p in ("A", "B")
    ]
    monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: [p for p in pkts if p.point == label])
    monkeypatch.setattr("netcross_core.security.findings.scan_capture_exploits", lambda label, path: [])
    return pkts


def test_bornes_partagees_avec_la_cli(_paquets):
    debut, fin = observed_bounds(_paquets)
    assert debut == datetime.fromtimestamp(1000.0, tz=timezone.utc)
    assert fin == datetime.fromtimestamp(1000.401, tz=timezone.utc)
    assert observed_bounds([]) == (None, None)


def test_pipeline_enregistre_l_historique_et_le_contexte(_paquets, tmp_path):
    db = str(tmp_path / "h.db")
    journal = []
    result = run_analysis_pipeline(
        CAPTURES,
        AnalysisOptions(parallel=False, history=HistorySettings(db_path=db, label="site-1")),
        on_progress=journal.append,
    )
    ctx = result.report_context
    assert ctx.captures == 2 and not ctx.redact
    assert ctx.observed_from == datetime.fromtimestamp(1000.0, tz=timezone.utc)
    assert ctx.history_message == f"Resume de ce run enregistre dans l'historique {db} (etiquette: site-1)."
    assert ctx.history_message in journal
    texte = history_text(db, 10, "site-1")
    assert "HISTORIQUE DES RUNS ENREGISTRES" in texte and "[site-1]" in texte and "points : A,B" in texte
    assert "Aucun run" in history_text(db, 10, "autre")


def test_pipeline_historique_illisible_garde_l_analyse(_paquets, tmp_path):
    faux = tmp_path / "pas-une-base.db"
    faux.write_text("ceci n'est pas une base sqlite" * 100, encoding="utf-8")
    result = run_analysis_pipeline(
        CAPTURES, AnalysisOptions(parallel=False, history=HistorySettings(db_path=str(faux)))
    )
    assert result.report is not None
    assert result.report_context.history_message.startswith("ERREUR historique non enregistre : ")


def test_siem_identique_a_la_cli(_paquets, tmp_path):
    result = run_analysis_pipeline(CAPTURES, AnalysisOptions(parallel=False, security=True))
    ctx = result.report_context
    for fmt in ("cef", "leef", "stix"):
        gui = export_siem(result.report, str(tmp_path / f"gui.{fmt}"), fmt, ctx)
        cli = write_siem(
            result.report,
            tmp_path / f"cli.{fmt}",
            fmt,
            observed_from=ctx.observed_from,
            observed_until=ctx.observed_until,
        )
        assert Path(gui).read_text(encoding="utf-8") == Path(cli).read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="format SIEM inconnu"):
        export_siem(result.report, str(tmp_path / "x"), "syslog", ctx)


def test_ticket_avec_consentement_seulement(tmp_path):
    ctx = ReportContext(captures=3, redact=True)
    with pytest.raises(ConsentRequiredError):
        write_support_ticket(str(tmp_path / "t.json"), ctx, consent=False)
    assert not (tmp_path / "t.json").exists()
    chemin, occurrences = write_support_ticket(str(tmp_path / "t.json"), ctx, consent=True)
    ticket = json.loads(Path(chemin).read_text(encoding="utf-8"))
    assert ticket["consentement"]["origine"] == "gui" and ticket["consentement"]["accorde"]
    assert ticket["nature"] == "diagnostic"
    assert occurrences >= 0
    assert "captures analysees : 3" in json.dumps(ticket, ensure_ascii=False)


def test_diagramme_de_sequence(_paquets):
    result = run_analysis_pipeline(CAPTURES, AnalysisOptions(parallel=False))
    assert sequence_views(result.flows, 0) is None
    vues = sequence_views(result.flows, 1)
    assert len(vues) == 1 and vues[0].steps


def test_record_history_avec_anonymisation(_paquets, tmp_path):
    result = run_analysis_pipeline(CAPTURES, AnalysisOptions(parallel=False))
    message = record_history(result.report, HistorySettings(db_path=str(tmp_path / "h.db")), redact=True)
    assert message == f"Resume de ce run enregistre dans l'historique {tmp_path / 'h.db'}."


# -- GTK (ignore sans GTK4 ni affichage) --


def _gtk():
    from gtk4_display import exiger_gtk4_avec_affichage

    return exiger_gtk4_avec_affichage()


def test_panneau(_paquets, tmp_path):
    _gtk()
    from netcross_gtk4.report_exports_panel import ReportExportsPanel

    panel = ReportExportsPanel()
    assert not panel.siem_btn.get_sensitive() and not panel.ticket_btn.get_sensitive()
    assert not panel.history_btn.get_sensitive()
    with pytest.raises(ValueError, match="Rapport de securite"):
        panel.export_siem_to(tmp_path / "x.cef")

    db = str(tmp_path / "h.db")
    result = run_analysis_pipeline(
        CAPTURES, AnalysisOptions(parallel=False, security=True, history=HistorySettings(db_path=db))
    )
    panel.set_context(result.report, result.security_report, result.report_context)
    assert panel.siem_btn.get_sensitive() and panel.history_btn.get_sensitive()
    assert panel.history_label.get_text().startswith("Resume de ce run enregistre")
    panel.siem_format.set_selected(1)
    chemin = panel.export_siem_to(tmp_path / "x.leef")
    assert "Export SIEM (leef) ecrit dans" in panel.status_label.get_text() and chemin.endswith("x.leef")

    assert not panel.ticket_btn.get_sensitive()
    with pytest.raises(ConsentRequiredError):
        panel.write_ticket_to(tmp_path / "t.json")
    panel.consent_check.set_active(True)
    assert panel.ticket_btn.get_sensitive()
    panel.write_ticket_to(tmp_path / "t.json")
    assert "Ticket de support anonymise ecrit" in panel.status_label.get_text()

    panel.history_show_spin.set_value(5)
    assert "HISTORIQUE DES RUNS ENREGISTRES" in panel.show_history()
    buf = panel.history_view.get_buffer()
    assert "HISTORIQUE" in buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)

    panel.set_context(None, None, None)
    assert not panel.siem_btn.get_sensitive() and not panel.ticket_btn.get_sensitive()
    with pytest.raises(ValueError, match="aucun historique"):
        panel.show_history()


def test_fenetre_reglages(tmp_path, monkeypatch):
    gtk = _gtk()
    from netcross_gtk4.app import MainWindow

    app = gtk.Application(application_id="org.netcross.test674")
    app.register(None)
    window = MainWindow(app)
    assert window.history_settings() == HistorySettings()
    window.history_option.set_path(str(tmp_path / "h.db"))
    window.history_label_entry.set_text("  site-2 ")
    assert window.history_settings() == HistorySettings(db_path=str(tmp_path / "h.db"), label="site-2")
    assert window.sequence_diagram_spin.get_value() == 0
    vus = []
    monkeypatch.setattr(window.report_exports_panel, "set_context", lambda *a: vus.append(a))
    ctx = ReportContext(captures=1)
    window._on_analysis_done("single", None, {}, None, "", None, None, [], None, None, None, None, ctx)
    assert vus[-1] == (None, None, ctx)
    window.close()
