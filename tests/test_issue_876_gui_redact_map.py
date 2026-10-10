"""Issue #876 : table d'anonymisation (--redact-map) dans la GUI, en
analyse simple et en comparaison, même fichier que la CLI."""

from __future__ import annotations

import pytest
from conftest import make_pkt

import netcross_gtk4.analysis_pipeline as pipeline_mod
from netcross_core.redact import AddressRedactor, write_redaction_map_csv
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline
from netcross_gtk4.diff_pipeline import DiffOptions, run_diff_pipeline
from netcross_gtk4.report_exports import ReportContext


def _pkts(point, extra=False):
    pkts = [make_pkt(point=point, src="10.0.0.5", dst="10.0.0.9", sport=1, ts=1000.0 + i * 0.1) for i in range(3)]
    if extra:
        pkts.append(make_pkt(point=point, src="10.7.7.7", dst="10.0.0.9", sport=2, ts=1001.0))
    return pkts


@pytest.fixture
def _lecture(monkeypatch):
    monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: _pkts(label, "courant" in path))
    monkeypatch.setattr("netcross_core.security.findings.scan_capture_exploits", lambda label, path: [])


def _cli_csv(tmp_path, *paquets):
    redactor = AddressRedactor()
    for lot in paquets:
        redactor.redact(lot)
    out = tmp_path / "cli.csv"
    write_redaction_map_csv(redactor, str(out))
    return out.read_bytes(), tuple(redactor.entries())


def test_pipeline_simple(_lecture, tmp_path):
    result = run_analysis_pipeline([("A", "a.pcap")], AnalysisOptions(parallel=False, redact=True))
    assert result.report_context.redaction_map == _cli_csv(tmp_path, _pkts("A"))[1]
    sans = run_analysis_pipeline([("A", "a.pcap")], AnalysisOptions(parallel=False))
    assert sans.report_context.redaction_map == ()


def test_pipeline_comparaison_table_commune(_lecture, tmp_path):
    result = run_diff_pipeline(
        [("A", "/x/base.pcap")],
        [("A", "/x/courant.pcap")],
        DiffOptions(auto_topology=False, parallel=False, redact=True),
    )
    attendu = _cli_csv(tmp_path, _pkts("A"), _pkts("A", True))[1]
    assert result.redaction_map == attendu
    assert {e[0] for e in attendu} == {"10.0.0.5", "10.0.0.9", "10.7.7.7"}
    sans = run_diff_pipeline(
        [("A", "/x/base.pcap")], [("A", "/x/courant.pcap")], DiffOptions(auto_topology=False, parallel=False)
    )
    assert sans.redaction_map == ()


def _gtk():
    from gtk4_display import exiger_gtk4_avec_affichage

    return exiger_gtk4_avec_affichage()


def test_panneau(tmp_path):
    _gtk()
    from netcross_gtk4.report_exports_panel import ReportExportsPanel

    attendu, entries = _cli_csv(tmp_path, _pkts("A"))
    panel = ReportExportsPanel()
    assert not panel.redact_map_btn.get_sensitive()
    with pytest.raises(ValueError, match="aucune table"):
        panel.write_redaction_map_to(tmp_path / "x.csv")
    panel.set_context(object(), None, ReportContext(redact=True, redaction_map=entries))
    assert panel.redact_map_btn.get_sensitive()
    chemin = tmp_path / "gui.csv"
    panel.write_redaction_map_to(chemin)
    assert chemin.read_bytes() == attendu
    assert "ne pas transmettre avec le rapport" in panel.status_label.get_text()
    # comparaison : pas de contexte, mais la table reste exportable
    panel.set_context(None, None, None)
    assert not panel.redact_map_btn.get_sensitive()
    panel.set_redaction_map(entries)
    assert panel.redact_map_btn.get_sensitive()
    panel.set_redaction_map(())
    assert not panel.redact_map_btn.get_sensitive()


def test_fenetre_comparaison_transmet_la_table(tmp_path):
    gtk = _gtk()
    from netcross_gtk4.app import MainWindow

    app = gtk.Application(application_id="org.netcross.test876")
    app.register(None)
    window = MainWindow(app)
    _, entries = _cli_csv(tmp_path, _pkts("A"))
    window._on_diff_done([], None, None, "", None, None, None, None, entries)
    assert window.report_exports_panel.redaction_map == entries
    assert window.report_exports_panel.redact_map_btn.get_sensitive()
