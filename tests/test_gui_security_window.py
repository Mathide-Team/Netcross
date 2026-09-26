"""Section Securite de la fenetre GTK (issue #357), pilotee via pygobject.

Ignore si GTK4/pygobject ou un affichage manquent (CI sans libgtk-4) ; la
logique est couverte sans GTK par test_gui_security.py.
"""

import pathlib

import pytest
from conftest import make_pkt
from gtk4_display import exiger_gtk4_avec_affichage

Gtk = exiger_gtk4_avec_affichage()

from netcross_core.analysis import analyse  # noqa: E402
from netcross_core.correlate import correlate  # noqa: E402
from netcross_core.models import Banner  # noqa: E402
from netcross_core.security.cve_seed import open_seed_db  # noqa: E402
from netcross_core.security.findings import apply_security_findings  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402
from netcross_gtk4.run_outcome import analysis_outcome, diff_outcome  # noqa: E402
from netcross_report.security_report import build_security_report  # noqa: E402


@pytest.fixture(scope="module")
def window():
    app = Gtk.Application(application_id="org.netcross.test357")
    app.register(None)
    return MainWindow(app)


def _security_report():
    banner = Banner("http", "Apache", "2.4.49", "Apache/2.4.49")
    pkts = [make_pkt(point="A", src="10.0.0.5", dst="10.0.0.9", sport=80, dport=51000, service_banners=(banner,))]
    report = analyse(correlate(pkts), ["A"], pkts)
    conn, _seed = open_seed_db()
    try:
        apply_security_findings(report, pkts, cve_conn=conn)
    finally:
        conn.close()
    return build_security_report(report)


def _text(view):
    buf = view.get_buffer()
    return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)


def test_section_securite_affiche_et_exporte(window, tmp_path):
    window._appliquer_outcome(analysis_outcome("single", None, [], None, "", security_report=_security_report()))
    window._show_security_report()
    assert window.security_expander.get_sensitive()
    assert window.security_html_btn.get_sensitive()
    assert "CVE-2021-41773" in _text(window.security_view)

    written = window.export_security_to(str(tmp_path / "securite.html"))
    assert "CVE-2021-41773" in pathlib.Path(written).read_text(encoding="utf-8")
    assert "Rapport de securite ecrit" in window.status_label.get_text()

    assert window.export_security_to(str(tmp_path / "securite.txt")) is None
    assert "Erreur rapport de securite" in window.status_label.get_text()


def test_diff_desactive_la_section(window):
    window._appliquer_outcome(diff_outcome([], None, None, ""))
    window._show_security_report()
    assert not window.security_expander.get_sensitive()
    assert not window.security_json_btn.get_sensitive()


def test_anonymisation_desactive_la_case_securite(window):
    window.security_check.set_active(True)
    window.redact_check.set_active(True)
    assert not window.security_check.get_sensitive()
    assert not window.security_check.get_active()
    window.redact_check.set_active(False)
    assert window.security_check.get_sensitive()
