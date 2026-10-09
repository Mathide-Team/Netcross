"""Issue #672 : options d'analyse avancees dans la GUI (--max-packets,
--sample, --parallel-workers, --test-net-external, --known-destinations,
--known-hosts, --cve-db). Partie sans GTK, puis fenetre."""

from __future__ import annotations

import json

import pytest
from conftest import make_pkt

import netcross_gtk4.analysis_pipeline as pipeline_mod
from netcross_core.packet_limits import apply_packet_limits
from netcross_gtk4.advanced_options import (
    AdvancedOptionError,
    AdvancedSettings,
    load_host_set,
    settings_from_values,
    validate,
    workers_note,
)
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline

CAPTURES = [("A", "a.pcap"), ("B", "b.pcap")]


def test_valeurs_des_widgets():
    assert settings_from_values(0, 1, 0) == AdvancedSettings()
    assert settings_from_values(500, 10, 4, True, "d.json", "", None) == AdvancedSettings(
        max_packets=500, sample_n=10, parallel_workers=4, test_net_external=True, known_destinations="d.json"
    )


def test_limites_partagees_avec_la_cli():
    import cross_capture_analyzer_cli as cli

    paquets = list(range(100))
    kept, note = apply_packet_limits(paquets, 5, 10)
    assert kept == [0, 10, 20, 30, 40]
    assert note.startswith("analyse tronquee -- echantillonnage 1 paquet sur 10 (10 retenus sur 100)")
    assert "limitee aux 5 premiers paquets sur 10" in note
    assert apply_packet_limits(paquets, 1000, None) == (paquets, None)
    assert cli._apply_packet_limits(paquets, 5, 10) == (kept, note)


def test_refus_comme_la_cli(tmp_path):
    fichier = tmp_path / "d.json"
    fichier.write_text("[]", encoding="utf-8")
    reglages = AdvancedSettings(known_destinations=str(fichier), cve_db=str(tmp_path / "absente.db"))
    assert validate(reglages, security=False) == [
        "--known-destinations necessite « Rapport de securite »",
        "--cve-db necessite « Rapport de securite »",
    ]
    assert validate(reglages, security=True) == [f"--cve-db : fichier introuvable : {tmp_path / 'absente.db'}"]
    assert validate(AdvancedSettings(test_net_external=True), security=False)
    assert validate(AdvancedSettings(max_packets=3), security=False) == []
    with pytest.raises(AdvancedOptionError, match="aucune IP lue"):
        load_host_set(str(fichier), "--known-destinations")
    fichier.write_text(json.dumps({"hosts": ["10.0.0.1"]}), encoding="utf-8")
    assert load_host_set(str(fichier), "--known-hosts") == frozenset({"10.0.0.1"})
    assert load_host_set(None, "--known-hosts") is None


def test_avertissement_lecteurs():
    assert workers_note(None, 4) is None and workers_note(4, 4) is None
    assert "8 lecteurs demandes pour 2 coeur(s)" in workers_note(8, 2)


@pytest.fixture
def _paquets(monkeypatch):
    pkts = [
        make_pkt(point=p, src="10.0.0.5", dst="10.0.0.9", sport=1, ts=1000.0 + i * 0.1 + (0.001 if p == "B" else 0))
        for i in range(10)
        for p in ("A", "B")
    ]
    monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: [p for p in pkts if p.point == label])


def test_pipeline_troncature_annoncee(_paquets):
    journal = []
    result = run_analysis_pipeline(
        CAPTURES,
        AnalysisOptions(parallel=False, advanced=AdvancedSettings(max_packets=4)),
        on_progress=journal.append,
    )
    assert result.report.truncated
    assert "limitee aux 4 premiers paquets sur 20" in result.report.truncation_note
    assert f"ATTENTION : {result.report.truncation_note}" in result.text
    assert any(line.startswith("ATTENTION : analyse tronquee") for line in journal)


def test_pipeline_sans_troncature(_paquets):
    result = run_analysis_pipeline(CAPTURES, AnalysisOptions(parallel=False, advanced=AdvancedSettings(max_packets=50)))
    assert not result.report.truncated


def test_pipeline_lecteurs_paralleles(monkeypatch):
    import pcap_parser.capture as capture

    vus = []
    monkeypatch.setattr(
        capture, "parse_captures_parallel", lambda caps, max_workers=None: vus.append(max_workers) or ([], [])
    )
    assert pipeline_mod.load_packets(CAPTURES, True, max_workers=3) == []
    assert vus == [3]


def test_pipeline_refuse_avant_lecture(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline_mod, "parse_capture", lambda *a: pytest.fail("captures lues malgre le refus"))
    with pytest.raises(ValueError, match="necessite"):
        run_analysis_pipeline(
            CAPTURES, AnalysisOptions(parallel=False, advanced=AdvancedSettings(test_net_external=True))
        )
    vide = tmp_path / "h.json"
    vide.write_text("{}", encoding="utf-8")
    with pytest.raises(AdvancedOptionError):
        run_analysis_pipeline(
            CAPTURES,
            AnalysisOptions(parallel=False, security=True, advanced=AdvancedSettings(known_hosts=str(vide))),
        )


def test_securite_recoit_le_contexte(monkeypatch, tmp_path):
    import netcross_core.security as security
    import netcross_core.security.findings as findings

    recus = {}

    def faux_apply(report, packets, **kwargs):
        recus.update(kwargs)

    monkeypatch.setattr(findings, "apply_security_findings", faux_apply)
    monkeypatch.setattr(findings, "scan_capture_exploits", lambda label, path: [])
    connexions = []
    connexion = object()
    monkeypatch.setattr(security, "connect_cve_db", lambda path: connexions.append(path) or connexion)
    fermees = []
    monkeypatch.setattr("netcross_core.security.cve_db.close_db", fermees.append)
    monkeypatch.setattr(
        "netcross_core.security.cve_seed.open_seed_db", lambda: pytest.fail("base embarquee ouverte malgre --cve-db")
    )
    journal = []
    from netcross_core.analysis import analyse

    report = analyse({}, ["A"], [], 1.0, False, 8000, 10)
    pipeline_mod.run_security_analysis(
        report,
        [],
        CAPTURES,
        journal.append,
        known_destinations=frozenset({"1.1.1.1"}),
        known_hosts=frozenset({"10.0.0.1"}),
        test_net_external=True,
        cve_db=str(tmp_path / "nvd.db"),
    )
    assert connexions == [str(tmp_path / "nvd.db")]
    assert fermees == [connexion] and recus["cve_conn"] is connexion
    assert recus["known_destinations"] == frozenset({"1.1.1.1"})
    assert recus["known_hosts"] == frozenset({"10.0.0.1"})
    assert recus["treat_test_net_as_external"] is True
    assert f"  Base CVE : {tmp_path / 'nvd.db'} (--cve-db)" in journal


# -- GTK (ignore sans GTK4 ni affichage) --


def test_fenetre_reglages_et_refus(tmp_path):
    from gtk4_display import exiger_gtk4_avec_affichage

    gtk = exiger_gtk4_avec_affichage()
    from netcross_gtk4.app import MainWindow

    app = gtk.Application(application_id="org.netcross.test672")
    app.register(None)
    window = MainWindow(app)
    assert window.advanced_settings() == AdvancedSettings()
    window.max_packets_spin.set_value(1000)
    window.sample_spin.set_value(5)
    window.parallel_workers_spin.set_value(2)
    window.test_net_external_check.set_active(True)
    window.known_hosts_option.set_path(str(tmp_path / "h.json"))
    assert window.known_hosts_option.clear_btn.get_sensitive()
    assert window.known_hosts_option.name_label.get_text() == "h.json"
    assert window.advanced_settings() == AdvancedSettings(
        max_packets=1000, sample_n=5, parallel_workers=2, test_net_external=True, known_hosts=str(tmp_path / "h.json")
    )
    window.known_hosts_option.clear_btn.emit("clicked")
    assert window.known_hosts_option.path is None
    assert window.known_hosts_option.name_label.get_text() == "(aucun)"
    window.close()
