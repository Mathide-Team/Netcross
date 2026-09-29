"""Tests de couverture de cross_capture_diff_cli.py (issue #677, suite #665).

Sorties optionnelles de main() apres la comparaison (triage, TLS, QUIC,
CSV, PDF, JSON, historique SQLite, code de sortie sur regression) et cas
rares de la capture en direct (progression, erreur d'un point, Ctrl+C,
duree maximale). Aucun tshark ni reseau : parse_capture / parse_live et
les decodeurs TLS/QUIC sont doubles.
"""

from __future__ import annotations

import dataclasses
import json
import sys

import pytest
from conftest import make_pkt

import cross_capture_diff_cli as cli

A, B = "10.0.0.1", "10.0.0.2"


def _flux(point, sports, ts0=0.0):
    return [
        make_pkt(point=point, ts=ts0 + i * 0.01 + (0.001 if point == "B" else 0.0), src=A, dst=B, sport=s, seq=s)
        for i, s in enumerate(sports)
    ]


# baseline : 20 paquets vus en A et en B ; courant : la moitie perdue en B.
CAPTURES = {
    "base_a.pcap": _flux("A", range(1000, 1020)),
    "base_b.pcap": _flux("B", range(1000, 1020)),
    "cour_a.pcap": _flux("A", range(2000, 2020)),
    "cour_b.pcap": _flux("B", range(2000, 2010)),
}


@pytest.fixture
def lance(monkeypatch):
    """Execute main() avec des captures synthetiques ; renvoie le code de
    sortie (0 si main() se termine sans sys.exit)."""

    def _parse(label, path, raise_on_error=False):
        return [dataclasses.replace(pk, point=label) for pk in CAPTURES[path]]

    monkeypatch.setattr(cli, "parse_capture", _parse)

    def _run(*extra, current=("A=cour_a.pcap", "B=cour_b.pcap")):
        argv = ["cross_capture_diff_cli.py", "--baseline", "A=base_a.pcap", "--baseline", "B=base_b.pcap"]
        for spec in current:
            argv += ["--current", spec]
        argv += ["--order", "A,B", *map(str, extra)]
        monkeypatch.setattr(sys, "argv", argv)
        try:
            cli.main()
        except SystemExit as exc:
            return exc.code
        return 0

    return _run


# -- sorties apres comparaison ------------------------------------------------------


def test_regression_triage_csv_json_et_historique(lance, tmp_path, capsys):
    """Lignes 659-663 : triage ; 733-734 : CSV ; 763-797 : JSON ; 800-817 :
    historique + --history-show ; ligne 825 : regression -> code 1."""
    csv = tmp_path / "ecarts.csv"
    rapport = tmp_path / "diff.json"
    db = tmp_path / "hist.db"
    code = lance(
        "--triage",
        "--diff-csv",
        csv,
        "--json-report",
        rapport,
        "--history-db",
        db,
        "--history-label",
        "site-a",
        "--history-show",
        "5",
    )
    out = capsys.readouterr().out
    assert code == 1
    assert csv.is_file() and f"Detail des ecarts ecrit dans {csv}" in out
    assert json.loads(rapport.read_text(encoding="utf-8"))
    assert "(etiquette: site-a)" in out
    assert db.is_file()


def test_historique_invalide_code_1(lance, tmp_path, capsys):
    """Lignes 818-822 : base d'historique qui n'est pas du SQLite."""
    db = tmp_path / "pas_sqlite.db"
    db.write_text("ceci n'est pas une base", encoding="utf-8")
    assert lance("--history-db", db) == 1
    assert str(db) in capsys.readouterr().err


def test_tls_et_quic_diagnostics(lance, monkeypatch, capsys):
    """Lignes 669-699 : section TLS ; lignes 701-730 : section QUIC, chacune
    executee sur le baseline puis sur le courant."""
    from netcross_core import quic_diagnostics, tls_diagnostics

    monkeypatch.setattr(tls_diagnostics, "parse_tls_capture", lambda label, path: [f"tls-{label}"])
    monkeypatch.setattr(tls_diagnostics, "build_handshake_status", lambda events: events)
    monkeypatch.setattr(tls_diagnostics, "diagnose_tls", lambda status, order: [f"diag:{len(status)}"])
    monkeypatch.setattr(tls_diagnostics, "print_tls_diagnostics", lambda f: print(f"TLS={f}"))
    monkeypatch.setattr(quic_diagnostics, "parse_quic_capture", lambda label, path: [label, label])
    monkeypatch.setattr(quic_diagnostics, "diagnose_quic", lambda events, order: [f"quic:{len(events)}"])
    monkeypatch.setattr(quic_diagnostics, "print_quic_diagnostics", lambda f: print(f"QUIC={f}"))
    lance("--tls", "--quic")
    out = capsys.readouterr().out
    assert "DIAGNOSTICS TLS/QUIC" in out
    assert out.count("TLS=['diag:2']") == 2
    assert out.count("QUIC=['quic:4']") == 2
    assert "[baseline/A] 1 evenements TLS trouves dans base_a.pcap" in out
    assert "[courant/B] 2 paquets QUIC Initial trouves dans cour_b.pcap" in out


def test_quic_sans_cryptography(lance, monkeypatch, capsys):
    """Lignes 708-714 : module QUIC non importable -> code 1."""
    monkeypatch.setitem(sys.modules, "netcross_core.quic_diagnostics", None)
    assert lance("--quic") == 1
    assert "--quic necessite cryptography" in capsys.readouterr().err


def test_pdf_genere_puis_dependances_absentes(lance, monkeypatch, tmp_path, capsys):
    """Lignes 736-760 : generation PDF (anonymisation signalee dans meta),
    puis message et code 1 quand reportlab & co. manquent."""
    import netcross_report

    appels = []
    monkeypatch.setattr(netcross_report, "generate_diff_pdf", lambda *a, **kw: appels.append(kw["meta"]))
    pdf = tmp_path / "diff.pdf"
    lance("--pdf-report", pdf, "--redact")
    assert appels == [{"Anonymisation": "adresses IP/MAC anonymisees (--redact)"}]
    assert f"Rapport PDF ecrit dans {pdf}" in capsys.readouterr().out

    monkeypatch.delattr(netcross_report, "generate_diff_pdf")
    assert lance("--pdf-report", pdf) == 1
    assert "--pdf-report necessite reportlab" in capsys.readouterr().err


# -- anonymisation en direct et scenario anonymise -------------------------------------


def test_courant_en_direct_anonymise_avec_table_de_correspondance(lance, monkeypatch, tmp_path, capsys):
    """Ligne 372 : baseline anonymise ; ligne 635 : run courant capture en
    direct anonymise ; lignes 641-644 : table de correspondance ecrite."""

    def _live(label, iface, bpf_filter=None, stop_event=None):
        yield from (dataclasses.replace(pk, point=label) for pk in CAPTURES["cour_a.pcap"][:3])

    monkeypatch.setattr(cli, "parse_live", _live)
    table = tmp_path / "table.csv"
    lance("--redact", "--redact-map", table, "--live-current", "A:eth0", "--live-current", "B:eth1", current=())
    out = capsys.readouterr().out
    assert "adresse(s) anonymisee(s)" in out
    assert f"ecrite dans {table}" in out
    assert A not in table.read_text(encoding="utf-8").split("\n")[0]
    assert A in table.read_text(encoding="utf-8")


# -- capture en direct : progression, erreur, Ctrl+C, duree maximale -----------------


def test_capture_en_direct_progression_erreur_ctrl_c_et_duree(monkeypatch, capsys):
    """Lignes 277-282 : message de progression toutes les 2 s et erreur d'un
    point rapportee sans arreter les autres ; lignes 287-292 : Ctrl+C ;
    lignes 295-300 : duree maximale atteinte."""
    horloge = iter([0.0, 5.0, 10.0, 15.0])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(horloge, 99.0))

    def _live(label, iface, bpf_filter=None, stop_event=None):
        if label == "KO":
            raise RuntimeError("interface absente")
        yield make_pkt(point=label)
        yield make_pkt(point=label, ts=1.0)

    gestionnaires = []

    def _signal(signum, handler):
        gestionnaires.append(handler)
        return None

    class _Minuteur:
        def __init__(self, delai, fonction):
            self.fonction = fonction
            self.daemon = False

        def start(self):
            self.fonction()

        def cancel(self):
            pass

    monkeypatch.setattr(cli, "parse_live", _live)
    monkeypatch.setattr(cli.signal, "signal", _signal)
    monkeypatch.setattr(cli.threading, "Timer", _Minuteur)
    paquets = cli._run_live_captures(["OK:eth0", "KO:eth1"], 3)
    gestionnaires[0](2, None)
    captured = capsys.readouterr()
    assert len(paquets) == 2
    assert "[courant/OK] 1 paquets..." in captured.out
    assert "[courant/KO] ERREUR : interface absente" in captured.err
    assert "Duree maximale (3s) atteinte" in captured.err
    assert "Arret demande (Ctrl+C)" in captured.err
