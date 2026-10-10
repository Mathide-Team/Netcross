"""Tests de couverture de main() dans cross_capture_analyzer_cli.py
(issue #678, suite #665).

Refus d'options incompatibles, lecture des captures (sequentielle et
parallele, fichiers en echec), anonymisation, doublons, limites de
paquets, rapport de securite (baselines d'hotes, HTML, SIEM, base CVE
embarquee illisible), comparaison client vs client, triage, moteur de
regles, TLS/QUIC, sorties CSV/PDF/Markdown/JSON, historique et ticket de
support. Les captures sont des Pkt synthetiques (parse_capture double) :
aucun tshark.
"""

from __future__ import annotations

import json
import sys

import pytest
from conftest import make_pkt

import cross_capture_analyzer_cli as cli
from netcross_core.security import findings as security_findings


def _conversation(point, t0):
    c = {"src": "10.0.0.1", "dst": "10.0.0.2", "sport": 50000, "dport": 80}
    s = {"src": "10.0.0.2", "dst": "10.0.0.1", "sport": 80, "dport": 50000}
    return [
        make_pkt(point=point, ts=t0, flags="SYN", seq=1, frame_number=1, **c),
        make_pkt(point=point, ts=t0 + 0.02, flags="SYN,ACK", seq=9, ack=2, frame_number=2, **s),
        make_pkt(point=point, ts=t0 + 0.021, flags="ACK", seq=2, frame_number=3, **c),
    ]


PKTS = [*_conversation("A", 100.0), *_conversation("B", 100.005)]


@pytest.fixture
def lance(monkeypatch):
    """main() sur deux captures synthetiques A et B ; renvoie le code de
    sortie (0 si main() rend la main normalement)."""
    monkeypatch.setattr(
        cli, "parse_capture", lambda label, path, raise_on_error=False: [p for p in PKTS if p.point == label]
    )
    monkeypatch.setattr(security_findings, "scan_capture_exploits", lambda label, path: [])

    def _run(*argv, captures=("A=a.pcap", "B=b.pcap")):
        args = ["cross_capture_analyzer_cli.py"]
        for spec in captures:
            args += ["--capture", spec]
        monkeypatch.setattr(sys, "argv", [*args, *map(str, argv)])
        try:
            cli.main()
        except SystemExit as exc:
            return exc.code
        return 0

    return _run


# -- options incompatibles -------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (("--live", "LAN:eth0"), "mutuellement exclusifs"),
        (("--security-html", "s.html"), "--security-html necessite --security-report"),
        (("--merge", "m.pcap", "--split", "packets:10"), "--merge et --split sont exclusifs"),
        (("--replay", "eth0", "--merge", "m.pcap"), "--replay est exclusif avec --merge/--split"),
        (("--convert", "o.pcapng", "--merge", "m.pcap"), "--convert est exclusif"),
        (("--replay-loop", "3"), "--replay-speed/--replay-loop necessitent --replay"),
        (("--replay", "eth0", "--triage"), "--replay rejoue un fichier sans lancer d'analyse"),
        (("--client-group", "seul=10.0.0.1"), "au moins 2 clients distincts"),
        (
            ("--client-group", "a=10.0.0.1", "--client-group", "b=10.0.0.2", "--client-reference", "c"),
            "ne correspond a aucun --client-group",
        ),
        (("--client-reference", "a"), "necessitent au moins deux --client-group"),
        (("--detect-duplicates", "--duplicate-threshold-ms", "-1"), "--duplicate-threshold-ms doit etre >= 0"),
    ],
)
def test_refus(lance, capsys, argv, message):
    """Lignes 2233-2238, 2333-2334, 2384-2400, 2608-2610, 2721-2748, 2885-2887."""
    assert lance(*argv) == 1
    assert message in capsys.readouterr().err


def test_convert_avec_live_seul(lance, capsys):
    """Lignes 2464-2465 : --convert sans --capture (mais avec --live)."""
    assert lance("--convert", "o.pcapng", "--live", "LAN:eth0", captures=()) == 1
    assert "--convert necessite --capture" in capsys.readouterr().err


# -- lecture des captures ------------------------------------------------------------------


def test_lecture_sequentielle_avec_un_fichier_en_echec(lance, monkeypatch, capsys):
    """Lignes 2839-2847 : fichier illisible signale, analyse poursuivie."""
    from pcap_parser import TsharkError

    def _parse(label, path, raise_on_error=False):
        if label == "B":
            raise TsharkError("fichier tronque")
        return [p for p in PKTS if p.point == label]

    monkeypatch.setattr(cli, "parse_capture", _parse)
    assert lance() == 0
    err = capsys.readouterr().err
    assert "[B] ECHEC sur b.pcap : fichier tronque" in err
    assert "au moins un fichier n'a pas pu etre lu" in err


@pytest.mark.parametrize(("cpus", "workers", "attendu"), [(1, None, "aucun gain de temps"), (2, 8, "ATTENTION : 8")])
def test_lecture_parallele(lance, monkeypatch, capsys, cpus, workers, attendu):
    """Lignes 2774-2819 : --parallel, avertissements selon le nombre de
    coeurs, fichier en echec rapporte."""
    monkeypatch.setattr(cli.os, "cpu_count", lambda: cpus)
    stats = [
        {"label": "A", "path": "a.pcap", "count": 3, "seconds": 0.5, "error": None},
        {"label": "B", "path": "b.pcap", "count": 0, "seconds": None, "error": "illisible"},
    ]
    monkeypatch.setattr(cli, "parse_captures_parallel", lambda captures, workers: (list(PKTS), stats))
    argv = ["--parallel"] + (["--parallel-workers", workers] if workers else [])
    assert lance(*argv) == 0
    captured = capsys.readouterr()
    assert attendu in captured.out
    assert "[A] 3 paquets charges depuis a.pcap (0.50s)" in captured.out
    assert "[B] ECHEC sur b.pcap : illisible" in captured.err


# -- pretraitement ----------------------------------------------------------------------------


def test_anonymisation_doublons_et_limite(lance, tmp_path, capsys):
    """Lignes 2866-2870 : table de correspondance ; 2892-2906 : doublons
    detectes puis exclus ; 2935-2939 : rapport tronque par --max-packets."""
    table = tmp_path / "table.csv"
    assert lance("--redact", "--redact-map", table, "--exclude-duplicates", "--max-packets", "2") == 0
    captured = capsys.readouterr()
    assert f"ecrite dans {table}" in captured.out
    assert "Doublons inter-captures" in captured.out
    assert "ATTENTION" in captured.err
    assert table.is_file()


# -- rapport de securite ---------------------------------------------------------------------


def test_securite_baselines_html_et_siem(lance, tmp_path, capsys):
    """Lignes 2264, 2282 : baselines d'hotes ; 2987-3021 : HTML et SIEM."""
    connus = tmp_path / "connus.json"
    connus.write_text(json.dumps(["10.0.0.1", "10.0.0.2"]), encoding="utf-8")
    html = tmp_path / "s.html"
    siem = tmp_path / "s.cef"
    code = lance(
        "--security-report",
        "--known-destinations",
        connus,
        "--known-hosts",
        connus,
        "--security-html",
        html,
        "--siem-export",
        "cef",
        "--siem-output",
        siem,
    )
    out = capsys.readouterr().out
    assert code == 0
    assert html.is_file() and siem.is_file()
    assert "Export SIEM (cef)" in out


def test_securite_base_cve_embarquee_illisible(lance, monkeypatch, capsys):
    """Lignes 2959-2961 : base CVE embarquee illisible -> sans correlation."""

    def _ko():
        raise OSError("seed absente")

    monkeypatch.setattr(cli, "open_seed_db", _ko)
    assert lance("--security-report") == 0
    assert "base embarquee illisible (seed absente)" in capsys.readouterr().out


# -- comparaison, triage, regles, TLS/QUIC ------------------------------------------------------


def test_clients_triage_et_moteur_de_regles(lance, tmp_path, capsys):
    """Lignes 3033-3049 : comparaison client vs client + CSV ; 3058-3064 :
    triage ; 3068-3084 : moteur de regles sans JSON."""
    csv = tmp_path / "clients.csv"
    code = lance(
        "--client-group",
        "poste=10.0.0.1",
        "--client-group",
        "serveur=10.0.0.2",
        "--client-reference",
        "poste",
        "--client-diff-csv",
        csv,
        "--triage",
        "--rule-engine",
    )
    out = capsys.readouterr().out
    assert code == 0
    assert csv.is_file()
    assert "MOTEUR DE REGLES DECLARATIF" in out
    assert "(utilisez --json-report" in out


def test_tls_quic_et_quic_absent(lance, monkeypatch, capsys):
    """Lignes 3087-3135 : diagnostics TLS/QUIC ; QUIC non importable -> 1."""
    from netcross_core import quic_diagnostics, tls_diagnostics

    monkeypatch.setattr(tls_diagnostics, "parse_tls_capture", lambda label, path: [label])
    monkeypatch.setattr(tls_diagnostics, "build_handshake_status", lambda events: events)
    monkeypatch.setattr(tls_diagnostics, "diagnose_tls", lambda status, points: ["tls"])
    monkeypatch.setattr(tls_diagnostics, "print_tls_diagnostics", lambda f: print(f"TLS={f}"))
    monkeypatch.setattr(quic_diagnostics, "parse_quic_capture", lambda label, path: [label, label])
    monkeypatch.setattr(quic_diagnostics, "diagnose_quic", lambda events, points: ["quic"])
    monkeypatch.setattr(quic_diagnostics, "print_quic_diagnostics", lambda f: print(f"QUIC={f}"))
    assert lance("--tls", "--quic") == 0
    out = capsys.readouterr().out
    assert "[A] 1 evenements TLS trouves dans a.pcap" in out
    assert "[B] 2 paquets QUIC Initial trouves dans b.pcap" in out
    assert "TLS=['tls']" in out and "QUIC=['quic']" in out

    monkeypatch.setitem(sys.modules, "netcross_core.quic_diagnostics", None)
    assert lance("--quic") == 1
    assert "--quic necessite cryptography" in capsys.readouterr().err


# -- sorties fichiers ------------------------------------------------------------------------------


def test_sorties_csv_markdown_json_sequence_et_expert(lance, tmp_path, capsys):
    """Lignes 3145-3239 : --detail-csv, --expert-section, --sequence-diagram
    avec --md-report, --json-report."""
    csv = tmp_path / "detail.csv"
    md = tmp_path / "r.md"
    js = tmp_path / "r.json"
    names = tmp_path / "noms.json"
    names.write_text(json.dumps([{"address": "10.0.0.1", "name": "poste"}]), encoding="utf-8")
    code = lance(
        "--names",
        names,
        "--detail-csv",
        csv,
        "--expert-section",
        "--sequence-diagram",
        "2",
        "--md-report",
        md,
        "--json-report",
        js,
    )
    out = capsys.readouterr().out
    assert code == 0
    assert csv.is_file() and md.is_file() and json.loads(js.read_text(encoding="utf-8"))
    assert "Table des noms chargee" in out


def test_pdf_genere_et_dependances_absentes(lance, monkeypatch, tmp_path, capsys):
    """Lignes 3167-3190 : PDF (meta d'anonymisation) puis reportlab absent."""
    import netcross_report

    appels = []
    monkeypatch.setattr(netcross_report, "generate_pdf", lambda r, path, **kw: appels.append(kw["meta"]))
    pdf = tmp_path / "r.pdf"
    assert lance("--pdf-report", pdf, "--redact") == 0
    assert appels == [{"Anonymisation": "adresses IP/MAC anonymisees (--redact)"}]
    monkeypatch.delattr(netcross_report, "generate_pdf")
    assert lance("--pdf-report", pdf) == 1
    assert "--pdf-report necessite reportlab" in capsys.readouterr().err


def test_historique_et_base_invalide(lance, tmp_path, capsys):
    """Lignes 3254-3280 : historique + etiquette + --history-show ; base
    qui n'est pas du SQLite -> 1."""
    db = tmp_path / "h.db"
    assert lance("--history-db", db, "--history-label", "site-a", "--history-show", "3") == 0
    assert "(etiquette: site-a)" in capsys.readouterr().out
    faux = tmp_path / "faux.db"
    faux.write_text("pas une base", encoding="utf-8")
    assert lance("--history-db", faux) == 1
    assert str(faux) in capsys.readouterr().err


def test_ticket_de_support_avec_correspondance(lance, monkeypatch, tmp_path, capsys):
    """Lignes 2721 et 3289-3309 : ticket anonymise ecrit en fin de run, avec
    sa table de correspondance privee."""
    installes = []
    monkeypatch.setattr(cli, "install_crash_handler", lambda path, consent, markers: installes.append(markers))
    ticket = tmp_path / "ticket.zip"
    carte = tmp_path / "carte.csv"
    code = lance(
        "--support-ticket", ticket, "--support-consent", "--support-map", carte, "--support-marker", "trace=T-1"
    )
    out = capsys.readouterr().out
    assert code == 0
    assert installes == [{"trace": "T-1"}]
    assert ticket.exists() and carte.is_file()
    assert "Ticket de support anonymise ecrit" in out


# -- derniers chemins ----------------------------------------------------------------------------


def test_qualite_media_et_extraction(lance, monkeypatch, tmp_path, capsys):
    """Lignes 1256-1267 et 3131 : section contenus, rappel d'usage sur
    stderr quand un repertoire d'extraction est donne."""
    from netcross_core.extract import contents

    recus = []

    def _extraction(captures, out_dir, kinds):
        recus.append((out_dir, kinds))
        return "resultat"

    monkeypatch.setattr(contents, "run_extraction", _extraction)
    monkeypatch.setattr(contents, "format_extraction", lambda result: [f"EXTRACTION={result}"])
    sortie = tmp_path / "contenus"
    assert lance("--extract-contents", sortie) == 0
    captured = capsys.readouterr()
    assert "CONTENUS AUDIO/VIDEO/DOCUMENTS" in captured.out
    assert "EXTRACTION=resultat" in captured.out
    assert contents.USAGE_REMINDER in captured.err
    assert recus[0][0] == str(sortie) and recus[0][1]


def test_moteur_de_regles_avec_constats(lance, monkeypatch, capsys):
    """Lignes 3079-3081 : constats du moteur de regles affiches."""
    from types import SimpleNamespace

    from netcross_report import rule_engine

    # print_rule_engine (partage CLI/GUI, issue #673) appelle les fonctions
    # de son module
    constat = SimpleNamespace(severity="elevee", category="perte", segment="A->B", message="pertes en rafale")
    monkeypatch.setattr(rule_engine, "available_rule_ids", lambda: ["r1"])
    monkeypatch.setattr(rule_engine, "evaluate", lambda rule_id, r: [constat])
    assert lance("--rule-engine") == 0
    out = capsys.readouterr().out
    assert "  [elevee] perte / A->B -- pertes en rafale" in out
    assert "1 regles evaluees, 1 Finding produits." in out


def test_split_interfaces_et_replay(lance, monkeypatch, capsys):
    """Ligne 2755 : --split-interfaces eclate les captures ; lignes
    2608-2610 : --replay seul rejoue puis s'arrete."""
    eclatees = []
    monkeypatch.setattr(cli, "_expand_split_interfaces", lambda captures: eclatees.append(captures) or captures)
    assert lance("--split-interfaces") == 0
    assert eclatees == [[("A", "a.pcap"), ("B", "b.pcap")]]

    rejoues = []
    monkeypatch.setattr(cli, "replay_capture", lambda p, i, speed, loop: rejoues.append((p, i)))
    assert lance("--replay", "eth0", captures=("A=a.pcap",)) == 0
    assert rejoues == [("a.pcap", "eth0")]
