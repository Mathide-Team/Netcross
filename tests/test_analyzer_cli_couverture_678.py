"""Issue #678 (suite #665) : branches restantes de cross_capture_analyzer_cli.py.

Complete tests/test_analyzer_cli_auxiliaires.py : chemins nominaux « sans
option » des fonctions auxiliaires (branche False des ``if``), ring buffer
de la capture en direct (#676), et chemins de ``main()`` exerces en
``--live`` avec une capture doublee -- ni tshark, ni interface reseau.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import make_pkt

import cross_capture_analyzer_cli as cli


class _Minuteur:
    """threading.Timer sans thread : ne declenche rien."""

    def __init__(self, delai, fonction):
        self.daemon = False

    def start(self):
        pass

    def cancel(self):
        pass


# -- capture en direct : ring buffer et erreur sans rapport temps reel ------------------


def test_capture_en_direct_ring_buffer_un_par_point(monkeypatch, tmp_path):
    """--ring-buffer N:S lance un enregistreur tshark en rotation par point
    (issue #676), l'arrete en fin de session, et l'analyse recoit toujours
    tous les paquets du flux de dissection."""
    from pcap_parser import capture

    lances, arretes = [], []

    class _Proc:
        returncode = 0

    def _start(iface, directory, **kwargs):
        lances.append((iface, directory, kwargs["max_files"], kwargs["max_duration_per_file"], kwargs["prefix"]))
        return _Proc()

    def _stop(proc):
        arretes.append(proc)
        return ""

    def _live(label, iface, bpf_filter=None, stop_event=None):
        yield make_pkt(point=label)
        yield make_pkt(point=label, ts=1.0)

    monkeypatch.setattr(capture, "start_ring_recorder", _start)
    monkeypatch.setattr(capture, "stop_ring_recorder", _stop)
    monkeypatch.setattr(cli.tempfile, "mkdtemp", lambda prefix: str(tmp_path))
    monkeypatch.setattr(cli, "parse_live", _live)
    monkeypatch.setattr(cli.signal, "signal", lambda signum, handler: None)
    monkeypatch.setattr(cli.threading, "Timer", _Minuteur)

    paquets = cli._run_live_captures(["LAN:eth0", "WAN:eth1"], 0, ring_buffer=(3, 30.0))

    assert len(paquets) == 4
    assert lances == [
        ("eth0", str(tmp_path), 3, 30.0, "LAN"),
        ("eth1", str(tmp_path), 3, 30.0, "WAN"),
    ]
    assert len(arretes) == 2


def test_capture_en_direct_erreur_sans_rapport_temps_reel(monkeypatch, capsys):
    """Branche 873->878 : un point en erreur sans --live-report est signale
    sur stderr, sans aggregateur a mettre a jour."""

    def _live(label, iface, bpf_filter=None, stop_event=None):
        yield make_pkt(point=label)
        raise RuntimeError("interface disparue")

    monkeypatch.setattr(cli, "parse_live", _live)
    monkeypatch.setattr(cli.signal, "signal", lambda signum, handler: None)
    monkeypatch.setattr(cli.threading, "Timer", _Minuteur)

    paquets = cli._run_live_captures(["LAN:eth0"], 0)

    captured = capsys.readouterr()
    assert len(paquets) == 1
    assert "[LAN] ERREUR : interface disparue" in captured.err
    assert "[LAN] capture arretee -- 1 paquet(s) au total." in captured.out


# -- fonctions auxiliaires : chemins sans l'option facultative ---------------------------


def test_extraction_media_quality_seul_sans_repertoire():
    """Branche 1303->1312 : --media-quality sans --extract-contents, aucun
    repertoire a verifier."""
    args = SimpleNamespace(extract_kinds=None, extract_contents=None, media_quality=True, live=None, redact=False)
    assert isinstance(cli._check_extraction_args(args), tuple)


def test_extraction_de_contenus_sans_repertoire_de_sortie(monkeypatch, capsys):
    """Branche 1323->1326 : sans repertoire de sortie, ni rappel d'usage ni
    avertissement, et aucun type n'est extrait."""
    from netcross_core.extract import contents

    appels = []
    monkeypatch.setattr(
        contents, "run_extraction", lambda captures, out_dir, kinds: appels.append((out_dir, kinds)) or "R"
    )
    monkeypatch.setattr(contents, "format_extraction", lambda result: [f"resultat={result}"])

    cli._run_content_extraction([("A", "a.pcap")], None, ("audio",))

    captured = capsys.readouterr()
    assert appels == [(None, ())]
    assert "resultat=R" in captured.out
    assert contents.USAGE_REMINDER not in captured.err


def test_rapport_temps_reel_arguments_valides(tmp_path):
    """Ligne 1353 : --live-report valide (repertoire neuf, port correct)."""
    args = SimpleNamespace(
        live_report=str(tmp_path / "live"), live_report_serve=8080, live_report_interval=5.0, live=["LAN:eth0"]
    )
    assert cli._check_live_report_args(args) is None


def test_rapport_temps_reel_sans_serveur_http(tmp_path, capsys):
    """Branche 1367->1387 : --live-report sans --live-report-serve, aucun
    serveur HTTP n'est demarre."""
    args = SimpleNamespace(live_report=str(tmp_path / "live"), live_report_serve=None, live_report_interval=5.0)
    reporter, server = cli._start_live_report(args)
    assert server is None
    assert reporter is not None
    assert "Rapport temps reel" in capsys.readouterr().out


def test_module_ia_sans_fichier_de_resultats(monkeypatch, capsys):
    """Branche 1460->1464 : sans --ai-report, les resultats sont seulement
    affiches."""
    from netcross_ai import pipeline

    monkeypatch.setattr(pipeline, "run_ai", lambda report, flows, options: {"ok": 1})
    monkeypatch.setattr(pipeline, "format_ai", lambda result: f"IA={result}")
    cli._run_ai(SimpleNamespace(ai_report=None), None, SimpleNamespace(flow_anomalies=[{"flux": 1}]), [])
    out = capsys.readouterr().out
    assert "IA={'ok': 1}" in out
    assert "ecrits dans" not in out


# -- main() en --live avec capture doublee -----------------------------------------------


def _main_live(monkeypatch, extra, paquets=None, serveur=None):
    """Lance main() en --live ; la capture et le rapport temps reel sont
    doubles. Renvoie (code de sortie, ce que la capture a recu)."""
    recu = {}

    def _capture(specs, duration, reporter, ring_buffer=None):
        recu["specs"] = list(specs)
        recu["ring_buffer"] = ring_buffer
        return list(paquets) if paquets is not None else [make_pkt(point="LAN"), make_pkt(point="LAN", ts=1.0)]

    monkeypatch.setattr(cli, "_run_live_captures", _capture)
    monkeypatch.setattr(cli, "_start_live_report", lambda args: (None, serveur))
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *extra])
    try:
        cli.main()
    except SystemExit as exc:
        return exc.code, recu
    return None, recu


def test_main_live_bibliotheque_bpf_ring_buffer_et_arret_du_serveur(monkeypatch, capsys):
    """Lignes 2849-2853 : --bpf-library remplace le filtre de chaque point ;
    ligne 2866 : le serveur HTTP du rapport temps reel est arrete."""
    from netcross_core.bpf_filters import PREDEFINED_BPF_FILTERS

    filtre = PREDEFINED_BPF_FILTERS[0]
    arrets = []
    serveur = SimpleNamespace(shutdown=lambda: arrets.append(True))
    code, recu = _main_live(
        monkeypatch,
        ["--live", "LAN:eth0:port 1", "--live", "WAN:eth1", "--bpf-library", filtre.name, "--ring-buffer", "3:30"],
        serveur=serveur,
    )
    assert code is None
    assert recu["specs"] == [f"LAN:eth0:{filtre.expression}", f"WAN:eth1:{filtre.expression}"]
    assert recu["ring_buffer"] == (3, 30.0)
    assert arrets == [True]
    assert "2 paquet(s) captures au total" in capsys.readouterr().out


def test_main_live_max_packets_sans_troncature(monkeypatch, capsys):
    """Branche 2978->2981 : --max-packets au-dessus du nombre de paquets,
    aucun avertissement de troncature."""
    code, _ = _main_live(monkeypatch, ["--live", "LAN:eth0", "--max-packets", "100"])
    assert code is None
    assert "ATTENTION" not in capsys.readouterr().err


def test_main_live_historique_sans_affichage(monkeypatch, tmp_path, capsys):
    """Branche 3366->3380 : --history-db sans --history-show."""
    base = tmp_path / "historique.db"
    code, _ = _main_live(monkeypatch, ["--live", "LAN:eth0", "--history-db", str(base)])
    assert code is None
    assert base.exists()
    assert "enregistre dans l'historique" in capsys.readouterr().out


def test_main_live_ticket_support_sans_correspondance(monkeypatch, tmp_path, capsys):
    """Branche 3399->3402 : --support-ticket sans --support-map."""
    ticket = tmp_path / "ticket.zip"
    code, _ = _main_live(monkeypatch, ["--live", "LAN:eth0", "--support-ticket", str(ticket), "--support-consent"])
    assert code is None
    assert ticket.exists()
    assert "correspondance privee" not in capsys.readouterr().out


def test_main_live_moteur_de_regles_avec_json(monkeypatch, tmp_path, capsys):
    """Branche 3175->3178 : --rule-engine avec --json-report, pas de rappel
    de l'option JSON."""
    code, _ = _main_live(
        monkeypatch, ["--live", "LAN:eth0", "--rule-engine", "--json-report", str(tmp_path / "r.json")]
    )
    assert code is None
    out = capsys.readouterr().out
    assert "MOTEUR DE REGLES DECLARATIF" in out
    assert "utilisez --json-report" not in out


def test_main_live_comparaison_clients_sans_csv(monkeypatch, capsys):
    """Branche 3139->3143 : --client-group sans --client-diff-csv."""
    paquets = [
        make_pkt(point="LAN", src="10.0.0.1", dst="10.0.0.9"),
        make_pkt(point="LAN", src="10.0.0.2", dst="10.0.0.9", ts=1.0),
    ]
    code, _ = _main_live(
        monkeypatch,
        ["--live", "LAN:eth0", "--client-group", "a=10.0.0.1", "--client-group", "b=10.0.0.2"],
        paquets=paquets,
    )
    assert code is None
    assert "ecrit dans" not in capsys.readouterr().out


def _plugin_local(tmp_path):
    chemin = tmp_path / "plugin_678.py"
    chemin.write_text(
        textwrap.dedent(
            """
            class Compte:
                name = "compte678"

                def export(self, report, chemin):
                    chemin.write_text("ok", encoding="utf-8")

            EXPORTERS = [Compte]
            """
        ),
        encoding="utf-8",
    )
    return chemin


def test_main_live_plugin_exporteur_sans_rapport_de_securite(monkeypatch, tmp_path, capsys):
    """Branche 2406->2410 : plugin sans detecteur ; lignes 3302-3311 : les
    exporteurs tournent et sont traces meme sans --security-report."""
    sortie = tmp_path / "export.txt"
    code, _ = _main_live(
        monkeypatch,
        [
            "--live",
            "LAN:eth0",
            "--plugins",
            "compte678,fantome",
            "--plugin-path",
            str(_plugin_local(tmp_path)),
            "--plugin-export",
            f"compte678={sortie}",
        ],
    )
    assert code is None
    assert sortie.read_text(encoding="utf-8") == "ok"
    lignes = [x for x in capsys.readouterr().out.splitlines() if x.startswith("Plugins : ")]
    assert any("fantome" in x for x in lignes)
    assert any("compte678" in x for x in lignes)


@pytest.mark.parametrize("workers", [None, 64])
def test_main_parallel_sans_erreur_de_lecture(monkeypatch, tmp_path, capsys, workers):
    """Branches 2882->2891 et 2910->2950 : --parallel sans fichier en echec,
    avec un nombre de workers qui ne depasse pas / depasse les coeurs."""
    pcap = tmp_path / "a.pcap"
    pcap.write_bytes(b"")
    monkeypatch.setattr(cli.os, "cpu_count", lambda: 4)
    stats = [{"label": "LAN", "path": str(pcap), "error": None, "count": 1, "seconds": 0.1}]
    monkeypatch.setattr(cli, "parse_captures_parallel", lambda captures, n: ([make_pkt(point="LAN")], stats))
    extra = ["--parallel-workers", str(workers)] if workers else []
    monkeypatch.setattr(
        sys, "argv", ["cross_capture_analyzer_cli.py", "--capture", f"LAN={pcap}", "--parallel", *extra]
    )
    try:
        cli.main()
        code = None
    except SystemExit as exc:
        code = exc.code
    captured = capsys.readouterr()
    assert code is None, captured.err
    assert "au moins un fichier n'a pas pu etre lu" not in captured.out
    assert ("ATTENTION : 64 workers demandes" in captured.out) is (workers == 64)


EXEMPLE_TELNET = Path(__file__).resolve().parent.parent / "examples" / "plugins" / "detecteur_telnet.py"


def _main_capture_doublee(monkeypatch, tmp_path, extra):
    """main() sur --capture --parallel avec lecture et recherche d'exploits
    doublees (sans tshark). Renvoie le code de sortie."""
    pcap = tmp_path / "a.pcap"
    pcap.write_bytes(b"")
    stats = [{"label": "LAN", "path": str(pcap), "error": None, "count": 1, "seconds": 0.1}]
    monkeypatch.setattr(cli, "parse_captures_parallel", lambda captures, n: ([make_pkt(point="LAN")], stats))
    monkeypatch.setattr(cli.security_findings, "scan_capture_exploits", lambda label, path: [])
    monkeypatch.setattr(
        sys, "argv", ["cross_capture_analyzer_cli.py", "--capture", f"LAN={pcap}", "--parallel", *extra]
    )
    try:
        cli.main()
    except SystemExit as exc:
        return exc.code
    return None


def test_main_rapport_de_securite_avec_detecteur_de_plugin_et_notification(monkeypatch, tmp_path, capsys):
    """Lignes 3079-3082 : les detecteurs de plugin alimentent le rapport de
    securite ; ligne 3085 : --notify-on declenche l'envoi ; branche
    3304->3309 : avec --security-report, les runs de plugin ne sont pas
    reimprimes a part."""
    envois = []
    monkeypatch.setattr(cli, "_send_notifications", lambda args, r, obj: envois.append(args.notify_on) or [])
    code = _main_capture_doublee(
        monkeypatch,
        tmp_path,
        [
            "--security-report",
            "--plugins",
            "telnet_clair",
            "--plugin-path",
            str(EXEMPLE_TELNET),
            "--notify-on",
            "critique",
            "--notify-webhook",
            "http://127.0.0.1:9/inutilise",
        ],
    )
    captured = capsys.readouterr()
    assert code is None, captured.err
    assert envois == ["critique"]
    assert not any(x.startswith("Plugins : ") for x in captured.out.splitlines())


def test_main_module_ia(monkeypatch, tmp_path, capsys):
    """Ligne 3125 : --ai-summary lance le module IA apres l'analyse."""
    appels = []
    monkeypatch.setattr(cli, "_run_ai", lambda args, options, r, paquets: appels.append(len(paquets)))
    code = _main_capture_doublee(monkeypatch, tmp_path, ["--ai-summary"])
    assert code is None, capsys.readouterr().err
    assert appels == [1]
