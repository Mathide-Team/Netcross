"""Tests de couverture des fonctions auxiliaires de
cross_capture_analyzer_cli.py (issue #678, suite #665).

Validations d'arguments et modes « outil » (--convert, --export-pcap,
--adjust-time, --replay), capture en direct, consentement du ticket
support, memoire, plugins, rapport temps reel et module IA -- sans tshark,
tcpreplay ni reseau : les fonctions externes sont doublees.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

from conftest import make_pkt

import cross_capture_analyzer_cli as cli


def _sortie(fn, *args, **kwargs):
    """Appelle fn et renvoie le code de sys.exit (None si pas de sortie)."""
    try:
        fn(*args, **kwargs)
    except SystemExit as exc:
        return exc.code
    return None


# -- --client-group ------------------------------------------------------------------


def test_client_group_formats(capsys):
    """Lignes 220-236 : NOM=IP1,IP2 ; format sans '=' ou sans IP refuse."""
    assert cli._parse_client_group_spec("poste=10.0.0.1, 10.0.0.2,") == ("poste", {"10.0.0.1", "10.0.0.2"})
    assert _sortie(cli._parse_client_group_spec, "sans-egal") == 1
    assert _sortie(cli._parse_client_group_spec, "vide=, ") == 1
    assert _sortie(cli._parse_client_group_spec, "=10.0.0.1") == 1
    assert capsys.readouterr().err.count("Format invalide pour --client-group") == 3


# -- modes outil -----------------------------------------------------------------------


def test_convert_sans_capture_csv_json_et_erreur(monkeypatch, capsys):
    """Lignes 541-542 : --convert sans --capture ; lignes 557-560 : export
    CSV / JSON ; erreur du convertisseur -> code 1."""
    appels = []
    monkeypatch.setattr(cli, "export_csv", lambda src, dst: appels.append(("csv", src, dst)))
    monkeypatch.setattr(cli, "export_json", lambda src, dst: appels.append(("json", src, dst)))

    def _ko(src, dst, fmt):
        raise RuntimeError("editcap absent")

    monkeypatch.setattr(cli, "convert_capture", _ko)
    assert _sortie(cli._run_convert, [], "x.csv", "csv") == 1
    assert _sortie(cli._run_convert, ["A=a.pcap"], "a.csv", "csv") is None
    assert _sortie(cli._run_convert, ["A=a.pcap"], "a.json", "json") is None
    assert appels == [("csv", "a.pcap", "a.csv"), ("json", "a.pcap", "a.json")]
    assert _sortie(cli._run_convert, ["A=a.pcap"], "a.pcapng", "pcapng") == 1
    err = capsys.readouterr().err
    assert "--convert necessite --capture" in err
    assert "--convert : editcap absent" in err


def test_export_pcap_refus(monkeypatch, capsys):
    """Lignes 576-577 : sans --capture ; lignes 589-594 : plusieurs segments ;
    lignes 605-608 : erreur de l'export."""

    def _ko(*a, **kw):
        raise ValueError("filtre BPF invalide")

    monkeypatch.setattr(cli, "export_filtered", _ko)
    assert _sortie(cli._run_export, [], "o.pcap", None, None, None, None) == 1
    assert _sortie(cli._run_export, ["A=a.pcap,b.pcap"], "o.pcap", None, None, None, None) == 1
    assert _sortie(cli._run_export, ["A=a.pcap"], "o.pcap", "port 99999", None, None, None) == 1
    err = capsys.readouterr().err
    assert "--export-pcap necessite --capture" in err
    assert "recu 2 segments dans A" in err
    assert "--export-pcap : filtre BPF invalide" in err


def test_adjust_time_refus(monkeypatch, capsys):
    """Lignes 708-709, 718-722 et 732-735 : memes refus pour --adjust-time."""

    def _ko(*a, **kw):
        raise FileNotFoundError("a.pcap")

    monkeypatch.setattr(cli, "adjust_timestamps", _ko)
    assert _sortie(cli._run_adjust_time, [], "o.pcap", 1.0, False, None) == 1
    assert _sortie(cli._run_adjust_time, ["A=a.pcap,b.pcap"], "o.pcap", 1.0, False, None) == 1
    assert _sortie(cli._run_adjust_time, ["A=a.pcap"], "o.pcap", 1.0, False, None) == 1
    err = capsys.readouterr().err
    assert "--adjust-time necessite --capture" in err
    assert "recu 2 segments dans A" in err
    assert "--adjust-time : a.pcap" in err


def test_replay_un_seul_fichier_succes_et_erreur(monkeypatch, capsys):
    """Lignes 750-772 : --replay exige exactement un fichier ; succes puis
    tcpreplay en echec."""
    rejoues = []
    monkeypatch.setattr(cli, "replay_capture", lambda p, i, speed, loop: rejoues.append((p, i, speed, loop)))
    assert _sortie(cli._run_replay, ["A=a.pcap", "B=b.pcap"], "eth0", 1.0, 1) == 1
    assert _sortie(cli._run_replay, ["A=a.pcap"], "eth0", 2.0, 3) is None
    assert rejoues == [("a.pcap", "eth0", 2.0, 3)]
    captured = capsys.readouterr()
    assert "a.pcap rejoue sur eth0 (speed=2.0, loop=3)." in captured.out
    assert "--replay necessite exactement un fichier" in captured.err

    def _ko(*a, **kw):
        raise RuntimeError("tcpreplay introuvable")

    monkeypatch.setattr(cli, "replay_capture", _ko)
    assert _sortie(cli._run_replay, ["A=a.pcap"], "eth0", 1.0, 1) == 1
    assert "--replay : tcpreplay introuvable" in capsys.readouterr().err


# -- capture en direct -------------------------------------------------------------------


def test_capture_en_direct_progression_ctrl_c_et_duree(monkeypatch, capsys):
    """Lignes 805-806 : progression toutes les 2 s ; lignes 820-825 :
    Ctrl+C ; lignes 828-833 : duree maximale atteinte."""
    horloge = iter([0.0, 5.0, 10.0])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(horloge, 99.0))

    def _live(label, iface, bpf_filter=None, stop_event=None):
        yield make_pkt(point=label)
        yield make_pkt(point=label, ts=1.0)

    gestionnaires = []

    class _Minuteur:
        def __init__(self, delai, fonction):
            self.fonction = fonction
            self.daemon = False

        def start(self):
            self.fonction()

        def cancel(self):
            pass

    monkeypatch.setattr(cli, "parse_live", _live)
    monkeypatch.setattr(cli.signal, "signal", lambda signum, handler: gestionnaires.append(handler))
    monkeypatch.setattr(cli.threading, "Timer", _Minuteur)
    paquets = cli._run_live_captures(["LAN:eth0"], 4)
    gestionnaires[0](2, None)
    captured = capsys.readouterr()
    assert len(paquets) == 2
    assert "[LAN] 1 paquets..." in captured.out
    assert "Duree maximale (4s) atteinte" in captured.err
    assert "Arret demande (Ctrl+C)" in captured.err


# -- ticket support ----------------------------------------------------------------------


def _args_support(**kw):
    base = {
        "support_ticket": None,
        "support_consent": False,
        "support_scope": None,
        "support_map": None,
        "support_marker": None,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_consentement_support(capsys):
    """Lignes 883-887 : options support sans --support-ticket ; lignes
    891-918 : consentement exige, portees inconnues, portees choisies."""
    assert _sortie(cli._build_support_consent, _args_support(support_consent=True)) == 1
    assert _sortie(cli._build_support_consent, _args_support(support_ticket="t.zip")) == 1
    assert (
        _sortie(
            cli._build_support_consent,
            _args_support(support_ticket="t.zip", support_consent=True, support_scope="journal,inconnue"),
        )
        == 1
    )
    err = capsys.readouterr().err
    assert "necessitent --support-ticket" in err
    assert "--support-ticket necessite --support-consent" in err
    assert "portee(s) inconnue(s) inconnue" in err

    portee = cli.SUPPORT_SCOPES[0]
    consent = cli._build_support_consent(
        _args_support(support_ticket="t.zip", support_consent=True, support_scope=f" {portee} ,")
    )
    assert consent.granted and consent.scopes == (portee,) and consent.source == "cli"
    assert cli._build_support_consent(_args_support(support_ticket="t.zip", support_consent=True)).scopes == (
        cli.SUPPORT_SCOPES
    )


def test_marqueurs_support(capsys):
    """Lignes 931-938 : CLE=VALEUR, espaces retires ; format invalide refuse."""
    assert cli._parse_support_markers(["trace_id = T-042", "site=Strasbourg"]) == {
        "trace_id": "T-042",
        "site": "Strasbourg",
    }
    assert _sortie(cli._parse_support_markers, ["sans-egal"]) == 1
    assert "format attendu CLE=VALEUR" in capsys.readouterr().err


# -- memoire -------------------------------------------------------------------------------


def test_memoire_taille_du_fichier_si_capinfos_ne_la_donne_pas(monkeypatch, tmp_path, capsys):
    """Lignes 1068-1071 : taille lue sur le disque, ou 0 si le fichier
    n'existe plus."""
    from pcap_parser import capinfos_source

    vus = []
    fichier = tmp_path / "a.pcap"
    fichier.write_bytes(b"x" * 123)
    monkeypatch.setattr(
        capinfos_source, "read_capture_info", lambda path: SimpleNamespace(file_size=None, packet_count=10)
    )
    monkeypatch.setattr(cli, "_memory_warning", lambda label, size, count: vus.append((label, size)) or "ALERTE")
    cli._check_memory_before_analysis([("A", str(fichier)), ("B", str(tmp_path / "absent.pcap"))])
    assert vus == [("A", 123), ("B", 0)]
    assert capsys.readouterr().err.count("ALERTE") == 2


# -- plugins ---------------------------------------------------------------------------------


def test_liste_des_plugins_vide_puis_en_erreur(monkeypatch, capsys):
    """Lignes 1180-1182 : aucun plugin ; ligne 1188 : plugin en erreur."""
    from netcross_core import plugins

    monkeypatch.setattr(plugins, "list_plugins", lambda authorized, paths: [])
    assert cli._list_plugins([], []) == 0
    assert "Aucun plugin installe" in capsys.readouterr().out

    ligne = {"name": "casse", "kind": "detector", "authorized": True, "origin": "local", "error": "ImportError"}
    monkeypatch.setattr(plugins, "list_plugins", lambda authorized, paths: [ligne])
    cli._list_plugins(["casse"], [])
    assert "  !! ImportError" in capsys.readouterr().out


def test_export_de_plugin_autorise():
    """Ligne 1211 : NOM=FICHIER d'un exporteur autorise."""
    assert cli._parse_plugin_exports([" csvplus = sortie.csv "], ["csvplus"]) == [("csvplus", "sortie.csv")]


# -- extraction de contenus ----------------------------------------------------------------


def _args_extraction(**kw):
    base = {"extract_kinds": None, "extract_contents": None, "media_quality": False, "live": None, "redact": False}
    base.update(kw)
    return SimpleNamespace(**base)


def test_extraction_types_invalides_et_repertoire_vide(tmp_path, capsys):
    """Lignes 1254-1255 : type d'extraction inconnu ; repertoire cible neuf
    accepte."""
    assert (
        _sortie(
            cli._check_extraction_args,
            _args_extraction(extract_contents=str(tmp_path / "x"), extract_kinds="hologramme"),
        )
        == 1
    )
    assert "--extract-kinds" in capsys.readouterr().err
    kinds = cli._check_extraction_args(_args_extraction(extract_contents=str(tmp_path / "neuf")))
    assert kinds


# -- rapport temps reel --------------------------------------------------------------------


def test_rapport_temps_reel_chemin_qui_n_est_pas_un_repertoire(tmp_path, capsys):
    """Lignes 1292-1294 : --live-report pointe sur un fichier."""
    fichier = tmp_path / "rapport.txt"
    fichier.write_text("", encoding="utf-8")
    args = SimpleNamespace(
        live_report=str(fichier), live_report_serve=None, live_report_interval=5.0, live=["LAN:eth0"]
    )
    assert _sortie(cli._check_live_report_args, args) == 1
    assert "n'est pas un repertoire" in capsys.readouterr().err


def test_rapport_temps_reel_port_indisponible(tmp_path, monkeypatch, capsys):
    """Lignes 1320-1326 : le port HTTP demande est deja pris."""
    import http.server

    def _occupe(*a, **kw):
        raise OSError("Address already in use")

    monkeypatch.setattr(http.server, "ThreadingHTTPServer", _occupe)
    args = SimpleNamespace(live_report=str(tmp_path / "live"), live_report_serve=8765, live_report_interval=5.0)
    assert _sortie(cli._start_live_report, args) == 1
    assert "impossible d'ecouter sur le port 8765" in capsys.readouterr().err


# -- module IA ---------------------------------------------------------------------------------


def _args_ia(**kw):
    base = {
        "ai_baseline_save": None,
        "ai_anomalies": None,
        "ai_training_export": None,
        "ai_classify": None,
        "ai_summary": False,
        "ai_report": None,
        "ai_endpoint": None,
        "ai_baseline_label": None,
        "ai_engine": None,
        "ai_model": None,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_ia_classification_exige_scikit_learn(tmp_path, monkeypatch):
    """Lignes 1366-1374 : --ai-classify verifie la dependance ML puis
    construit les options."""
    from netcross_ai import optional

    modele = tmp_path / "modele.json"
    modele.write_text("{}", encoding="utf-8")
    demandes = []
    monkeypatch.setattr(optional, "require_ml", demandes.append)
    options = cli._check_ai_args(_args_ia(ai_classify=str(modele)))
    assert demandes == ["--ai-classify"]
    assert options is not None


def test_run_ai_flux_calcules_erreur_et_rapport(tmp_path, monkeypatch, capsys):
    """Lignes 1386-1406 : flux recalcules si le rapport n'en a pas, erreur
    du pipeline -> code 1, resultats ecrits dans --ai-report."""
    from netcross_ai import pipeline

    recus = []
    monkeypatch.setattr(pipeline, "run_ai", lambda report, flows, options: recus.append(flows) or {"ok": 1})
    monkeypatch.setattr(pipeline, "format_ai", lambda result: f"IA={result}")
    sortie = tmp_path / "ia.json"
    report = SimpleNamespace(flow_anomalies=[])
    cli._run_ai(SimpleNamespace(ai_report=str(sortie)), None, report, [make_pkt()])
    assert isinstance(recus[0], list)
    assert "IA={'ok': 1}" in capsys.readouterr().out
    assert sortie.read_text(encoding="utf-8").strip().startswith("{")

    def _ko(*a):
        raise RuntimeError("modele corrompu")

    monkeypatch.setattr(pipeline, "run_ai", _ko)
    report = SimpleNamespace(flow_anomalies=[{"flux": 1}])
    assert _sortie(cli._run_ai, SimpleNamespace(ai_report=None), None, report, []) == 1
    assert "Module IA : modele corrompu" in capsys.readouterr().err


# -- sous-commande lua-doc -------------------------------------------------------------------


def test_sous_commande_lua_doc(monkeypatch):
    """Lignes 1412-1414 : `netcross lua-doc ...` delegue a netcross_lua_doc_cli."""
    import netcross_lua_doc_cli

    recus = []
    monkeypatch.setattr(netcross_lua_doc_cli, "main", lambda argv: recus.append(argv) or 0)
    monkeypatch.setattr(sys, "argv", ["netcross", "lua-doc", "list"])
    assert _sortie(cli.main) == 0
    assert recus == [["list"]]
