"""
Tests du mode debug de netcross_core.logging_config (issue #245 : « activer
le tracing en mode debug pour suivre efficacement l'exécution »).

La configuration loguru est un etat global du processus : chaque scenario
tourne dans un sous-processus avec son propre environnement, pour ne pas
dependre de l'ordre des tests ni polluer les autres.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _run(
    code: str,
    env_extra: dict[str, str] | None = None,
    args: list[str] | None = None,
    script: Path | None = None,
):
    """Execute ``code`` dans un sous-processus propre. ``script`` : ecrit le
    code dans ce fichier plutot que ``-c`` (lignes source disponibles pour
    les tracebacks annotes)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("NETCROSS_")}
    env["PYTHONPATH"] = str(SRC)
    env.update(env_extra or {})
    if script is not None:
        script.write_text(textwrap.dedent(code), encoding="utf-8")
        cible = [str(script)]
    else:
        cible = ["-c", textwrap.dedent(code)]
    r = subprocess.run(
        [sys.executable, *cible, *(args or [])],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    # La CI GitHub force la couleur (codes ANSI entre « └ » et la valeur) :
    # on compare le texte, pas la mise en forme.
    r.stderr = _ANSI.sub("", r.stderr)
    return r


_EMIT = """
from netcross_core.logging_config import get_logger, is_debug_enabled, current_level
logger = get_logger("essai")
logger.debug("message-debug-temoin")
logger.info("message-info-temoin")
print(current_level(), is_debug_enabled())
"""


def test_defaut_info_sans_debug():
    r = _run(_EMIT)
    assert r.stdout.split() == ["INFO", "False"]
    assert "message-info-temoin" in r.stderr
    assert "message-debug-temoin" not in r.stderr
    assert "tracing debug actif" not in r.stderr


def test_netcross_debug_active_le_tracing_avec_le_thread():
    r = _run(_EMIT, {"NETCROSS_DEBUG": "1"})
    assert r.stdout.split() == ["DEBUG", "True"]
    assert "tracing debug actif : niveau=DEBUG" in r.stderr
    ligne = next(line for line in r.stderr.splitlines() if "message-debug-temoin" in line)
    # processus et thread emetteurs presents en mode debug
    assert "MainProcess:MainThread" in ligne


@pytest.mark.parametrize("valeur", ["true", "oui", "ON"])
def test_netcross_debug_valeurs_vraies(valeur):
    assert _run(_EMIT, {"NETCROSS_DEBUG": valeur}).stdout.split() == ["DEBUG", "True"]


def test_netcross_log_level_prioritaire_sur_netcross_debug():
    r = _run(_EMIT, {"NETCROSS_DEBUG": "1", "NETCROSS_LOG_LEVEL": "warning"})
    assert r.stdout.split() == ["WARNING", "False"]
    assert "message-debug-temoin" not in r.stderr
    assert "message-info-temoin" not in r.stderr


def test_niveau_trace_est_un_mode_debug():
    assert _run(_EMIT, {"NETCROSS_LOG_LEVEL": "TRACE"}).stdout.split() == ["TRACE", "True"]


def test_niveau_inconnu_repli_sur_info_avec_avertissement():
    r = _run(_EMIT, {"NETCROSS_LOG_LEVEL": "BAVARD"})
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["INFO", "False"]
    assert "niveau de log inconnu 'BAVARD', repli sur INFO" in r.stderr


def test_netcross_log_file_copie_les_logs_avec_le_thread_du_worker(tmp_path):
    fichier = tmp_path / "netcross.log"
    code = """
    import threading
    from netcross_core.logging_config import get_logger
    logger = get_logger("essai")
    t = threading.Thread(target=lambda: logger.debug("depuis-le-worker"), name="analyse-worker")
    t.start(); t.join()
    """
    r = _run(code, {"NETCROSS_DEBUG": "1", "NETCROSS_LOG_FILE": str(fichier)})
    assert r.returncode == 0, r.stderr
    contenu = fichier.read_text(encoding="utf-8")
    assert "depuis-le-worker" in contenu
    assert ":analyse-worker |" in contenu
    assert "\x1b[" not in contenu  # pas de codes couleur dans le fichier


def test_enable_debug_a_chaud_sans_doubler_les_handlers():
    code = """
    from netcross_core.logging_config import enable_debug, get_logger
    logger = get_logger("essai")
    logger.debug("avant-enable")
    enable_debug()
    logger.debug("apres-enable")
    """
    r = _run(code)
    assert "avant-enable" not in r.stderr
    assert r.stderr.count("apres-enable") == 1


def test_diagnose_affiche_les_valeurs_des_variables_en_debug(tmp_path):
    code = """
    from netcross_core.logging_config import get_logger
    logger = get_logger("essai")
    def echoue(valeur_temoin):
        return 1 / (valeur_temoin - 987654)
    try:
        echoue(987654)
    except ZeroDivisionError:
        logger.exception("echec-temoin")
    """
    debug = _run(code, {"NETCROSS_DEBUG": "1"}, script=tmp_path / "debug.py")
    normal = _run(code, script=tmp_path / "normal.py")
    assert "echec-temoin" in debug.stderr and "echec-temoin" in normal.stderr
    # diagnose=True annote la pile avec la valeur des variables (« └ 987654 »)
    assert "└ 987654" in debug.stderr
    assert "└" not in normal.stderr


def test_option_debug_argparse():
    code = """
    import argparse, sys
    from netcross_core.logging_config import add_debug_argument, apply_debug_argument, is_debug_enabled
    ap = argparse.ArgumentParser()
    add_debug_argument(ap)
    args = ap.parse_args(sys.argv[1:])
    apply_debug_argument(args)
    print(args.debug, is_debug_enabled())
    """
    assert _run(code, args=["--debug"]).stdout.split() == ["True", "True"]
    assert _run(code).stdout.split() == ["False", "False"]


CLIS = [
    "cross_capture_analyzer_cli.py",
    "cross_capture_diff_cli.py",
    "cross_capture_batch_cli.py",
    "cross_history_cli.py",
    "netcross_ai_models_cli.py",
    "netcross_lua_doc_cli.py",
]


@pytest.mark.parametrize("cli", CLIS)
def test_chaque_cli_expose_debug(cli):
    """--debug est declare dans le parseur de chaque point d'entree CLI."""
    source = (SRC / cli).read_text(encoding="utf-8")
    assert "add_debug_argument(" in source
    assert "apply_debug_argument(args)" in source


def test_gui_retire_debug_avant_gtk():
    """Gtk.Application.run refuserait --debug : main() doit le retirer et
    activer le mode debug (verification statique, GTK absent en CI)."""
    source = (SRC / "netcross_gtk4" / "app.py").read_text(encoding="utf-8")
    main = source.split("def main():", 1)[1].split("\ndef ", 1)[0]
    assert "DEBUG_FLAG in argv" in main
    assert "enable_debug()" in main
    assert "app.run(argv)" in main
