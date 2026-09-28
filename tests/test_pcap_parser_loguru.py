"""
Tests de non-regression pour l'issue #446 : pcap_parser utilise seul
n'ecrit pas de logs DEBUG sur stderr (handler loguru par defaut).

Verifie dans des sous-processus (pour isoler l'etat global de loguru) :
1. pcap_parser importe seul -> aucun log DEBUG sur stderr
2. configure_logging(force=True) puis pcap_parser -> logs visibles au niveau DEBUG
3. pcap_parser puis configure_logging(force=True) -> logs visibles (ordre inverse)
4. pcap_parser seul avec logger.enable manuel -> logs visibles

Ces tests ne necessitent pas tshark : on declenche des logs via
pcap_parser.remote.parse_source (parsing d'URI, pas d'appel tshark).
"""

from __future__ import annotations

import subprocess
import sys

import pytest

PYTHONPATH = "src"

# Snippet qui declenche un logger.debug dans pcap_parser (sans tshark) :
# parse_source("sshdump://...") produit plusieurs logger.debug avant
# d'appeler tshark.
_TRIGGERS = (
    "from pcap_parser.remote import parse_source\n"
    "try:\n"
    '    parse_source("sshdump://bob@srv.example/eth1")\n'
    "except Exception:\n"
    "    pass\n"
)


def _run_snippet(code: str, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Execute un snippet Python dans un sous-processus isole."""
    env = {"PYTHONPATH": PYTHONPATH, "PATH": "/usr/bin:/bin"}
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )


def test_pcap_parser_seul_n_ecrit_rien_sur_stderr():
    """Sans configure_logging(), pcap_parser doit etre silencieux
    (loguru desactive pour le package dans __init__.py)."""
    result = _run_snippet(_TRIGGERS)
    stderr = result.stderr.strip()
    debug_lines = [l for l in stderr.splitlines() if "DEBUG" in l and "pcap_parser" in l]
    assert not debug_lines, (
        f"pcap_parser a ecrit {len(debug_lines)} ligne(s) DEBUG sur stderr sans configure_logging() :\n"
        + "\n".join(debug_lines[:5])
    )


def test_configure_logging_force_puis_pcap_parser_affiche_les_logs():
    """configure_logging(force=True, level=DEBUG) reactive pcap_parser :
    les logs DEBUG doivent etre visibles.

    force=True est necessaire car l'import de netcross_core declenche
    configure_logging() a INFO (via get_logger dans les modules),
    et sans force, le second appel retourne sans rien faire.
    C'est le meme mecanisme que enable_debug() utilise par --debug.
    """
    code = (
        "from netcross_core.logging_config import configure_logging\n"
        'configure_logging("DEBUG", force=True)\n'
        + _TRIGGERS
    )
    result = _run_snippet(code)
    stderr = result.stderr
    debug_lines = [l for l in stderr.splitlines() if "DEBUG" in l and "pcap_parser" in l]
    assert len(debug_lines) > 0, (
        "Aucun log DEBUG de pcap_parser trouve apres configure_logging('DEBUG', force=True) "
        "+ import de pcap_parser. stderr :\n" + stderr[:500]
    )


def test_pcap_parser_puis_configure_logging_force_affiche_les_logs():
    """Ordre inverse : pcap_parser importe AVANT configure_logging(force=True).
    Le disable de __init__.py ne doit pas annuler le enable de
    configure_logging (l'import dans configure_logging le gere)."""
    code = (
        "import pcap_parser\n"
        "from netcross_core.logging_config import configure_logging\n"
        'configure_logging("DEBUG", force=True)\n'
        + _TRIGGERS
    )
    result = _run_snippet(code)
    stderr = result.stderr
    debug_lines = [l for l in stderr.splitlines() if "DEBUG" in l and "pcap_parser" in l]
    assert len(debug_lines) > 0, (
        "Aucun log DEBUG de pcap_parser trouve apres import pcap_parser "
        "+ configure_logging('DEBUG', force=True). stderr :\n" + stderr[:500]
    )


def test_pcap_parser_seul_avec_logger_enable_manuel():
    """Un utilisateur de la bibliotheque seule peut reactive les logs
    via logger.enable('pcap_parser') sans configure_logging().
    Doit importer pcap_parser en premier (son __init__ desactive le
    package), puis appeler enable."""
    code = (
        "import pcap_parser\n"
        "from loguru import logger\n"
        'logger.enable("pcap_parser")\n'
        + _TRIGGERS
    )
    result = _run_snippet(code)
    stderr = result.stderr
    debug_lines = [l for l in stderr.splitlines() if "DEBUG" in l and "pcap_parser" in l]
    assert len(debug_lines) > 0, (
        "Aucun log DEBUG de pcap_parser trouve apres logger.enable('pcap_parser') "
        "sans configure_logging(). stderr :\n" + stderr[:500]
    )


def test_netcross_log_level_debug_active_pcap_parser():
    """NETCROSS_LOG_LEVEL=DEBUG doit activer les logs de pcap_parser,
    meme si configure_logging est appele pendant l'import de netcross_core
    (avant l'import explicite de pcap_parser)."""
    code = (
        "import netcross_core.logging_config\n"
        + _TRIGGERS
    )
    result = _run_snippet(code, env_extra={"NETCROSS_LOG_LEVEL": "DEBUG"})
    stderr = result.stderr
    debug_lines = [l for l in stderr.splitlines() if "DEBUG" in l and "pcap_parser" in l]
    assert len(debug_lines) > 0, (
        "Aucun log DEBUG de pcap_parser trouve avec NETCROSS_LOG_LEVEL=DEBUG. "
        "stderr :\n" + stderr[:500]
    )
