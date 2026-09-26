"""
Tests de non-régression de l'issue #446 : `pcap_parser` utilisé seul
n'écrit rien sur stderr (handler loguru par défaut), et les points
d'entrée Netcross le réactivent quel que soit l'ordre des imports.

Chaque cas tourne dans un sous-processus : l'état de loguru (handlers,
`enable`/`disable`) et `sys.modules` sont globaux au processus, un test en
processus ne verrait que l'ordre d'import déjà figé par la session pytest.

Les journaux sont déclenchés par `pcap_parser.remote.parse_source` sur une
URI `sshdump://`, qui trace le schéma, l'hôte et la cible sans lancer
tshark ni ouvrir de connexion.

Chaque snippet imprime une sentinelle sur stdout après l'appel : sans
elle, un test « aucune ligne DEBUG » passerait à vide si l'import ou
l'appel échouait avant de produire le moindre journal.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
SENTINELLE = "SNIPPET-TERMINE"

_DECLENCHE = (
    "from pcap_parser.remote import parse_source\n"
    'parse_source("sshdump://bob@srv.example/eth1")\n'
    f"print({SENTINELLE!r})\n"
)


def _executer(code: str, **env_extra: str) -> subprocess.CompletedProcess:
    """Exécute `code` dans un interpréteur neuf, `src/` en tête du chemin.

    Environnement du parent sans les variables NETCROSS_* (un
    NETCROSS_DEBUG=1 du développeur fausserait le cas par défaut), plus
    `env_extra`. Échoue si le snippet n'est pas allé au bout.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("NETCROSS_")}
    env["PYTHONPATH"] = str(SRC)
    env.update(env_extra)
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, f"snippet en échec (code {result.returncode}) :\n{result.stderr}"
    assert SENTINELLE in result.stdout, f"snippet interrompu avant la fin :\n{result.stderr}"
    return result


def _lignes_debug_pcap_parser(stderr: str) -> list[str]:
    return [ligne for ligne in stderr.splitlines() if "DEBUG" in ligne and "pcap_parser.remote" in ligne]


def test_pcap_parser_seul_n_ecrit_rien_sur_stderr():
    """Critère 1 : sans configuration Netcross, aucune ligne sur stderr
    (le handler par défaut de loguru écrirait dès DEBUG)."""
    result = _executer(_DECLENCHE)
    assert result.stderr == ""


def test_pcap_parser_seul_reste_muet_meme_si_netcross_debug_est_positionne():
    """Les variables NETCROSS_* ne concernent que les points d'entrée
    Netcross : une bibliothèque importée seule ne les lit pas."""
    result = _executer(_DECLENCHE, NETCROSS_DEBUG="1")
    assert result.stderr == ""


@pytest.mark.parametrize(
    "prelude",
    [
        pytest.param(
            "from netcross_core.logging_config import enable_debug\nenable_debug()\nimport pcap_parser\n",
            id="configure-puis-import",
        ),
        pytest.param(
            "import pcap_parser\nfrom netcross_core.logging_config import enable_debug\nenable_debug()\n",
            id="import-puis-configure",
        ),
        pytest.param(
            "import pcap_parser.remote\nimport netcross_core\nfrom netcross_core.logging_config import enable_debug\n"
            "enable_debug()\n",
            id="sous-module-puis-netcross_core",
        ),
    ],
)
def test_debug_netcross_active_pcap_parser_quel_que_soit_l_ordre_des_imports(prelude):
    """Critère 2 : `enable_debug()` (option --debug) réactive pcap_parser,
    que pcap_parser soit importé avant ou après la configuration."""
    result = _executer(prelude + _DECLENCHE)
    assert _lignes_debug_pcap_parser(result.stderr), result.stderr


@pytest.mark.parametrize(
    ("variable", "valeur"),
    [("NETCROSS_LOG_LEVEL", "DEBUG"), ("NETCROSS_DEBUG", "1")],
)
def test_variables_d_environnement_agissent_sur_pcap_parser(variable, valeur):
    """NETCROSS_LOG_LEVEL / NETCROSS_DEBUG, lus par la configuration
    implicite déclenchée à l'import de netcross_core (get_logger)."""
    result = _executer("import netcross_core\n" + _DECLENCHE, **{variable: valeur})
    assert _lignes_debug_pcap_parser(result.stderr), result.stderr


def test_niveau_info_par_defaut_masque_le_debug_de_pcap_parser():
    """pcap_parser réactivé suit le niveau Netcross : INFO par défaut,
    donc aucune ligne DEBUG."""
    result = _executer("import netcross_core\n" + _DECLENCHE)
    assert not _lignes_debug_pcap_parser(result.stderr), result.stderr


def test_logger_enable_manuel_apres_import():
    """Usage bibliothèque documenté : `logger.enable("pcap_parser")` après
    l'import de pcap_parser, sans aucune configuration Netcross."""
    code = 'import pcap_parser\nfrom loguru import logger\nlogger.enable("pcap_parser")\n' + _DECLENCHE
    result = _executer(code)
    assert _lignes_debug_pcap_parser(result.stderr), result.stderr
