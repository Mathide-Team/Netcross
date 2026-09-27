"""
netcross_core.tshark_stats.runner -- invocation de ``tshark -z``.

Le runner est deliberement separe des parsers : il ne fait que lancer
``tshark -q -r <capture> -z <stat>`` et retourner la sortie texte brute.
Les parsers (conversations, endpoints...) consomment cette sortie.

tshark n'est pas requis a l'import du module ni a l'execution des parsers
(testes avec des fixtures texte) ; il ne l'est qu'au moment de l'appel
effectif du runner.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)


class TsharkUnavailableError(RuntimeError):
    """Levee quand le binaire ``tshark`` est absent du chemin."""


def run_tshark_stat(
    capture_path: str | Path,
    z_arg: str,
    *,
    tshark_bin: str = "tshark",
    timeout: float | None = 60.0,
    extra_args: tuple[str, ...] = (),
) -> str:
    """Lance ``tshark -q -r <capture> -z <z_arg> [extra_args]`` et retourne
    la sortie standard (texte). ``-q`` supprime le decodage paquet par
    paquet pour ne garder que les statistiques demande.

    Leve :class:`TsharkUnavailableError` si tshark est absent, ou propage
    une ``subprocess.TimeoutExpired`` / ``CalledProcessError`` sinon.
    """
    cmd = [tshark_bin, "-q", "-r", str(capture_path), "-z", z_arg, *extra_args]
    logger.debug("run_tshark_stat: {} -z {}", capture_path, z_arg)
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        logger.exception("échec dans run_tshark_stat: {}", exc)
        raise TsharkUnavailableError(
            f"tshark introuvable sur le chemin ({tshark_bin!r}) -- installez "
            "Wireshark/tshark pour utiliser les statistiques -z"
        ) from exc
    # tshark retourne un code non nul sur pcap illisible ou option inconnue ;
    # on garde la sortie stdout quand elle contient le tableau attendu.
    if completed.returncode != 0 and not completed.stdout.strip():
        logger.debug("run_tshark_stat: code de retour {} (aucune sortie)", completed.returncode)
        raise subprocess.CalledProcessError(completed.returncode, cmd, completed.stdout, completed.stderr)
    if completed.returncode != 0:
        logger.debug("run_tshark_stat: code de retour {} (sortie partielle conservée)", completed.returncode)
    logger.debug("run_tshark_stat: retour completed.stdout={}", summarize(completed.stdout, "stdout"))
    return completed.stdout
