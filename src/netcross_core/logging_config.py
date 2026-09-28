"""
netcross_core.logging_config -- configuration centrale du logging (issue #245).

Configure loguru avec un format structure et un niveau configurable.

Usage dans les modules :

    from netcross_core.logging_config import get_logger
    logger = get_logger(__name__)
    logger.info("demarrage de l'analyse")
    logger.debug("paquet recu : src={} dst={}", pkt.src, pkt.dst)

Ne configure le handler qu'une seule fois (idempotent) -- un module qui
importe ``get_logger`` peut le faire sans risque de doubler les handlers.

Mode debug (tracing de l'execution)
-----------------------------------

Active par l'option ``--debug`` des CLI et de la GUI, par
``NETCROSS_DEBUG=1`` ou par ``NETCROSS_LOG_LEVEL=DEBUG`` (ou ``TRACE``).
Par rapport au mode normal, chaque ligne indique en plus le processus et
le thread emetteurs (les analyses GTK tournent dans des threads, le
parsing multi-captures dans un pool), et les ``logger.exception``
affichent la pile complete avec la valeur des variables
(``backtrace``/``diagnose`` de loguru). Ces valeurs peuvent contenir des
donnees de capture : le mode debug est un outil de diagnostic, pas un
reglage de production.

Variables d'environnement :

- ``NETCROSS_LOG_LEVEL`` : niveau loguru (defaut ``INFO``) ; prioritaire
  sur ``NETCROSS_DEBUG`` ;
- ``NETCROSS_DEBUG`` : ``1``/``true``/``oui``/``on`` equivaut a ``DEBUG`` ;
- ``NETCROSS_LOG_FILE`` : copie des logs dans ce fichier (rotation a
  10 Mo, 5 fichiers conserves), utile pour la GUI dont le stderr n'est
  pas visible.

Issue #446 : pcap_parser (couche la plus basse) desactive loguru dans
son ``__init__.py`` pour etre silencieux en usage bibliotheque.
``configure_logging`` le reactive via ``logger.enable("pcap_parser")``.
L'import de pcap_parser ici (avant ``enable``) gere le cas ou
pcap_parser serait importe APRES ``configure_logging`` : son ``disable``
annulerait le ``enable`` sinon. Cet import (``netcross_core`` ->
``pcap_parser``) respecte le contrat de couches import-linter.
"""

from __future__ import annotations

import os
import sys

from loguru import logger as _logger

DEBUG_LEVELS = frozenset({"TRACE", "DEBUG"})
DEFAULT_LEVEL = "INFO"
DEBUG_FLAG = "--debug"
_TRUE = frozenset({"1", "true", "yes", "oui", "on"})

_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)
_DEBUG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<magenta>{process.name}:{thread.name}</magenta> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)

_CONFIGURED = False
_LEVEL = DEFAULT_LEVEL
_HANDLER_IDS: list[int] = []


def level_from_env() -> str:
    """Niveau demande par l'environnement (``NETCROSS_LOG_LEVEL`` puis ``NETCROSS_DEBUG``)."""
    level = os.environ.get("NETCROSS_LOG_LEVEL", "").strip()
    if level:
        return level.upper()
    if os.environ.get("NETCROSS_DEBUG", "").strip().lower() in _TRUE:
        return "DEBUG"
    return DEFAULT_LEVEL


def is_debug_level(level: str) -> bool:
    """Vrai si ``level`` active le mode debug (``DEBUG`` ou ``TRACE``)."""
    return level.strip().upper() in DEBUG_LEVELS


def configure_logging(level: str | None = None, *, log_file: str | None = None, force: bool = False) -> None:
    """Configure loguru (idempotent sauf ``force=True``).

    ``level`` : niveau explicite, sinon ``level_from_env()``. ``log_file`` :
    fichier de copie, sinon ``NETCROSS_LOG_FILE``. ``force`` : remplace la
    configuration deja posee (utilise par ``enable_debug`` apres lecture
    des options de la ligne de commande).
    """
    global _CONFIGURED, _LEVEL
    if _CONFIGURED and not force:
        return

    # Issue #446 : reactive pcap_parser (desactive dans pcap_parser/__init__.py).
    # Import avant enable pour le cas ou pcap_parser serait importe APRES
    # configure_logging : son disable annulerait le enable sinon.
    import pcap_parser  # noqa: F401 -- effet de bord : __init__ desactive puis on reactive

    _logger.enable("pcap_parser")

    requested = (level or level_from_env()).strip().upper()
    niveau_inconnu = False
    try:
        _logger.level(requested)
    except ValueError:
        _logger.debug("configure_logging: niveau {!r} refuse par loguru", requested)
        niveau_inconnu = True
        requested_invalide, requested = requested, DEFAULT_LEVEL
    if log_file is None:
        log_file = os.environ.get("NETCROSS_LOG_FILE", "").strip() or None

    debug = is_debug_level(requested)
    fmt = _DEBUG_FORMAT if debug else _FORMAT
    if _CONFIGURED:
        for handler_id in _HANDLER_IDS:
            _logger.remove(handler_id)
    else:
        _logger.remove()  # handler par defaut de loguru (id 0)
    _HANDLER_IDS.clear()
    _HANDLER_IDS.append(_logger.add(sys.stderr, level=requested, format=fmt, backtrace=debug, diagnose=debug))
    if log_file:
        _HANDLER_IDS.append(
            _logger.add(
                log_file,
                level=requested,
                format=fmt,
                backtrace=debug,
                diagnose=debug,
                rotation="10 MB",
                retention=5,
                encoding="utf-8",
            )
        )
    _CONFIGURED = True
    _LEVEL = requested

    if niveau_inconnu:
        _logger.warning("niveau de log inconnu {!r}, repli sur {}", requested_invalide, DEFAULT_LEVEL)
    _logger.debug(
        "tracing debug actif : niveau={} fichier={} pid={} python={}",
        requested,
        log_file or "aucun",
        os.getpid(),
        sys.version.split()[0],
    )


def enable_debug(level: str = "DEBUG", *, log_file: str | None = None) -> None:
    """Active le mode debug a chaud (option ``--debug`` d'une CLI ou de la GUI)."""
    configure_logging(level, log_file=log_file, force=True)


def current_level() -> str:
    """Niveau effectivement configure."""
    if not _CONFIGURED:
        configure_logging()
    return _LEVEL


def is_debug_enabled() -> bool:
    """Vrai si le mode debug est actif."""
    return is_debug_level(current_level())


def add_debug_argument(parser) -> None:
    """Ajoute l'option ``--debug`` commune a un ``argparse.ArgumentParser``."""
    parser.add_argument(
        DEBUG_FLAG,
        action="store_true",
        help="Active le tracing debug : niveau DEBUG, thread emetteur, tracebacks detailles "
        "(equivaut a NETCROSS_DEBUG=1 ; NETCROSS_LOG_FILE=chemin pour copier les logs dans un fichier).",
    )


def apply_debug_argument(args) -> None:
    """Active le mode debug si ``args.debug`` est vrai (apres ``parse_args``)."""
    if getattr(args, "debug", False):
        enable_debug()


def get_logger(name: str):
    """Retourne un logger loguru configure pour le module ``name``."""
    if not _CONFIGURED:
        configure_logging()
    return _logger.bind(name=name)
