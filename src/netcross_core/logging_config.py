"""
netcross_core.logging_config -- configuration centrale du logging (issue #245).

Configure loguru avec un format structuré et un niveau configurable.

Usage dans les modules :

    from netcross_core.logging_config import get_logger
    logger = get_logger(__name__)
    logger.info("demarrage de l'analyse")
    logger.debug("paquet reçu : src={} dst={}", pkt.src, pkt.dst)

Ne configure le handler qu'une seule fois (idempotent) -- un module qui
importe ``get_logger`` peut le faire sans risque de doubler les handlers.

Mode debug (tracing de l'exécution)
-----------------------------------

Activé par l'option ``--debug`` des CLI et de la GUI, par
``NETCROSS_DEBUG=1`` ou par ``NETCROSS_LOG_LEVEL=DEBUG`` (ou ``TRACE``).
Par rapport au mode normal, chaque ligne indique en plus le processus et
le thread émetteurs (les analyses GTK tournent dans des threads, le
parsing multi-captures dans un pool), et les ``logger.exception``
affichent la pile complète avec la valeur des variables
(``backtrace``/``diagnose`` de loguru). Ces valeurs peuvent contenir des
données de capture : le mode debug est un outil de diagnostic, pas un
réglage de production.

Variables d'environnement :

- ``NETCROSS_LOG_LEVEL`` : niveau loguru (défaut ``INFO``) ; prioritaire
  sur ``NETCROSS_DEBUG`` ;
- ``NETCROSS_DEBUG`` : ``1``/``true``/``oui``/``on`` équivaut à ``DEBUG`` ;
- ``NETCROSS_LOG_FILE`` : copie des logs dans ce fichier (rotation à
  10 Mo, 5 fichiers conservés), utile pour la GUI dont le stderr n'est
  pas visible.

Journaux de ``pcap_parser`` (issue #446)
-----------------------------------------

``pcap_parser`` est la couche la plus basse : le contrat import-linter lui
interdit d'importer ``netcross_core``, il utilise donc loguru directement.
Pour rester silencieux en usage bibliothèque, son ``__init__`` appelle
``logger.disable("pcap_parser")`` (convention loguru pour les
bibliothèques). ``configure_logging`` le réactive avec
``logger.enable("pcap_parser")``. ``pcap_parser`` est importé en tête de
ce module (dépendance ``netcross_core`` -> ``pcap_parser``, conforme au
contrat de couches) : son ``disable`` s'exécute donc toujours AVANT le
premier ``enable``, quel que soit l'ordre des imports de l'appelant.
"""

from __future__ import annotations

import os
import sys

from loguru import logger as _logger

# Import pour son effet de bord (issue #446) : exécute
# pcap_parser/__init__.py, donc son logger.disable("pcap_parser"), avant
# tout appel à configure_logging -- sinon un import de pcap_parser postérieur
# annulerait le logger.enable("pcap_parser") ci-dessous.
import pcap_parser  # noqa: F401

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
    """Niveau demandé par l'environnement (``NETCROSS_LOG_LEVEL`` puis ``NETCROSS_DEBUG``)."""
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
    configuration déjà posée (utilisé par ``enable_debug`` après lecture
    des options de la ligne de commande).
    """
    global _CONFIGURED, _LEVEL
    if _CONFIGURED and not force:
        return

    # Issue #446 : pcap_parser se désactive dans son __init__ (usage
    # bibliothèque) ; les points d'entrée Netcross le réactivent ici.
    _logger.enable("pcap_parser")

    requested = (level or level_from_env()).strip().upper()
    niveau_inconnu = False
    try:
        _logger.level(requested)
    except ValueError:
        _logger.debug("configure_logging: niveau {!r} refusé par loguru", requested)
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
        _logger.remove()  # handler par défaut de loguru (id 0)
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
    """Active le mode debug à chaud (option ``--debug`` d'une CLI ou de la GUI)."""
    configure_logging(level, log_file=log_file, force=True)


def current_level() -> str:
    """Niveau effectivement configuré."""
    if not _CONFIGURED:
        configure_logging()
    return _LEVEL


def is_debug_enabled() -> bool:
    """Vrai si le mode debug est actif."""
    return is_debug_level(current_level())


def add_debug_argument(parser) -> None:
    """Ajoute l'option ``--debug`` commune à un ``argparse.ArgumentParser``."""
    parser.add_argument(
        DEBUG_FLAG,
        action="store_true",
        help="Active le tracing debug : niveau DEBUG, thread émetteur, tracebacks détaillés "
        "(equivaut a NETCROSS_DEBUG=1 ; NETCROSS_LOG_FILE=chemin pour copier les logs dans un fichier).",
    )


def apply_debug_argument(args) -> None:
    """Active le mode debug si ``args.debug`` est vrai (après ``parse_args``)."""
    if getattr(args, "debug", False):
        enable_debug()


def get_logger(name: str):
    """Retourne un logger loguru configuré pour le module ``name``."""
    if not _CONFIGURED:
        configure_logging()
    return _logger.bind(name=name)
