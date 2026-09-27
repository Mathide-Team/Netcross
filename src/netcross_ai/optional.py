"""Detection de disponibilite des dependances ML et repli gracieux."""

from __future__ import annotations

import importlib.util

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

INSTALL_HINT = 'installer le module IA : pip install "netcross[ai]" (ou uv sync --extra ai)'


class AIUnavailableError(RuntimeError):
    """scikit-learn absent : fonction IA demandee explicitement mais non installee."""


def ml_available() -> bool:
    """True si scikit-learn (et donc numpy) est importable -- sans l'importer."""
    logger.debug("ml_available()")
    result = importlib.util.find_spec("sklearn") is not None
    logger.debug("ml_available: disponible={}", result)
    return result


def require_ml(feature: str) -> None:
    if not ml_available():
        logger.debug("require_ml: refus, AIUnavailableError")
        raise AIUnavailableError(f"{feature} necessite scikit-learn : {INSTALL_HINT}.")
    logger.debug("require_ml: fin")
