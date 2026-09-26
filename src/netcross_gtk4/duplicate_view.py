"""Presentation helpers for cross-capture duplicate detection (Job 41).

Pure Python: no GTK import, so the formatting logic can be tested without a
display server.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


def format_duplicate_indicator(report: Any) -> str:
    """Return the compact duplicate status shown by the GTK4 results page.

    The report is intentionally duck-typed so this helper stays independent
    from GTK and remains usable with lightweight test doubles.
    """
    counts: Mapping[tuple[str, str], int] = getattr(report, "duplicate_count", {}) or {}
    total = sum(counts.values())
    logger.debug("format_duplicate_indicator: {} paquet(s) en double sur {} paire(s)", total, len(counts))
    if total == 0:
        return "Doublons inter-captures : aucun détecté."

    details = ", ".join(f"{a} ↔ {b} : {count}" for (a, b), count in sorted(counts.items()))
    logger.debug("format_duplicate_indicator: exclus={}", getattr(report, "duplicates_excluded", False))
    suffix = (
        " — exclus des statistiques et de la corrélation"
        if getattr(report, "duplicates_excluded", False)
        else " — inclus dans les statistiques"
    )
    return f"Doublons inter-captures : {total} paquet(s) ({details}){suffix}"


__all__ = ["format_duplicate_indicator"]
