"""netcross_gtk4.expertise_view -- sections d'expertise de l'analyse simple
(issue #673), sans GTK.

Équivalents de ``--rule-engine``, ``--expert-section``, ``--media-quality``
(sections du rapport texte, mêmes fonctions que la CLI), ``--flow-timeline``
et ``--tshark-stats`` (documents JSON identiques à ceux de la CLI, exportés
depuis la page Résultats).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

# Bornes du réglage « Fenêtre (s) » ; la CLI exige seulement > 0.
FLOW_TIMELINE_WINDOW_MIN = 0.1
FLOW_TIMELINE_WINDOW_MAX = 3600.0


@dataclass(frozen=True)
class ExpertiseSettings:
    """Cases « Expertise » de la configuration (analyse simple)."""

    rule_engine: bool = False
    expert_section: bool = False
    media_quality: bool = False
    tshark_stats: bool = False
    flow_timeline: bool = False
    flow_timeline_window: float = 1.0

    @property
    def active(self) -> bool:
        return self.rule_engine or self.expert_section or self.media_quality or self.tshark_stats or self.flow_timeline


@dataclass(frozen=True)
class ExpertiseExports:
    """Documents JSON calculés pendant l'analyse ; None si non demandés."""

    flow_timelines: dict | None = None
    tshark_stats: dict | None = None


class ExpertiseSettingsError(ValueError):
    """Réglage refusé, message pour l'utilisateur."""


def validate_settings(settings: ExpertiseSettings, *, live: bool = False) -> None:
    """Mêmes refus que la CLI : fenêtre > 0 ; qualité média et statistiques
    tshark relisent les fichiers, donc indisponibles en capture en direct."""
    if settings.flow_timeline and settings.flow_timeline_window <= 0:
        raise ExpertiseSettingsError("la fenetre de la chronologie des flux doit etre positive")
    if live and settings.media_quality:
        raise ExpertiseSettingsError("la qualite media relit les fichiers de capture : indisponible en direct")
    if live and settings.tshark_stats:
        raise ExpertiseSettingsError(
            "les statistiques tshark relisent les fichiers de capture : indisponibles en direct"
        )


def timeline_summary(doc: dict | None) -> str:
    if not doc:
        return "Chronologie des flux : non calculee (cochez « Chronologie des flux » puis relancez l'analyse)."
    flows = doc.get("flows") or []
    points = sorted({f.get("point") for f in flows if f.get("point")})
    return (
        f"Chronologie des flux : {len(flows)} conversation(s), {len(points)} point(s), fenetre {doc.get('window_s')} s."
    )


def tshark_stats_summary(doc: dict | None) -> str:
    if not doc:
        return "Statistiques tshark : non calculees (cochez « Statistiques tshark » puis relancez l'analyse)."
    captures = doc.get("captures") or []
    errors = [c for c in captures if "error" in c]
    line = f"Statistiques tshark : {len(captures)} capture(s)"
    if errors:
        details = "; ".join(f"{c['label']} : {c['error']}" for c in errors)
        line += f", {len(errors)} en echec ({details})"
    return line + "."


def write_json(path: str | os.PathLike, payload: Any) -> str:
    """Même écriture que ``--flow-timeline``/``--tshark-stats`` de la CLI."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    logger.debug("expertise_view.write_json: {}", path)
    return os.fspath(path)
