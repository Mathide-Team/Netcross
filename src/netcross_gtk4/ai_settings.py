"""netcross_gtk4.ai_settings -- module IA local dans la GUI (issue #866).

Equivalent GUI des options ``--ai-*`` de la CLI (issue #146), avec les
memes validations, faites AVANT l'analyse (``_check_ai_args``) :

- ``--ai-baseline-save`` / ``--ai-baseline-label`` : baseline des flux de
  la capture, supposee normale (creee ou enrichie) ;
- ``--ai-anomalies`` : anomalies de flux par rapport a une baseline ;
- ``--ai-training-export`` / ``--ai-classify`` : jeu pre-etiquete,
  classification des flux ;
- ``--ai-summary`` / ``--ai-endpoint`` : resume executif (template ou
  modele local, boucle locale uniquement) ;
- ``--ai-report`` : resultats en JSON.

Le pipeline execute ``netcross_ai.pipeline.run_ai`` apres l'analyse de
securite, comme la CLI ; une erreur du module IA est journalisee sans faire
perdre l'analyse. Module sans GTK (aucun import de gi).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

__all__ = ["AISettings", "run_ai_section", "settings_from_widgets", "to_options", "validate_settings"]


@dataclass(frozen=True)
class AISettings:
    baseline_save: str | None = None
    baseline_label: str = ""
    anomalies: str | None = None
    training_export: str | None = None
    classify: str | None = None
    summary: str | None = None
    endpoint: str | None = None
    report: str | None = None

    @property
    def requested(self) -> bool:
        """Au moins un usage d'analyse demande (comme ``_check_ai_args``)."""
        return bool(self.baseline_save or self.anomalies or self.training_export or self.classify or self.summary)


def _path(text: str | None) -> str | None:
    value = (text or "").strip()
    return os.path.expanduser(value) if value else None


def settings_from_widgets(
    baseline_save: str,
    baseline_label: str,
    anomalies: str | None,
    training_export: str,
    classify: str | None,
    summary: str,
    endpoint: str,
    report: str,
) -> AISettings:
    """Reglages depuis les champs (texte rogne, champ vide = non demande)."""
    settings = AISettings(
        baseline_save=_path(baseline_save),
        baseline_label=baseline_label.strip(),
        anomalies=_path(anomalies),
        training_export=_path(training_export),
        classify=_path(classify),
        summary=summary.strip() or None,
        endpoint=endpoint.strip() or None,
        report=_path(report),
    )
    logger.debug("settings_from_widgets: retour {}", summarize(settings, "settings"))
    return settings


def validate_settings(settings: AISettings) -> list[str]:
    """Erreurs bloquantes, memes regles et messages que la CLI."""
    logger.debug("validate_settings: settings={}", summarize(settings, "settings"))
    if not settings.requested:
        if settings.report or settings.endpoint or settings.baseline_label:
            logger.debug("validate_settings: refus, option sans usage d'analyse")
            return ["--ai-report/--ai-endpoint/--ai-baseline-label necessitent une option --ai-* d'analyse."]
        logger.debug("validate_settings: aucun usage demande")
        return []
    from netcross_ai.optional import AIUnavailableError, require_ml
    from netcross_ai.report_writer import WriterConfigError, parse_engine

    errors: list[str] = []
    if settings.baseline_label and not settings.baseline_save:
        errors.append("--ai-baseline-label necessite --ai-baseline-save.")
    if settings.endpoint and not settings.summary:
        errors.append("--ai-endpoint necessite --ai-summary.")
    for flag, path in (("--ai-anomalies", settings.anomalies), ("--ai-classify", settings.classify)):
        if path and not os.path.isfile(path):
            errors.append(f"{flag} : fichier introuvable : {path}")
    try:
        if settings.anomalies:
            require_ml("--ai-anomalies")
        if settings.classify:
            require_ml("--ai-classify")
        if settings.summary:
            parse_engine(settings.summary, settings.endpoint)
    except (AIUnavailableError, WriterConfigError) as exc:
        logger.debug("validate_settings: module IA refuse ({})", exc)
        errors.append(f"Module IA : {exc}")
    logger.debug("validate_settings: retour {} erreur(s)", len(errors))
    return errors


def to_options(settings: AISettings) -> Any:
    """``netcross_ai.pipeline.AIOptions`` equivalent (memes champs que la CLI)."""
    from netcross_ai.pipeline import AIOptions

    return AIOptions(
        baseline_path=settings.anomalies,
        baseline_save=settings.baseline_save,
        baseline_label=settings.baseline_label,
        training_path=settings.classify,
        training_export=settings.training_export,
        summary_engine=settings.summary,
        endpoint=settings.endpoint,
    )


def run_ai_section(settings: AISettings, report: Any, all_packets: list) -> tuple[dict | None, str, list[str]]:
    """Execute le module IA : (resultat JSON ou None, texte de la section,
    lignes de journal). Ne leve pas : une erreur devient une ligne
    « Module IA : ... » et l'analyse reste valable."""
    logger.debug("run_ai_section: settings={}", summarize(settings, "settings"))
    from netcross_ai.pipeline import format_ai, run_ai

    flows = report.flow_anomalies
    if not flows:
        from netcross_core.security.flow_stats import analyze_flow_stats

        flows = [f.to_dict() for f in analyze_flow_stats(all_packets).flows]
    try:
        result = run_ai(report, flows, to_options(settings))
    except (RuntimeError, ValueError, OSError) as exc:
        logger.exception(f"échec dans run_ai_section: {exc}")
        return None, "", [f"Module IA : {exc}"]
    logs = [f"Module IA : {len(flows)} flux analyse(s)."]
    if settings.report:
        try:
            with open(settings.report, "w", encoding="utf-8") as fh:
                json.dump(result, fh, ensure_ascii=False, indent=2)
            logs.append(f"Resultats du module IA ecrits dans {settings.report}")
        except OSError as exc:
            logger.exception(f"échec d'écriture du rapport IA: {exc}")
            logs.append(f"Module IA : rapport JSON non ecrit ({exc})")
    logger.debug("run_ai_section: retour {} ligne(s) de journal", len(logs))
    return result, format_ai(result), logs
