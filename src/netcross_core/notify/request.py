"""netcross_core.notify.request -- notifications d'une analyse terminee,
reglages et envoi partages par la GUI (issue #676) et l'API (issue #875).

Equivalent de ``--notify-on``, ``--notify-webhook``, ``--notify-slack``,
``--notify-email`` et ``--notify-detail`` : meme point d'entree
(``run_notifications``), meme resume, meme fenetre anti-repetition et meme
configuration (``.netcross.toml`` section ``[notify]``, variables
``NETCROSS_SLACK_WEBHOOK`` / ``NETCROSS_SMTP_*``). Les notifications portent
sur le rapport de securite : sans lui, aucune. Sans seuil, aucun canal n'est
construit et aucun appel reseau n'a lieu.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from netcross_core.logging_config import get_logger
from netcross_core.notify.dispatch import STATUS_FAILED, DeliveryResult
from netcross_core.notify.summary import DETAIL_LEVELS, SEVERITIES
from netcross_core.notify.transports import validate_http_url

logger = get_logger(__name__)

SECURITY_HINT_GUI = "cochez « Rapport de securite »"


@dataclass(frozen=True)
class NotifySettings:
    """Reglages de notification releves sur le thread principal (widgets
    GTK non thread-safe), transmis tels quels au thread d'analyse."""

    threshold: str | None = None
    webhook: str | None = None
    slack: str | None = None
    email: str | None = None
    detail: str = "resume"

    @property
    def active(self) -> bool:
        return bool(self.threshold)


def validate_settings(settings: NotifySettings, security: bool, security_hint: str = SECURITY_HINT_GUI) -> list[str]:
    """Erreurs bloquantes avant de lancer l'analyse (liste vide = valide).

    Meme principe que la CLI : echec immediat plutot qu'apres de longues
    minutes d'analyse."""
    if not settings.active:
        return []
    errors: list[str] = []
    if settings.threshold not in SEVERITIES:
        errors.append(f"seuil inconnu : {settings.threshold}")
    if settings.detail not in DETAIL_LEVELS:
        errors.append(f"niveau de detail inconnu : {settings.detail}")
    if not security:
        errors.append(f"les notifications portent sur le rapport de securite : {security_hint}")
    for name, url in (("webhook", settings.webhook), ("Slack", settings.slack)):
        if url:
            try:
                validate_http_url(url)
            except ValueError as exc:
                logger.debug("validate_settings: URL {} refusee ({})", name, exc)
                errors.append(f"URL {name} invalide : {exc}")
    logger.debug("validate_settings: {} erreur(s)", len(errors))
    return errors


def send_notifications(
    report: Any,
    security_report: Any,
    settings: NotifySettings,
    *,
    report_path: str | None = None,
    runner: Callable[..., list] | None = None,
    config_loader: Callable[[], Any] | None = None,
) -> list[dict]:
    """Envoie le resume de l'analyse (comme ``_send_notifications`` de la
    CLI) ; renvoie les lignes de tracabilite (``DeliveryResult.to_dict``).
    Ne leve jamais : un canal en echec est une ligne, pas un echec
    d'analyse."""
    if not settings.active or security_report is None:
        logger.debug("send_notifications: inactif ou sans rapport de securite")
        return []
    from netcross_core.notify import build_summary, run_notifications

    if runner is None:
        runner = run_notifications
    if config_loader is None:
        from netcross_core.config import load_config

        config_loader = load_config
    dash = security_report.dashboard
    try:
        results = runner(
            lambda threshold: build_summary(
                report.security_findings or [],
                score=dash.score,
                level=dash.level,
                threshold=threshold,
                report_path=os.path.abspath(report_path) if report_path else None,
                detail=settings.detail,
            ),
            threshold=settings.threshold,
            cfg=config_loader().notify,
            webhook=settings.webhook,
            slack=settings.slack,
            email_to=settings.email,
        )
    except Exception as exc:  # noqa: BLE001 -- une notification ne fait jamais perdre l'analyse
        logger.exception(f"échec dans send_notifications: {exc}")
        return [DeliveryResult("notifications", STATUS_FAILED, str(exc)).to_dict()]
    lines = [res.to_dict() for res in results]
    logger.debug("send_notifications: {} ligne(s)", len(lines))
    return lines
