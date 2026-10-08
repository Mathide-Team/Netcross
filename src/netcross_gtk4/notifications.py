"""netcross_gtk4.notifications -- notifications sortantes (webhook, Slack,
courriel) apres une analyse de la GUI (issue #676).

Equivalent GUI de ``--notify-on``, ``--notify-webhook``, ``--notify-slack``,
``--notify-email`` et ``--notify-detail`` de la CLI : meme point d'entree
(``netcross_core.notify.run_notifications``), meme resume, meme fenetre
anti-repetition et meme configuration (``.netcross.toml`` section
``[notify]``, variables ``NETCROSS_SLACK_WEBHOOK`` / ``NETCROSS_SMTP_*``).

Comme dans la CLI, les notifications portent sur le rapport de securite :
sans lui, aucune notification. Sans seuil, aucun canal n'est construit et
aucun appel reseau n'a lieu.

Module sans GTK (aucun import de gi) : testable sans interface graphique.
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

# Libelles du menu « Notifier si » : (valeur CLI, libelle). None = desactive.
THRESHOLD_CHOICES: tuple[tuple[str | None, str], ...] = (
    (None, "Pas de notification"),
    ("critique", "critique"),
    ("elevee", "élevée ou plus"),
    ("moyenne", "moyenne ou plus"),
    ("faible", "faible ou plus"),
)


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


def settings_from_widgets(
    threshold_index: int, webhook: str, slack: str, email: str, complete_detail: bool
) -> NotifySettings:
    """Reglages depuis les valeurs brutes des widgets (texte rogne, champ
    vide = canal non demande)."""
    threshold = THRESHOLD_CHOICES[threshold_index][0] if 0 <= threshold_index < len(THRESHOLD_CHOICES) else None
    return NotifySettings(
        threshold=threshold,
        webhook=webhook.strip() or None,
        slack=slack.strip() or None,
        email=email.strip() or None,
        detail="complet" if complete_detail else "resume",
    )


def validate_settings(settings: NotifySettings, security: bool) -> list[str]:
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
        errors.append("les notifications portent sur le rapport de securite : cochez « Rapport de securite »")
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
    except Exception as exc:  # noqa: BLE001 -- la GUI ne doit jamais perdre l'analyse pour une notification
        logger.exception(f"échec dans send_notifications: {exc}")
        return [DeliveryResult("notifications", STATUS_FAILED, str(exc)).to_dict()]
    lines = [res.to_dict() for res in results]
    logger.debug("send_notifications: {} ligne(s)", len(lines))
    return lines
