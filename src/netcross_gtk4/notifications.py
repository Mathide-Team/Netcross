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

Reglages et envoi : ``netcross_core.notify.request``, partage avec l'API
(issue #875). Module sans GTK (aucun import de gi).
"""

from __future__ import annotations

from netcross_core.logging_config import get_logger
from netcross_core.notify.request import NotifySettings, send_notifications, validate_settings

__all__ = ["THRESHOLD_CHOICES", "NotifySettings", "send_notifications", "settings_from_widgets", "validate_settings"]

logger = get_logger(__name__)

# Libelles du menu « Notifier si » : (valeur CLI, libelle). None = desactive.
THRESHOLD_CHOICES: tuple[tuple[str | None, str], ...] = (
    (None, "Pas de notification"),
    ("critique", "critique"),
    ("elevee", "élevée ou plus"),
    ("moyenne", "moyenne ou plus"),
    ("faible", "faible ou plus"),
)


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
