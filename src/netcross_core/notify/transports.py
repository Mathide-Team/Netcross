"""
netcross_core.notify.transports -- canaux de notification (issue #280).

Protocole commun : `Notifier.send(resume) -> bool`. Un envoi qui echoue
LEVE `NotifyError` avec un motif lisible (« delai depasse », « HTTP 404 ») :
c'est le repartiteur (`dispatch.send_notifications`) qui transforme l'echec
en ligne de tracabilite, jamais en exception qui ferait echouer l'analyse.

Bibliotheque standard uniquement (`urllib.request`, `smtplib`) : aucune
dependance d'execution ajoutee.
"""

from __future__ import annotations

import json
import smtplib
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any, Protocol
from urllib.parse import urlparse

from netcross_core.logging_config import get_logger, summarize
from netcross_core.notify.summary import NotificationSummary

logger = get_logger(__name__)

DEFAULT_TIMEOUT = 10.0
_USER_AGENT = "netcross-notify/1.0"


class NotifyError(Exception):
    """Echec d'envoi, avec un motif destine au rapport."""


class Notifier(Protocol):
    name: str

    def send(self, summary: NotificationSummary) -> bool: ...


def validate_http_url(url: str) -> str:
    """Refuse tout schema autre que http(s) (pas de file://, pas de ftp://)."""
    logger.debug("validate_http_url: url={}", summarize(url, "url"))
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        logger.debug("validate_http_url: refus, ValueError")
        raise ValueError(f"URL invalide (http:// ou https:// attendu) : {url!r}")
    return url


def _reason(exc: BaseException) -> str:
    logger.debug("_reason: exc={}", summarize(exc, "exc"))
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, TimeoutError | socket.timeout):
        return "delai depasse"
    if isinstance(exc, urllib.error.URLError):
        inner = exc.reason
        if isinstance(inner, TimeoutError | socket.timeout):
            return "delai depasse"
        return f"injoignable ({inner})"
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "authentification SMTP refusee"
    if isinstance(exc, smtplib.SMTPException):
        return f"erreur SMTP ({exc.__class__.__name__})"
    if isinstance(exc, OSError):
        return f"injoignable ({exc.strerror or exc})"
    return f"{exc.__class__.__name__}: {exc}"


def _post_json(url: str, payload: dict[str, Any], timeout: float) -> None:
    request = urllib.request.Request(  # noqa: S310 -- schema valide par validate_http_url
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": _USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            if not 200 <= response.status < 300:
                raise NotifyError(f"HTTP {response.status}")
    except NotifyError:
        logger.exception("échec dans _post_json")
        raise
    except (OSError, ValueError) as exc:
        logger.exception(f"échec dans _post_json: {exc}")
        raise NotifyError(_reason(exc)) from exc


@dataclass(slots=True)
class WebhookNotifier:
    """POST JSON du resume : le plus generique (Teams via connecteur, n8n,
    PagerDuty via un relais...)."""

    url: str
    timeout: float = DEFAULT_TIMEOUT
    name: str = "webhook"

    def __post_init__(self) -> None:
        validate_http_url(self.url)

    def send(self, summary: NotificationSummary) -> bool:
        _post_json(self.url, {"source": "netcross", **summary.to_dict()}, self.timeout)
        return True


def slack_blocks(summary: NotificationSummary) -> list[dict[str, Any]]:
    """Mise en forme Block Kit du resume."""
    logger.debug("slack_blocks: summary={}", summarize(summary, "summary"))
    counts = " · ".join(f"{sev} : {summary.by_severity.get(sev, 0)}" for sev in summary.by_severity)
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": summary.title[:150]}},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Niveau :* {summary.level or 'aucun'}   *Score :* {summary.score}/100\n{counts}",
            },
        },
    ]
    if summary.top:
        lines = "\n".join(f"• *{t['severity']}* {t['category']} : {t['detail']}" for t in summary.top)
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": lines[:3000]}})
    context = f"Seuil : {summary.threshold}"
    if summary.report_path:
        context += f" · Rapport : {summary.report_path}"
    if summary.anonymized:
        context += " · adresses internes anonymisees"
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": context[:3000]}]})
    return blocks


@dataclass(slots=True)
class SlackNotifier:
    """Webhook entrant Slack, Block Kit ; si Slack refuse les blocs (HTTP
    400, `invalid_blocks`), second essai en texte seul plutot qu'aucun
    message."""

    url: str
    timeout: float = DEFAULT_TIMEOUT
    name: str = "slack"
    degraded: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        validate_http_url(self.url)

    def send(self, summary: NotificationSummary) -> bool:
        text = summary.to_text()
        try:
            _post_json(self.url, {"text": text, "blocks": slack_blocks(summary)}, self.timeout)
        except NotifyError as exc:
            logger.exception(f"échec dans send: {exc}")
            if str(exc) != "HTTP 400":
                raise
            self.degraded = True
            _post_json(self.url, {"text": text}, self.timeout)
        return True


@dataclass(slots=True)
class EmailNotifier:
    """Courriel SMTP (`smtplib`). Identifiants JAMAIS sur la ligne de
    commande : `.netcross.toml` ([notify] smtp_*) ou variables
    d'environnement `NETCROSS_SMTP_*` (voir dispatch.notifiers_from_config)."""

    host: str
    recipients: tuple[str, ...]
    sender: str
    port: int = 587
    username: str | None = None
    password: str | None = None
    starttls: bool = True
    timeout: float = DEFAULT_TIMEOUT
    name: str = "courriel"

    def __post_init__(self) -> None:
        if not self.host:
            raise ValueError("serveur SMTP manquant (smtp_host / NETCROSS_SMTP_HOST)")
        if not self.recipients:
            raise ValueError("aucun destinataire")

    def build_message(self, summary: NotificationSummary) -> EmailMessage:
        logger.debug("EmailNotifier.build_message: summary={}", summarize(summary, "summary"))
        msg = EmailMessage()
        msg["Subject"] = f"[Netcross] {summary.level or 'aucun constat'} -- score {summary.score}/100"
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(summary.to_text())
        return msg

    def send(self, summary: NotificationSummary) -> bool:
        msg = self.build_message(summary)
        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
                if self.starttls:
                    smtp.starttls(context=ssl.create_default_context())
                if self.username:
                    smtp.login(self.username, self.password or "")
                smtp.send_message(msg)
        except (OSError, smtplib.SMTPException) as exc:
            logger.exception(f"échec dans send: {exc}")
            raise NotifyError(_reason(exc)) from exc
        return True
