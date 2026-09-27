"""
netcross_core.notify.dispatch -- repartition, garde-fous et tracabilite
des notifications (issue #280).

Un outil qui notifie trop est un outil qu'on coupe. Trois garde-fous,
dans cet ordre :

1. **seuil explicite** : sans `threshold`, `run_notifications` rend la main
   immediatement -- aucun canal construit, aucun appel reseau ;
2. **une notification par analyse** : un seul resume (voir summary.py) ;
3. **anti-repetition** : l'empreinte du lot de constats est memorisee dans
   un petit fichier d'etat ; le meme lot n'est pas re-notifie pendant la
   fenetre de silence. L'etat n'est enregistre que si AU MOINS un canal a
   reussi : apres un echec total, l'analyse suivante reessaie.

Un canal en echec ne fait JAMAIS echouer l'analyse : l'echec est journalise
en WARNING et rendu comme une ligne de tracabilite (« notification slack :
echec, delai depasse ») destinee au rapport. Un envoi silencieusement rate
est pire que pas d'envoi : on croit etre prevenu.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netcross_core.config import NotifyConfig
from netcross_core.logging_config import get_logger, summarize
from netcross_core.notify.summary import NotificationSummary, meets_threshold
from netcross_core.notify.transports import EmailNotifier, Notifier, SlackNotifier, WebhookNotifier

logger = get_logger(__name__)

CHANNELS = ("webhook", "slack", "courriel")
DEFAULT_SILENCE_HOURS = 24.0
DEFAULT_STATE_PATH = Path.home() / ".cache" / "netcross" / "notify-state.json"
_MAX_STATE_ENTRIES = 500

STATUS_SENT = "envoye"
STATUS_FAILED = "echec"
STATUS_NOT_CONFIGURED = "non_configure"
STATUS_SILENCED = "silence"
STATUS_BELOW_THRESHOLD = "sous_le_seuil"

_STATUS_LABELS = {
    STATUS_SENT: "envoyee",
    STATUS_FAILED: "echec",
    STATUS_NOT_CONFIGURED: "non configuree",
    STATUS_SILENCED: "non envoyee (anti-repetition)",
    STATUS_BELOW_THRESHOLD: "non envoyee (sous le seuil)",
}


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    channel: str
    status: str
    reason: str | None = None

    def line(self) -> str:
        text = f"notification {self.channel} : {_STATUS_LABELS.get(self.status, self.status)}"
        return f"{text}, {self.reason}" if self.reason else text

    def to_dict(self) -> dict[str, Any]:
        return {"channel": self.channel, "status": self.status, "reason": self.reason, "line": self.line()}


# -- etat anti-repetition ------------------------------------------------------


def _load_state(path: Path) -> dict[str, float]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.exception("échec dans _load_state")
        return {}
    except (OSError, ValueError) as exc:
        logger.warning("notification : etat anti-repetition illisible ({}), ignore : {}", path, exc)
        return {}
    if not isinstance(data, dict):
        logger.debug("_load_state: format inattendu, ignore")
        return {}
    result = {str(k): float(v) for k, v in data.items() if isinstance(v, int | float)}
    logger.debug("_load_state: {} entree(s)", len(result))
    return result


def _save_state(path: Path, state: dict[str, float]) -> None:
    newest = dict(sorted(state.items(), key=lambda kv: kv[1], reverse=True)[:_MAX_STATE_ENTRIES])
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(newest, indent=0, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        # jamais bloquant, mais dit : la prochaine analyse re-notifiera
        logger.warning("notification : etat anti-repetition non enregistre ({}) : {}", path, exc)


def is_silenced(fingerprint: str, state_path: Path, silence_seconds: float, now: float) -> float | None:
    """Age (s) de la derniere notification du meme lot si elle est dans la
    fenetre de silence, sinon None."""
    logger.debug(
        "is_silenced: fingerprint={} state_path={} silence_seconds={} now={}",
        summarize(fingerprint, "fingerprint"),
        summarize(state_path, "state_path"),
        summarize(silence_seconds, "silence_seconds"),
        summarize(now, "now"),
    )
    if silence_seconds <= 0:
        logger.debug("is_silenced: silence desactive")
        return None
    last = _load_state(state_path).get(fingerprint)
    if last is None or now - last >= silence_seconds:
        logger.debug("is_silenced: non silencieux (last={})", last)
        return None
    age = max(0.0, now - last)
    logger.debug("is_silenced: silencieux, age={:.1f}s", age)
    return age


def _fmt_age(seconds: float) -> str:
    if seconds < 3600:
        result = f"{int(seconds // 60)} min"
        logger.debug("_fmt_age: {}s -> {}", seconds, result)
        return result
    result = f"{seconds / 3600:.1f} h"
    logger.debug("_fmt_age: {}s -> {}", seconds, result)
    return result


# -- envoi ---------------------------------------------------------------------


def _deliver(notifier: Notifier, summary: NotificationSummary) -> DeliveryResult:
    try:
        notifier.send(summary)
    except Exception as exc:  # noqa: BLE001 -- un canal ne fait jamais echouer l'analyse
        reason = str(exc) or exc.__class__.__name__
        logger.warning("notification {} : echec, {}", notifier.name, reason)
        return DeliveryResult(notifier.name, STATUS_FAILED, reason)
    degraded = getattr(notifier, "degraded", False)
    result = DeliveryResult(notifier.name, STATUS_SENT, "texte seul (blocs refuses)" if degraded else None)
    logger.debug("_deliver: canal={} status={}", notifier.name, result.status)
    return result


def send_notifications(
    summary: NotificationSummary,
    notifiers: Sequence[Notifier],
    *,
    state_path: Path = DEFAULT_STATE_PATH,
    silence_seconds: float = DEFAULT_SILENCE_HOURS * 3600,
    now: float | None = None,
) -> list[DeliveryResult]:
    """Envoie le resume a chaque canal ; ne leve jamais."""
    now = time.time() if now is None else now
    if not meets_threshold(summary.level, summary.threshold):
        reason = f"niveau {summary.level or 'aucun'} < seuil {summary.threshold}"
        logger.debug("send_notifications: sous le seuil, {} canal/aux ignore(s)", len(notifiers))
        return [DeliveryResult(n.name, STATUS_BELOW_THRESHOLD, reason) for n in notifiers]
    age = is_silenced(summary.fingerprint, state_path, silence_seconds, now)
    if age is not None:
        reason = f"meme lot de constats deja notifie il y a {_fmt_age(age)}"
        logger.info("notification : {}", reason)
        return [DeliveryResult(n.name, STATUS_SILENCED, reason) for n in notifiers]
    results = [_deliver(notifier, summary) for notifier in notifiers]
    if any(r.status == STATUS_SENT for r in results):
        state = _load_state(state_path)
        state[summary.fingerprint] = now
        _save_state(state_path, state)
    logger.debug("send_notifications: {} resultat(s)", len(results))
    return results


def notifiers_from_config(
    cfg: NotifyConfig,
    *,
    webhook: str | None = None,
    slack: str | None = None,
    email_to: str | None = None,
    env: dict[str, str] | None = None,
) -> tuple[list[Notifier], list[DeliveryResult]]:
    """Construit les canaux : ligne de commande > variables d'environnement
    > `.netcross.toml`. Renvoie aussi une ligne `non_configure` par canal
    absent, et `echec` pour un canal mal configure (URL invalide, SMTP sans
    serveur) -- la configuration defaillante est dite, pas ignoree."""
    env = dict(os.environ) if env is None else env
    notifiers: list[Notifier] = []
    lines: list[DeliveryResult] = []

    webhook_url = webhook or env.get("NETCROSS_NOTIFY_WEBHOOK") or cfg.webhook
    slack_url = slack or env.get("NETCROSS_SLACK_WEBHOOK") or cfg.slack_webhook
    recipients_raw = email_to or env.get("NETCROSS_NOTIFY_EMAIL") or cfg.email_to

    def _try(channel: str, factory: Any) -> None:
        try:
            notifiers.append(factory())
        except ValueError as exc:
            logger.exception(f"échec dans _try: {exc}")
            lines.append(DeliveryResult(channel, STATUS_FAILED, f"configuration invalide : {exc}"))

    if webhook_url:
        _try("webhook", lambda: WebhookNotifier(webhook_url))
    else:
        lines.append(DeliveryResult("webhook", STATUS_NOT_CONFIGURED))
    if slack_url:
        _try("slack", lambda: SlackNotifier(slack_url))
    else:
        lines.append(DeliveryResult("slack", STATUS_NOT_CONFIGURED))
    if recipients_raw:
        recipients = tuple(r.strip() for r in recipients_raw.split(",") if r.strip())
        port_raw = env.get("NETCROSS_SMTP_PORT")
        _try(
            "courriel",
            lambda: EmailNotifier(
                host=env.get("NETCROSS_SMTP_HOST") or cfg.smtp_host,
                recipients=recipients,
                sender=env.get("NETCROSS_SMTP_FROM") or cfg.smtp_from or "netcross@localhost",
                port=int(port_raw) if port_raw else cfg.smtp_port,
                username=env.get("NETCROSS_SMTP_USER") or cfg.smtp_user or None,
                password=env.get("NETCROSS_SMTP_PASSWORD") or cfg.smtp_password or None,
                starttls=cfg.smtp_starttls,
            ),
        )
    else:
        lines.append(DeliveryResult("courriel", STATUS_NOT_CONFIGURED))
    logger.debug("notifiers_from_config: {} canal/aux configure(s), {} ligne(s)", len(notifiers), len(lines))
    return notifiers, lines


def run_notifications(
    summary_factory: Any,
    *,
    threshold: str | None,
    cfg: NotifyConfig,
    webhook: str | None = None,
    slack: str | None = None,
    email_to: str | None = None,
    state_path: Path | None = None,
    silence_hours: float | None = None,
    env: dict[str, str] | None = None,
) -> list[DeliveryResult]:
    """Point d'entree de la CLI. `summary_factory(threshold)` construit le
    resume -- il n'est meme pas construit sans seuil.

    Sans seuil : liste vide, AUCUN canal construit, aucun appel reseau."""
    logger.debug(
        "run_notifications: summary_factory={} threshold={} cfg={} webhook={} slack={} email_to={} "
        "state_path={} silence_hours={} env={}",
        summarize(summary_factory, "summary_factory"),
        summarize(threshold, "threshold"),
        summarize(cfg, "cfg"),
        summarize(webhook, "webhook"),
        summarize(slack, "slack"),
        summarize(email_to, "email_to"),
        summarize(state_path, "state_path"),
        summarize(silence_hours, "silence_hours"),
        summarize(env, "env"),
    )
    if not threshold:
        logger.debug("run_notifications: aucun seuil, retour vide")
        return []
    notifiers, lines = notifiers_from_config(cfg, webhook=webhook, slack=slack, email_to=email_to, env=env)
    if not notifiers:
        logger.debug("run_notifications: aucun canal configure")
        return lines
    summary = summary_factory(threshold)
    hours = cfg.silence_hours if silence_hours is None else silence_hours
    path = state_path or (Path(cfg.state_path).expanduser() if cfg.state_path else DEFAULT_STATE_PATH)
    results = send_notifications(summary, notifiers, state_path=path, silence_seconds=hours * 3600)
    order = {c: i for i, c in enumerate(CHANNELS)}
    merged = sorted(results + lines, key=lambda r: order.get(r.channel, len(order)))
    logger.debug("run_notifications: {} resultat(s) final(aux)", len(merged))
    return merged
