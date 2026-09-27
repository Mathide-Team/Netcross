"""
netcross_core.notify.summary -- resume d'analyse a notifier (issue #280).

Une notification par ANALYSE, jamais par constat : 400 retransmissions ne
produisent pas 400 messages. Le resume porte le score, le niveau, les
compteurs par severite, les trois pires constats et le chemin du rapport.

Une notification traverse un service tiers (Slack, un relais SMTP, un
webhook) : par defaut (`detail="resume"`), le texte des constats et le
chemin du rapport passent par `support.scrubber.TextScrubber` (IP, MAC,
FQDN, courriels, URL, repertoires personnels pseudonymises, secrets
rediges), et les champs structures (hote, port, source, banniere) ne sont
JAMAIS copies. `detail="complet"` assume explicitement l'inverse.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from netcross_core.logging_config import get_logger, summarize
from netcross_core.support.scrubber import TextScrubber

logger = get_logger(__name__)

SEVERITIES = ("critique", "elevee", "moyenne", "faible")
DETAIL_LEVELS = ("resume", "complet")
TOP_FINDINGS = 3
MAX_DETAIL_CHARS = 200

# Parties variables d'un constat d'une analyse a l'autre, sans changer le
# probleme : un compteur d'occurrences, un numero de trame.
_VOLATILE = re.compile(r"\b\d+ occurrences?\b|\btrames? \d+\b")


def severity_rank(severity: str | None) -> int:
    """0 = critique ... 3 = faible ; severite inconnue -> apres faible."""
    try:
        return SEVERITIES.index(str(severity).lower())
    except ValueError:
        logger.exception("échec dans severity_rank")
        return len(SEVERITIES)


def meets_threshold(severity: str | None, threshold: str) -> bool:
    """Vrai si `severity` est au moins aussi grave que `threshold`."""
    result = severity_rank(severity) <= severity_rank(threshold)
    logger.debug("meets_threshold: severity={} threshold={} -> {}", severity, threshold, result)
    return result


def finding_key(finding: Mapping[str, Any]) -> str:
    """Identite stable d'un constat (pour l'anti-repetition)."""
    detail = _VOLATILE.sub("", str(finding.get("detail") or "")).strip()
    parts = [
        str(finding.get(k) or "") for k in ("severity", "category", "cve_id", "signature_id", "host", "port", "point")
    ]
    key = "|".join([*parts, detail])
    logger.debug("finding_key: {}", key)
    return key


def findings_fingerprint(findings: Iterable[Mapping[str, Any]]) -> str:
    """Empreinte SHA-256 du LOT de constats, independante de leur ordre et
    des compteurs volatils : deux analyses de la meme capture -- ou une tache
    planifiee qui retrouve le meme probleme toutes les heures -- donnent la
    meme empreinte."""
    logger.debug("findings_fingerprint: findings={}", summarize(findings, "findings"))
    keys = sorted({finding_key(f) for f in findings})
    return hashlib.sha256(json.dumps(keys, ensure_ascii=False).encode("utf-8")).hexdigest()


@dataclass(slots=True)
class NotificationSummary:
    score: int
    level: str | None
    threshold: str
    by_severity: dict[str, int]
    total: int
    top: list[dict[str, str]]
    report_path: str | None
    fingerprint: str
    detail: str = "resume"
    anonymized: bool = True
    title: str = field(default="Netcross -- analyse de securite")

    def to_dict(self) -> dict[str, Any]:
        result = {
            "title": self.title,
            "score": self.score,
            "level": self.level,
            "threshold": self.threshold,
            "by_severity": dict(self.by_severity),
            "total": self.total,
            "top": [dict(t) for t in self.top],
            "report_path": self.report_path,
            "fingerprint": self.fingerprint,
            "detail": self.detail,
            "anonymized": self.anonymized,
        }
        logger.debug("to_dict: total={} fingerprint={}", self.total, self.fingerprint)
        return result

    def to_text(self) -> str:
        logger.debug("NotificationSummary.to_text()")
        counts = ", ".join(f"{sev}={self.by_severity.get(sev, 0)}" for sev in SEVERITIES)
        lines = [
            f"{self.title} : niveau {self.level or 'aucun'}, score {self.score}/100",
            f"{self.total} constat(s) ({counts}) -- seuil de notification : {self.threshold}",
        ]
        if self.top:
            lines.append("Pires constats :")
            lines += [f"- [{t['severity']}] {t['category']} : {t['detail']}" for t in self.top]
        if self.report_path:
            lines.append(f"Rapport : {self.report_path}")
        if self.anonymized:
            lines.append("(adresses et noms internes anonymises)")
        result = "\n".join(lines)
        logger.debug("to_text: {} ligne(s)", len(lines))
        return result


def _top_detail(finding: Mapping[str, Any], scrubber: TextScrubber | None) -> str:
    if finding.get("category") == "cve" and finding.get("cve_id"):
        # l'identifiant et le score suffisent ; la description NVD n'apporte
        # rien a une alerte et peut citer le produit/la version exacts
        cvss = finding.get("cvss")
        text = f"{finding['cve_id']}" + (f" (CVSS {cvss})" if cvss is not None else "")
    else:
        text = str(finding.get("detail") or "")
    if scrubber is not None:
        text = scrubber.scrub(text)[0] or ""
    if len(text) > MAX_DETAIL_CHARS:
        text = text[: MAX_DETAIL_CHARS - 3] + "..."
    logger.debug("_top_detail: longueur={}", len(text))
    return text


def build_summary(
    findings: Iterable[Mapping[str, Any]],
    *,
    score: int,
    level: str | None,
    threshold: str,
    report_path: str | None = None,
    detail: str = "resume",
) -> NotificationSummary:
    """Construit le resume a notifier.

    `score`/`level` viennent du tableau de bord du rapport de securite (un
    seul calcul du score dans le projet, pas une seconde formule ici).
    L'empreinte ne porte que sur les constats AU-DESSUS du seuil : un
    constat faible qui change ne doit pas re-notifier une alerte critique."""
    if threshold not in SEVERITIES:
        logger.trace("build_summary: refus, ValueError")
        raise ValueError(f"seuil inconnu : {threshold!r} (attendu : {', '.join(SEVERITIES)})")
    if detail not in DETAIL_LEVELS:
        logger.trace("build_summary: refus, ValueError")
        raise ValueError(f"niveau de detail inconnu : {detail!r} (attendu : {', '.join(DETAIL_LEVELS)})")
    items = list(findings)
    by_severity = dict.fromkeys(SEVERITIES, 0)
    for f in items:
        sev = str(f.get("severity") or "").lower()
        if sev in by_severity:
            by_severity[sev] += 1
    relevant = [f for f in items if meets_threshold(f.get("severity"), threshold)]
    scrubber = TextScrubber() if detail == "resume" else None
    worst = sorted(relevant, key=lambda f: (severity_rank(f.get("severity")), -float(f.get("cvss") or 0)))
    top = [
        {
            "severity": str(f.get("severity") or ""),
            "category": str(f.get("category") or ""),
            "detail": _top_detail(f, scrubber),
        }
        for f in worst[:TOP_FINDINGS]
    ]
    path = report_path
    if path and scrubber is not None:
        path = scrubber.scrub(path)[0]
    summary = NotificationSummary(
        score=score,
        level=level,
        threshold=threshold,
        by_severity=by_severity,
        total=len(items),
        top=top,
        report_path=path,
        fingerprint=findings_fingerprint(relevant),
        detail=detail,
        anonymized=scrubber is not None,
    )
    logger.debug("build_summary: total={} top={} fingerprint={}", len(items), len(top), summary.fingerprint)
    return summary
