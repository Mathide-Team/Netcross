"""
netcross_core.tshark_stats.response_time -- adaptateur ``tshark -z <proto>,rtt``.

Convertit les statistiques de temps de reponse applicatif (ex:
``http,rtt``, ``dns,rtt``) en :class:`ResponseTimeStat`. La sortie tshark
presente typiquement un compte, un min, un max et une moyenne ; on mappe
ces valeurs par mot-cle, toutes conservees dans ``raw_fields``.
"""

from __future__ import annotations

import re

from netcross_core.logging_config import get_logger, summarize
from netcross_core.tshark_stats.models import ResponseTimeStat
from netcross_core.tshark_stats.parse_utils import (
    is_filter_line,
    is_separator,
    parse_float,
)

logger = get_logger(__name__)

#: Ligne "etiquette .... nombre" avec unite optionnelle (ms, s...).
_LABELED_RE = re.compile(r"^\s*(.+?)\s{2,}([\d.,]+)\s*$")


def _match(label: str, *keywords: str) -> bool:
    low = label.lower()
    logger.debug("_match: retour any(…)")
    return any(kw in low for kw in keywords)


def parse_response_time(text: str, application: str = "http") -> ResponseTimeStat | None:
    """Convertit la sortie ``tshark -z <proto>,rtt`` en ResponseTimeStat.

    Retourne None si aucune metrique identifiable.
    """
    logger.debug(
        "parse_response_time: text={} application={}",
        summarize(text, "text"),
        summarize(application, "application"),
    )
    count = min_ms = max_ms = mean_ms = median_ms = None
    raw: dict[str, str] = {}
    for line in text.splitlines():
        if is_separator(line) or is_filter_line(line):
            continue
        m = _LABELED_RE.match(line)
        if not m:
            continue
        label = re.sub(r"\s+", " ", m.group(1).strip()).strip()
        val = parse_float(m.group(2))
        if val is None:
            continue
        raw[label.lower()] = m.group(2)
        if _match(label, "count", "requests", "total") and "replies" not in label.lower():
            count = int(val)
        elif _match(label, "min"):
            min_ms = val
        elif _match(label, "max"):
            max_ms = val
        elif _match(label, "mean", "average", "avg"):
            mean_ms = val
        elif _match(label, "median"):
            median_ms = val
    if not any(v is not None for v in (count, min_ms, max_ms, mean_ms, median_ms)):
        logger.debug("parse_response_time: aucune métrique trouvée pour {}", application)
        return None
    logger.debug(
        "parse_response_time: {} -> count={}, min={}ms, max={}ms, mean={}ms",
        application,
        count,
        min_ms,
        max_ms,
        mean_ms,
    )
    return ResponseTimeStat(
        application=application,
        count=count,
        min_ms=min_ms,
        max_ms=max_ms,
        mean_ms=mean_ms,
        median_ms=median_ms,
        raw_fields=raw,
    )
