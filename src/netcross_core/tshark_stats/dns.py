"""
netcross_core.tshark_stats.dns -- adaptateur ``tshark -z dns,tree``.

Convertit les statistiques DNS en :class:`ApplicationStat`. La sortie
``dns,tree`` est un arbre de compteurs (types de requetes, codes de
reponse...) ; on normalise chaque feuille etiquette + compteur en entree
de ``metrics``.
"""

from __future__ import annotations

import re

from netcross_core.logging_config import get_logger
from netcross_core.tshark_stats.models import ApplicationStat
from netcross_core.tshark_stats.parse_utils import (
    is_filter_line,
    is_separator,
    parse_int,
)

logger = get_logger(__name__)

_LABELED_RE = re.compile(r"^\s*(.+?)\s{2,}(\d[\d,]*)\s*$")


def parse_dns_stat(text: str, application: str = "dns") -> list[ApplicationStat]:
    """Convertit la sortie ``tshark -z dns,tree`` en ApplicationStat."""
    metrics: dict[str, float] = {}
    raw: dict[str, str] = {}
    for line in text.splitlines():
        if is_separator(line) or is_filter_line(line):
            continue
        m = _LABELED_RE.match(line)
        if not m:
            continue
        label = re.sub(r"\s+", " ", m.group(1).strip()).strip().lower()
        count = parse_int(m.group(2))
        if count is None:
            continue
        metrics[label] = count
        raw[label] = m.group(2)
    if not metrics:
        logger.debug("parse_dns_stat: aucune métrique DNS trouvée")
        return []
    logger.debug("parse_dns_stat: {} métrique(s) DNS", len(metrics))
    return [
        ApplicationStat(
            application=application,
            labels={"source": "tshark -z dns,tree"},
            metrics=metrics,
            raw_fields=raw,
        )
    ]
