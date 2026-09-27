"""
netcross_core.tshark_stats.http -- adaptateur ``tshark -z http,stat``.

Convertit les statistiques HTTP en :class:`ApplicationStat`. La sortie
``http,stat`` liste les methodes de requete et les codes de reponse avec
leurs comptes ; on normalise chaque ligne etiquette + compteur en entree
de ``metrics`` (ex: ``{"GET": 12, "200": 30, "404": 2}``), toutes les
lignes brutes conservees dans ``raw_fields``.
"""

from __future__ import annotations

import re

from netcross_core.logging_config import get_logger, summarize
from netcross_core.tshark_stats.models import ApplicationStat
from netcross_core.tshark_stats.parse_utils import (
    is_filter_line,
    is_separator,
    parse_int,
)

logger = get_logger(__name__)

#: Ligne "etiquette .... nombre" (ex: "GET requests            12").
_LABELED_RE = re.compile(r"^\s*(.+?)\s{2,}(\d[\d,]*)\s*$")


def parse_http_stat(text: str, application: str = "http") -> list[ApplicationStat]:
    """Convertit la sortie ``tshark -z http,stat`` en ApplicationStat.

    Retourne une liste (typiquement un seul record agregeant les
    metriques) ; vide si aucune metrique identifiable.
    """
    logger.debug(
        "parse_http_stat: text={} application={}",
        summarize(text, "text"),
        summarize(application, "application"),
    )
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
        return []
    return [
        ApplicationStat(
            application=application,
            labels={"source": "tshark -z http,stat"},
            metrics=metrics,
            raw_fields=raw,
        )
    ]
