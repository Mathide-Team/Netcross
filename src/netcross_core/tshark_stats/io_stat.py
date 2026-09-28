"""
netcross_core.tshark_stats.io_stat -- adaptateur ``tshark -z io,stat``.

Convertit les statistiques I/O temporelles (``tshark -q -z io,stat,<interval>``)
en :class:`MetricSeries`. Chaque intervalle temporel donne un
:class:`MetricPoint` (start, end, valeurs nommees : frames, bytes...).

Les colonnes sont mappees par mot-cle sur l'en-tete reconstruit ; les
intervalles sont detectes par leur motif ``debut-fin``.
"""

from __future__ import annotations

import re

from netcross_core.logging_config import get_logger, summarize
from netcross_core.tshark_stats.models import MetricPoint, MetricSeries
from netcross_core.tshark_stats.parse_utils import (
    is_filter_line,
    is_separator,
    parse_float,
    reconstruct_headers,
    split_fields,
)

logger = get_logger(__name__)

#: Motif d'un intervalle temporel tshark : ``000.000-001.000`` ou
#: ``000.000-`` (intervalle ouvert, derniere ligne).
_INTERVAL_RE = re.compile(r"(\d+(?:\.\d+)?)\s*-\s*(\d+(?:\.\d+)?)?")


def parse_io_stat(text: str, name: str = "io_stat") -> MetricSeries:
    """Convertit la sortie ``tshark -z io,stat`` en MetricSeries.

    Les valeurs nommees sont tirees des en-tetes de colonnes (frames,
    bytes...) quand elles sont reconnaissables ; sinon ``value_0``,
    ``value_1``... Retourne une serie vide si aucun intervalle n'est
    trouve.
    """
    logger.debug("parse_io_stat: text={} name={}", summarize(text, "text"), summarize(name, "name"))
    headers = reconstruct_headers(text)
    # En-tete des colonnes de valeurs (hors colonne "time").
    value_headers = [h for h in headers if h and "time" not in h]
    points: list[MetricPoint] = []
    for line in text.splitlines():
        if is_separator(line) or is_filter_line(line):
            continue
        m = _INTERVAL_RE.search(line)
        if not m:
            continue
        start = parse_float(m.group(1))
        end = parse_float(m.group(2)) if m.group(2) is not None else None
        # Valeurs numeriques apres l'intervalle : on les extrait par champ
        # si la ligne est pipe-delimmitee, sinon par tokens.
        # Chaque candidat est conserve avec sa valeur numerique deja parsee :
        # seuls les champs convertibles en float sont retenus ici, donc la
        # boucle finale n'a plus de cas "non numerique" a ecarter.
        fields = split_fields(line)
        if fields:
            vals = [(f, p) for f in fields if (p := parse_float(f)) is not None]
        else:
            vals = [(t, p) for t in line.split() if (p := parse_float(t)) is not None]
        # Retire les bornes de l'intervalle elles-memes.
        bounds = {m.group(1)}
        if m.group(2) is not None:
            bounds.add(m.group(2))
        numbers = [p for raw, p in vals if raw not in bounds]
        values: dict[str, float] = {}
        for i, parsed in enumerate(numbers):
            key = value_headers[i] if i < len(value_headers) else f"value_{i}"
            values[key] = parsed
        points.append(MetricPoint(start=start, end=end, values=values))
    logger.debug("parse_io_stat: {} point(s) de mesure", len(points))
    return MetricSeries(name=name, points=tuple(points))
