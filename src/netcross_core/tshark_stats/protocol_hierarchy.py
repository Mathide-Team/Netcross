"""
netcross_core.tshark_stats.protocol_hierarchy -- adaptateur ``tshark -z io,phs``.

Convertit la hierarchie protocolaire en :class:`ProtocolHierarchyStat`.
La sortie ``io,phs`` est un arbre aligne par espaces (indentation = profondeur),
sans delimitateurs ``|`` : on parse l'indentation et les deux derniers tokens
numeriques (frames, bytes).
"""

from __future__ import annotations

import re

from netcross_core.logging_config import get_logger, summarize
from netcross_core.tshark_stats.models import ProtocolHierarchyStat
from netcross_core.tshark_stats.parse_utils import (
    is_filter_line,
    is_separator,
    parse_int,
)

logger = get_logger(__name__)

#: Indentation par niveau dans la sortie io,phs (espaces).
_INDENT = 4

_DATA_RE = re.compile(r"\d")


def parse_protocol_hierarchy(text: str) -> list[ProtocolHierarchyStat]:
    """Convertit la sortie ``tshark -z io,phs`` en ProtocolHierarchyStat."""
    # Indentation minimale observee parmi les lignes de donnees -> niveau 0.
    logger.debug("parse_protocol_hierarchy: text={}", summarize(text, "text"))
    data: list[tuple[int, str, list[str]]] = []
    for line in text.splitlines():
        if is_separator(line) or is_filter_line(line):
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if "Hierarchy" in stripped or "Filter" in stripped:
            continue
        tokens = stripped.split()
        # Une ligne de donnees contient au moins un protocole + un chiffre.
        if len(tokens) < 2 or not _DATA_RE.search(stripped):
            continue
        leading = len(line) - len(line.lstrip())
        data.append((leading, tokens[0], tokens[1:]))
    if not data:
        return []
    base = min(leading for leading, _, _ in data)
    out: list[ProtocolHierarchyStat] = []
    for leading, proto, rest in data:
        depth = max(0, (leading - base) // _INDENT)
        # io,phs ne contient que des compteurs entiers (frames, bytes).
        frame_count = parse_int(rest[0]) if rest else None
        byte_count = parse_int(rest[-1]) if len(rest) >= 2 else None
        out.append(
            ProtocolHierarchyStat(
                protocol=proto,
                depth=depth,
                frame_count=frame_count,
                byte_count=byte_count,
            )
        )
    logger.debug("parse_protocol_hierarchy: {} protocole(s)", len(out))
    return out
