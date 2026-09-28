"""
netcross_core.tshark_stats.conversations -- adaptateur ``tshark -z conv,<proto>``.

Parse les statistiques de conversations (TCP/UDP/IP...) produites par
``tshark -q -r <capture> -z conv,<proto>`` et les convertit en
:class:`ConversationStat`.

Ordre des colonnes (documente par la page de manuel tshark(1), stable entre
versions) : apres les deux adresses combinees dans le premier champ, la ligne
contient, dans l'ordre : frames A->B, bytes A->B, frames B->A, bytes B->A,
total frames, total bytes, debut relatif, duree, bits/s. Toutes les colonnes
brutes sont egalement conservees dans ``raw_fields`` (en-tete reconstruit
quand il est disponible) pour absorber d'eventuelles variations.
"""

from __future__ import annotations

from netcross_core.logging_config import get_logger
from netcross_core.tshark_stats.models import ConversationStat
from netcross_core.tshark_stats.parse_utils import (
    data_rows,
    parse_float,
    parse_int,
    raw_fields_from,
    reconstruct_headers,
    split_fields,
)

logger = get_logger(__name__)


def _split_endpoints(field: str) -> tuple[str, str]:
    """Separe le premier champ (adresses A et B combinees) en deux."""
    tokens = field.split()
    if len(tokens) >= 2:
        logger.debug("_split_endpoints: si len(tokens) >= 2 -> retour tuple de 2")
        return tokens[0], tokens[-1]
    logger.debug("_split_endpoints: retour tuple de 2")
    return (field, "")


#: Ordre positionnel documente des colonnes numeriques d'une conversation.
_COL_ORDER = (
    "packets_ab",
    "bytes_ab",
    "packets_ba",
    "bytes_ba",
    "packets_total",
    "bytes_total",
    "rel_start",
    "duration",
    "bits_per_second",
)


def parse_conversations(text: str, protocol: str = "tcp") -> list[ConversationStat]:
    """Convertit la sortie ``tshark -z conv,<proto>`` en ConversationStat.

    ``protocol`` est le protocole demande (tcp/udp/ip...) -- reporte tel
    quel sur chaque record. Retourne une liste vide si la sortie ne
    contient pas de tableau exploitable.
    """
    headers = reconstruct_headers(text)
    out: list[ConversationStat] = []
    for line in data_rows(text):
        # data_rows ne rend que des lignes d'au moins deux champs.
        fields = split_fields(line)
        endpoint_a, endpoint_b = _split_endpoints(fields[0])
        # Numeriques apres le champ d'adresses, dans l'ordre documente.
        numerics = fields[1:]
        attrs: dict[str, int | float | None] = {}
        for i, name in enumerate(_COL_ORDER):
            val = numerics[i] if i < len(numerics) else ""
            if name in ("rel_start", "duration", "bits_per_second"):
                attrs[name] = parse_float(val)
            else:
                attrs[name] = parse_int(val)
        out.append(
            ConversationStat(
                protocol=protocol,
                endpoint_a=endpoint_a,
                endpoint_b=endpoint_b,
                raw_fields=raw_fields_from(headers, fields),
                **attrs,  # type: ignore[arg-type]
            )
        )
    logger.debug("parse_conversations: {} conversation(s) {}", len(out), protocol)
    return out
