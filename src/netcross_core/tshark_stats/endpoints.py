"""
netcross_core.tshark_stats.endpoints -- adaptateur ``tshark -z endpoints,<proto>``.

Convertit les statistiques d'endpoints (TCP/UDP/IP...) en :class:`EndpointStat`.

Ordre des colonnes (documente par tshark(1)) : apres l'adresse, total
paquets, total octets, paquets sens 1, octets sens 1, paquets sens 2,
octets sens 2, bits/s. Le sens 1 est mappe vers ``out``, le sens 2 vers
``in`` (convention ; l'attribution exacte depend du sens de capture).
Toutes les colonnes brutes conservees dans ``raw_fields``.
"""

from __future__ import annotations

from netcross_core.logging_config import get_logger, summarize
from netcross_core.tshark_stats.models import EndpointStat
from netcross_core.tshark_stats.parse_utils import (
    data_rows,
    parse_float,
    parse_int,
    raw_fields_from,
    reconstruct_headers,
    split_fields,
)

logger = get_logger(__name__)

#: Ordre positionnel documente des colonnes numeriques d'un endpoint.
_COL_ORDER = (
    "packets_total",
    "bytes_total",
    "packets_out",
    "bytes_out",
    "packets_in",
    "bytes_in",
    "bits_per_second",
)


def parse_endpoints(text: str, protocol: str = "tcp") -> list[EndpointStat]:
    """Convertit la sortie ``tshark -z endpoints,<proto>`` en EndpointStat."""
    logger.debug("parse_endpoints: text={} protocol={}", summarize(text, "text"), summarize(protocol, "protocol"))
    headers = reconstruct_headers(text)
    out: list[EndpointStat] = []
    for line in data_rows(text):
        fields = split_fields(line)
        if len(fields) < 2:
            continue
        address = fields[0]
        numerics = fields[1:]
        attrs: dict[str, int | float | None] = {}
        for i, name in enumerate(_COL_ORDER):
            val = numerics[i] if i < len(numerics) else ""
            if name == "bits_per_second":
                attrs[name] = parse_float(val)
            else:
                attrs[name] = parse_int(val)
        out.append(
            EndpointStat(
                protocol=protocol,
                address=address,
                raw_fields=raw_fields_from(headers, fields),
                **attrs,  # type: ignore[arg-type]
            )
        )
    return out
