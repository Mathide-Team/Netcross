"""
netcross_core.tshark_stats -- adaptateurs de statistiques ``tshark -z``
(Job 19 / issue #20, section 6.19 de features-backlog.md).

Sous-package de wrappers ciblés pour les statistiques tshark reutilisables :
conversations, endpoints, hierarchie protocolaire, I/O temporel, HTTP, DNS,
temps de reponse. Chaque adaptateur convertit la sortie texte ``tshark -z``
vers le modele commun (:mod:`models`) -- des statistiques AGREGEES, distinctes
des objets per-paquet du moteur (``Flow`` / ``Conversation`` / ``ExpertEvent``).

Les parsers sont des fonctions pures testables sans tshark (fixtures texte) ;
le runner (:mod:`runner`) n'invoque tshark qu'a l'appel effectif.
"""

from __future__ import annotations

from pathlib import Path

from netcross_core.logging_config import get_logger
from netcross_core.tshark_stats.conversations import parse_conversations
from netcross_core.tshark_stats.dns import parse_dns_stat
from netcross_core.tshark_stats.endpoints import parse_endpoints
from netcross_core.tshark_stats.http import parse_http_stat
from netcross_core.tshark_stats.io_stat import parse_io_stat
from netcross_core.tshark_stats.models import (
    ApplicationStat,
    ConversationStat,
    EndpointStat,
    MetricPoint,
    MetricSeries,
    ProtocolHierarchyStat,
    ResponseTimeStat,
)
from netcross_core.tshark_stats.protocol_hierarchy import parse_protocol_hierarchy
from netcross_core.tshark_stats.response_time import parse_response_time
from netcross_core.tshark_stats.runner import (
    TsharkUnavailableError,
    run_tshark_stat,
)

logger = get_logger(__name__)

__all__ = [
    "ApplicationStat",
    "ConversationStat",
    "EndpointStat",
    "MetricPoint",
    "MetricSeries",
    "ProtocolHierarchyStat",
    "ResponseTimeStat",
    "TsharkUnavailableError",
    "collect_conversations",
    "collect_endpoints",
    "collect_io_stat",
    "collect_protocol_hierarchy",
    "parse_conversations",
    "parse_dns_stat",
    "parse_endpoints",
    "parse_http_stat",
    "parse_io_stat",
    "parse_protocol_hierarchy",
    "parse_response_time",
    "run_tshark_stat",
]


def collect_conversations(capture_path: str | Path, protocol: str = "tcp") -> list[ConversationStat]:
    """Lance ``tshark -z conv,<proto>`` sur la capture et parse le resultat."""
    text = run_tshark_stat(capture_path, f"conv,{protocol}")
    result = parse_conversations(text, protocol=protocol)
    logger.debug("collect_conversations: {} conversation(s) {}", len(result), protocol)
    return result


def collect_endpoints(capture_path: str | Path, protocol: str = "tcp") -> list[EndpointStat]:
    text = run_tshark_stat(capture_path, f"endpoints,{protocol}")
    result = parse_endpoints(text, protocol=protocol)
    logger.debug("collect_endpoints: {} endpoint(s) {}", len(result), protocol)
    return result


def collect_protocol_hierarchy(
    capture_path: str | Path,
) -> list[ProtocolHierarchyStat]:
    text = run_tshark_stat(capture_path, "io,phs")
    result = parse_protocol_hierarchy(text)
    logger.debug("collect_protocol_hierarchy: {} protocole(s)", len(result))
    return result


def collect_io_stat(capture_path: str | Path, interval: float = 1.0, name: str = "io_stat") -> MetricSeries:
    text = run_tshark_stat(capture_path, f"io,stat,{interval}")
    result = parse_io_stat(text, name=name)
    logger.debug("collect_io_stat: {} point(s) de mesure", len(result.points))
    return result
