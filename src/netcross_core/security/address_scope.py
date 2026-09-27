"""Portee d'une adresse (interne / externe) pour les detecteurs de securite.

Issue #365 : les plages de documentation TEST-NET (RFC 5737) --
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 -- sont considerees par la
bibliotheque standard comme privees (`is_private`) et non globales
(`is_global`). Beaconing et exfiltration, qui ne regardent que les
destinations externes, restent donc muets sur une capture de
demonstration qui les utilise. `treat_test_net_as_external=True` (CLI :
`--test-net-external`) les traite comme externes. Voir docs/detectors.md.
"""

from __future__ import annotations

import ipaddress

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

TEST_NET_RANGES = (
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
)


def _parse(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        logger.debug("_parse: retour ipaddress.ip_address(…)")
        return ipaddress.ip_address(address)
    except ValueError:
        # appele pour chaque adresse de chaque paquet : niveau TRACE (NETCROSS_LOG_LEVEL=TRACE)
        logger.trace("_parse: adresse non IP {!r}", address)
        logger.debug("_parse: except ValueError -> retour None")
        return None  # adresse absente ou non IP (ARP, trame L2) : ni externe ni TEST-NET


def is_test_net(address: str) -> bool:
    """Vrai pour une adresse dans une plage TEST-NET (RFC 5737)."""
    addr = _parse(address)
    logger.debug("is_test_net: retour addr is not None and any((addr in net for net in …")
    return addr is not None and any(addr in net for net in TEST_NET_RANGES)


def is_external(address: str, *, treat_test_net_as_external: bool = False) -> bool:
    """Adresse routable sur Internet (`ipaddress.is_global`) ; les plages
    TEST-NET ne le sont que si `treat_test_net_as_external`."""
    addr = _parse(address)
    if addr is None:
        logger.debug("is_external: si addr is None -> retour False")
        return False
    if treat_test_net_as_external and any(addr in net for net in TEST_NET_RANGES):
        logger.debug("is_external: si treat_test_net_as_external and any((addr in net for net in … -> retour True")
        return True
    logger.debug("is_external: retour addr.is_global={}", summarize(addr.is_global, "is_global"))
    return addr.is_global
