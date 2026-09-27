"""
netcross_core.application.http -- construction de transactions HTTP a
partir des paquets (Job 23, §6.10).

Apparie requêtes et réponses HTTP sur un même flux TCP (même 5-tuple
directionnel) en FIFO. Une requête sans réponse devient une transaction
avec classification missing_response.
"""

from __future__ import annotations

from collections import defaultdict, deque

from netcross_core.application.models import ApplicationTransaction
from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt

logger = get_logger(__name__)


def _flow_key(pkt: Pkt) -> tuple[str, str, int | None, int | None]:
    """Clé directionnelle client -> serveur pour apparier HTTP."""
    logger.debug("_flow_key: retour tuple")
    return (pkt.src, pkt.dst, pkt.sport, pkt.dport)


def _reverse_flow_key(pkt: Pkt) -> tuple[str, str, int | None, int | None]:
    """Clé inverse serveur -> client pour trouver la requête correspondante."""
    logger.debug("_reverse_flow_key: retour tuple")
    return (pkt.dst, pkt.src, pkt.dport, pkt.sport)


def build_http_transactions(
    packets: list[Pkt],
    network_signals: dict[tuple[str, str, int | None, int | None], list[str]] | None = None,
) -> list[ApplicationTransaction]:
    """Construit les transactions HTTP en apparieant requêtes et réponses.

    Stratégie : FIFO par flux. Chaque requête (http_is_request) est mise
    en attente ; chaque réponse (http_is_response) dépile la plus ancienne
    requête du flux inverse. Les requêtes non servies deviennent des
    transactions missing_response.

    Args:
        packets: liste triée par timestamp croissant.
        network_signals: signaux TCP par flux (clé = 5-tuple directionnel),
            injectés par analyse.py depuis les expert_flags. Si None, vide.
    """
    if network_signals is None:
        network_signals = {}

    pending: dict[tuple[str, str, int | None, int | None], deque[Pkt]] = defaultdict(deque)
    transactions: list[ApplicationTransaction] = []

    for pkt in packets:
        if pkt.proto != "TCP":
            continue
        if pkt.http_is_request:
            key = _flow_key(pkt)
            pending[key].append(pkt)
        elif pkt.http_is_response:
            # La réponse vient du serveur -> le flux inverse est la requête
            req_key = _reverse_flow_key(pkt)
            queue = pending.get(req_key)
            if queue and queue[0].ts <= pkt.ts:
                req = queue.popleft()
                txn = _build_http_transaction(req, pkt, network_signals)
                transactions.append(txn)

    # Requêtes sans réponse
    for key, queue in pending.items():
        for req in queue:
            client, server, _sport, _dport = key
            txn = ApplicationTransaction(
                protocol="HTTP",
                point=req.point,
                client=client,
                server=server,
                request_ts=req.ts,
                response_ts=None,
                total_time_ms=None,
                request_summary=f"{req.http_method or 'GET'} {req.http_uri or '/'}",
                response_summary="",
                network_signals=list(network_signals.get(key, [])),
            )
            transactions.append(txn)

    transactions.sort(key=lambda t: t.request_ts or 0.0)
    logger.debug("build_http_transactions: retour transactions")
    return transactions


def _build_http_transaction(
    request: Pkt,
    response: Pkt,
    network_signals: dict[tuple[str, str, int | None, int | None], list[str]],
) -> ApplicationTransaction:
    """Construit une transaction HTTP appariée."""
    total_ms = (response.ts - request.ts) * 1000.0 if response.ts and request.ts else None
    flow_key = (request.src, request.dst, request.sport, request.dport)
    signals = network_signals.get(flow_key, [])

    # http_response_time_ms est le temps serveur estimé par tshark
    # (de la requête au premier octet de réponse). Si disponible, on
    # l'utilise comme server_time_ms ; sinon on laisse None (on ne
    # prétend pas séparer réseau/serveur avec un seul point de capture).
    server_time_ms = response.http_response_time_ms if response.http_response_time_ms is not None else None

    logger.debug("_build_http_transaction: retour ApplicationTransaction(...)")
    return ApplicationTransaction(
        protocol="HTTP",
        point=request.point,
        client=request.src,
        server=request.dst,
        request_ts=request.ts,
        response_ts=response.ts,
        total_time_ms=total_ms,
        server_time_ms=server_time_ms,
        request_summary=f"{request.http_method or 'GET'} {request.http_uri or '/'}",
        response_summary=str(response.http_status_code or ""),
        network_signals=list(signals),
    )
