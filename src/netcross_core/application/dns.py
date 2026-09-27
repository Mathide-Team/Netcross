"""
netcross_core.application.dns -- construction de transactions DNS a
partir des paquets (Job 23, §6.9).

Apparie requêtes et réponses DNS par clé (point, endpoints, txn_id,
query_name) en FIFO pour gérer les IDs réutilisés.
"""

from __future__ import annotations

from collections import defaultdict, deque

from netcross_core.application.models import ApplicationTransaction
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Pkt

logger = get_logger(__name__)


def _dns_key(pkt: Pkt) -> tuple[str, str, str, int | None, int | None, str | int]:
    """Clé d'appariement DNS : point + endpoints + ports + txn_id + query.

    Inclure query_name réduit les collisions d'ID réutilisés ; inclure
    endpoints évite de confondre deux clients avec le même txn_id.
    """
    logger.debug("_dns_key: retour tuple de 6")
    return (pkt.point, pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.dns_txn_id or 0)


def build_dns_transactions(
    packets: list[Pkt],
) -> list[ApplicationTransaction]:
    """Construit les transactions DNS en apparieant requêtes et réponses.

    Stratégie : FIFO par clé (point, endpoints, ports, txn_id, query_name).
    Chaque requête (dns_txn_id présent, pas dns_is_response) est mise en
    attente ; chaque réponse (dns_is_response) dépile la plus ancienne
    requête de même clé. Les requêtes sans réponse deviennent
    missing_response.

    Args:
        packets: liste triée par timestamp croissant.
    """
    pending: dict[tuple, deque[Pkt]] = defaultdict(deque)
    transactions: list[ApplicationTransaction] = []

    for pkt in packets:
        if pkt.proto not in ("UDP", "TCP"):
            continue
        if pkt.dns_txn_id is None:
            continue

        if not pkt.dns_is_response:
            # Requête DNS
            key = _dns_key(pkt)
            pending[key].append(pkt)
        else:
            # Réponse DNS : cherche la requête correspondante
            # La réponse inverse src/dst par rapport à la requête
            req_key = (
                pkt.point,
                pkt.dst,  # client = dst de la réponse
                pkt.src,  # serveur = src de la réponse
                pkt.dport,
                pkt.sport,
                pkt.dns_txn_id or 0,
            )
            queue = pending.get(req_key)
            if queue and queue[0].ts <= pkt.ts:
                req = queue.popleft()
                txn = _build_dns_transaction(req, pkt)
                transactions.append(txn)

    # Requêtes sans réponse
    for key, queue in pending.items():
        for req in queue:
            point, client, server, _sport, _dport, _txn_id = key
            txn = ApplicationTransaction(
                protocol="DNS",
                point=point,
                client=client,
                server=server,
                request_ts=req.ts,
                response_ts=None,
                total_time_ms=None,
                request_summary=req.dns_qry_name or "",
                response_summary="",
            )
            transactions.append(txn)

    transactions.sort(key=lambda t: t.request_ts or 0.0)
    logger.debug("build_dns_transactions: retour transactions={}", summarize(transactions, "transactions"))
    return transactions


def _build_dns_transaction(
    request: Pkt,
    response: Pkt,
) -> ApplicationTransaction:
    """Construit une transaction DNS appariée."""
    total_ms = (response.ts - request.ts) * 1000.0 if response.ts and request.ts else None
    query_name = request.dns_qry_name or response.dns_qry_name or ""

    logger.debug("_build_dns_transaction: retour ApplicationTransaction(…)")
    return ApplicationTransaction(
        protocol="DNS",
        point=request.point,
        client=request.src,
        server=request.dst,
        request_ts=request.ts,
        response_ts=response.ts,
        total_time_ms=total_ms,
        request_summary=query_name,
        response_summary=str(response.dns_rcode or 0),
    )
