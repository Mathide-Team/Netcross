"""
netcross_core.application.classify -- classification automatique des
transactions applicatives (Job 23, §6.9).

Distinction automatique :
- missing_response : pas de réponse (déjà positionné par les builders)
- network_slow : lenteur + signaux réseau (retrans, lost_segment, out_of_order)
- server_slow : server_time_ms mesuré et dominant
- application_slow : lenteur sans signal réseau ni split serveur fiable
- normal : tout va bien

Seuils réutilisés depuis expert_rules.py :
- DNS slow resolution : mean_duration_ms_min = 200 ms
- HTTP slow response : mean_duration_ms_min = 500 ms
"""

from __future__ import annotations

from dataclasses import dataclass

from netcross_core.application.models import ApplicationTransaction, TransactionClassification
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

# Seuils par protocole (en ms), alignés sur expert_rules.py
_DNS_SLOW_MS = 200.0
_HTTP_SLOW_MS = 500.0


@dataclass(slots=True)
class TransactionThresholds:
    """Seuils configurables pour la classification des transactions."""

    dns_slow_ms: float = _DNS_SLOW_MS
    http_slow_ms: float = _HTTP_SLOW_MS
    # Fraction du temps total imputable au serveur pour classer server_slow
    server_dominant_ratio: float = 0.6


def classify_transaction(
    txn: ApplicationTransaction,
    thresholds: TransactionThresholds | None = None,
) -> TransactionClassification:
    """Classifie une transaction automatiquement.

    Logique :
    1. Pas de réponse -> missing_response (déjà positionné, on confirme)
    2. Lenteur + signaux réseau dans la transaction -> network_slow
    3. server_time_ms mesuré et dominant (>= ratio du total) -> server_slow
    4. Lenteur sans preuve réseau ni serveur -> application_slow
    5. Sinon -> normal
    """
    if thresholds is None:
        thresholds = TransactionThresholds()

    # 1. Absence de réponse
    if txn.response_ts is None:
        logger.debug("classify_transaction: retour valeur")
        return TransactionClassification.MISSING_RESPONSE

    # Seuil de lenteur selon le protocole
    slow_ms = thresholds.dns_slow_ms if txn.protocol == "DNS" else thresholds.http_slow_ms

    is_slow = txn.total_time_ms is not None and txn.total_time_ms >= slow_ms

    if not is_slow:
        logger.debug("classify_transaction: retour valeur")
        return TransactionClassification.NORMAL

    # 2. Lenteur + signaux réseau -> network_slow
    if txn.network_signals:
        logger.debug("classify_transaction: retour valeur")
        return TransactionClassification.NETWORK_SLOW

    # 3. server_time_ms mesuré et dominant -> server_slow
    if (
        txn.server_time_ms is not None
        and txn.total_time_ms is not None
        and txn.server_time_ms >= thresholds.server_dominant_ratio * txn.total_time_ms
    ):
        logger.debug("classify_transaction: retour valeur")
        return TransactionClassification.SERVER_SLOW

    # 4. Lenteur sans preuve réseau ni serveur -> application_slow
    logger.debug("classify_transaction: retour valeur")
    return TransactionClassification.APPLICATION_SLOW
