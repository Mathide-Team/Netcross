"""
netcross_core.application.models -- structures de donnees du modele
transactionnel applicatif (Job 23, §6.9/§6.10).

Une ApplicationTransaction represente un cycle requête -> réponse pour
un protocole applicatif (HTTP, DNS...), avec les temps decomposes et
une classification automatique.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


class TransactionClassification(str, Enum):
    """Classification automatique d'une transaction applicative."""

    NORMAL = "normal"
    MISSING_RESPONSE = "missing_response"
    NETWORK_SLOW = "network_slow"
    SERVER_SLOW = "server_slow"
    APPLICATION_SLOW = "application_slow"


@dataclass(slots=True)
class ApplicationTransaction:
    """Un cycle requête -> réponse pour un protocole applicatif.

    Champs temporels (tous en millisecondes, None si non mesure) :
    - request_ts / response_ts : timestamps absolus (secondes epoch)
    - total_time_ms : temps total requête -> réponse
    - network_time_ms : temps réseau aller (estimé si multi-points)
    - server_time_ms : temps de traitement serveur (think time)
    - ttfb_ms : time to first byte (debut reponse)
    """

    protocol: str  # "HTTP", "DNS", "SMB"...
    point: str  # point de capture
    client: str  # adresse client
    server: str  # adresse serveur
    request_ts: float | None = None
    response_ts: float | None = None
    total_time_ms: float | None = None
    network_time_ms: float | None = None
    server_time_ms: float | None = None
    # Résumé de la requête (méthode+URI pour HTTP, query name pour DNS)
    request_summary: str = ""
    # Résumé de la réponse (status code pour HTTP, rcode pour DNS)
    response_summary: str = ""
    # Signaux réseau dans la fenêtre temporelle de la transaction
    # (retransmissions, lost_segment, out_of_order vus sur ce flux)
    network_signals: list[str] = field(default_factory=list)
    classification: TransactionClassification = TransactionClassification.NORMAL

    def to_dict(self) -> dict:
        """Sérialisation pour Report.application_transactions (liste de
        dicts, comme http_objects)."""
        logger.debug("ApplicationTransaction.to_dict: retour dictionnaire")
        return {
            "protocol": self.protocol,
            "point": self.point,
            "client": self.client,
            "server": self.server,
            "request_ts": self.request_ts,
            "response_ts": self.response_ts,
            "total_time_ms": self.total_time_ms,
            "network_time_ms": self.network_time_ms,
            "server_time_ms": self.server_time_ms,
            "request_summary": self.request_summary,
            "response_summary": self.response_summary,
            "network_signals": list(self.network_signals),
            "classification": self.classification.value,
        }
