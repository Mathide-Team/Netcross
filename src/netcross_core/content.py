"""Extraction des objets applicatifs HTTP/1.x sans conservation du corps.

Le module travaille uniquement sur les metadonnees deja extraites par tshark.
Aucun corps HTTP n'est copie, stocke ou exporte. Le mode forensic ajoute les
references de trame et le hash deja calcule par le parseur, afin de permettre
une verification ulterieure sans conserver le contenu.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt

logger = get_logger(__name__)


@dataclass(frozen=True)
class HttpObject:
    """Objet HTTP transfere, relie a une transaction et a sa connexion."""

    point: str
    src: str
    sport: int | None
    dst: str
    dport: int | None
    method: str | None
    uri: str | None
    status_code: int | None
    content_type: str | None
    content_length: int | None
    response_time_ms: float | None
    request_frame: int | None
    response_frame: int | None
    response_payload_hash: str | None = None

    @property
    def volume_bytes(self) -> int:
        """Volume applicatif declare par Content-Length, 0 s'il est absent."""
        return self.content_length or 0

    @property
    def flow(self) -> tuple:
        """Identifiant directionnel de connexion TCP (hors sequence TCP)."""
        return (self.src, self.sport, self.dst, self.dport)


def _connection_key(pk: Pkt) -> tuple:
    """Cle canonique d'une connexion TCP, independante du sens."""
    a = (pk.src, pk.sport)
    b = (pk.dst, pk.dport)
    return (a, b) if a <= b else (b, a)


def extract_http_objects(
    packets: list[Pkt],
    *,
    privacy_mode: str = "metadata",
    max_objects: int | None = None,
) -> list[HttpObject]:
    """Inventorie les reponses HTTP et les relie aux requetes precedentes.

    privacy_mode:
      - metadata (defaut): URI, type, taille, statut et timing.
      - forensic: ajoute les numeros de trame et le hash du payload de la
        reponse, mais JAMAIS le corps HTTP.

    Le rapprochement est limite a HTTP/1.x disseque par tshark. Les transactions
    sans requete correspondante restent inventoriees, avec request_frame=None.
    Les reponses sans Content-Length restent valides; volume_bytes vaut alors 0
    car aucune taille observee fiable de l'objet n'est deduite artificiellement
    a partir des segments TCP.
    """
    if privacy_mode not in {"metadata", "forensic"}:
        raise ValueError("privacy_mode doit etre 'metadata' ou 'forensic'")

    pending: dict[tuple, deque[Pkt]] = defaultdict(deque)
    objects: list[HttpObject] = []

    for pk in sorted(packets, key=lambda p: (p.ts, p.frame_number or 0)):
        if pk.proto != "TCP" or not (pk.http_is_request or pk.http_is_response):
            continue

        key = _connection_key(pk)

        if pk.http_is_request:
            pending[key].append(pk)
            continue

        request = None
        if pending[key]:
            if pk.http_uri is None:
                request = pending[key].popleft()
            else:
                for candidate in pending[key]:
                    if candidate.http_uri == pk.http_uri:
                        request = candidate
                        pending[key].remove(candidate)
                        break
                if request is None:
                    request = pending[key].popleft()

        objects.append(
            HttpObject(
                point=pk.point,
                src=pk.src,
                sport=pk.sport,
                dst=pk.dst,
                dport=pk.dport,
                method=request.http_method if request else None,
                uri=pk.http_uri or (request.http_uri if request else None),
                status_code=pk.http_status_code,
                content_type=pk.http_content_type,
                content_length=pk.http_content_length,
                response_time_ms=pk.http_response_time_ms,
                request_frame=request.frame_number if request else None,
                response_frame=pk.frame_number,
                response_payload_hash=pk.payload_hash if privacy_mode == "forensic" else None,
            )
        )
        if max_objects is not None and len(objects) >= max_objects:
            logger.debug("extract_http_objects: limite max_objects atteinte ({})", max_objects)
            break

    logger.debug(
        "extract_http_objects: {} objet(s) HTTP (mode={}, requêtes en attente: {})",
        len(objects),
        privacy_mode,
        sum(len(q) for q in pending.values()),
    )
    return objects


def objects_to_dicts(objects: list[HttpObject]) -> list[dict]:
    """Serialization JSON/CSV stable, sans corps HTTP."""
    return [asdict(obj) for obj in objects]


__all__ = ["HttpObject", "extract_http_objects", "objects_to_dicts"]
