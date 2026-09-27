"""
netcross_core.forensic_search -- moteur de recherche analytique post-capture
transversal (Job 17 / issue #16, section 6.13 de FEATURES.md).

Contrairement a ``netcross_core.forensic`` (Job 8 / issue #5), qui est un
INDEX DE CORRELATION bidirectionnel evenement <-> flow <-> paquet, le present
module est un MOTEUR DE RECHERCHE transversal : il repond a la question
« ou, dans cette capture, trouve-t-on telle adresse / SNI / URI / code HTTP /
Call-ID / DNS name / protocole / fenetre temporelle ? » en parcourant TOUTES
les donnees deja decodees, et non un seul objet pris isolement.

Sources indexees (toutes optionnelles sauf les paquets) :

1. ``all_packets`` (liste de ``Pkt``) -- champs HTTP/DNS/SIP/TLS deja extraits
   par tshark au moment du parsing.
2. ``flows`` (dict produit par ``correlate()``) -- flux et leurs endpoints.
3. ``events`` (liste d'``ExpertEvent``) -- messages, protocole, segment.
4. ``http_objects`` (liste d'``HttpObject``, Job 25) -- URI, statut, type.
5. ``tls_events`` (liste d'``TlsEvent``, tls_diagnostics) -- SNI, version.
6. ``quic_events`` (liste d'``QuicEvent``, quic_diagnostics) -- SNI, version.

Le module est un CONSOMMATEUR pur : il ne reparse aucune capture, n'importe
aucun objet du paquet brut au-dela de ``Pkt``, et ne depend ni du moteur de
regles (``netcross_report``), ni du CLI, ni du PDF, ni de la GUI. Les types
TLS/QUIC sont references en ``TYPE_CHECKING`` uniquement -- le module reste
importable sans ``cryptography`` ni ``pcap_parser`` au runtime, et accepte
n'importe quel objet presentant les attributs attendus (duck typing).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from netcross_core.content import HttpObject
from netcross_core.expert_model import ExpertEvent, Flow
from netcross_core.models import Pkt

if TYPE_CHECKING:  # evite d'importer pcap_parser / cryptography au runtime
    from netcross_core.quic_diagnostics import QuicEvent
    from netcross_core.tls_diagnostics import TlsEvent
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


# -- Types de resultats -----------------------------------------------------

#: Types d'objets qu'une recherche peut retourner.
RESULT_KINDS = ("packet", "flow", "event", "http_object", "tls", "quic")


# -- Requete et resultat ----------------------------------------------------


@dataclass(frozen=True)
class ForensicSearchQuery:
    """Requete de recherche forensique transversale.

    Les filtres (``point``, ``protocol``, ``address``, ``port``, plage
    temporelle) sont combines par ET lorsqu'ils sont renseignes. La
    correspondance textuelle (``text`` ou ``field``/``field_value``) est
    insensible a la casse.

    ``field`` designe un champ logique decode parmi : ``sni``, ``uri``,
    ``http_status``, ``call_id``, ``dns_name``, ``method``,
    ``content_type``, ``message``. Si ``field_value`` est omis, on teste
    la simple presence du champ ; si ``field`` est omis mais
    ``field_value`` renseigne, la valeur est cherchee dans tous les champs.
    """

    text: str | None = None
    point: str | None = None
    protocol: str | None = None
    address: str | None = None
    port: int | None = None
    time_start: float | None = None
    time_end: float | None = None
    field: str | None = None
    field_value: str | None = None


@dataclass(frozen=True)
class ForensicSearchResult:
    """Un resultat de recherche forensique.

    ``matched_fields`` liste les champs logiques dont la valeur a
    declenche la correspondance (vide si seul un filtre a matche).
    ``snippet`` est un court extrait lisible justifiant le rattachement.
    """

    kind: str
    point: str | None
    frame_number: int | None
    ts: float | None
    matched_fields: tuple[str, ...] = ()
    snippet: str = ""


# -- Document interne ------------------------------------------------------


@dataclass
class _SearchDoc:
    """Vue indexable d'un objet deja decode.

    ``fields`` mappe un nom logique (``sni``, ``uri``...) a une valeur
    textuelle ; ``text`` est un blob concatenant toutes les valeurs pour
    la recherche en texte libre. Un meme objet peut produire plusieurs
    champs logiques (ex: un paquet HTTP porte ``uri``, ``http_status``,
    ``method``).
    """

    kind: str
    point: str | None
    frame_number: int | None
    ts: float | None
    src: str | None
    dst: str | None
    sport: int | None
    dport: int | None
    protocol: str | None
    fields: dict[str, str] = field(default_factory=dict)
    text: str = ""


def _doc_from_packet(pk: Pkt) -> _SearchDoc:
    proto = pk.proto
    fields: dict[str, str] = {}

    if pk.http_uri:
        fields["uri"] = pk.http_uri
    if pk.http_status_code is not None:
        fields["http_status"] = str(pk.http_status_code)
    if pk.http_method:
        fields["method"] = pk.http_method
    if pk.sip_call_id:
        fields["call_id"] = pk.sip_call_id
    if pk.dns_qry_name:
        fields["dns_name"] = pk.dns_qry_name
    if pk.sip_user_agent:
        fields["sip_user_agent"] = pk.sip_user_agent
    if pk.dhcp_msg_type:
        fields["dhcp_msg_type"] = pk.dhcp_msg_type

    text = " ".join(fields.values())
    return _SearchDoc(
        kind="packet",
        point=pk.point,
        frame_number=pk.frame_number,
        ts=pk.ts,
        src=pk.src,
        dst=pk.dst,
        sport=pk.sport,
        dport=pk.dport,
        protocol=proto,
        fields=fields,
        text=text,
    )


def _doc_from_flow(flow: Flow) -> _SearchDoc:
    endpoints: tuple[str, str] | None = flow.endpoints
    fields: dict[str, str] = {}
    if endpoints:
        fields["endpoints"] = " ".join(endpoints)
    if flow.points:
        fields["points"] = " ".join(flow.points)
    text = " ".join(fields.values())
    return _SearchDoc(
        kind="flow",
        point=flow.points[0] if flow.points else None,
        frame_number=None,
        ts=None,
        src=endpoints[0] if endpoints else None,
        dst=endpoints[1] if endpoints and len(endpoints) > 1 else None,
        sport=None,
        dport=None,
        protocol=None,
        fields=fields,
        text=text,
    )


def _doc_from_event(ev: ExpertEvent) -> _SearchDoc:
    fields: dict[str, str] = {}
    if ev.message:
        fields["message"] = ev.message
    if ev.protocol:
        fields["protocol"] = ev.protocol
    if ev.category:
        fields["category"] = ev.category
    if ev.cause:
        fields["cause"] = ev.cause
    text = " ".join(fields.values())
    return _SearchDoc(
        kind="event",
        point=ev.segment or None,
        frame_number=None,
        ts=ev.first_seen,
        src=None,
        dst=None,
        sport=None,
        dport=None,
        protocol=ev.protocol,
        fields=fields,
        text=text,
    )


def _doc_from_http_object(obj: HttpObject) -> _SearchDoc:
    fields: dict[str, str] = {}
    if obj.uri:
        fields["uri"] = obj.uri
    if obj.status_code is not None:
        fields["http_status"] = str(obj.status_code)
    if obj.method:
        fields["method"] = obj.method
    if obj.content_type:
        fields["content_type"] = obj.content_type
    text = " ".join(fields.values())
    return _SearchDoc(
        kind="http_object",
        point=obj.point,
        frame_number=obj.response_frame or obj.request_frame,
        ts=None,
        src=obj.src,
        dst=obj.dst,
        sport=obj.sport,
        dport=obj.dport,
        protocol="HTTP",
        fields=fields,
        text=text,
    )


def _doc_from_tls_event(ev: TlsEvent) -> _SearchDoc:
    fields: dict[str, str] = {}
    if ev.sni:
        fields["sni"] = ev.sni
    if ev.tls_version:
        fields["tls_version"] = ev.tls_version
    if ev.cipher:
        fields["cipher"] = ev.cipher
    if ev.handshake_type:
        fields["handshake_type"] = ev.handshake_type
    if ev.alert_description:
        fields["alert"] = ev.alert_description
    text = " ".join(fields.values())
    return _SearchDoc(
        kind="tls",
        point=ev.point,
        frame_number=None,
        ts=ev.ts,
        src=ev.src,
        dst=ev.dst,
        sport=ev.sport,
        dport=ev.dport,
        protocol="TLS",
        fields=fields,
        text=text,
    )


def _doc_from_quic_event(ev: QuicEvent) -> _SearchDoc:
    fields: dict[str, str] = {}
    if ev.sni:
        fields["sni"] = ev.sni
    if ev.tls_version:
        fields["tls_version"] = ev.tls_version
    text = " ".join(fields.values())
    return _SearchDoc(
        kind="quic",
        point=ev.point,
        frame_number=None,
        ts=ev.ts,
        src=ev.src,
        dst=ev.dst,
        sport=ev.sport,
        dport=ev.dport,
        protocol="QUIC",
        fields=fields,
        text=text,
    )


# -- Index ------------------------------------------------------------------


class ForensicSearchIndex:
    """Index de recherche analytique post-capture transversal.

    Construit en une passe sur chaque source a l'initialisation. La
    recherche est ensuite lineaire sur les documents indexes (leur nombre
    est borne par celui des paquets/evenements/objets deja calcules).
    """

    def __init__(
        self,
        all_packets: list[Pkt],
        flows: dict | None = None,
        events: list[ExpertEvent] | None = None,
        http_objects: list[HttpObject] | None = None,
        tls_events: list | None = None,
        quic_events: list | None = None,
    ) -> None:
        self._docs: list[_SearchDoc] = [_doc_from_packet(pk) for pk in all_packets]

        if flows:
            for per_point in flows.values():
                # flows est dict[flow_key, dict[point, list[Pkt]]] ; on
                # reconstruit un Flow synthetique minimal pour l'index.
                points = [p for p, pkts in per_point.items() if pkts]
                if not points:
                    continue
                first_pkts = per_point[points[0]]
                endpoints = None
                if first_pkts:
                    endpoints = tuple(sorted((first_pkts[0].src, first_pkts[0].dst)))
                flow = Flow(key=(), points=points, endpoints=endpoints)
                self._docs.append(_doc_from_flow(flow))

        if events:
            self._docs.extend(_doc_from_event(ev) for ev in events)
        if http_objects:
            self._docs.extend(_doc_from_http_object(o) for o in http_objects)
        if tls_events:
            self._docs.extend(_doc_from_tls_event(e) for e in tls_events)
        if quic_events:
            self._docs.extend(_doc_from_quic_event(e) for e in quic_events)

        logger.debug(
            "ForensicSearchIndex.__init__: {} document(s) indexé(s)",
            len(self._docs),
        )

    # -- Recherche --------------------------------------------------------

    def search(self, query: ForensicSearchQuery) -> list[ForensicSearchResult]:
        """Execute la requete et retourne les resultats tries par temps
        croissant puis par type."""
        results: list[ForensicSearchResult] = []
        needle = (query.text or "").lower()
        field_val = (query.field_value or "").lower()

        for doc in self._docs:
            if not self._match_filters(doc, query):
                continue

            matched_fields = self._match_text(doc, query, needle, field_val)
            # Si ni text ni field/field_value n'est demande, on accepte le
            # document (la requete est purement filtree).
            text_requested = bool(query.text) or bool(query.field_value)
            if text_requested and not matched_fields:
                continue

            results.append(self._to_result(doc, matched_fields))

        results.sort(key=lambda r: r.ts if r.ts is not None else float("inf"))
        logger.debug(
            "search: {} résultat(s) pour la requête",
            len(results),
        )
        return results

    @staticmethod
    def _match_filters(doc: _SearchDoc, q: ForensicSearchQuery) -> bool:
        if q.point and doc.point != q.point:
            return False
        if q.protocol and (not doc.protocol or doc.protocol.upper() != q.protocol.upper()):
            return False
        if q.address and doc.src != q.address and doc.dst != q.address:
            return False
        if q.port is not None and doc.sport != q.port and doc.dport != q.port:
            return False
        if q.time_start is not None and (doc.ts is None or doc.ts < q.time_start):
            return False
        return not (q.time_end is not None and (doc.ts is None or doc.ts > q.time_end))

    @staticmethod
    def _match_text(
        doc: _SearchDoc,
        q: ForensicSearchQuery,
        needle: str,
        field_val: str,
    ) -> tuple[str, ...]:
        matched: list[str] = []

        if q.field:
            # Recherche sur un champ logique nomme.
            value = doc.fields.get(q.field)
            if value is None:
                return ()
            if not field_val:
                # Presence seule du champ.
                return (q.field,)
            if field_val in value.lower():
                return (q.field,)
            return ()

        # Recherche en texte libre (text) ET/OU valeur de champ diffuse.
        terms: list[str] = []
        if needle:
            terms.append(needle)
        if field_val and not q.field:
            terms.append(field_val)
        if not terms:
            return ()
        blob = doc.text.lower()
        for term in terms:
            if term in blob:
                matched.extend(name for name, val in doc.fields.items() if term in val.lower() and name not in matched)
        return tuple(matched) if matched else ()

    @staticmethod
    def _to_result(doc: _SearchDoc, matched_fields: tuple[str, ...]) -> ForensicSearchResult:
        if matched_fields:
            snippet = " | ".join(f"{name}={doc.fields[name]}" for name in matched_fields)
        else:
            snippet = doc.text or doc.kind
        return ForensicSearchResult(
            kind=doc.kind,
            point=doc.point,
            frame_number=doc.frame_number,
            ts=doc.ts,
            matched_fields=matched_fields,
            snippet=snippet,
        )

    # -- Acces utilitaire ------------------------------------------------

    def __len__(self) -> int:
        return len(self._docs)
