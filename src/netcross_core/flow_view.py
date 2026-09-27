"""
netcross_core.flow_view -- vue enrichie d'un flux (FlowView), sixieme
objet de contrat de la Session 0 (Job 9/issue #6, section 6.4 et 6.14 de
FEATURES.md).

`FlowView` transforme un `Flow` (agregation typee de paquets par cle de
correlation) en objet central exposant : duree, timeline, latence, debit,
synthese TCP, evenements et transactions.

Module volontairement autonome depuis `dev` : ne depend que de
`netcross_core.expert_model` (Flow, ExpertEvent, PacketEvidence) et
`netcross_core.models` (Pkt). L'integration fine avec l'index forensic
(Job 8) sera naturelle apres merge de la PR correspondante -- il
suffira de passer les evenements filtres par segment a
`build_flow_view()`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netcross_core.expert_model import ExpertEvent, Flow
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Pkt

logger = get_logger(__name__)


@dataclass
class TcpSummary:
    """Synthese TCP d'un flux : compteurs cles, pas de reparse."""

    retransmissions: int = 0
    fast_retransmissions: int = 0
    spurious_retransmissions: int = 0
    syn_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False
    mss: int | None = None
    wscale: int | None = None
    sack_permitted: bool = False


@dataclass
class Transaction:
    """Une transaction (ex: requete HTTP / reponse) au sein d'un flux.

    `request_ts` et `response_ts` sont les timestamps du paquet de
    requete et de reponse. `response_time_ms` est la difference.
    """

    kind: str  # "http", "dns", "sip", "tcp_handshake", etc.
    request_ts: float | None = None
    response_ts: float | None = None
    response_time_ms: float | None = None
    detail: str = ""


@dataclass
class FlowView:
    """Vue enrichie d'un `Flow` -- objet central d'analyse.

    Toutes les metriques sont calculees a partir des `Pkt` deja
    disponibles dans le dict `flows` produit par `correlate()`. Aucun
    reparse, aucun recalcul de correlation.
    """

    flow: Flow
    duration_s: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    throughput_bps: float = 0.0
    # Latence estimee par point (ts du premier paquet vu a ce point).
    first_ts_by_point: dict[str, float] = field(default_factory=dict)
    # Latence inter-points (difference entre premier paquet vu a B et
    # premier paquet vu a A, si les deux points ont vu le meme flux).
    inter_point_latency_ms: dict[str, float] = field(default_factory=dict)
    tcp: TcpSummary = field(default_factory=TcpSummary)
    transactions: list[Transaction] = field(default_factory=list)
    events: list[ExpertEvent] = field(default_factory=list)
    # Timeline ordonnee : liste de (ts, point, direction) pour chaque
    # paquet du flux, tous points confondus.
    timeline: list[tuple[float, str, str]] = field(default_factory=list)


def build_flow_view(
    flow: Flow,
    packets_by_point: dict[str, list[Pkt]],
    events: list[ExpertEvent] | None = None,
) -> FlowView:
    """Construit un `FlowView` a partir d'un `Flow` et du dict
    `{point: [Pkt, ...]}` correspondant (produit par `correlate()`).

    `events` (optionnel) : liste d'`ExpertEvent` deja filtres pour ce
    flux. Si None, `FlowView.events` reste vide -- l'integration avec
    l'index forensic se fera apres merge de la PR correspondante.
    """
    logger.debug(
        "build_flow_view: flow={} packets_by_point={} events={}",
        summarize(flow, "flow"),
        summarize(packets_by_point, "packets_by_point"),
        summarize(events, "events"),
    )
    view = FlowView(flow=flow)

    all_pkts: list[Pkt] = []
    for point in flow.points:
        pkts = packets_by_point.get(point, [])
        if not pkts:
            continue
        all_pkts.extend(pkts)
        view.first_ts_by_point[point] = min(pk.ts for pk in pkts)
        view.packet_count += len(pkts)
        view.byte_count += sum(pk.length for pk in pkts)

    if not all_pkts:
        logger.debug("build_flow_view: retour view")
        return view

    # Duree et debit
    ts_min = min(pk.ts for pk in all_pkts)
    ts_max = max(pk.ts for pk in all_pkts)
    view.duration_s = ts_max - ts_min
    if view.duration_s > 0:
        view.throughput_bps = (view.byte_count * 8) / view.duration_s

    # Latence inter-points : pour chaque paire de points consecutifs
    # dans l'ordre d'apparition, difference entre le premier paquet vu.
    points_in_order = [p for p in flow.points if p in view.first_ts_by_point]
    for i in range(1, len(points_in_order)):
        prev = points_in_order[i - 1]
        curr = points_in_order[i]
        delta = (view.first_ts_by_point[curr] - view.first_ts_by_point[prev]) * 1000.0
        view.inter_point_latency_ms[f"{prev} -> {curr}"] = max(0.0, delta)

    # Synthese TCP
    tcp = TcpSummary()
    for pk in all_pkts:
        if pk.proto != "TCP":
            continue
        if pk.is_retransmission:
            tcp.retransmissions += 1
        if pk.is_fast_retransmission:
            tcp.fast_retransmissions += 1
        if pk.is_spurious_retransmission:
            tcp.spurious_retransmissions += 1
        if pk.flags:
            flags = pk.flags if isinstance(pk.flags, str) else ""
            if "S" in flags and "A" not in flags:
                tcp.syn_seen = True
            if "F" in flags:
                tcp.fin_seen = True
            if "R" in flags:
                tcp.rst_seen = True
        if pk.mss_val is not None and tcp.mss is None:
            tcp.mss = pk.mss_val
        if pk.wscale_shift is not None and tcp.wscale is None:
            tcp.wscale = pk.wscale_shift
        if pk.sack_permitted:
            tcp.sack_permitted = True
    view.tcp = tcp

    # Transactions : detectees depuis les champs HTTP/DNS/SIP des Pkt
    view.transactions = _detect_transactions(all_pkts)

    # Timeline : (ts, point, direction) pour chaque paquet
    for pk in all_pkts:
        direction = f"{pk.src} -> {pk.dst}"
        view.timeline.append((pk.ts, pk.point, direction))
    view.timeline.sort(key=lambda x: x[0])

    # Evenements
    if events is not None:
        view.events = list(events)

    logger.debug("build_flow_view: retour view")
    return view


def _detect_transactions(packets: list[Pkt]) -> list[Transaction]:
    """Detecte les transactions HTTP/DNS/SIP/TCP-handshake depuis les
    champs specialises des `Pkt`. Retourne une liste triee par timestamp."""
    logger.debug("_detect_transactions: packets={}", summarize(packets, "packets"))
    transactions: list[Transaction] = []

    # HTTP : paire request/response (meme point, peu importe la direction)
    http_reqs: dict[str, float] = {}  # point -> ts de la derniere requete
    for pk in packets:
        if pk.http_is_request and pk.http_uri:
            http_reqs[pk.point] = pk.ts
        elif pk.http_is_response and pk.http_status_code is not None:
            req_ts = http_reqs.get(pk.point)
            rtt_ms = None
            if req_ts is not None:
                rtt_ms = (pk.ts - req_ts) * 1000.0
            transactions.append(
                Transaction(
                    kind="http",
                    request_ts=req_ts,
                    response_ts=pk.ts,
                    response_time_ms=rtt_ms,
                    detail=f"HTTP {pk.http_status_code}",
                )
            )

    # DNS : paire request/response
    dns_reqs: dict[str, float] = {}
    for pk in packets:
        if pk.dns_txn_id is not None and pk.dns_qry_name:
            key = f"{pk.point}:{pk.dns_txn_id}"
            if not pk.dns_is_response:
                dns_reqs[key] = pk.ts
            else:
                req_ts = dns_reqs.get(key)
                rtt_ms = None
                if req_ts is not None:
                    rtt_ms = (pk.ts - req_ts) * 1000.0
                transactions.append(
                    Transaction(
                        kind="dns",
                        request_ts=req_ts,
                        response_ts=pk.ts,
                        response_time_ms=rtt_ms,
                        detail=f"DNS {pk.dns_qry_name}",
                    )
                )

    # TCP handshake : SYN / SYN-ACK (meme point)
    syn_ts: dict[str, float] = {}
    for pk in packets:
        if pk.proto != "TCP" or not pk.flags:
            continue
        flags = pk.flags if isinstance(pk.flags, str) else ""
        if "S" in flags and "A" not in flags:
            syn_ts[pk.point] = pk.ts
        elif "S" in flags and "A" in flags:
            req_ts = syn_ts.get(pk.point)
            rtt_ms = None
            if req_ts is not None:
                rtt_ms = (pk.ts - req_ts) * 1000.0
            transactions.append(
                Transaction(
                    kind="tcp_handshake",
                    request_ts=req_ts,
                    response_ts=pk.ts,
                    response_time_ms=rtt_ms,
                    detail="SYN -> SYN-ACK",
                )
            )

    transactions.sort(key=lambda t: t.response_ts or t.request_ts or 0.0)
    logger.debug("_detect_transactions: retour transactions")
    return transactions
