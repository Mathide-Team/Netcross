r"""
netcross_core.flow_timeline -- vue temporelle detaillee d'un flux
(Job 13/issue #10, section 6.4 de FEATURES.md).

Etend le \`FlowView\` (Job 9/issue #6) avec une analyse temporelle fine :
inter-arrivee des paquets, fenetres de debit glissant, estimation RTT,
et phases temporelles.

Ce module est un complement de \`flow_view\` : il part des memes \`Pkt\`
deja disponibles et calcule des metriques temporelles supplementaires.
Aucun reparse, aucune nouvelle correlation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Pkt

logger = get_logger(__name__)


@dataclass
class PacketTiming:
    """Timing d'un paquet dans la timeline d'un flux.

    ``ts`` : timestamp absolu du paquet.

    ``delta_ms`` : temps ecoule depuis le paquet precedent (inter-arrival).

    ``cumulative_bytes`` : total d'octets cumules a ce paquet inclus.
    """

    ts: float
    point: str
    delta_ms: float = 0.0
    cumulative_bytes: int = 0


@dataclass
class ThroughputWindow:
    r"""Debit sur une fenetre temporelle de \`window_s\` secondes.

    ``start_ts`` : debut de la fenetre.

    ``end_ts`` : fin de la fenetre.

    ``bytes`` : total d'octets dans la fenetre.

    ``bps`` : debit en bits par seconde.
    """

    start_ts: float
    end_ts: float
    bytes: int = 0
    bps: float = 0.0


@dataclass
class FlowTimeline:
    """Vue temporelle detaillee d'un flux.

    ``packet_timings`` : liste ordonnee de \\`PacketTiming\\` (un par paquet).

    ``throughput_windows`` : liste de \\`ThroughputWindow\\` (debit par
    fenetre glissante de \\`window_s\\` secondes).

    ``inter_arrival_stats`` : statistiques d'inter-arrivee (min, max,
    moyenne, mediane en ms).

    ``phases`` : phases temporelles detectees (ex: \"slow-start\",
    \"steady\", \"idle\", \"burst\").

    ``rtt_estimate_ms`` : estimation RTT basee sur les paires
    SYN/SYN-ACK ou requete/reponse.
    """

    packet_timings: list[PacketTiming] = field(default_factory=list)
    throughput_windows: list[ThroughputWindow] = field(default_factory=list)
    inter_arrival_stats: dict[str, float] = field(default_factory=dict)
    phases: list[str] = field(default_factory=list)
    rtt_estimate_ms: float | None = None

    def to_dict(self) -> dict:
        """Serialisation JSON (issue #359)."""
        return {
            "packet_timings": [
                {"ts": pt.ts, "point": pt.point, "delta_ms": pt.delta_ms, "cumulative_bytes": pt.cumulative_bytes}
                for pt in self.packet_timings
            ],
            "throughput_windows": [
                {"start_ts": tw.start_ts, "end_ts": tw.end_ts, "bytes": tw.bytes, "bps": tw.bps}
                for tw in self.throughput_windows
            ],
            "inter_arrival_stats": dict(self.inter_arrival_stats),
            "phases": list(self.phases),
            "rtt_estimate_ms": self.rtt_estimate_ms,
        }


def build_flow_timeline(
    packets: list[Pkt],
    window_s: float = 1.0,
) -> FlowTimeline:
    r"""Construit un \`FlowTimeline\` a partir des paquets d'un flux.

    ``window_s`` : duree de la fenetre glissante pour le calcul du debit
    par troncon (defaut 1.0s).
    """
    timeline = FlowTimeline()

    if not packets:
        return timeline

    # Trier par timestamp
    sorted_pkts = sorted(packets, key=lambda p: p.ts)

    # -- Packet timings (inter-arrival) -----------------------------------
    cumulative = 0
    prev_ts: float | None = None
    for pk in sorted_pkts:
        delta_ms = 0.0
        if prev_ts is not None:
            delta_ms = (pk.ts - prev_ts) * 1000.0
        cumulative += pk.length
        timeline.packet_timings.append(
            PacketTiming(
                ts=pk.ts,
                point=pk.point,
                delta_ms=delta_ms,
                cumulative_bytes=cumulative,
            )
        )
        prev_ts = pk.ts

    # -- Inter-arrival stats ----------------------------------------------
    deltas = [pt.delta_ms for pt in timeline.packet_timings[1:]]  # skip first (0.0)
    if deltas:
        deltas_sorted = sorted(deltas)
        n = len(deltas_sorted)
        timeline.inter_arrival_stats = {
            "min_ms": deltas_sorted[0],
            "max_ms": deltas_sorted[-1],
            "mean_ms": sum(deltas_sorted) / n,
            "median_ms": _median(deltas_sorted),
        }

    # -- Throughput windows (fenetres glissantes) -------------------------
    ts_min = sorted_pkts[0].ts
    ts_max = sorted_pkts[-1].ts
    duration = ts_max - ts_min

    if duration > 0 and window_s > 0:
        # Fenetres non chevauchantes pour simplicite
        window_start = ts_min
        while window_start < ts_max:
            window_end = window_start + window_s
            window_bytes = sum(pk.length for pk in sorted_pkts if window_start <= pk.ts < window_end)
            actual_end = min(window_end, ts_max)
            actual_duration = actual_end - window_start
            bps = (window_bytes * 8 / actual_duration) if actual_duration > 0 else 0.0
            timeline.throughput_windows.append(
                ThroughputWindow(
                    start_ts=window_start,
                    end_ts=actual_end,
                    bytes=window_bytes,
                    bps=bps,
                )
            )
            window_start = window_end

    # -- Phases temporelles -----------------------------------------------
    timeline.phases = _detect_phases(timeline.packet_timings, sorted_pkts)

    # -- RTT estimate ------------------------------------------------------
    timeline.rtt_estimate_ms = _estimate_rtt(sorted_pkts)

    logger.debug(
        "build_flow_timeline: {} paquet(s), {} phase(s) {}, RTT={}ms",
        len(sorted_pkts),
        len(timeline.phases),
        timeline.phases,
        round(timeline.rtt_estimate_ms, 2) if timeline.rtt_estimate_ms is not None else "N/A",
    )
    return timeline


def _median(sorted_values: list[float]) -> float:
    """Mediane d'une liste triee."""
    n = len(sorted_values)
    if n == 0:
        return 0.0
    if n % 2 == 1:
        return sorted_values[n // 2]
    return (sorted_values[n // 2 - 1] + sorted_values[n // 2]) / 2.0


def _detect_phases(timings: list[PacketTiming], packets: list[Pkt]) -> list[str]:
    """Detecte des phases temporelles simples dans un flux.

    Phases possibles :
    - \"tcp-handshake\" : SYN/SYN-ACK/ACK initial
    - \"burst\" : plusieurs paquets rapproches (delta < 10ms)
    - \"steady\" : paquets reguliers (delta entre 10ms et 100ms)
    - \"idle\" : pause longue (delta > 1000ms)
    - \"teardown\" : FIN/RST final
    """
    phases: list[str] = []
    if not timings:
        return phases

    # Phase initiale : handshake ?
    first_pk = packets[0]
    if first_pk.proto == "TCP" and first_pk.flags:
        flags = first_pk.flags if isinstance(first_pk.flags, str) else ""
        if "S" in flags and "A" not in flags:
            phases.append("tcp-handshake")

    # Phases intermediaires basees sur les deltas
    for pt in timings[1:]:
        if pt.delta_ms < 10.0:
            if not phases or phases[-1] != "burst":
                phases.append("burst")
        elif pt.delta_ms > 1000.0:
            if not phases or phases[-1] != "idle":
                phases.append("idle")
        else:
            if not phases or phases[-1] not in ("steady", "tcp-handshake"):
                phases.append("steady")

    # Phase finale : teardown ?
    last_pk = packets[-1]
    if last_pk.proto == "TCP" and last_pk.flags:
        flags = last_pk.flags if isinstance(last_pk.flags, str) else ""
        if ("F" in flags or "R" in flags) and (not phases or phases[-1] != "teardown"):
            phases.append("teardown")

    logger.debug("_detect_phases: {} phase(s) détectée(s) : {}", len(phases), phases)
    return phases


def _estimate_rtt(packets: list[Pkt]) -> float | None:
    """Estime le RTT a partir des paires SYN/SYN-ACK ou requete/reponse.

    Retourne le RTT en millisecondes, ou None si aucune paire n'est
    trouvee.
    """
    # TCP handshake : SYN -> SYN-ACK
    syn_ts: float | None = None
    for pk in packets:
        if pk.proto != "TCP" or not pk.flags:
            continue
        flags = pk.flags if isinstance(pk.flags, str) else ""
        if "S" in flags and "A" not in flags:
            syn_ts = pk.ts
        elif "S" in flags and "A" in flags and syn_ts is not None:
            return (pk.ts - syn_ts) * 1000.0

    # HTTP : request -> response
    http_req_ts: float | None = None
    for pk in packets:
        if pk.http_is_request:
            http_req_ts = pk.ts
        elif pk.http_is_response and http_req_ts is not None:
            return (pk.ts - http_req_ts) * 1000.0

    # DNS : request -> response
    dns_req_ts: float | None = None
    for pk in packets:
        if pk.dns_txn_id is not None and pk.dns_qry_name:
            if not pk.dns_is_response:
                dns_req_ts = pk.ts
            elif dns_req_ts is not None:
                rtt = (pk.ts - dns_req_ts) * 1000.0
                logger.debug("_estimate_rtt: RTT DNS={}ms", round(rtt, 2))
                return rtt

    logger.debug("_estimate_rtt: aucune paire SYN/SYN-ACK, HTTP ou DNS trouvée")
    return None


TIMELINES_FORMAT_VERSION = 1


def _conversation(pk: Pkt) -> tuple:
    """Cle de conversation BIDIRECTIONNELLE : les deux sens d'une meme
    connexion forment une seule chronologie (le RTT SYN/SYN-ACK en a besoin)."""
    a, b = (pk.src, pk.sport), (pk.dst, pk.dport)
    lo, hi = sorted((a, b), key=lambda e: (e[0], -1 if e[1] is None else e[1]))
    return (pk.proto, lo, hi)


def build_flow_timelines(packets: list[Pkt], window_s: float = 1.0, min_packets: int = 2) -> dict:
    """Chronologies de toutes les conversations, POINT PAR POINT (issue #359).

    Un meme paquet vu a deux points de capture n'est pas un paquet de plus :
    les melanger dans une seule chronologie fabriquerait des inter-arrivees
    quasi nulles et un debit double. Une conversation de moins de
    `min_packets` paquets a un point est omise (pas d'inter-arrivee).
    Resultat JSON trie par point puis par debut de conversation."""
    logger.debug(
        "build_flow_timelines: packets={} window_s={} min_packets={}",
        summarize(packets, "packets"),
        summarize(window_s, "window_s"),
        summarize(min_packets, "min_packets"),
    )
    groups: dict[tuple, list[Pkt]] = {}
    for pk in packets:
        groups.setdefault((pk.point, _conversation(pk)), []).append(pk)
    flows = []
    for (point, (proto, lo, hi)), pkts in groups.items():
        if len(pkts) < min_packets:
            continue
        timeline = build_flow_timeline(pkts, window_s=window_s)
        flows.append(
            {
                "point": point,
                "protocol": proto,
                "endpoints": [{"address": lo[0], "port": lo[1]}, {"address": hi[0], "port": hi[1]}],
                "packets": len(pkts),
                "bytes": sum(p.length for p in pkts),
                "start_ts": timeline.packet_timings[0].ts,
                "end_ts": timeline.packet_timings[-1].ts,
                **timeline.to_dict(),
            }
        )
    flows.sort(key=lambda f: (f["point"], f["start_ts"], f["protocol"], repr(f["endpoints"])))
    logger.debug(
        "build_flow_timelines: {} conversation(s) -> {} chronologie(s)",
        len(groups),
        len(flows),
    )
    return {"version": TIMELINES_FORMAT_VERSION, "window_s": window_s, "flows": flows}
