"""Exploration statistique interactive (Job 27 / issue #22, section 6.8).

Couche generique d'exploration statistique sur les donnees deja calculees
par le moteur (flows, conversations, report). Ne recalcule rien : restructure
et trie les agregats existants selon les criteres choisis par l'analyste.

Le module est volontairement independant de la GUI (netcross_gtk4) : toute la
logique de Top-N, tri, regroupement et export vit ici, testable sans GTK. La
GUI branche un appelant mince sur ces fonctions.

Couche : netcross_core -- n'importe que des modules netcross_core/pcap_parser.
"""

from __future__ import annotations

import csv
import io
from dataclasses import asdict, dataclass, field

from netcross_core.expert_model import Flow
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Pkt, Report

logger = get_logger(__name__)

# -- Types d'enumeration (chaines pour serialisation simple) -----------------

SORT_BY: tuple[str, ...] = (
    "packets",
    "bytes",
    "duration_ms",
    "throughput_bps",
    "latency_ms",
    "events",
)

GROUP_BY: tuple[str, ...] = (
    "endpoint",
    "protocol",
    "segment",
    "flow",
)

# -- Structures de donnees ---------------------------------------------------


@dataclass(frozen=True)
class StatRow:
    """Une ligne de resultat statistique : un groupe (endpoint, protocole,
    segment ou flux) avec ses metriques agergees.

    `label` : etiquette lisible du groupe (ex: "10.0.0.1 <-> 10.0.0.2",
    "TCP", "LAN -> WAN", ou la cle de flux formatee).

    `flow_keys` : cles de flux de ce groupe, pour le drill-down.
    """

    label: str
    group_by: str
    packets: int = 0
    bytes: int = 0
    duration_ms: float = 0.0
    throughput_bps: float = 0.0
    latency_ms: float | None = None
    events: int = 0
    flow_keys: list[tuple] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        """Duree en secondes."""
        logger.debug("StatRow.duration_s: retour self.duration_ms / 1000.0")
        return self.duration_ms / 1000.0


@dataclass(frozen=True)
class StatsQuery:
    """Parametres d'une requete d'exploration statistique.

    - group_by : dimension de regroupement (endpoint, protocol, segment, flow).
    - sort_by : metrique de tri (packets, bytes, duration, throughput, latency, events).
    - top_n : nombre maximum de lignes (None = toutes).
    - time_start / time_end : filtre temporel en secondes (None = pas de filtre).
    - segment : filtre par segment/point (None = tous les segments).
    """

    group_by: str = "endpoint"
    sort_by: str = "bytes"
    top_n: int | None = 10
    time_start: float | None = None
    time_end: float | None = None
    segment: str | None = None

    def __post_init__(self):
        if self.group_by not in GROUP_BY:
            logger.debug("StatsQuery.__post_init__: si self.group_by not in GROUP_BY -> levée ValueError")
            raise ValueError(f"group_by doit etre dans {GROUP_BY}, recu: {self.group_by!r}")
        if self.sort_by not in SORT_BY:
            logger.debug("StatsQuery.__post_init__: si self.sort_by not in SORT_BY -> levée ValueError")
            raise ValueError(f"sort_by doit etre dans {SORT_BY}, recu: {self.sort_by!r}")
        if self.top_n is not None and self.top_n < 1:
            logger.debug("StatsQuery.__post_init__: si self.top_n is not None and self.top_n < 1 -> levée ValueError")
            raise ValueError("top_n doit etre >= 1 ou None")
        logger.debug("StatsQuery.__post_init__: fin")


# -- Calculs -----------------------------------------------------------------


def _flow_packets(f: Flow, all_packets: list[Pkt]) -> list[Pkt]:
    """Retourne les paquets d'un flux, filtres par temps/segment si demande."""
    logger.debug("_flow_packets: f={} all_packets={}", summarize(f, "f"), summarize(all_packets, "all_packets"))
    pkts = [pk for pk in all_packets if pk.point in f.points]
    # Le filtrage par flux precis (cle exacte) n'est pas faisable sans
    # reappeler flow_key() -- on filtre par appartenance au point et par
    # les timestamps du flux.
    logger.debug("_flow_packets: retour _time_filter(…)")
    return _time_filter(pkts, f)


def _time_filter(pkts: list[Pkt], f: Flow) -> list[Pkt]:
    """Filtre les paquets par fenetre temporelle du flux."""
    logger.debug("_time_filter: pkts={} f={}", summarize(pkts, "pkts"), summarize(f, "f"))
    if not pkts:
        logger.debug("_time_filter: si not pkts -> retour liste vide")
        return []
    all_ts = list(f.first_ts.values()) + list(f.last_ts.values())
    if not all_ts:
        logger.debug("_time_filter: si not all_ts -> retour pkts={}", summarize(pkts, "pkts"))
        return pkts
    f_start = min(all_ts)
    f_end = max(all_ts)
    logger.debug("_time_filter: retour liste")
    return [pk for pk in pkts if f_start <= pk.ts <= f_end]


def _flow_duration_ms(f: Flow) -> float:
    """Duree d'un flux en millisecondes (du premier au dernier paquet vu)."""
    logger.debug("_flow_duration_ms: f={}", summarize(f, "f"))
    all_ts = list(f.first_ts.values()) + list(f.last_ts.values())
    if not all_ts:
        logger.debug("_flow_duration_ms: si not all_ts -> retour 0.0")
        return 0.0
    logger.debug("_flow_duration_ms: retour (max(all_ts) - min(all_ts)) * 1000.0")
    return (max(all_ts) - min(all_ts)) * 1000.0


def _flow_total_packets(f: Flow) -> int:
    logger.debug("_flow_total_packets: retour sum(…)")
    return sum(f.packet_count.values())


def _flow_total_bytes(f: Flow) -> int:
    logger.debug("_flow_total_bytes: retour sum(…)")
    return sum(f.byte_count.values())


def _flow_throughput_bps(f: Flow) -> float:
    """Debit moyen en bits par seconde."""
    logger.debug("_flow_throughput_bps: f={}", summarize(f, "f"))
    duration_s = _flow_duration_ms(f) / 1000.0
    if duration_s <= 0:
        logger.debug("_flow_throughput_bps: si duration_s <= 0 -> retour 0.0")
        return 0.0
    logger.debug("_flow_throughput_bps: retour _flow_total_bytes(f) * 8 / duration_s")
    return (_flow_total_bytes(f) * 8) / duration_s


def _flow_label(f: Flow, group_by: str) -> str:
    """Etiquette lisible d'un flux selon la dimension de regroupement."""
    if group_by == "flow":
        key = f.key
        if len(key) >= 5:
            proto = key[0] if key[0] != "NAT" else key[1]
            src = key[1] if key[0] != "NAT" else "NAT"
            sport = key[2]
            dst = key[3] if key[0] != "NAT" else "NAT"
            dport = key[4] if key[0] != "NAT" else key[3]
            logger.debug("_flow_label: si len(key) >= 5 -> retour chaîne formatée")
            return f"{proto} {src}:{sport} -> {dst}:{dport}"
        logger.debug("_flow_label: si group_by == 'flow' -> retour str(…)")
        return str(key)
    if group_by == "endpoint":
        if f.endpoints:
            logger.debug("_flow_label: si f.endpoints -> retour chaîne formatée")
            return f"{f.endpoints[0]} <-> {f.endpoints[1]}"
        logger.debug("_flow_label: si group_by == 'endpoint' -> retour 'endpoints inconnus'")
        return "endpoints inconnus"
    if group_by == "protocol":
        key = f.key
        logger.debug("_flow_label: si group_by == 'protocol' -> retour key[0] if key[0] != 'NAT' else key[1]")
        return key[0] if key[0] != "NAT" else key[1]
    if group_by == "segment":
        logger.debug(
            "_flow_label: si group_by == 'segment' -> retour ' -> '.join(f.points) if f.points else 'segment i…"
        )
        return " -> ".join(f.points) if f.points else "segment inconnu"
    logger.debug("_flow_label: retour str(…)")
    return str(f.key)


def _group_flows(
    flows: list[Flow],
    group_by: str,
) -> dict[str, list[Flow]]:
    """Regroupe les flux par dimension."""
    logger.debug("_group_flows: flows={} group_by={}", summarize(flows, "flows"), summarize(group_by, "group_by"))
    groups: dict[str, list[Flow]] = {}
    for f in flows:
        label = _flow_label(f, group_by)
        groups.setdefault(label, []).append(f)
    logger.debug("_group_flows: retour groups={}", summarize(groups, "groups"))
    return groups


def _aggregate_group(
    label: str,
    group_by: str,
    group_flows: list[Flow],
    report: Report,
    all_packets: list[Pkt],
    query: StatsQuery,
) -> StatRow:
    """Agregge un groupe de flux en une ligne StatRow."""
    total_packets = sum(_flow_total_packets(f) for f in group_flows)
    total_bytes = sum(_flow_total_bytes(f) for f in group_flows)

    # Duree : du premier paquet au dernier, tous flux confondus
    all_starts: list[float] = []
    all_ends: list[float] = []
    for f in group_flows:
        all_starts.extend(f.first_ts.values())
        all_ends.extend(f.last_ts.values())
    duration_ms = (max(all_ends) - min(all_starts)) * 1000.0 if all_starts and all_ends else 0.0

    # Debit moyen
    duration_s = duration_ms / 1000.0
    throughput_bps = (total_bytes * 8) / duration_s if duration_s > 0 else 0.0

    # Latence moyenne (si disponible dans le report)
    latency_ms: float | None = None
    latencies = []
    for f in group_flows:
        for pair in report.latency:
            for point in f.points:
                if point in pair:
                    latencies.extend(report.latency[pair])
    if latencies:
        latency_ms = sum(latencies) / len(latencies)

    # Evenements : nombre d'ExpertEvent sur les segments de ces flux
    # -- les evenements viennent du ForensicIndex, pas du Report.
    # Le comptage est fait dans compute_stats() si l'index est fourni.
    events = 0

    flow_keys = [f.key for f in group_flows]

    logger.debug("_aggregate_group: retour StatRow(…)")
    return StatRow(
        label=label,
        group_by=group_by,
        packets=total_packets,
        bytes=total_bytes,
        duration_ms=duration_ms,
        throughput_bps=throughput_bps,
        latency_ms=latency_ms,
        events=events,
        flow_keys=flow_keys,
    )


def compute_stats(
    flows: list[Flow],
    report: Report,
    all_packets: list[Pkt],
    query: StatsQuery,
    events_by_segment: dict[str, list] | None = None,
) -> list[StatRow]:
    """Calcule les statistiques selon la requete.

    flows : liste de Flow (produit par build_flows()).
    report : le Report (pour latence, evenements...).
    all_packets : tous les Pkt de la capture.
    query : parametres (group_by, sort_by, top_n, filtres).
    events_by_segment : index evenement -> segment (optionnel, pour le
    comptage d'evenements).

    Retourne une liste de StatRow triee par sort_by decroissant, limitee
    a top_n.
    """
    # Filtre temporel sur les flux
    filtered_flows: list[Flow] = []
    for f in flows:
        # Filtre par segment si demande
        if query.segment is not None and query.segment not in f.points:
            continue
        # Filtre temporel
        if query.time_start is not None or query.time_end is not None:
            all_ts = list(f.first_ts.values()) + list(f.last_ts.values())
            if all_ts:
                f_start = min(all_ts)
                f_end = max(all_ts)
                if query.time_start is not None and f_end < query.time_start:
                    continue
                if query.time_end is not None and f_start > query.time_end:
                    continue
        filtered_flows.append(f)

    # Regroupement
    logger.debug(
        "compute_stats: {} flux -> {} après filtres (segment={} fenêtre={}..{})",
        len(flows),
        len(filtered_flows),
        query.segment,
        query.time_start,
        query.time_end,
    )
    groups = _group_flows(filtered_flows, query.group_by)

    # Aggregation
    rows: list[StatRow] = []
    for label, group_flows in groups.items():
        row = _aggregate_group(label, query.group_by, group_flows, report, all_packets, query)

        # Comptage des evenements si l'index est fourni
        if events_by_segment is not None:
            event_count = 0
            for f in group_flows:
                for point in f.points:
                    event_count += len(events_by_segment.get(point, []))
            row = StatRow(
                label=row.label,
                group_by=row.group_by,
                packets=row.packets,
                bytes=row.bytes,
                duration_ms=row.duration_ms,
                throughput_bps=row.throughput_bps,
                latency_ms=row.latency_ms,
                events=event_count,
                flow_keys=row.flow_keys,
            )

        rows.append(row)

    # Tri
    sort_key = query.sort_by
    rows.sort(key=lambda r: getattr(r, sort_key) or 0, reverse=True)

    # Top-N
    if query.top_n is not None:
        rows = rows[: query.top_n]

    logger.debug(
        "compute_stats: {} ligne(s) groupées par {}, tri {} top {}",
        len(rows),
        query.group_by,
        query.sort_by,
        query.top_n,
    )
    return rows


# -- Export ------------------------------------------------------------------


def export_csv(rows: list[StatRow]) -> str:
    """Exporte les lignes en CSV (en memoire).

    Les flow_keys sont serialises en representation Python (tuple) car un CSV
    ne supporte pas les listes nativement.
    """
    if not rows:
        logger.debug("export_csv: si not rows -> retour ''")
        return ""

    output = io.StringIO()
    fieldnames = [
        "label",
        "group_by",
        "packets",
        "bytes",
        "duration_ms",
        "throughput_bps",
        "latency_ms",
        "events",
        "flow_keys",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        d = asdict(row)
        d["flow_keys"] = ";".join(str(k) for k in row.flow_keys)
        writer.writerow(d)
    logger.debug("export_csv: {} ligne(s) de statistiques", len(rows))
    return output.getvalue()


def export_json(rows: list[StatRow]) -> list[dict]:
    """Exporte les lignes en liste de dicts (serialisable en JSON)."""
    result = []
    for row in rows:
        d = asdict(row)
        d["flow_keys"] = [list(k) if isinstance(k, tuple) else k for k in row.flow_keys]
        result.append(d)
    logger.debug("export_json: {} ligne(s) de statistiques", len(result))
    return result


# -- Point d'entree commun CLI / API (issue #912) ----------------------------

EXPORT_FORMATS: tuple[str, ...] = ("csv", "json")


def build_events_by_segment(findings) -> dict[str, list]:
    """Index evenement -> segment depuis les findings (attribut ``segment``
    ou ``pair`` ; ``"?"`` sans information). Deplace de
    ``netcross_gtk4.stats_view`` (issue #912) pour que la CLI et l'API
    comptent les evenements comme la GUI."""
    if not findings:
        logger.debug("build_events_by_segment: aucun finding")
        return {}
    index: dict[str, list] = {}
    for f in findings:
        seg = getattr(f, "segment", None) or getattr(f, "pair", None)
        index.setdefault(str(seg) if seg is not None else "?", []).append(f)
    logger.debug("build_events_by_segment: {} finding(s) -> {} segment(s)", len(findings), len(index))
    return index


def explore_stats(
    flows,
    report: Report,
    findings=None,
    *,
    group_by: str = "endpoint",
    sort_by: str = "bytes",
    top_n: int | None = 10,
) -> list[StatRow]:
    """Exploration statistique de la GUI pour la CLI (``--stats``) et l'API
    (``GET /analyses/{id}/stats``), issue #912.

    ``flows`` : dict de ``correlate()`` ou liste de ``Flow`` deja construite.
    ``top_n`` : None ou <= 0 = toutes les lignes. ValueError si ``group_by``
    ou ``sort_by`` sont inconnus."""
    if group_by not in GROUP_BY:
        raise ValueError(f"regroupement inconnu : {group_by} (attendu : {', '.join(GROUP_BY)})")
    if sort_by not in SORT_BY:
        raise ValueError(f"tri inconnu : {sort_by} (attendu : {', '.join(SORT_BY)})")
    if isinstance(flows, dict):
        from netcross_core.correlate import build_flows

        flows = build_flows(flows)
    flows = list(flows or [])
    if not flows or report is None:
        logger.debug("explore_stats: aucun flux ou rapport -> []")
        return []
    query = StatsQuery(group_by=group_by, sort_by=sort_by, top_n=top_n if top_n and top_n > 0 else None)
    return compute_stats(flows, report, [], query, build_events_by_segment(findings))


def stats_format_for(path: str, fmt: str | None = None) -> str:
    """Format d'export : ``fmt`` s'il est donne, sinon d'apres l'extension
    (``.csv`` -> csv, tout le reste -> json)."""
    if fmt is not None:
        if fmt not in EXPORT_FORMATS:
            raise ValueError(f"format inconnu : {fmt} (attendu : csv ou json)")
        return fmt
    return "csv" if str(path).lower().endswith(".csv") else "json"


def render_stats(rows: list[StatRow], fmt: str) -> str:
    """Texte de l'export ``csv`` ou ``json`` (memes colonnes que la GUI)."""
    import json

    if fmt == "csv":
        return export_csv(rows)
    return json.dumps(export_json(rows), ensure_ascii=False, indent=2)


__all__ = [
    "EXPORT_FORMATS",
    "GROUP_BY",
    "SORT_BY",
    "StatRow",
    "StatsQuery",
    "build_events_by_segment",
    "compute_stats",
    "explore_stats",
    "export_csv",
    "export_json",
    "render_stats",
    "stats_format_for",
]
