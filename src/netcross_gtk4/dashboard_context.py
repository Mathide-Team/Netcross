"""
netcross_gtk4.dashboard_context -- contexte d'analyse partage pour le
dashboard analytique interactif (issue #18, section 6.17).

Etat de PRESENTATION / interaction UI, mais pur Python (aucun import Gtk) :
testable sans display, comme la logique extraite de la cartographie des
communications (MainWindow._comm_map_filters). Le câblage des widgets GTK
reel reste dans app.py et n'est pas couvert par les tests (pas de display en
CI) -- ce module porte toute la logique verifiable.

Objet : les memes objets que le rapport (Report, flows, findings, evenements
d'expertise Wireshark) alimentent six vues -- timeline, segments, flows,
endpoints, protocoles, evenements. Une selection sur une vue modifie un
CONTEXTE PARTAGE (DashboardSelection) et declenche le rafraichissement des
vues liees : selectionner un flow renseigne son endpoint/protocole/paire ;
selectionner un protocole filtre flows/endpoints/evenements ; etc.

Ce module ne garde JAMAIS all_packets en memoire : il consomme uniquement
last_report / last_flows / last_findings / last_tls_findings /
last_quic_findings / last_wireshark_expert_events, comme le reste de la
fenetre (voir MainWindow._on_analysis_done).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from netcross_core.expert_model import Conversation, Flow
from netcross_core.logging_config import get_logger
from netcross_core.models import Report

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Contexte de selection partage
# ---------------------------------------------------------------------------


@dataclass
class DashboardSelection:
    """Selection courante du dashboard, partagee entre les six vues.

    Tous les champs sont facultatifs : un champ None signifie \"pas de
    filtre sur cette dimension\". Les select_* ci-dessous renseignent les
    champs LIES a la selection principale (ex: selectionner un flow
    renseigne aussi endpoint/protocol/pair), par derivation depuis les
    objets reels -- jamais en devinant.
    """

    point: str | None = None
    endpoint: str | None = None  # adresse IP (Flow.endpoints)
    protocol: str | None = None
    flow_key: tuple | None = None
    pair: tuple[str, str] | None = None
    bucket: int | None = None  # indice de bucket timeline
    event_id: int | None = None  # indice dans la liste des evenements


def clear_selection(selection: DashboardSelection) -> DashboardSelection:
    """Reinitialise toutes les dimensions de la selection."""
    logger.debug("clear_selection: sélection réinitialisée")
    return DashboardSelection()


# ---------------------------------------------------------------------------
# Selecteurs : modifient le contexte et propagent les champs lies
# ---------------------------------------------------------------------------


def _flow_protocol(flow: Flow) -> str | None:
    """Protocole d'un Flow, robuste aux deux formes de cle flow_key
    (strict : (proto, src, ...) ; NAT : (\"NAT\", proto, ...))."""
    key = flow.key
    if not key:
        logger.debug("_flow_protocol: flux sans clé, protocole inconnu")
        return None
    if key[0] == "NAT" and len(key) >= 2:
        logger.debug("_flow_protocol: clé NAT, protocole {}", key[1])
        return key[1]
    return key[0]


def select_flow(selection: DashboardSelection, flow: Flow) -> DashboardSelection:
    """Selectionne un flow et propage endpoint/protocole/paire.

    pair n'est derive que si le flow a ete vu sur exactement deux points
    (semantique d'un segment A -> B) ; sinon laisse la paire inchangee
    (un flow vu sur un seul point ou sur trois+ points ne definit pas une
    paire de segment unique).
    """
    proto = _flow_protocol(flow)
    endpoints = flow.endpoints  # (src, dst) | None
    new_pair = selection.pair
    if len(flow.points) == 2:
        new_pair = (flow.points[0], flow.points[1])
    logger.debug(
        "select_flow: flow={} proto={} endpoints={} paire={}",
        flow.key,
        proto,
        endpoints,
        new_pair,
    )
    return replace(
        selection,
        flow_key=flow.key,
        endpoint=endpoints[0] if endpoints else selection.endpoint,
        protocol=proto or selection.protocol,
        pair=new_pair,
    )


def select_endpoint(selection: DashboardSelection, endpoint: str) -> DashboardSelection:
    logger.debug("select_endpoint: {}", endpoint)
    return replace(selection, endpoint=endpoint)


def select_protocol(selection: DashboardSelection, protocol: str) -> DashboardSelection:
    logger.debug("select_protocol: {}", protocol)
    return replace(selection, protocol=protocol)


def select_point(selection: DashboardSelection, point: str) -> DashboardSelection:
    logger.debug("select_point: {}", point)
    return replace(selection, point=point)


def select_bucket(selection: DashboardSelection, bucket: int) -> DashboardSelection:
    logger.debug("select_bucket: {}", bucket)
    return replace(selection, bucket=bucket)


def select_event(
    selection: DashboardSelection,
    event_id: int,
    events: list[Any],
) -> DashboardSelection:
    """Selectionne un evenement et propage point/protocole si presents.

    Les evenements sont heterogenes (ExpertEvent issus de Finding ou de
    tshark) : on lit les champs via getattr avec valeur par defaut, sans
    jamais supposer un attribut absent.
    """
    if not (0 <= event_id < len(events)):
        logger.debug("select_event: indice {} hors bornes ({} événement(s)), pas de propagation", event_id, len(events))
        return replace(selection, event_id=event_id)
    ev = events[event_id]
    proto = getattr(ev, "protocol", None)
    segment = getattr(ev, "segment", None)
    point = None
    if segment and "->" not in segment:
        point = segment  # segment = un point seul, pas une paire "A -> B"
    logger.debug("select_event: #{} proto={} point={}", event_id, proto, point)
    return replace(
        selection,
        event_id=event_id,
        protocol=proto or selection.protocol,
        point=point or selection.point,
    )


# ---------------------------------------------------------------------------
# Snapshot : les six vues, filtres par la selection courante
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DashboardSnapshot:
    """Lignes pretes a afficher pour les six vues du dashboard, plus un
    resume textuel du contexte selectionne. Toutes les listes sont
    potentiellement filtrees par DashboardSelection."""

    timeline_rows: list[dict] = field(default_factory=list)
    segment_rows: list[dict] = field(default_factory=list)
    flow_rows: list[dict] = field(default_factory=list)
    endpoint_rows: list[dict] = field(default_factory=list)
    protocol_rows: list[dict] = field(default_factory=list)
    event_rows: list[dict] = field(default_factory=list)
    selection_summary: str = ""


def _flow_matches(flow: Flow, sel: DashboardSelection) -> bool:
    if sel.protocol is not None and _flow_protocol(flow) != sel.protocol:
        return False
    if sel.endpoint is not None:
        eps = flow.endpoints or ()
        if sel.endpoint not in eps:
            return False
    if sel.flow_key is not None and flow.key != sel.flow_key:
        return False
    return not (sel.point is not None and sel.point not in flow.points)


def _event_matches(ev: Any, sel: DashboardSelection) -> bool:
    if sel.protocol is not None:
        proto = getattr(ev, "protocol", None)
        if proto is not None and proto != sel.protocol:
            return False
    if sel.point is not None:
        segment = getattr(ev, "segment", None)
        if segment is not None and segment != sel.point and sel.point not in (segment or ""):
            return False
    return True


def _summary(sel: DashboardSelection) -> str:
    parts = []
    if sel.point is not None:
        parts.append(f"point={sel.point}")
    if sel.endpoint is not None:
        parts.append(f"endpoint={sel.endpoint}")
    if sel.protocol is not None:
        parts.append(f"proto={sel.protocol}")
    if sel.flow_key is not None:
        parts.append("flow=selectionne")
    if sel.pair is not None:
        parts.append(f"segment={' -> '.join(sel.pair)}")
    if sel.bucket is not None:
        parts.append(f"bucket={sel.bucket}")
    if sel.event_id is not None:
        parts.append(f"evenement=#{sel.event_id}")
    logger.debug("_summary: {} dimension(s) active(s)", len(parts))
    return " | ".join(parts) if parts else "aucune selection active"


def build_dashboard_snapshot(
    report: Report | None,
    flows: list[Flow] | None,
    findings: list[Any] | None = None,
    tls_findings: list[Any] | None = None,
    quic_findings: list[Any] | None = None,
    wireshark_expert_events: list[Any] | None = None,
    selection: DashboardSelection | None = None,
) -> DashboardSnapshot:
    """Construit le snapshot des six vues a partir des memes objets que le
    rapport, en appliquant les filtres de la selection courante.

    Tolere des entrees None (analyse pas encore lancee) : renvoie un
    snapshot vide plutot que de planter.
    """
    logger.debug(
        "build_dashboard_snapshot: rapport={} flux={} findings={} tls={} quic={} tshark={}",
        report is not None,
        len(flows or []),
        len(findings or []),
        len(tls_findings or []),
        len(quic_findings or []),
        len(wireshark_expert_events or []),
    )
    sel = selection or DashboardSelection()
    flows = flows or []
    findings = findings or []
    tls_findings = tls_findings or []
    quic_findings = quic_findings or []
    expert_events = wireshark_expert_events or []

    # Evenements : union des Finding (source netcross) et ExpertEvent tshark,
    # chaque entree portant son indice dans la liste fusionnee (cle de
    # selection via select_event). Les ExpertEvent issus de tshark sont des
    # signaux bruts, jamais des diagnostics definitifs -- gardes distincts
    # par le champ source.
    all_events: list[Any] = []
    all_events.extend(findings)
    all_events.extend(tls_findings)
    all_events.extend(quic_findings)
    all_events.extend(expert_events)

    # -- flows filtres --
    visible_flows = [f for f in flows if _flow_matches(f, sel)]
    logger.debug("build_dashboard_snapshot: {}/{} flux visible(s) après filtre", len(visible_flows), len(flows))

    flow_rows: list[dict] = []
    for f in visible_flows:
        eps = f.endpoints or (None, None)
        total_pkts = sum(f.packet_count.values())
        total_bytes = sum(f.byte_count.values())
        first_ts = min(f.first_ts.values()) if f.first_ts else None
        last_ts = max(f.last_ts.values()) if f.last_ts else None
        flow_rows.append(
            {
                "flow_key": f.key,
                "label": f"{_flow_protocol(f) or '?'} {eps[0]}:{_port(f, 0)} -> {eps[1]}:{_port(f, 1)}",
                "endpoints": list(eps),
                "protocol": _flow_protocol(f),
                "points": list(f.points),
                "packets": total_pkts,
                "bytes": total_bytes,
                "first_ts": first_ts,
                "last_ts": last_ts,
            }
        )

    # -- endpoints (regroupes par conversation) --
    conversations = _build_conversations(visible_flows)
    endpoint_rows: list[dict] = [
        {
            "endpoint": ep,
            "peer": eps[1] if ep == eps[0] else eps[0],
            "flows": len(conv.flow_keys),
            "packets": conv.packet_count,
            "bytes": conv.byte_count,
        }
        for conv in conversations
        for ep in conv.endpoints
    ]
    # deduplique par endpoint en sommant
    endpoint_rows = _dedup_endpoints(endpoint_rows)

    # -- protocoles --
    proto_stats: dict[str, dict] = {}
    for f in visible_flows:
        p = _flow_protocol(f) or "?"
        s = proto_stats.setdefault(p, {"flows": 0, "packets": 0, "endpoints": set()})
        s["flows"] += 1
        s["packets"] += sum(f.packet_count.values())
        if f.endpoints:
            s["endpoints"].update(f.endpoints)
    protocol_rows = [
        {
            "protocol": p,
            "flows": s["flows"],
            "packets": s["packets"],
            "endpoints": sorted(s["endpoints"]),
        }
        for p, s in sorted(proto_stats.items())
    ]

    # -- segments (paires de points) --
    segment_rows: list[dict] = []
    if report is not None:
        for pair in report.pairs:
            if sel.point is not None and sel.point not in pair:
                continue
            a, b = pair
            loss = report.loss_count.get(a, 0) + report.loss_count.get(b, 0)
            retrans = report.retrans.get(a, 0) + report.retrans.get(b, 0)
            lats = report.latency.get(pair, [])
            avg_lat = round(sum(lats) / len(lats), 3) if lats else None
            segment_rows.append(
                {
                    "pair": f"{a} -> {b}",
                    "pair_tuple": pair,
                    "loss": loss,
                    "retrans": retrans,
                    "latency_ms": avg_lat,
                }
            )

    # -- timeline (pertes par bucket) --
    timeline_rows: list[dict] = []
    if report is not None:
        bucket_events: dict[int, list[str]] = {}
        for pair, buckets in report.loss_event_buckets.items():
            if sel.point is not None and sel.point not in pair:
                continue
            for bk in buckets:
                bucket_events.setdefault(bk, []).append(" -> ".join(pair))
        timeline_rows = [
            {
                "bucket": bk,
                "label": _bucket_label(bk, report.bucket_seconds),
                "loss_events": len(bucket_events[bk]),
                "segments": sorted(set(bucket_events[bk])),
            }
            for bk in sorted(bucket_events)
        ]

    # -- evenements filtres --
    event_rows: list[dict] = []
    for idx, ev in enumerate(all_events):
        if not _event_matches(ev, sel):
            continue
        event_rows.append(
            {
                "id": idx,
                "category": getattr(ev, "category", None),
                "severity": getattr(ev, "severity", None),
                "segment": getattr(ev, "segment", None),
                "message": getattr(ev, "message", None),
                "source": getattr(ev, "source", "netcross"),
                "protocol": getattr(ev, "protocol", None),
            }
        )

    logger.debug(
        "build_dashboard_snapshot: timeline={} segments={} flows={} endpoints={} protocoles={} evenements={}/{}",
        len(timeline_rows),
        len(segment_rows),
        len(flow_rows),
        len(endpoint_rows),
        len(protocol_rows),
        len(event_rows),
        len(all_events),
    )
    return DashboardSnapshot(
        timeline_rows=timeline_rows,
        segment_rows=segment_rows,
        flow_rows=flow_rows,
        endpoint_rows=endpoint_rows,
        protocol_rows=protocol_rows,
        event_rows=event_rows,
        selection_summary=_summary(sel),
    )


# ---------------------------------------------------------------------------
# Helpers prives
# ---------------------------------------------------------------------------


def _port(flow: Flow, side: int) -> str:
    """Port d'un cote du flow, robuste aux deux formes de cle. Retourne
    une chaine (\"?\" si indeterminable) -- affichage uniquement."""
    key = flow.key
    if not key:
        return "?"
    if key[0] == "NAT":
        logger.debug("_port: clé NAT, port illisible")
        return "?"  # cle NAT : pas de port lisible
    # strict : (proto, src, sport, dst, dport, key_id)
    try:
        return str(key[2] if side == 0 else key[4])
    except IndexError:
        # repli attendu (cle plus courte que la forme stricte) : affichage "?"
        logger.debug("_port: clé de flux trop courte pour le côté {} : {}", side, key)
        return "?"


def _build_conversations(flows: list[Flow]) -> list[Conversation]:
    """Regroupe les flows par paire d'endpoints (qui parle a qui)."""
    convs: dict[tuple[str, str], Conversation] = {}
    for f in flows:
        if not f.endpoints:
            continue
        ep = tuple(sorted(f.endpoints))
        conv = convs.setdefault(ep, Conversation(endpoints=ep))  # type: ignore[arg-type]
        conv.flow_keys.append(f.key)
        conv.packet_count += sum(f.packet_count.values())
        conv.byte_count += sum(f.byte_count.values())
    logger.debug("_build_conversations: {} flux -> {} conversation(s)", len(flows), len(convs))
    return list(convs.values())


def _dedup_endpoints(rows: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for r in rows:
        ep = r["endpoint"]
        m = merged.setdefault(ep, {"endpoint": ep, "peers": set(), "flows": 0, "packets": 0, "bytes": 0})
        m["peers"].add(r["peer"])
        m["flows"] += r["flows"]
        m["packets"] += r["packets"]
        m["bytes"] += r["bytes"]
    logger.debug("_dedup_endpoints: {} ligne(s) -> {} endpoint(s)", len(rows), len(merged))
    return [
        {
            "endpoint": ep,
            "peers": sorted(m["peers"]),
            "flows": m["flows"],
            "packets": m["packets"],
            "bytes": m["bytes"],
        }
        for ep, m in sorted(merged.items())
    ]


def _bucket_label(bucket: int, bucket_seconds: float) -> str:
    start = bucket * bucket_seconds
    end = start + bucket_seconds
    logger.debug("_bucket_label: bucket={} -> {:.1f}-{:.1f}s", bucket, start, end)
    return f"{start:.1f}-{end:.1f}s"


__all__ = [
    "DashboardSelection",
    "DashboardSnapshot",
    "build_dashboard_snapshot",
    "clear_selection",
    "select_bucket",
    "select_endpoint",
    "select_event",
    "select_flow",
    "select_point",
    "select_protocol",
]
