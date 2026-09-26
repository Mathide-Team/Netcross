"""
Resume d'un export NetFlow (issue #362) : volumes, protocoles, principaux
emetteurs, conversations et ports de destination.

Le paquet `netcross_core.netflow` (Job 32, issue #32) n'etait appele par
aucun point d'entree. Ce module produit la vue exposee par le CLI
(`--netflow`, sortie texte et `--json-report`). Il travaille sur les
FlowRecord eux-memes, sans passer par l'adaptateur Pkt : un flux NetFlow
est un agregat vu par UN exportateur, et l'analyse croisee multi-points
(pertes, latence entre points) n'y a pas de sens -- voir
docs/adr/netflow-sflow-architecture.md.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone

from netcross_core.logging_config import get_logger
from netcross_core.netflow.models import FlowRecord

logger = get_logger(__name__)

SUMMARY_FORMAT_VERSION = 1

_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}


def protocol_name(number: int) -> str:
    return _PROTO_NAMES.get(number, str(number))


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def _counter() -> dict[str, int]:
    return {"flows": 0, "packets": 0, "octets": 0}


def _add(bucket: dict[str, int], flow: FlowRecord) -> None:
    bucket["flows"] += 1
    bucket["packets"] += flow.packets
    bucket["octets"] += flow.octets


def _top(items: dict, top: int, fields) -> list[dict]:
    ranked = sorted(items.items(), key=lambda kv: (-kv[1]["octets"], -kv[1]["flows"], repr(kv[0])))
    return [{**fields(key), **counts} for key, counts in ranked[:top]]


def summarize_flow_records(records: Iterable[FlowRecord], *, top: int = 10) -> dict:
    """Resume serialisable en JSON (cles stables, `version` pour les evolutions).

    Classements par volume (octets) decroissant, departage par nombre de
    flux puis par cle -- deterministe. `top` borne chaque classement."""
    totals = _counter()
    exporters: dict[str, dict[str, int]] = defaultdict(_counter)
    protocols: dict[str, dict[str, int]] = defaultdict(_counter)
    talkers: dict[str, dict[str, int]] = defaultdict(_counter)
    conversations: dict[tuple, dict[str, int]] = defaultdict(_counter)
    dst_ports: dict[tuple, dict[str, int]] = defaultdict(_counter)
    start: float | None = None
    end: float | None = None
    versions: set[int] = set()

    for flow in records:
        proto = protocol_name(flow.protocol)
        versions.add(flow.version)
        _add(totals, flow)
        _add(exporters[flow.exporter], flow)
        _add(protocols[proto], flow)
        _add(talkers[flow.src_addr], flow)
        _add(conversations[(flow.src_addr, flow.src_port, flow.dst_addr, flow.dst_port, proto)], flow)
        if flow.dst_port is not None and proto in ("TCP", "UDP"):
            _add(dst_ports[(proto, flow.dst_port)], flow)
        start = flow.start_ts if start is None else min(start, flow.start_ts)
        end = flow.end_ts if end is None else max(end, flow.end_ts)

    logger.debug(
        "summarize_flow_records: {} flux, {} exportateur(s), {} protocole(s), versions={} top={}",
        totals["flows"],
        len(exporters),
        len(protocols),
        sorted(versions),
        top,
    )
    return {
        "version": SUMMARY_FORMAT_VERSION,
        "source": "netflow",
        "netflow_versions": sorted(versions),
        "totals": totals,
        "start": _iso(start),
        "end": _iso(end),
        "exporters": _top(exporters, len(exporters), lambda k: {"exporter": k}),
        "protocols": _top(protocols, len(protocols), lambda k: {"protocol": k}),
        "top_talkers": _top(talkers, top, lambda k: {"address": k}),
        "top_conversations": _top(
            conversations,
            top,
            lambda k: {"src": k[0], "src_port": k[1], "dst": k[2], "dst_port": k[3], "protocol": k[4]},
        ),
        "top_dst_ports": _top(dst_ports, top, lambda k: {"protocol": k[0], "port": k[1]}),
    }


def _octets(n: int) -> str:
    for unit, size in (("Go", 1 << 30), ("Mo", 1 << 20), ("Ko", 1 << 10)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} o"


def _endpoint(addr: str, port: int | None) -> str:
    return addr if port is None else f"{addr}:{port}"


def format_flow_summary(summary: dict) -> list[str]:
    """Lignes du resume texte affiche par le CLI."""
    t = summary["totals"]
    lines = ["=== Resume NetFlow ==="]
    logger.debug("format_flow_summary: {} flux à formater", t["flows"])
    if not t["flows"]:
        lines.append("Aucun flux dans les fichiers fournis.")
        return lines
    versions = ", ".join(f"v{v}" for v in summary["netflow_versions"])
    lines.append(f"{t['flows']} flux, {t['packets']} paquets, {_octets(t['octets'])} (NetFlow {versions})")
    lines.append(f"Periode : {summary['start']} -> {summary['end']}")
    lines.append("\n-- Exportateurs --")
    lines.extend(f"  {e['exporter']:20s} {e['flows']:6d} flux  {_octets(e['octets'])}" for e in summary["exporters"])
    lines.append("\n-- Protocoles --")
    lines.extend(
        f"  {p['protocol']:8s} {p['flows']:6d} flux  {p['packets']:8d} paquets  {_octets(p['octets'])}"
        for p in summary["protocols"]
    )
    lines.append("\n-- Principaux emetteurs (octets envoyes) --")
    lines.extend(f"  {a['address']:40s} {_octets(a['octets']):>10s}  {a['flows']} flux" for a in summary["top_talkers"])
    lines.append("\n-- Principales conversations --")
    for c in summary["top_conversations"]:
        src = _endpoint(c["src"], c["src_port"])
        dst = _endpoint(c["dst"], c["dst_port"])
        lines.append(f"  {c['protocol']:5s} {src} -> {dst}  {_octets(c['octets'])}  {c['packets']} paquets")
    if summary["top_dst_ports"]:
        lines.append("\n-- Ports de destination --")
        lines.extend(
            f"  {p['protocol']}/{p['port']:<6d} {p['flows']:6d} flux  {_octets(p['octets'])}"
            for p in summary["top_dst_ports"]
        )
    return lines
