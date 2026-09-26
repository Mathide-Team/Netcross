"""netcross_gtk4.stats_view -- logique de presentation pour la vue
d'exploration statistique (Job 27 / issue #22, section 6.8).

Etat de PRESENTATION / interaction UI, mais pur Python (aucun import Gtk) :
testable sans display, comme dashboard_context.py. Le cablage des widgets
GTK reels reste dans app.py.

Objet : formater les StatRow produites par netcross_core.stats.compute_stats()
pour l'affichage, gerer le drill-down (selection d'une ligne -> ses flux),
et valider les entrees UI.
"""

from __future__ import annotations

from typing import Any

from netcross_core.expert_model import Flow
from netcross_core.i18n import N_, _
from netcross_core.logging_config import get_logger
from netcross_core.models import Report
from netcross_core.stats import GROUP_BY, SORT_BY, StatRow, StatsQuery, compute_stats

logger = get_logger(__name__)

# -- Formatage pour affichage -----------------------------------------------

_SORT_LABELS: dict[str, str] = {
    "packets": N_("Paquets"),
    "bytes": N_("Octets"),
    "duration_ms": N_("Duree (ms)"),
    "throughput_bps": N_("Debit (bps)"),
    "latency_ms": N_("Latence (ms)"),
    "events": N_("Evenements"),
}

_GROUP_LABELS: dict[str, str] = {
    "endpoint": N_("Endpoint"),
    "protocol": N_("Protocole"),
    "segment": N_("Segment"),
    "flow": N_("Flux"),
}


def sort_options() -> list[tuple[str, str]]:
    """Options de tri pour un DropDown : (valeur, etiquette)."""
    logger.debug("sort_options: {} option(s)", len(SORT_BY))
    return [(s, _(_SORT_LABELS[s]) if s in _SORT_LABELS else s) for s in SORT_BY]


def group_options() -> list[tuple[str, str]]:
    """Options de regroupement pour un DropDown : (valeur, etiquette)."""
    logger.debug("group_options: {} option(s)", len(GROUP_BY))
    return [(g, _(_GROUP_LABELS[g]) if g in _GROUP_LABELS else g) for g in GROUP_BY]


def format_bytes(n: int) -> str:
    """Formate un nombre d'octets en unite lisible."""
    if n < 1024:
        return _("{n} o").format(n=n)
    if n < 1024 * 1024:
        return _("{v:.1f} Ko").format(v=n / 1024)
    if n < 1024 * 1024 * 1024:
        return _("{v:.1f} Mo").format(v=n / (1024 * 1024))
    return _("{v:.1f} Go").format(v=n / (1024 * 1024 * 1024))


def format_bps(bps: float) -> str:
    """Formate un debit en bits/s en unite lisible."""
    if bps < 1000:
        return f"{bps:.0f} bps"
    if bps < 1_000_000:
        return f"{bps / 1000:.1f} kbps"
    return f"{bps / 1_000_000:.1f} Mbps"


def format_row(row: StatRow) -> str:
    """Formate une ligne StatRow pour affichage dans un bouton/label.

    Format : "label | paquets=N octets=X duree=Dms debit=Bps latence=Lms evenements=E"
    Les champs None (latence) sont omis.
    """
    parts = [row.label]
    parts.append(_("paquets={n}").format(n=row.packets))
    parts.append(_("octets={v}").format(v=format_bytes(row.bytes)))
    if row.duration_ms > 0:
        parts.append(_("duree={v:.0f}ms").format(v=row.duration_ms))
    if row.throughput_bps > 0:
        parts.append(_("debit={v}").format(v=format_bps(row.throughput_bps)))
    if row.latency_ms is not None:
        parts.append(_("latence={v:.1f}ms").format(v=row.latency_ms))
    if row.events > 0:
        parts.append(_("evenements={n}").format(n=row.events))
    logger.debug("format_row: {} -> {} champ(s)", row.label, len(parts))
    return " | ".join(parts)


def format_rows(rows: list[StatRow]) -> list[str]:
    """Formate une liste de StatRow pour affichage."""
    logger.debug("format_rows: {} ligne(s)", len(rows))
    return [format_row(r) for r in rows]


# -- Drill-down : selection d'une ligne -> ses flux ---------------------------


def flows_for_row(row: StatRow, all_flows: list[Flow]) -> list[Flow]:
    """Retourne les flux correspondant a une ligne statistique.

    Utilise les flow_keys stockees dans la StatRow pour retrouver les flux
    dans la liste complete.
    """
    key_set = set(row.flow_keys)
    logger.debug("flows_for_row: {} -> {} clé(s) parmi {} flux", row.label, len(key_set), len(all_flows))
    return [f for f in all_flows if f.key in key_set]


def format_flow_summary(flow: Flow) -> str:
    """Resume un flux pour l'affichage drill-down."""
    total_pkts = sum(flow.packet_count.values())
    total_bytes = sum(flow.byte_count.values())
    points = " -> ".join(flow.points) if flow.points else "?"
    endpoints = " <-> ".join(flow.endpoints) if flow.endpoints else "?"
    if not flow.points or not flow.endpoints:
        logger.debug(
            "format_flow_summary: flux {} sans points={} ou endpoints={}, affiché ?",
            flow.key,
            not flow.points,
            not flow.endpoints,
        )
    return _("{points} | {endpoints} | {packets} pkts | {size}").format(
        points=points, endpoints=endpoints, packets=total_pkts, size=format_bytes(total_bytes)
    )


# -- Construction de la requete depuis les entrees UI -------------------------


def build_query(
    group_by: str,
    sort_by: str,
    top_n: int,
    time_start: float | None = None,
    time_end: float | None = None,
    segment: str | None = None,
) -> StatsQuery:
    """Construit un StatsQuery depuis les valeurs des widgets UI.

    Leve ValueError si group_by ou sort_by sont invalides (devrait etre
    impossible depuis un DropDown, mais le filet de securite est la).
    """
    logger.debug(
        "build_query: group_by={} sort_by={} top_n={} fenêtre={}-{} segment={}",
        group_by,
        sort_by,
        top_n,
        time_start,
        time_end,
        segment,
    )
    return StatsQuery(
        group_by=group_by,
        sort_by=sort_by,
        top_n=top_n if top_n > 0 else None,
        time_start=time_start,
        time_end=time_end,
        segment=segment,
    )


# -- Execution de la requete -------------------------------------------------


def run_stats(
    flows: list[Flow],
    report: Report,
    query: StatsQuery,
    events_by_segment: dict[str, list[Any]] | None = None,
) -> list[StatRow]:
    """Execute compute_stats avec une liste de flux vide si flows est None.

    Wrapper defensif : si l'analyse n'a pas encore tourne (flows=None),
    retourne une liste vide plutot que de crasher.
    """
    if not flows or report is None:
        logger.debug("run_stats: flux={} rapport={}, aucune statistique", len(flows or []), report is not None)
        return []
    # all_packets n'est pas conserve dans la GUI apres l'analyse, mais
    # compute_stats l'utilise uniquement pour _flow_packets qui n'est pas
    # appele dans le pipeline d'aggregation -- on passe une liste vide.
    logger.debug(
        "run_stats: {} flux, group_by={} sort_by={} segments_evenements={}",
        len(flows),
        query.group_by,
        query.sort_by,
        len(events_by_segment or {}),
    )
    return compute_stats(
        flows=flows,
        report=report,
        all_packets=[],
        query=query,
        events_by_segment=events_by_segment,
    )


def build_events_by_segment(
    findings: list[Any] | None,
    flows: list[Flow] | None,
) -> dict[str, list[Any]]:
    """Construit l'index evenement -> segment depuis les findings.

    Les findings ont un attribut `segment` (paire de points) ou `point`.
    On mappe chaque finding vers les segments des flux qui partagent ce
    point. En l'absence d'information de segment, on regroupe sous "?".
    """
    if not findings:
        logger.debug("build_events_by_segment: aucun finding")
        return {}
    index: dict[str, list[Any]] = {}
    for f in findings:
        seg = getattr(f, "segment", None) or getattr(f, "pair", None)
        if seg is None:
            seg = "?"
        index.setdefault(str(seg), []).append(f)
    logger.debug(
        "build_events_by_segment: {} finding(s) -> {} segment(s), {} sans segment",
        len(findings),
        len(index),
        len(index.get("?", [])),
    )
    return index


__all__ = [
    "build_events_by_segment",
    "build_query",
    "flows_for_row",
    "format_bps",
    "format_bytes",
    "format_flow_summary",
    "format_row",
    "format_rows",
    "group_options",
    "run_stats",
    "sort_options",
]
