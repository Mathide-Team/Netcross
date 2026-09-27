"""
Mode batch : inventaire d'un dossier de captures et regroupement
automatique CONSERVATEUR des captures qui semblent etre plusieurs points
de vue d'un meme evenement (issue #277).

Principe de conception (voir le canvas de l'issue) : regrouper a tort deux
captures sans rapport produit un rapport croise faux mais d'apparence
normale (pertes/latences inventees) -- c'est le risque grave. Ne pas
regrouper ne coute qu'une analyse que l'utilisateur peut relancer a la
main. D'ou :

- les TROIS criteres doivent etre satisfaits pour regrouper deux captures
  (recouvrement temporel, IP communes hors infrastructure, conversation
  commune) ;
- un groupe n'accepte une capture que si elle est compatible avec CHACUN
  de ses membres (pas de chainage A~B, B~C => A+B+C) ;
- chaque decision est justifiee par ecrit, dans les deux sens : un groupe
  dit pourquoi il existe, une capture isolee dit pourquoi elle l'est, une
  capture en echec donne son motif ;
- invariant : entrees = groupees + isolees + echecs (verifie par
  `BatchPlan.check_invariant`, et par un test).

Ce module est pur (aucun appel tshark, aucun fichier) : l'inventaire se
construit a partir de paquets deja decodes (`inventory_from_packets`), ce
qui le rend testable sans capture reelle. La lecture du dossier, le
decodage et l'ecriture des rapports sont dans `cross_capture_batch_cli.py`.
"""

from __future__ import annotations

import ipaddress
import statistics
from collections.abc import Iterable
from dataclasses import dataclass, field

# Ports des services d'infrastructure omnipresents (DNS, NTP, DHCP, mDNS,
# LLMNR, NetBIOS, SSDP) : une IP qui n'apparait QUE dans ce trafic (le
# resolveur, le serveur NTP...) est presente dans toutes les captures d'un
# meme reseau et ne prouve rien sur le fait qu'elles observent le meme flux.
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)
INFRA_PORTS = frozenset({53, 67, 68, 123, 137, 138, 5353, 5355, 1900})

DEFAULT_MIN_OVERLAP = 0.5
DEFAULT_MIN_COMMON_IPS = 2
DEFAULT_GROUP_WINDOW = 60.0
# En dessous, un decalage estime n'est pas mentionne : c'est l'ordre de
# grandeur de la latence entre deux points de capture, pas un defaut
# d'horloge.
CLOCK_OFFSET_REPORT_THRESHOLD = 0.5


@dataclass
class CaptureInventory:
    """Resume d'une capture, suffisant pour decider d'un regroupement."""

    label: str
    path: str
    packet_count: int = 0
    start: float | None = None
    end: float | None = None
    ips: set[str] = field(default_factory=set)
    # premier instant ou chaque conversation (src, dst) orientee est vue --
    # sert a estimer un decalage d'horloge entre deux captures.
    pairs: dict[tuple[str, str], float] = field(default_factory=dict)
    protocols: set[str] = field(default_factory=set)
    error: str | None = None

    @property
    def duration(self) -> float:
        if self.start is None or self.end is None:
            return 0.0
        return max(0.0, self.end - self.start)

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "path": self.path,
            "packet_count": self.packet_count,
            "start": self.start,
            "end": self.end,
            "ips": sorted(self.ips),
            "pairs": [[s, d, ts] for (s, d), ts in sorted(self.pairs.items())],
            "protocols": sorted(self.protocols),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CaptureInventory:
        return cls(
            label=data["label"],
            path=data["path"],
            packet_count=int(data.get("packet_count", 0)),
            start=data.get("start"),
            end=data.get("end"),
            ips=set(data.get("ips", [])),
            pairs={(s, d): float(ts) for s, d, ts in data.get("pairs", [])},
            protocols=set(data.get("protocols", [])),
            error=data.get("error"),
        )


def _is_meaningful_ip(addr: str) -> bool:
    """Exclut broadcast, multicast, non specifiee, loopback et lien-local :
    presentes partout, elles ne distinguent aucune capture."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        logger.exception("échec dans _is_meaningful_ip")
        return False
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
        return False
    return not (isinstance(ip, ipaddress.IPv4Address) and (addr == "255.255.255.255" or addr.endswith(".255")))


def _is_infra(pkt) -> bool:
    return (pkt.sport in INFRA_PORTS) or (pkt.dport in INFRA_PORTS)


def inventory_from_packets(label: str, path: str, packets: Iterable) -> CaptureInventory:
    """Construit l'inventaire d'une capture a partir de ses paquets decodes
    (objets exposant ts, src, dst, sport, dport, proto -- `Pkt` ou
    equivalent)."""
    logger.debug("inventory_from_packets(label={}, path={})", label, path)
    inv = CaptureInventory(label=label, path=path)
    for pkt in packets:
        inv.packet_count += 1
        ts = float(pkt.ts)
        inv.start = ts if inv.start is None else min(inv.start, ts)
        inv.end = ts if inv.end is None else max(inv.end, ts)
        if pkt.proto:
            inv.protocols.add(str(pkt.proto).upper())
        if _is_infra(pkt):
            continue
        src_ok = _is_meaningful_ip(pkt.src)
        dst_ok = _is_meaningful_ip(pkt.dst)
        if src_ok:
            inv.ips.add(pkt.src)
        if dst_ok:
            inv.ips.add(pkt.dst)
        if src_ok and dst_ok:
            key = (pkt.src, pkt.dst)
            prev = inv.pairs.get(key)
            if prev is None or ts < prev:
                inv.pairs[key] = ts
    return inv


@dataclass
class PairEvaluation:
    """Resultat de la comparaison de deux captures, avec ses chiffres :
    c'est ce qui alimente la justification ecrite."""

    a: str
    b: str
    overlap_ratio: float
    overlap_start: float | None
    overlap_end: float | None
    common_ips: list[str]
    common_pairs: list[tuple[str, str]]
    common_protocols: list[str]
    clock_offset: float | None  # b - a, estime sur les conversations communes
    offset_applied: bool
    failed: list[str]  # criteres non satisfaits, en clair

    @property
    def compatible(self) -> bool:
        return not self.failed

    @property
    def score(self) -> int:
        """Nombre de criteres satisfaits (0-3) : sert a choisir, pour une
        capture isolee, le candidat le plus proche a citer dans le motif."""
        return 3 - len(self.failed)


def _estimate_offset(a: CaptureInventory, b: CaptureInventory, common_pairs) -> float | None:
    if not common_pairs:
        return None
    return statistics.median(b.pairs[p] - a.pairs[p] for p in common_pairs)


def _fmt_ts(ts: float | None) -> str:
    if ts is None:
        return "?"
    import datetime

    return datetime.datetime.fromtimestamp(ts, tz=datetime.UTC).strftime("%H:%M:%S")


def _fmt_list(items, limit: int = 3) -> str:
    items = list(items)
    shown = ", ".join(items[:limit])
    if len(items) > limit:
        shown += f", ... (+{len(items) - limit})"
    return shown


def _fmt_gap(seconds: float) -> str:
    seconds = abs(seconds)
    if seconds >= 86400:
        return f"{seconds / 86400:.0f} jour(s)"
    if seconds >= 3600:
        return f"{seconds / 3600:.1f} h"
    if seconds >= 60:
        return f"{seconds / 60:.0f} min"
    return f"{seconds:.1f} s"


def evaluate_pair(
    a: CaptureInventory,
    b: CaptureInventory,
    *,
    min_overlap: float = DEFAULT_MIN_OVERLAP,
    min_common_ips: int = DEFAULT_MIN_COMMON_IPS,
    group_window: float = DEFAULT_GROUP_WINDOW,
) -> PairEvaluation:
    """Applique les trois criteres de l'issue #277 a deux captures.

    `group_window` est le decalage d'horloge maximal tolere (secondes) : si
    un decalage est estime sur les conversations communes et reste dans
    cette fenetre, le recouvrement temporel est calcule APRES correction --
    deux sondes aux horloges non synchronisees ne sont pas ecartees a tort.
    Au-dela, aucune correction : on refuse plutot que de recaler au hasard.
    """
    logger.debug("evaluate_pair(a={}, b={})", a, b)
    common_ips = sorted(a.ips & b.ips)
    common_pairs = sorted(set(a.pairs) & set(b.pairs))
    common_protocols = sorted(a.protocols & b.protocols)
    offset = _estimate_offset(a, b, common_pairs)
    applied = offset is not None and abs(offset) <= group_window

    failed: list[str] = []
    ratio = 0.0
    ov_start = ov_end = None
    if a.start is None or b.start is None or a.end is None or b.end is None:
        failed.append("aucun horodatage exploitable")
    else:
        shift = offset if applied and offset is not None else 0.0
        b_start, b_end = b.start - shift, b.end - shift
        ov_start = max(a.start, b_start)
        ov_end = min(a.end, b_end)
        shortest = min(a.duration, b.duration)
        overlap = max(0.0, ov_end - ov_start)
        # capture ponctuelle (un seul instant) : recouvre si l'instant tombe
        # dans l'autre fenetre.
        point_ratio = 1.0 if ov_end >= ov_start else 0.0
        ratio = point_ratio if shortest <= 0.0 else min(1.0, overlap / shortest)
        if ratio < min_overlap:
            if ov_end < ov_start:
                failed.append(f"hors fenetre ({_fmt_gap(ov_start - ov_end)} d'ecart)")
            else:
                failed.append(f"recouvrement temporel {ratio:.0%} < {min_overlap:.0%}")
    if len(common_ips) < min_common_ips:
        if not common_ips:
            failed.append("aucune IP commune")
        else:
            failed.append(f"{len(common_ips)} IP commune(s) < {min_common_ips}")
    if not common_pairs:
        failed.append("aucune conversation commune")
    return PairEvaluation(
        a=a.label,
        b=b.label,
        overlap_ratio=ratio,
        overlap_start=ov_start,
        overlap_end=ov_end,
        common_ips=common_ips,
        common_pairs=common_pairs,
        common_protocols=common_protocols,
        clock_offset=offset,
        offset_applied=applied,
        failed=failed,
    )


def justify(ev: PairEvaluation) -> str:
    """Justification ecrite d'un rapprochement (criteres satisfaits)."""
    logger.debug("justify(ev={})", ev)
    parts = [
        f"recouvrement {ev.overlap_ratio:.0%} ({_fmt_ts(ev.overlap_start)}-{_fmt_ts(ev.overlap_end)} UTC)",
        f"{len(ev.common_ips)} IP communes ({_fmt_list(ev.common_ips)})",
        f"{len(ev.common_pairs)} conversation(s) commune(s) ({_fmt_list(f'{s}->{d}' for s, d in ev.common_pairs)})",
    ]
    if ev.common_protocols:
        parts.append(f"{'/'.join(ev.common_protocols)} de part et d'autre")
    if ev.clock_offset is not None and abs(ev.clock_offset) >= CLOCK_OFFSET_REPORT_THRESHOLD:
        state = "corrige" if ev.offset_applied else "NON corrige (hors --group-window)"
        parts.append(f"decalage d'horloge estime {ev.clock_offset:+.3f} s ({ev.b} vs {ev.a}, {state})")
    return ", ".join(parts)


@dataclass
class CaptureGroup:
    members: list[CaptureInventory]
    evaluations: list[PairEvaluation]

    @property
    def labels(self) -> list[str]:
        return [m.label for m in self.members]


@dataclass
class IsolatedCapture:
    capture: CaptureInventory
    reason: str


@dataclass
class BatchPlan:
    total: int
    groups: list[CaptureGroup]
    isolated: list[IsolatedCapture]
    failures: list[CaptureInventory]
    grouping_enabled: bool = True

    @property
    def grouped_count(self) -> int:
        return sum(len(g.members) for g in self.groups)

    def check_invariant(self) -> None:
        """Aucun fichier perdu en route : leve AssertionError sinon."""
        logger.debug("BatchPlan.check_invariant()")
        counted = self.grouped_count + len(self.isolated) + len(self.failures)
        if counted != self.total:
            logger.debug("BatchPlan.check_invariant: refus, AssertionError")
            raise AssertionError(
                f"invariant du lot viole : {self.total} entree(s) mais {self.grouped_count} groupee(s) + "
                f"{len(self.isolated)} isolee(s) + {len(self.failures)} echec(s) = {counted}"
            )


def plan_batch(
    inventories: list[CaptureInventory],
    *,
    group: bool = True,
    min_overlap: float = DEFAULT_MIN_OVERLAP,
    min_common_ips: int = DEFAULT_MIN_COMMON_IPS,
    group_window: float = DEFAULT_GROUP_WINDOW,
) -> BatchPlan:
    """Regroupe les captures d'un lot.

    Glouton et conservateur : les captures sont parcourues par ordre de
    debut ; chacune rejoint le premier groupe dont elle est compatible avec
    TOUS les membres, sinon elle en ouvre un nouveau. Les groupes d'un seul
    membre deviennent des captures isolees, avec pour motif les criteres
    manques face au candidat le plus proche.
    """
    logger.debug("plan_batch(inventories={})", inventories)
    failures = [inv for inv in inventories if inv.error is not None]
    usable = [inv for inv in inventories if inv.error is None]
    empty = [inv for inv in usable if inv.packet_count == 0]
    candidates = sorted(
        (inv for inv in usable if inv.packet_count > 0),
        key=lambda i: (i.start if i.start is not None else float("inf"), i.label),
    )

    isolated: list[IsolatedCapture] = [IsolatedCapture(inv, "aucun paquet IP exploitable") for inv in empty]

    if not group:
        isolated.extend(IsolatedCapture(inv, "regroupement desactive (--no-group)") for inv in candidates)
        plan = BatchPlan(len(inventories), [], isolated, failures, grouping_enabled=False)
        plan.check_invariant()
        return plan

    evals: dict[tuple[str, str], PairEvaluation] = {}

    def ev(x: CaptureInventory, y: CaptureInventory) -> PairEvaluation:
        logger.debug("ev(x={}, y={})", x, y)
        key = (x.label, y.label)
        if key not in evals:
            evals[key] = evaluate_pair(
                x, y, min_overlap=min_overlap, min_common_ips=min_common_ips, group_window=group_window
            )
        return evals[key]

    buckets: list[list[CaptureInventory]] = []
    for inv in candidates:
        for bucket in buckets:
            if all(ev(m, inv).compatible for m in bucket):
                bucket.append(inv)
                break
        else:
            buckets.append([inv])

    groups: list[CaptureGroup] = []
    for bucket in buckets:
        if len(bucket) >= 2:
            pair_evals = [ev(bucket[i], bucket[j]) for i in range(len(bucket)) for j in range(i + 1, len(bucket))]
            groups.append(CaptureGroup(bucket, pair_evals))
            continue
        inv = bucket[0]
        others = [o for o in candidates if o is not inv]
        if not others:
            isolated.append(IsolatedCapture(inv, "seule capture exploitable du lot"))
            continue
        best = max(
            (ev(o, inv) if o.label < inv.label else ev(inv, o) for o in others),
            key=lambda e: (e.score, e.overlap_ratio, len(e.common_ips)),
        )
        other = best.b if best.a == inv.label else best.a
        if best.compatible:
            # compatible avec ce candidat, mais pas avec tous les membres de
            # son groupe : on le dit plutot que de pretendre a une absence
            # de lien.
            reason = f"compatible avec {other} mais pas avec tous les membres de son groupe"
        else:
            reason = f"{'; '.join(best.failed)} (candidat le plus proche : {other})"
        isolated.append(IsolatedCapture(inv, reason))

    plan = BatchPlan(len(inventories), groups, isolated, failures)
    plan.check_invariant()
    return plan


def format_batch_index(
    plan: BatchPlan,
    folder: str,
    *,
    group_reports: dict[int, str] | None = None,
    capture_reports: dict[str, str] | None = None,
    synthesis: list[str] | None = None,
) -> str:
    """Rend l'index du lot -- le vrai livrable du mode batch."""
    logger.debug("format_batch_index(plan={}, folder={})", plan, folder)
    group_reports = group_reports or {}
    capture_reports = capture_reports or {}
    lines = [f"LOT : {plan.total} capture(s), {folder}"]
    if plan.grouping_enabled:
        lines.append(
            f"  regroupees : {len(plan.groups)} groupe(s) ({plan.grouped_count} capture(s)), "
            f"{len(plan.isolated)} capture(s) isolee(s), {len(plan.failures)} echec(s)"
        )
    else:
        lines.append(f"  regroupement desactive : {len(plan.isolated)} capture(s), {len(plan.failures)} echec(s)")
    for idx, grp in enumerate(plan.groups, start=1):
        target = group_reports.get(idx)
        suffix = f"  -> analyse croisee : {target}" if target else ""
        lines.append(f"  [groupe {idx}] {' + '.join(grp.labels)}{suffix}")
        lines.extend(f"             {e.a} / {e.b} : {justify(e)}" for e in grp.evaluations)
        indiv = [capture_reports[m] for m in grp.labels if m in capture_reports]
        if indiv:
            lines.append(f"             rapports individuels : {', '.join(indiv)}")
    if plan.isolated:
        lines.append("  isolees :")
        for iso in plan.isolated:
            rep = capture_reports.get(iso.capture.label)
            rep_txt = f" -> {rep}" if rep else ""
            lines.append(f"    {iso.capture.label} ({iso.capture.path}) : {iso.reason}{rep_txt}")
    if plan.failures:
        lines.append("  echecs :")
        lines.extend(f"    {f.label} ({f.path}) : {f.error}" for f in plan.failures)
    if synthesis:
        lines.append("  synthese :")
        lines.extend(f"    {s}" for s in synthesis)
    return "\n".join(lines) + "\n"
