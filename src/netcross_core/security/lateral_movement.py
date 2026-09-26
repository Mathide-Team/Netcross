"""
netcross_core.security.lateral_movement -- issue #149 (SCENARIO-3, parent
#141) : detection de mouvements latéraux internes (scans réseau,
propagation, brute force, protocoles inhabituels, nouvelles connexions).

Le module exploite uniquement les champs deja decodes de ``Pkt`` (``ts``,
``src``, ``dst``, ``sport``, ``dport``, ``proto``, ``protocol``, ``flags``,
``length``) : aucune nouvelle dissection tshark, aucune dependance externe.

Cinq detecteurs :

- **port_scan** : une source contacte >= ``port_scan_min_ports`` ports
  distincts sur >= ``port_scan_min_hosts`` hotes distincts (pattern en
  eventail). Un paquet SYN sans ACK (``flags`` commence par ``S`` sans
  ``A``) est un paquet de scan typique ; si ``scan_syn_only`` est True
  (defaut), seuls ces paquets sont comptes.

- **host_scan** : une source contacte >= ``host_scan_min_hosts`` hotes
  distincts dont les adresses IP forment une plage consecutive (au moins
  ``host_scan_consecutive_min`` adresses dans le meme /24).

- **brute_force** : tentatives repetees d'authentification (SSH port 22,
  RDP port 3389, WinRM port 5985/5986) -- >= ``brute_force_min_attempts``
  sessions (dst, port source) vers >= ``brute_force_min_hosts`` hotes distincts dans une
  fenetre glissante de ``brute_force_window_seconds`` secondes.

- **unusual_protocol** : protocoles internes inhabituels (RDP, WinRM, SMB)
  depuis un poste utilisateur (port source ephemere > 1024) vers un autre
  hote interne (RFC1918).

- **new_connection** : paire (src, dst) interne non presente dans la
  ``baseline_pairs`` fournie par l'appelant.

Anti faux positifs (critere « aucun faux positif sur trafic legitime ») :
- les adresses externes (non-RFC1918, non link-local) sont ignorees pour
  les scans/brute force (le mouvement lateral est INTERNE par definition) ;
- DNS (53), NTP (123), DHCP (67/68) sont exclus du comptage de scan ;
- un flux normal entre deux hotes internes (serveur → client) n'est pas
  un mouvement lateral : le sens « client vers serveur » est exige pour
  brute_force (port de destination bien connu) ;
- ``new_connection`` ne se declenche que si la baseline est non vide (sinon
  tout est nouveau → pas de signal utile).
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt

logger = get_logger(__name__)

# Ports d'authentification surveilles pour le brute force.
_AUTH_PORTS: frozenset[int] = frozenset({22, 3389, 5985, 5986})

# Ports ignores pour les scans (services de fond, pas des cibles).
_IGNORED_SCAN_PORTS: frozenset[int] = frozenset({53, 67, 68, 123, 137, 138, 1900, 5353})

# Ports inhabituels en interne (depuis un poste utilisateur).
# SMB=445, RDP=3389, WinRM=5985/5986
_UNUSUAL_PORTS: frozenset[int] = frozenset({445, 3389, 5985, 5986})
_UNUSUAL_PORT_LABELS: dict[int, str] = {
    445: "SMB",
    3389: "RDP",
    5985: "WinRM",
    5986: "WinRM",
}


def _is_internal(ip: str) -> bool:
    """Vrai pour une adresse RFC1918 ou link-local (169.254/16).

    Issue #365 : les plages TEST-NET (RFC 5737, 192.0.2.0/24,
    198.51.100.0/24, 203.0.113.0/24) sont aussi considerees comme privees
    par ipaddress.is_private -- documente dans docs/detectors.md.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # appele pour chaque paquet : TRACE (adresse absente ou non IP, trame L2)
        logger.trace("_is_internal: adresse non IP {!r}", ip)
        return False
    return addr.is_private or addr.is_link_local


def _is_syn_only(flags: str | None) -> bool:
    """Vrai pour un paquet TCP SYN sans ACK (drapeau S sans A)."""
    if not flags:
        return False
    has_syn = "S" in flags
    has_ack = "A" in flags
    return has_syn and not has_ack


@dataclass
class LateralMovementThresholds:
    """Seuils de detection des mouvements latéraux (tous configurables)."""

    # Port scan
    port_scan_min_ports: int = 10
    port_scan_min_hosts: int = 3
    scan_syn_only: bool = True
    # Host scan
    host_scan_min_hosts: int = 10
    host_scan_consecutive_min: int = 5
    # Brute force
    brute_force_min_attempts: int = 10
    brute_force_min_hosts: int = 2
    brute_force_window_seconds: float = 300.0
    # New connection
    new_connection_baseline_pairs: frozenset[tuple[str, str]] = field(default_factory=frozenset)


@dataclass
class LateralMovementEvent:
    """Un evenement de mouvement lateral detecte.

    Issue #346 : un meme mouvement lateral vu sur N points = UN evenement.
    `points` liste tous les points ou il a ete observe (`point` reste un
    alias retro-compatible : premier point trie, ou None si vide)."""

    point: str
    source: str
    event_type: str  # port_scan | host_scan | brute_force | unusual_protocol | new_connection
    details: str
    score: float  # 0.0 a 1.0
    targets: list[str] = field(default_factory=list)
    points: tuple[str, ...] = ()

    @property
    def points_list(self) -> list[str]:
        return list(self.points) if self.points else ([self.point] if self.point else [])


@dataclass
class LateralMovementResult:
    """Resultat de la detection de mouvements latéraux."""

    events: list[LateralMovementEvent] = field(default_factory=list)
    suspicious: bool = False

    @property
    def events_by_type(self) -> dict[str, list[LateralMovementEvent]]:
        grouped: dict[str, list[LateralMovementEvent]] = defaultdict(list)
        for ev in self.events:
            grouped[ev.event_type].append(ev)
        return grouped


def detect_port_scans(
    packets: list[Pkt],
    thresholds: LateralMovementThresholds,
) -> list[LateralMovementEvent]:
    """Detecte les scans de ports : 1 source -> N ports sur M hotes."""
    # point -> source -> {(dst, dport)}
    scan_map: dict[str, dict[str, set[tuple[str, int]]]] = defaultdict(lambda: defaultdict(set))
    for pkt in packets:
        if not _is_internal(pkt.src) or not _is_internal(pkt.dst):
            continue
        if pkt.dport in _IGNORED_SCAN_PORTS:
            continue
        if thresholds.scan_syn_only and not _is_syn_only(pkt.flags):
            continue
        if pkt.dport is not None:
            scan_map[pkt.point][pkt.src].add((pkt.dst, pkt.dport))

    events: list[LateralMovementEvent] = []
    for point, sources in scan_map.items():
        for src, dst_port_pairs in sources.items():
            ports = {p for _, p in dst_port_pairs}
            hosts = {h for h, _ in dst_port_pairs}
            if len(ports) >= thresholds.port_scan_min_ports and len(hosts) >= thresholds.port_scan_min_hosts:
                # Score : proportion des ports/hotes par rapport aux seuils.
                score = min(1.0, 0.5 + 0.5 * (len(ports) / max(len(ports), thresholds.port_scan_min_ports * 2)))
                events.append(
                    LateralMovementEvent(
                        point=point,
                        source=src,
                        event_type="port_scan",
                        details=f"scan de ports : {len(ports)} ports distincts sur {len(hosts)} hotes",
                        score=round(score, 3),
                        targets=sorted(hosts)[:20],
                    )
                )
    logger.debug("detect_port_scans: {} événement(s)", len(events))
    return events


def detect_host_scans(
    packets: list[Pkt],
    thresholds: LateralMovementThresholds,
) -> list[LateralMovementEvent]:
    """Detecte les scans d'hotes : 1 source -> plage d'IPs consecutives."""
    # point -> source -> set of dst IPs
    host_map: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for pkt in packets:
        if not _is_internal(pkt.src) or not _is_internal(pkt.dst):
            continue
        if pkt.dport in _IGNORED_SCAN_PORTS:
            continue
        if thresholds.scan_syn_only and not _is_syn_only(pkt.flags):
            continue
        host_map[pkt.point][pkt.src].add(pkt.dst)

    events: list[LateralMovementEvent] = []
    for point, sources in host_map.items():
        for src, hosts in sources.items():
            if len(hosts) < thresholds.host_scan_min_hosts:
                continue
            # Verifier si les IPs forment une plage consecutive dans le meme /24.
            try:
                addrs = sorted(ipaddress.ip_address(h) for h in hosts)
            except ValueError:
                logger.debug("detect_host_scans: {} au {}, cibles non IP ignorées", src, point)
                continue
            # Grouper par /24 et chercher des plages consecutives.
            by_prefix: dict[str, list[int]] = defaultdict(list)
            for addr in addrs:
                if isinstance(addr, ipaddress.IPv4Address):
                    net = ipaddress.ip_network(f"{addr}/24", strict=False)
                    by_prefix[str(net)].append(int(addr) % 256)

            max_consecutive = 0
            for last_octets in by_prefix.values():
                last_octets.sort()
                run = 1
                for i in range(1, len(last_octets)):
                    if last_octets[i] == last_octets[i - 1] + 1:
                        run += 1
                    else:
                        max_consecutive = max(max_consecutive, run)
                        run = 1
                max_consecutive = max(max_consecutive, run)

            if max_consecutive >= thresholds.host_scan_consecutive_min:
                score = min(1.0, max_consecutive / (thresholds.host_scan_consecutive_min * 2))
                events.append(
                    LateralMovementEvent(
                        point=point,
                        source=src,
                        event_type="host_scan",
                        details=f"scan d'hotes : {len(hosts)} hotes distincts, {max_consecutive} consecutifs",
                        score=round(score, 3),
                        targets=sorted(hosts)[:20],
                    )
                )
    logger.debug("detect_host_scans: {} événement(s)", len(events))
    return events


def detect_brute_force(
    packets: list[Pkt],
    thresholds: LateralMovementThresholds,
) -> list[LateralMovementEvent]:
    """Detecte les tentatives de brute force : auth repetee vers N hotes."""
    # Issue #346 : une tentative = une SESSION (dst, port source), pas un
    # paquet -- 36 sessions SSH de 4 paquets etaient rapportees comme
    # « 144 tentatives ». On retient l'horodatage du premier paquet.
    # point -> source -> (dst, sport) -> ts du premier paquet
    sessions: dict[str, dict[str, dict[tuple[str, int | None], float]]] = defaultdict(lambda: defaultdict(dict))
    for pkt in packets:
        if pkt.dport not in _AUTH_PORTS:
            continue
        if not _is_internal(pkt.src) or not _is_internal(pkt.dst):
            continue
        per_src = sessions[pkt.point][pkt.src]
        skey = (pkt.dst, pkt.sport)
        if skey not in per_src or pkt.ts < per_src[skey]:
            per_src[skey] = pkt.ts

    events: list[LateralMovementEvent] = []
    for point, sources in sessions.items():
        for src, per_session in sources.items():
            attempts = [(ts, dst) for (dst, _sport), ts in per_session.items()]
            if len(attempts) < thresholds.brute_force_min_attempts:
                continue
            # Fenetre glissante : trouver une fenetre ou il y a >= min_attempts
            # vers >= min_hosts hotes distincts.
            attempts.sort()
            window = thresholds.brute_force_window_seconds
            best_count = 0
            best_hosts: set[str] = set()
            for _i, (ts_start, _) in enumerate(attempts):
                window_attempts = [(ts, dst) for ts, dst in attempts if ts_start <= ts <= ts_start + window]
                hosts = {dst for _, dst in window_attempts}
                if (
                    len(window_attempts) >= thresholds.brute_force_min_attempts
                    and len(hosts) >= thresholds.brute_force_min_hosts
                ) and len(window_attempts) > best_count:
                    best_count = len(window_attempts)
                    best_hosts = hosts

            if best_count >= thresholds.brute_force_min_attempts:
                score = min(1.0, best_count / (thresholds.brute_force_min_attempts * 2))
                events.append(
                    LateralMovementEvent(
                        point=point,
                        source=src,
                        event_type="brute_force",
                        details=f"brute force : {best_count} tentatives vers {len(best_hosts)} hotes",
                        score=round(score, 3),
                        targets=sorted(best_hosts)[:20],
                    )
                )
    logger.debug("detect_brute_force: {} événement(s)", len(events))
    return events


def detect_unusual_protocols(
    packets: list[Pkt],
    thresholds: LateralMovementThresholds,
) -> list[LateralMovementEvent]:
    """Detecte les protocoles inhabituels en interne (SMB, RDP, WinRM).
    Base sur les ports de destination : 445 (SMB), 3389 (RDP), 5985/5986
    (WinRM) depuis un poste utilisateur (port source > 1024)."""
    # point -> source -> set of (dst, port_label)
    proto_map: dict[str, dict[str, set[tuple[str, str]]]] = defaultdict(lambda: defaultdict(set))
    for pkt in packets:
        if pkt.dport not in _UNUSUAL_PORTS:
            continue
        if not _is_internal(pkt.src) or not _is_internal(pkt.dst):
            continue
        # Port source ephemere (client) -> poste utilisateur
        if pkt.sport is None or pkt.sport <= 1024:
            continue
        label = _UNUSUAL_PORT_LABELS.get(pkt.dport, str(pkt.dport))
        proto_map[pkt.point][pkt.src].add((pkt.dst, label))

    events: list[LateralMovementEvent] = []
    for point, sources in proto_map.items():
        for src, targets in sources.items():
            protocols = {p for _, p in targets}
            hosts = {h for h, _ in targets}
            score = min(1.0, 0.4 + 0.2 * len(protocols))
            events.append(
                LateralMovementEvent(
                    point=point,
                    source=src,
                    event_type="unusual_protocol",
                    details=(
                        f"protocole(s) inhabituel(s) en interne : "
                        f"{', '.join(sorted(protocols))} vers {len(hosts)} hote(s)"
                    ),
                    score=round(score, 3),
                    targets=sorted(hosts)[:20],
                )
            )
    logger.debug("detect_unusual_protocols: {} événement(s)", len(events))
    return events


def detect_new_connections(
    packets: list[Pkt],
    thresholds: LateralMovementThresholds,
) -> list[LateralMovementEvent]:
    """Detecte les nouvelles connexions internes non presentes dans la baseline."""
    baseline = thresholds.new_connection_baseline_pairs
    if not baseline:
        logger.debug("detect_new_connections: pas de baseline, détection ignorée")
        return []  # Sans baseline, tout est nouveau → pas de signal utile.

    # point -> set of (src, dst) internes non dans la baseline
    new_pairs: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for pkt in packets:
        if not _is_internal(pkt.src) or not _is_internal(pkt.dst):
            continue
        pair = (pkt.src, pkt.dst)
        if pair not in baseline:
            new_pairs[pkt.point].add(pair)

    events: list[LateralMovementEvent] = []
    for point, pairs in new_pairs.items():
        if not pairs:
            continue
        # Grouper par source
        by_source: dict[str, set[str]] = defaultdict(set)
        for src, dst in pairs:
            by_source[src].add(dst)
        for src, dsts in by_source.items():
            score = min(1.0, 0.3 + 0.1 * len(dsts))
            events.append(
                LateralMovementEvent(
                    point=point,
                    source=src,
                    event_type="new_connection",
                    details=f"nouvelle connexion interne vers {len(dsts)} hote(s) non baseline",
                    score=round(score, 3),
                    targets=sorted(dsts)[:20],
                )
            )
    logger.debug("detect_new_connections: {} événement(s)", len(events))
    return events


def detect_lateral_movement(
    packets: Iterable[Pkt],
    thresholds: LateralMovementThresholds | None = None,
) -> LateralMovementResult:
    """Detection des mouvements latéraux internes.

    ``thresholds`` : configuration des seuils (defauts si None).
    ``thresholds.new_connection_baseline_pairs`` : ensemble de paires
    (src, dst) considerees comme normales ; si vide, la detection
    ``new_connection`` est desactivee (pas de baseline → pas de signal).

    Retourne un :class:`LateralMovementResult` avec les evenements
    detectes et un flag ``suspicious`` si au moins un evenement a ete leve.
    """
    if thresholds is None:
        thresholds = LateralMovementThresholds()

    packets = list(packets)
    events: list[LateralMovementEvent] = []
    events.extend(detect_port_scans(packets, thresholds))
    events.extend(detect_host_scans(packets, thresholds))
    events.extend(detect_brute_force(packets, thresholds))
    events.extend(detect_unusual_protocols(packets, thresholds))
    events.extend(detect_new_connections(packets, thresholds))

    # Issue #346 : dedoublonner les evenements multi-points -- un meme
    # mouvement lateral (source, type, cibles) vu sur N points de capture
    # est UN evenement avec N points, pas N evenements separes.
    deduped: dict[tuple[str, str, str], LateralMovementEvent] = {}
    for ev in events:
        key = (ev.source, ev.event_type, ev.details)
        if key in deduped:
            existing = deduped[key]
            pts = set(existing.points_list) | {ev.point}
            deduped[key] = LateralMovementEvent(
                point=sorted(pts)[0] if pts else ev.point,
                source=ev.source,
                event_type=ev.event_type,
                details=ev.details,
                score=max(existing.score, ev.score),
                targets=sorted(set(existing.targets) | set(ev.targets)),
                points=tuple(sorted(pts)),
            )
        else:
            deduped[key] = LateralMovementEvent(
                point=ev.point,
                source=ev.source,
                event_type=ev.event_type,
                details=ev.details,
                score=ev.score,
                targets=ev.targets,
                points=(ev.point,) if ev.point else (),
            )
    events = list(deduped.values())

    logger.debug("detect_lateral_movement: {} événement(s) au total", len(events))
    return LateralMovementResult(events=events, suspicious=bool(events))
