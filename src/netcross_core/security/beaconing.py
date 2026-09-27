"""
netcross_core.security.beaconing -- issue #147 (SCENARIO-1, parent #141) :
detection de beaconing C2 (communications periodiques d'un hote interne
vers une destination externe : check-in regulier, petites requetes).

Le module exploite uniquement les champs deja decodes de `Pkt` (`ts`,
`src`, `dst`, `sport`, `dport`, `proto`, `length`, `tcp_len`) : aucune
nouvelle dissection tshark, et aucune dependance a #145 (`flow_stats`).

Groupement : PAR POINT DE CAPTURE puis par (protocole, source, destination,
port de destination) -- l'issue propose (IP source, IP destination) ; le
port de destination est ajoute pour qu'un beacon vers `dst:443` ne soit pas
noye dans le trafic `dst:80` du meme couple. Seul le sens « client vers
serveur » est evalue (port de destination < port source) : sans cela, les
reponses periodiques d'un serveur produiraient un second constat miroir.

Un « check-in » est une rafale de paquets a charge utile non triviale : les
paquets separes de moins de `burst_gap_seconds` sont fusionnes (une requete
et ses segments ne sont pas une periodicite). Les intervalles sont mesures
entre DEBUTS de check-in.

Signaux CENTRAUX (les TROIS sont requis pour lever une suspicion) :
- **periodic** : au moins `min_checkins` check-ins, intervalle moyen >=
  `min_interval_seconds`, et coefficient de variation des intervalles
  (ecart-type / moyenne) <= `max_interval_cv`. Le CV est l'ecart-type
  « configurable » du critere d'acceptation, rendu independant de la
  cadence (un beacon de 60 s et un de 5 min se comparent) ;
- **small_payload** : charge utile mediane par check-in <=
  `small_payload_bytes` (requetes de check-in, pas un transfert) ;
- **stable_size** : CV des tailles de check-in <= `max_size_cv` (volume
  constant).

Signaux FAIBLES (jamais suffisants seuls -- ils aggravent une suspicion deja
levee, severite « elevee » au lieu de « moyenne ») :
- **asymmetric_ratio** : le serveur renvoie plus d'octets qu'il n'en recoit
  (`asymmetry_ratio`) -- telechargement de commandes ;
- **off_hours** : au moins `off_hours_ratio` des check-ins hors de
  `office_hours_utc`. Les horodatages `Pkt.ts` sont en epoch UTC : le
  fuseau du site n'est pas connu, donc les heures de bureau se reglent en
  UTC (limite assumee).

Score de confiance par flux (0 a 1, arrondi a 3 decimales) : 0.3 a 0.5 pour
la periodicite (plus le CV est bas, plus il est haut) + 0.15 par signal de
volume central + 0.1 par signal faible.

Anti faux positifs (critere « aucun faux positif sur trafic legitime ») :
- ports ignores par defaut (`ignored_ports`) : DNS (53 : voir `dns_tunnel`),
  NTP (123), DHCP (67/68), NetBIOS (137/138), SSDP (1900), mDNS (5353) ;
- un keepalive TCP (segment sans charge utile, ou d'un seul octet) n'est
  jamais un check-in (`min_payload_bytes`) ; un paquet TCP sans `tcp_len`
  (adaptateur NetFlow) est ignore ;
- destinations externes seulement (`external_only`, adresse routable
  globalement) : ni RFC 1918, ni multicast, ni broadcast, ni loopback.

Limites assumees :
- une periodicite est un INDICE a confirmer : un heartbeat cloud, un
  telemetry agent ou un polling de messagerie legitimes sont eux aussi
  reguliers, petits et constants. Les seuils par defaut sont prudents, mais
  seul l'analyste tranche (comme `dns_tunnel`/`expert_correlation`) ;
- le CV des intervalles remplace FFT/autocorrelation : il detecte bien la
  cadence fixe et la gigue moderee, pas une gigue tres forte (> ~15 %) ni
  un beacon a intervalles multiples ;
- ICMP et le trafic sans ports ne sont pas evalues ;
- l'absence de « reputation » de la destination (liste d'IP/domaines) n'est
  pas evaluee : aucune donnee de reputation dans le depot.

Sortie pure (`detect_beaconing`) : `suspicions` (une par flux).
`security.findings` la convertit en constats du rapport de securite.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from statistics import mean, median, pstdev

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt
from netcross_core.security.address_scope import is_external

logger = get_logger(__name__)

KIND_BEACON = "beacon"

SIGNAL_PERIODIC = "periodic"
SIGNAL_SMALL_PAYLOAD = "small_payload"
SIGNAL_STABLE_SIZE = "stable_size"
SIGNAL_ASYMMETRIC = "asymmetric_ratio"
SIGNAL_OFF_HOURS = "off_hours"

CORE_SIGNALS = (SIGNAL_PERIODIC, SIGNAL_SMALL_PAYLOAD, SIGNAL_STABLE_SIZE)
WEAK_SIGNALS = (SIGNAL_ASYMMETRIC, SIGNAL_OFF_HOURS)

# Nombre maximal de numeros de trame conserves comme preuve par suspicion.
_MAX_FRAMES = 10

# Poids du score de confiance (voir la docstring du module).
_SCORE_PERIODIC_BASE = 0.3
_SCORE_PERIODIC_BONUS = 0.2
_SCORE_VOLUME_SIGNAL = 0.15
_SCORE_WEAK_SIGNAL = 0.1

_SECONDS_PER_HOUR = 3600
_SECONDS_PER_DAY = 86400


@dataclass(frozen=True)
class BeaconingThresholds:
    """Seuils des signaux (voir la docstring du module). Tous parametrables."""

    min_checkins: int = 10
    max_interval_cv: float = 0.15
    min_interval_seconds: float = 5.0
    burst_gap_seconds: float = 2.0
    min_payload_bytes: int = 2
    small_payload_bytes: int = 512
    max_size_cv: float = 0.5
    asymmetry_ratio: float = 1.5
    office_hours_utc: tuple[int, int] = (7, 19)
    off_hours_ratio: float = 0.8
    external_only: bool = True
    # Issue #365 : traiter les plages TEST-NET (RFC 5737) comme externes
    # pour les demonstrations (voir security.address_scope).
    treat_test_net_as_external: bool = False
    ignored_ports: frozenset[int] = frozenset({53, 67, 68, 123, 137, 138, 1900, 5353})


DEFAULT_THRESHOLDS = BeaconingThresholds()


@dataclass
class BeaconingResult:
    """Sortie de `detect_beaconing`, meme forme de dicts que les autres detecteurs de securite."""

    suspicions: list[dict] = field(default_factory=list)


def _payload(pk: Pkt) -> int | None:
    """Octets de charge utile du paquet : `tcp_len` en TCP (None si inconnu,
    le paquet est alors ignore), longueur de la trame en UDP."""
    if pk.proto == "TCP":
        logger.debug("_payload: retour attribut")
        return pk.tcp_len
    logger.debug("_payload: retour attribut")
    return pk.length


def _cv(values: list[float]) -> float:
    """Coefficient de variation (ecart-type / moyenne) ; infini si la moyenne est nulle."""
    avg = mean(values)
    logger.debug("_cv: retour conditionnel")
    return pstdev(values) / avg if avg > 0 else float("inf")


def _checkins(events: list[tuple[float, int | None, int]], gap: float) -> list[tuple[float, int | None, int]]:
    """Fusionne les paquets separes de moins de `gap` secondes en check-ins
    `(debut, premiere trame, octets cumules)`."""
    merged: list[list] = []
    last_ts: float | None = None
    for ts, frame, size in sorted(events, key=lambda e: e[0]):
        if last_ts is None or ts - last_ts > gap:
            merged.append([ts, frame, size])
        else:
            merged[-1][2] += size
        last_ts = ts
    logger.debug("_checkins: retour liste")
    return [(m[0], m[1], m[2]) for m in merged]


def _off_hours_share(starts: list[float], office_hours: tuple[int, int]) -> float:
    start_hour, end_hour = office_hours
    off = sum(1 for ts in starts if not start_hour <= int(ts % _SECONDS_PER_DAY // _SECONDS_PER_HOUR) < end_hour)
    logger.debug("_off_hours_share: retour calcul")
    return off / len(starts)


def detect_beaconing(packets: Iterable[Pkt], thresholds: BeaconingThresholds = DEFAULT_THRESHOLDS) -> BeaconingResult:
    """Applique les signaux de la docstring du module a `packets`."""
    t = thresholds
    # Cle de flux : (point, proto, client, serveur, port serveur).
    events: dict[tuple, list[tuple[float, int | None, int]]] = defaultdict(list)
    sent: dict[tuple, int] = defaultdict(int)
    replied: dict[tuple, int] = defaultdict(int)

    for pk in packets:
        if pk.proto not in ("TCP", "UDP") or pk.sport is None or pk.dport is None:
            continue
        if pk.sport in t.ignored_ports or pk.dport in t.ignored_ports:
            continue
        size = _payload(pk)
        if size is None:
            continue
        if pk.dport < pk.sport:  # sens client -> serveur
            key = (pk.point, pk.proto, pk.src, pk.dst, pk.dport)
            sent[key] += size
            if size >= t.min_payload_bytes:
                events[key].append((pk.ts, pk.frame_number, size))
        elif pk.sport < pk.dport:  # sens serveur -> client : octets « recus » du flux miroir
            replied[(pk.point, pk.proto, pk.dst, pk.src, pk.sport)] += size

    result = BeaconingResult()
    logger.debug("beaconing : {} flux candidats a analyser", len(events))
    for key, raw_events in sorted(events.items()):
        point, proto, src, dst, dport = key
        if len(raw_events) < t.min_checkins:
            continue
        if t.external_only and not is_external(dst, treat_test_net_as_external=t.treat_test_net_as_external):
            continue
        checkins = _checkins(raw_events, t.burst_gap_seconds)
        if len(checkins) < t.min_checkins:
            continue

        starts = [c[0] for c in checkins]
        intervals = [b - a for a, b in zip(starts, starts[1:], strict=False)]
        mean_interval = mean(intervals)
        if mean_interval < t.min_interval_seconds:
            continue
        interval_cv = _cv(intervals)
        if interval_cv > t.max_interval_cv:
            continue

        sizes = [float(c[2]) for c in checkins]
        median_size = median(sizes)
        size_cv = _cv(sizes)
        signals = [SIGNAL_PERIODIC]
        if median_size <= t.small_payload_bytes:
            signals.append(SIGNAL_SMALL_PAYLOAD)
        if size_cv <= t.max_size_cv:
            signals.append(SIGNAL_STABLE_SIZE)
        if any(s not in signals for s in CORE_SIGNALS):
            continue  # une cadence reguliere seule (streaming, sauvegarde) n'est pas un beacon

        bytes_up, bytes_down = sent[key], replied[key]
        if bytes_up > 0 and bytes_down > bytes_up * t.asymmetry_ratio:
            signals.append(SIGNAL_ASYMMETRIC)
        if _off_hours_share(starts, t.office_hours_utc) >= t.off_hours_ratio:
            signals.append(SIGNAL_OFF_HOURS)

        weak = [s for s in signals if s in WEAK_SIGNALS]
        score = (
            _SCORE_PERIODIC_BASE
            + _SCORE_PERIODIC_BONUS * (1.0 - interval_cv / t.max_interval_cv)
            + _SCORE_VOLUME_SIGNAL * 2  # small_payload + stable_size, tous deux presents ici
            + _SCORE_WEAK_SIGNAL * len(weak)
        )
        frames = [c[1] for c in checkins if c[1] is not None][:_MAX_FRAMES]
        result.suspicions.append(
            {
                "kind": KIND_BEACON,
                "point": point,
                "proto": proto,
                "src": src,
                "dst": dst,
                "dport": dport,
                "signals": signals,
                "severity": "elevee" if weak else "moyenne",
                "score": round(min(score, 1.0), 3),
                "checkins": len(checkins),
                "mean_interval": round(mean_interval, 3),
                "interval_stddev": round(pstdev(intervals), 3),
                "interval_cv": round(interval_cv, 3),
                "median_bytes": round(median_size, 1),
                "bytes_up": bytes_up,
                "bytes_down": bytes_down,
                "frames": frames,
            }
        )

    logger.info("beaconing : {} suspicion(s) levee(s) sur {} flux candidats", len(result.suspicions), len(events))
    return result
