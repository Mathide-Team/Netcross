"""
netcross_core.security.expert_correlation -- issue #137 (CVE-3) :
exploitation des alertes Expert Info de tshark pour DETECTER des
tentatives d'exploitation (fuzzing, depassement de tampon, deni de
service) a partir de paquets malformes et de sequences TCP anormales.

Source des donnees : `Pkt.expert_flags`/`Pkt.expert_details`, qui portent
desormais, en plus des signaux L3/L4, les conditions d'expertise des
couches APPLICATIVES (http/dns/tls/smb/smb2) et la couche de premier
niveau `_ws_malformed` que tshark ajoute a un paquet dont un dissecteur a
leve une exception (voir pcap_parser.packet.build_packet). Aucune nouvelle
dissection : on exploite ce que tshark a deja identifie.

Trois correlations, chacune parametrable (`CorrelationThresholds`) :

- **fuzzing** : au moins `fuzzing_min_malformed` paquets malformes sur un
  MEME flux bidirectionnel (un fuzzer envoie des entrees invalides en
  rafale vers le meme service).
- **overflow** : un paquet malforme survenant au plus `overflow_window_s`
  secondes apres (ou dans) un paquet portant une anomalie de sequence TCP
  (segment perdu, ACK d'un segment non vu, desordre) sur le MEME flux --
  la signature d'une charge utile forgee qui perturbe aussi le transport.
- **dos** : au moins `dos_min_events` paquets malformes ou en erreur
  applicative (severite native Error/Warning) d'une meme source vers une
  meme destination dans une fenetre de `dos_window_s` secondes, tous flux
  confondus -- un volume anormal d'erreurs.

Une suspicion est un INDICE a confirmer (principe de
netcross_core.wireshark_expert : les signaux Wireshark sont des preuves
supplementaires, pas des diagnostics definitifs) : un equipement bogue, un
lien qui corrompt ou une capture tronquee (snaplen) produisent aussi des
paquets malformes. Les seuils par defaut sont volontairement prudents.

Sortie : pure (`correlate_expert_alerts`), puis recopiee dans `Report` par
`apply_expert_correlation` (champs `expert_malformed*` et
`exploit_suspicion*`, voir netcross_core.models.Report).
"""

from __future__ import annotations

from bisect import bisect_right
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt, Report

logger = get_logger(__name__)

KIND_FUZZING = "fuzzing"
KIND_OVERFLOW = "overflow"
KIND_DOS = "dos"

# Nombre maximal de numeros de trame conserves comme preuve par entree.
_MAX_FRAMES = 10

# Anomalies de sequence TCP (noms EK natifs tshark) : trou de numerotation
# non retransmis, ACK d'un segment jamais vu, segment hors ordre. Les
# retransmissions et ACK dupliques sont volontairement exclus : frequents
# sur un lien sain, ils ne discriminent pas une tentative d'exploitation.
_TCP_SEQUENCE_ANOMALY_FLAGS = frozenset(
    {
        "tcp_tcp_analysis_lost_segment",
        "tcp_tcp_analysis_ack_lost_segment",
        "tcp_tcp_analysis_out_of_order",
    }
)

# Cle de couche EK (prefixe du nom de condition) -> protocole affiche.
_LAYER_PROTOCOL = {"http": "HTTP", "dns": "DNS", "tls": "TLS", "smb": "SMB", "smb2": "SMB"}
_MALFORMED_PREFIX = "_ws_malformed"
_GROUP_MALFORMED = "Malformed"
_ERROR_SEVERITIES = frozenset({"Error", "Warning"})

# Indice de repli pour attribuer un protocole a un paquet malforme quand
# aucune couche applicative n'a survecu a l'exception du dissecteur.
_PORT_PROTOCOL = {
    53: "DNS",
    5353: "DNS",
    80: "HTTP",
    8000: "HTTP",
    8080: "HTTP",
    8888: "HTTP",
    443: "TLS",
    8443: "TLS",
    139: "SMB",
    445: "SMB",
}
PROTOCOL_OTHER = "OTHER"


@dataclass(frozen=True)
class CorrelationThresholds:
    """Seuils des trois correlations (voir la docstring du module)."""

    fuzzing_min_malformed: int = 3
    overflow_window_s: float = 2.0
    dos_min_events: int = 20
    dos_window_s: float = 5.0


DEFAULT_THRESHOLDS = CorrelationThresholds()


@dataclass(frozen=True)
class AppAnomaly:
    """Anomalie applicative portee par UN paquet."""

    protocol: str
    malformed: bool  # False -> simple erreur applicative (severite Error/Warning)


@dataclass
class CorrelationResult:
    """Sortie de `correlate_expert_alerts`, meme forme que les champs Report."""

    malformed_by_point: dict[str, dict[str, int]] = field(default_factory=dict)
    malformed_flows: list[dict] = field(default_factory=list)
    suspicions: list[dict] = field(default_factory=list)


def _protocol_hint(pk: Pkt) -> str:
    """Protocole probable d'un paquet malforme sans couche applicative nommee."""
    if pk.dns_txn_id is not None or pk.dns_qry_name:
        return "DNS"
    if pk.http_is_request or pk.http_is_response:
        return "HTTP"
    if pk.tls_client_hello or pk.tls_server_hello or pk.tls_application_data:
        return "TLS"
    for port in (pk.dport, pk.sport):
        if port in _PORT_PROTOCOL:
            return _PORT_PROTOCOL[port]
    return PROTOCOL_OTHER


def app_anomaly(pk: Pkt) -> AppAnomaly | None:
    """Anomalie APPLICATIVE d'un paquet, ou None.

    Retient : les conditions `_ws_malformed*` et toute condition du groupe
    natif Malformed (malformed=True), ainsi que les conditions applicatives
    de severite native Error/Warning (malformed=False). Les severites
    Note/Chat/Comment, les signaux L3/L4 et les conditions sans metadonnees
    de severite (paquet synthetique sans `expert_details`) ne comptent pas.
    """
    if not pk.expert_flags:
        return None
    details = {d[0]: d for d in pk.expert_details}
    protocol: str | None = None
    malformed = False
    found = False
    for name in pk.expert_flags:
        is_malformed_layer = name.startswith(_MALFORMED_PREFIX)
        layer_protocol = None if is_malformed_layer else _LAYER_PROTOCOL.get(name.split("_", 1)[0])
        if not is_malformed_layer and layer_protocol is None:
            continue  # signal L3/L4 : hors perimetre applicatif
        detail = details.get(name)
        severity = detail[1] if detail else None
        group = detail[2] if detail else None
        if is_malformed_layer or group == _GROUP_MALFORMED:
            malformed = True
        elif severity not in _ERROR_SEVERITIES:
            continue
        found = True
        protocol = protocol or layer_protocol
    if not found:
        return None
    return AppAnomaly(protocol=protocol or _protocol_hint(pk), malformed=malformed)


def has_tcp_sequence_anomaly(pk: Pkt) -> bool:
    return pk.proto == "TCP" and any(f in _TCP_SEQUENCE_ANOMALY_FLAGS for f in pk.expert_flags)


def _endpoint(ip: str, port: int | None) -> tuple[str, int]:
    return (ip, port if port is not None else -1)


def flow_id(pk: Pkt) -> str:
    """Identifiant BIDIRECTIONNEL d'un flux : protocole + deux extremites triees.

    Distinct de netcross_core.correlate.flow_key, qui inclut `key_id`
    (numero de sequence TCP) et sert a apparier un MEME paquet entre points.
    """
    lo, hi = sorted((_endpoint(pk.src, pk.sport), _endpoint(pk.dst, pk.dport)))

    def fmt(ep: tuple[str, int]) -> str:
        return f"{ep[0]}:{ep[1]}" if ep[1] >= 0 else ep[0]

    return f"{pk.proto} {fmt(lo)} <-> {fmt(hi)}"


@dataclass
class _FlowState:
    malformed: list[tuple[float, int | None, str]] = field(default_factory=list)  # (ts, frame, protocol)
    tcp_anomalies: list[float] = field(default_factory=list)  # ts


def _frames(frames: Iterable[int | None]) -> list[int]:
    return [f for f in frames if f is not None][:_MAX_FRAMES]


def _protocol_counts(protocols: Iterable[str]) -> dict[str, int]:
    return dict(sorted(Counter(protocols).items()))


def _dos_bursts(events: list[tuple[float, int | None, str]], t: CorrelationThresholds):
    """Rafales de >= dos_min_events evenements dans dos_window_s (evenements tries par ts)."""
    bursts = []
    n = len(events)
    start = end = 0
    while start < n:
        end = max(end, start)
        while end < n and events[end][0] - events[start][0] <= t.dos_window_s:
            end += 1
        if end - start >= t.dos_min_events:
            bursts.append(events[start:end])
            start = end
        else:
            start += 1
    return bursts


def _follows_tcp_anomaly(ts: float, tcp_ts: list[float], window_s: float) -> bool:
    """Vrai si une anomalie TCP (tcp_ts trie) precede `ts` d'au plus window_s (egalite incluse)."""
    i = bisect_right(tcp_ts, ts) - 1
    return i >= 0 and ts - tcp_ts[i] <= window_s


def correlate_expert_alerts(
    packets: Iterable[Pkt], thresholds: CorrelationThresholds = DEFAULT_THRESHOLDS
) -> CorrelationResult:
    """Detecte fuzzing / overflow / dos a partir des alertes Expert Info (voir module)."""
    flows: dict[tuple[str, str], _FlowState] = defaultdict(_FlowState)
    hosts: dict[tuple[str, str, str], list[tuple[float, int | None, str]]] = defaultdict(list)
    by_point: dict[str, Counter] = defaultdict(Counter)

    for pk in packets:
        anomaly = app_anomaly(pk)
        tcp_anomaly = has_tcp_sequence_anomaly(pk)
        if anomaly is None and not tcp_anomaly:
            continue
        state = flows[(pk.point, flow_id(pk))]
        if tcp_anomaly:
            state.tcp_anomalies.append(pk.ts)
        if anomaly is None:
            continue
        event = (pk.ts, pk.frame_number, anomaly.protocol)
        if anomaly.malformed:
            state.malformed.append(event)
            by_point[pk.point][anomaly.protocol] += 1
        hosts[(pk.point, pk.src, pk.dst)].append(event)

    result = CorrelationResult()
    result.malformed_by_point = {pt: dict(sorted(c.items())) for pt, c in sorted(by_point.items())}

    for (point, flow), state in sorted(flows.items()):
        if not state.malformed:
            continue
        events = sorted(state.malformed, key=lambda e: e[0])
        result.malformed_flows.append(
            {
                "point": point,
                "flow": flow,
                "count": len(events),
                "protocols": _protocol_counts(e[2] for e in events),
                "frames": _frames(e[1] for e in events),
            }
        )
        if len(events) >= thresholds.fuzzing_min_malformed:
            result.suspicions.append(_suspicion(point, flow, KIND_FUZZING, events))
        tcp_ts = sorted(state.tcp_anomalies)
        hits = [e for e in events if _follows_tcp_anomaly(e[0], tcp_ts, thresholds.overflow_window_s)]
        if hits:
            result.suspicions.append(_suspicion(point, flow, KIND_OVERFLOW, hits))

    for (point, src, dst), events in sorted(hosts.items()):
        events.sort(key=lambda e: e[0])
        bursts = _dos_bursts(events, thresholds)
        if bursts:
            burst_events = [e for burst in bursts for e in burst]
            entry = _suspicion(point, f"{src} -> {dst}", KIND_DOS, burst_events)
            entry["bursts"] = len(bursts)
            result.suspicions.append(entry)

    result.malformed_flows.sort(key=lambda d: (-d["count"], d["point"], d["flow"]))
    result.suspicions.sort(key=lambda d: (d["kind"], -d["count"], d["point"], d["flow"]))
    logger.debug(
        "correlate_expert_alerts: {} point(s) avec malformations, {} flux malformé(s), {} suspicion(s)",
        len(result.malformed_by_point),
        len(result.malformed_flows),
        len(result.suspicions),
    )
    return result


def _suspicion(point: str, flow: str, kind: str, events: list[tuple[float, int | None, str]]) -> dict:
    return {
        "point": point,
        "flow": flow,
        "kind": kind,
        "count": len(events),
        "protocols": _protocol_counts(e[2] for e in events),
        "frames": _frames(e[1] for e in events),
    }


def apply_expert_correlation(
    r: Report, all_packets: Iterable[Pkt], thresholds: CorrelationThresholds = DEFAULT_THRESHOLDS
) -> None:
    """Calcule la correlation et recopie le resultat dans les champs Report dedies."""
    result = correlate_expert_alerts(all_packets, thresholds)
    for point, per_proto in result.malformed_by_point.items():
        for protocol, n in per_proto.items():
            r.expert_malformed[point][protocol] = n
    r.expert_malformed_flows = result.malformed_flows
    for s in result.suspicions:
        r.exploit_suspicion[s["point"]][s["kind"]] += 1
    r.exploit_suspicion_flows = result.suspicions
    logger.debug(
        "apply_expert_correlation: {} flux malformé(s), {} suspicion(s) recopiés dans le rapport",
        len(result.malformed_flows),
        len(result.suspicions),
    )
