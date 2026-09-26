"""
netcross_core.security.flow_stats -- issue #145 (FLOW-4, parent #141) :
analyse statistique des flux pour detecter les comportements anormaux.

Metriques calculees PAR FLUX (groupe par paire source->destination) :

- **SPLT** (Sequence of Packet Lengths and Times) : les N premiers
  paquets du flux, chacun decrit par (taille, delta_t depuis le precedent).
  Un flux SSH interactif a des petits paquets reguliers (< 100 octets),
  un transfert a de gros paquets unidirectionnels, un flux obfusque a
  une distribution aleatoire des tailles.
- **Entropie des octets de la charge utile** (issue #351, critere
  « flux chiffre, entropie ~8,0 » de #145) : l'histogramme 0-255 des
  octets de chaque payload est calcule au parsing (``Pkt.payload_entropy``,
  ``Pkt.payload_len`` : Pkt ne garde pas les octets). Par flux :
  ``byte_entropy`` = moyenne, ponderee par la taille du payload, de
  l'entropie de chaque paquet (bits/octet, 0-8) ; ``byte_entropy_ratio`` =
  meme moyenne de l'entropie NORMALISEE par son maximum atteignable
  log2(min(n, 256)) -- n octets ne peuvent pas depasser log2(n) bits, un
  payload chiffre de 100 octets plafonne donc vers 6,2 bits et serait
  rate par un seuil absolu. Seuls les payloads d'au moins
  ``_MIN_PAYLOAD_FOR_ENTROPY`` octets entrent dans le calcul (en dessous
  l'entropie n'est pas significative).
- **Entropie de Shannon des tailles de paquets** (``entropy``) : conservee
  comme metrique descriptive (profil SPLT) mais PAS utilisee pour la
  classification -- un flux chiffre de 12 Mo en paquets MTU sort a 0,00,
  un trafic HTTP texte aux tailles variees depasse 3 bits.
- **Ratio up/down** : volume envoye vs recu par flux.
- **Regularite temporelle** : ecart-type des intervalles entre paquets
  (un flux de beaconing a une regularite elevee).

Classification produite :
- **interactif** : petits paquets (< 100 octets en mediane), reguliers
- **transfert** : gros paquets (> 500 octets en mediane), unidirectionnel
- **obfusque** : charge utile a forte entropie -- ``byte_entropy_ratio``
  >= 0,85 sur au moins ``_MIN_FLOW_PAYLOAD_BYTES`` octets de payload
  (chiffre, compresse ou aleatoire ; du texte HTTP/SMTP est vers 0,55-0,7).
  Prioritaire sur les autres classes.
- **normal** : aucun des criteres ci-dessus

Comme dns_tunnel et beaconing, ce module ne fait que produire des
donnees : la traduction en constats du rapport de securite se fait dans
``security.findings``.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from statistics import mean, median, pstdev

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt

logger = get_logger(__name__)

# -- Constantes ---------------------------------------------------------------

# Nombre de paquets conserves dans le SPLT.
_SPLT_MAX_PACKETS = 20

# Seuils de classification (voir docstring du module).
_SMALL_PACKET_THRESHOLD = 100  # octets
_LARGE_PACKET_THRESHOLD = 500  # octets
# Issue #351 : entropie des octets de la charge utile.
_HIGH_BYTE_ENTROPY_RATIO = 0.85  # entropie / log2(min(n, 256))
_MIN_PAYLOAD_FOR_ENTROPY = 128  # octets, par paquet (en dessous, texte et alea se confondent)
_MIN_FLOW_PAYLOAD_BYTES = 256  # octets de payload cumules par flux

CLASSIFICATION_INTERACTIVE = "interactif"
CLASSIFICATION_TRANSFER = "transfert"
CLASSIFICATION_OBFUSCATED = "obfusque"
CLASSIFICATION_NORMAL = "normal"


@dataclass(frozen=True)
class FlowStatsThresholds:
    """Seuils de classification (voir la docstring du module)."""

    small_packet_threshold: int = _SMALL_PACKET_THRESHOLD
    large_packet_threshold: int = _LARGE_PACKET_THRESHOLD
    high_byte_entropy_ratio: float = _HIGH_BYTE_ENTROPY_RATIO
    min_payload_for_entropy: int = _MIN_PAYLOAD_FOR_ENTROPY
    min_flow_payload_bytes: int = _MIN_FLOW_PAYLOAD_BYTES
    splt_max_packets: int = _SPLT_MAX_PACKETS


DEFAULT_THRESHOLDS = FlowStatsThresholds()


@dataclass
class FlowStat:
    """Statistiques d'un flux (paire source->destination)."""

    src: str
    dst: str
    packet_count: int = 0
    byte_count: int = 0
    # SPLT : liste de (taille, delta_t) pour les N premiers paquets
    splt: list[tuple[int, float]] = field(default_factory=list)
    # Distribution des tailles de paquets (histogramme)
    size_distribution: Counter = field(default_factory=Counter)
    # Ratio up/down (bytes src->dst / bytes dst->src)
    upload_bytes: int = 0
    download_bytes: int = 0
    # Intervalles entre paquets (pour regularite temporelle)
    inter_arrivals: list[float] = field(default_factory=list)
    # Classification
    classification: str = CLASSIFICATION_NORMAL
    # Metriques derivees
    entropy: float = 0.0
    # Issue #351 : entropie des octets de la charge utile (voir la
    # docstring du module) -- moyenne ponderee par la taille du payload,
    # brute (bits/octet) et normalisee (0-1), et nombre d'octets de payload
    # pris en compte.
    byte_entropy: float = 0.0
    byte_entropy_ratio: float = 0.0
    payload_bytes: int = 0
    median_size: float = 0.0
    upload_ratio: float = 0.0
    regularity_cv: float = 0.0  # coefficient de variation des intervalles
    # Issue #346 : point de capture du flux (un seul : les flux sont par point)
    points: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "src": self.src,
            "dst": self.dst,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "splt": list(self.splt),
            "size_distribution": dict(self.size_distribution),
            "upload_bytes": self.upload_bytes,
            "download_bytes": self.download_bytes,
            "inter_arrivals": list(self.inter_arrivals),
            "classification": self.classification,
            "entropy": self.entropy,
            "byte_entropy": self.byte_entropy,
            "byte_entropy_ratio": self.byte_entropy_ratio,
            "payload_bytes": self.payload_bytes,
            "median_size": self.median_size,
            "upload_ratio": self.upload_ratio,
            "regularity_cv": self.regularity_cv,
            "points": list(self.points),
            "point": self.points[0] if self.points else None,
        }


@dataclass
class FlowStatsResult:
    """Sortie de `analyze_flow_stats`, meme forme que les autres detecteurs."""

    flows: list[FlowStat] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"flows": [f.to_dict() for f in self.flows]}


def _shannon_entropy(counter: Counter) -> float:
    """Entropie de Shannon sur une distribution (Counter), en bits."""
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counter.values())


def _classify_flow(flow: FlowStat, thresholds: FlowStatsThresholds) -> str:
    """Classifie un flux selon les seuils."""
    sizes = list(flow.size_distribution.elements())
    if not sizes:
        return CLASSIFICATION_NORMAL

    flow.median_size = median(sizes)
    flow.entropy = _shannon_entropy(flow.size_distribution)
    total_bytes = flow.upload_bytes + flow.download_bytes
    flow.upload_ratio = flow.upload_bytes / total_bytes if total_bytes > 0 else 0.0

    # Regularite temporelle : coefficient de variation des intervalles
    if len(flow.inter_arrivals) >= 2:
        m = mean(flow.inter_arrivals)
        if m > 0:
            sd = pstdev(flow.inter_arrivals)
            flow.regularity_cv = sd / m

    # Issue #351 : seule l'entropie des octets de la charge utile signale
    # un flux chiffre/obfusque ; l'entropie des tailles reste descriptive.
    if (
        flow.payload_bytes >= thresholds.min_flow_payload_bytes
        and flow.byte_entropy_ratio >= thresholds.high_byte_entropy_ratio
    ):
        return CLASSIFICATION_OBFUSCATED
    if flow.median_size < thresholds.small_packet_threshold and flow.regularity_cv < 0.5:
        return CLASSIFICATION_INTERACTIVE
    if flow.median_size > thresholds.large_packet_threshold and flow.upload_ratio > 0.8:
        return CLASSIFICATION_TRANSFER
    return CLASSIFICATION_NORMAL


def analyze_flow_stats(
    packets: Iterable[Pkt],
    thresholds: FlowStatsThresholds = DEFAULT_THRESHOLDS,
) -> FlowStatsResult:
    """
    Calcule les statistiques de flux par paire (source, destination).

    Groupe les paquets par (src, dst), calcule SPLT, distribution des
    tailles, entropie (tailles et octets de la charge utile), ratio
    up/down, regularite temporelle, et
    classifie chaque flux.
    """
    # Issue #346 : un flux est identifie PAR POINT de capture. Sans le point
    # dans la cle, un meme paquet vu sur N points etait compte N fois et les
    # horodatages de points differents s'entremelaient (inter-arrivees et
    # classification faussees).
    flows: dict[tuple[str, str, str], FlowStat] = {}
    # Garder les timestamps par flux pour calculer les inter-arrivees
    flow_timestamps: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    # Issue #351 : sommes ponderees (entropie brute, entropie normalisee)
    # par flux, divisees par payload_bytes en fin de parcours.
    entropy_sums: dict[tuple[str, str, str], list[float]] = defaultdict(lambda: [0.0, 0.0])

    for pk in packets:
        key = (pk.point, pk.src, pk.dst)
        flow = flows.get(key)
        if flow is None:
            flow = FlowStat(src=pk.src, dst=pk.dst, points=[pk.point] if pk.point else [])
            flows[key] = flow

        flow.packet_count += 1
        flow.byte_count += pk.length
        flow.size_distribution[pk.length] += 1

        # SPLT : garder les N premiers paquets
        if len(flow.splt) < thresholds.splt_max_packets:
            delta = pk.ts - flow_timestamps[key][-1] if flow_timestamps[key] else 0.0
            flow.splt.append((pk.length, delta))

        # Upload/download
        flow.upload_bytes += pk.length
        # Issue #351 : entropie des octets du payload, ponderee par sa
        # taille (un paquet isole compresse ne fait pas basculer le flux).
        n = pk.payload_len
        if n >= thresholds.min_payload_for_entropy:
            sums = entropy_sums[key]
            sums[0] += pk.payload_entropy * n
            sums[1] += pk.payload_entropy / math.log2(min(n, 256)) * n
            flow.payload_bytes += n
        # Timestamps pour inter-arrivees
        flow_timestamps[key].append(pk.ts)

        # Download : paquets dans l'autre sens (dst->src)
        rev_key = (pk.point, pk.dst, pk.src)
        rev_flow = flows.get(rev_key)
        if rev_flow is not None:
            rev_flow.download_bytes += pk.length

    # Recalculer download pour tous les flux
    for key, flow in flows.items():
        rev_key = (key[0], key[2], key[1])
        if rev_key in flows:
            flow.download_bytes = flows[rev_key].upload_bytes

    # Calculer les inter-arrivees et classifier
    for key, flow in flows.items():
        timestamps = flow_timestamps[key]
        if len(timestamps) >= 2:
            flow.inter_arrivals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if flow.payload_bytes:
            raw_sum, ratio_sum = entropy_sums[key]
            flow.byte_entropy = raw_sum / flow.payload_bytes
            flow.byte_entropy_ratio = min(1.0, ratio_sum / flow.payload_bytes)
        flow.classification = _classify_flow(flow, thresholds)

    logger.debug("analyze_flow_stats: {} flux analysés", len(flows))
    return FlowStatsResult(flows=list(flows.values()))
