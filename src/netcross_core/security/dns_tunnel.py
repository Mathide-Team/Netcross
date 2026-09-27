"""
netcross_core.security.dns_tunnel -- issue #144 (FLOW-3, parent #141) :
detection de tunneling DNS (exfiltration, C2, VPN over DNS).

Un tunnel DNS encode des donnees dans des noms de domaine (requetes) et
dans les reponses. Le module exploite uniquement les champs deja decodes
de `Pkt` (`dns_txn_id`, `dns_qry_name`, `dns_is_response`, `length`,
`ts`) : aucune nouvelle dissection tshark.

Signaux calcules PAR POINT DE CAPTURE puis PAR DOMAINE ENREGISTRE (les deux
derniers labels, trois pour les SLD generiques du type `co.uk`) :

Signaux FORTS (suffisent seuls a lever une suspicion) :
- **long_label** : au moins une requete avec un label > 63 caracteres
  (limite RFC 1035 -- un label plus long n'existe pas dans du DNS valide) ;
- **long_name** : au moins `long_name_min_queries` requetes dont le nom
  complet depasse 100 caracteres ;
- **high_entropy** : au moins `entropy_min_unique` sous-domaines DISTINCTS
  dont l'entropie de Shannon moyenne depasse `entropy_min_bits` bits/car.
  Un nom isole a haute entropie (CDN, hash) ne suffit pas : c'est la
  multiplicite de sous-domaines aleatoires sous un meme domaine qui
  caracterise un tunnel.

Signaux FAIBLES (jamais suffisants seuls -- un capteur sain peut les
produire -- ils aggravent une suspicion deja levee) :
- **large_response** : au moins `large_response_min_count` reponses de
  plus de `large_response_bytes` octets (trame entiere ; DNSSEC/EDNS0
  produisent aussi de grosses reponses legitimes) ;
- **dominant_domain** : un seul domaine genere plus de `dominance_ratio`
  des requetes du point (au moins `dominance_min_queries` requetes) ;
- **regular_timing** : au moins `regular_min_queries` requetes a
  intervalles reguliers (coefficient de variation <= `regular_max_cv`).

Signal de VOLUME, par point (constat distinct, severite faible) : part des
paquets DNS dans le trafic du point superieure a `volume_ratio` (au moins
`volume_min_packets` paquets DNS). Une capture filtree sur le DNS le
declenche naturellement -- c'est un indice de contexte, pas une preuve.

Limite assumee : `Pkt` ne porte pas le type d'enregistrement (TXT, NULL,
CNAME...), donc « TXT > 100 octets » est approxime par la taille de la
reponse (`large_response`).

Comme `expert_correlation`, une suspicion est un INDICE a confirmer : les
seuils par defaut sont prudents (critere « aucun faux positif sur trafic
DNS legitime »). Sortie pure (`detect_dns_tunneling`) : `suspicions` (une
par domaine ou par point) et `domain_entropy` (score de Shannon moyen de
CHAQUE domaine interroge, suspect ou non). `security.findings` la convertit
en constats du rapport de securite.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from statistics import mean, pstdev

from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Pkt

logger = get_logger(__name__)

KIND_DOMAIN = "domain"
KIND_VOLUME = "volume"

SIGNAL_LONG_LABEL = "long_label"
SIGNAL_LONG_NAME = "long_name"
SIGNAL_HIGH_ENTROPY = "high_entropy"
SIGNAL_LARGE_RESPONSE = "large_response"
SIGNAL_DOMINANT_DOMAIN = "dominant_domain"
SIGNAL_REGULAR_TIMING = "regular_timing"

STRONG_SIGNALS = (SIGNAL_LONG_LABEL, SIGNAL_LONG_NAME, SIGNAL_HIGH_ENTROPY)
WEAK_SIGNALS = (SIGNAL_LARGE_RESPONSE, SIGNAL_DOMINANT_DOMAIN, SIGNAL_REGULAR_TIMING)

# Nombre maximal de numeros de trame conserves comme preuve par suspicion.
_MAX_FRAMES = 10

# Suffixes sans tunnel plausible : DNS inverse (noms tres longs, hexadecimaux)
# et mDNS.
_IGNORED_SUFFIXES = ("in-addr.arpa", "ip6.arpa", "local")

# SLD generiques : `example.co.uk` a pour domaine enregistre les TROIS derniers labels.
_GENERIC_SLDS = frozenset({"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go"})


@dataclass(frozen=True)
class DnsTunnelThresholds:
    """Seuils des signaux (voir la docstring du module). Tous parametrables."""

    max_label_len: int = 63
    max_name_len: int = 100
    long_name_min_queries: int = 3
    entropy_min_bits: float = 3.6
    entropy_min_unique: int = 10
    entropy_min_subdomain_len: int = 16  # longueur moyenne du sous-domaine
    large_response_bytes: int = 512
    large_response_min_count: int = 5
    dominance_ratio: float = 0.8
    dominance_min_queries: int = 30
    regular_min_queries: int = 10
    regular_max_cv: float = 0.15
    volume_ratio: float = 0.5
    volume_min_packets: int = 50


DEFAULT_THRESHOLDS = DnsTunnelThresholds()


@dataclass
class DnsTunnelResult:
    """Sortie de `detect_dns_tunneling`, meme forme de dicts que les autres detecteurs de securite."""

    suspicions: list[dict] = field(default_factory=list)
    domain_entropy: list[dict] = field(default_factory=list)


def shannon_entropy(text: str) -> float:
    """Entropie de Shannon de `text`, en bits par caractere (0.0 si vide)."""
    if not text:
        logger.debug("shannon_entropy: si not text -> retour 0.0")
        return 0.0
    n = len(text)
    logger.debug("shannon_entropy: retour -sum((c / n * math.log2(c / n) for c in Counter(t…")
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def split_domain(name: str) -> tuple[str, str]:
    """Decoupe un nom en (domaine enregistre, sous-domaine). Approximation
    sans liste des suffixes publics : deux labels, trois si le SLD est
    generique (`co.uk`). Un nom sans sous-domaine renvoie `(nom, "")`."""
    labels = [lb for lb in name.lower().strip(".").split(".") if lb]
    if len(labels) <= 2:
        logger.debug("split_domain: si len(labels) <= 2 -> retour tuple de 2")
        return ".".join(labels), ""
    keep = 3 if (len(labels[-1]) == 2 and labels[-2] in _GENERIC_SLDS and len(labels) > 3) else 2
    logger.debug("split_domain: retour tuple de 2")
    return ".".join(labels[-keep:]), ".".join(labels[:-keep])


def _is_ignored(name: str) -> bool:
    lowered = name.lower().strip(".")
    logger.debug("_is_ignored: retour any(…)")
    return any(lowered == s or lowered.endswith("." + s) for s in _IGNORED_SUFFIXES)


@dataclass
class _DomainState:
    queries: list[tuple[float, int | None, str]] = field(default_factory=list)  # (ts, frame, nom)
    large_responses: list[int | None] = field(default_factory=list)


def _frames(frames: Iterable[int | None]) -> list[int]:
    logger.debug("_frames: retour [f for f in frames if f is not None][:_MAX_FRAMES]")
    return [f for f in frames if f is not None][:_MAX_FRAMES]


def _regular_timing(timestamps: list[float], t: DnsTunnelThresholds) -> bool:
    if len(timestamps) < t.regular_min_queries:
        logger.debug("_regular_timing: si len(timestamps) < t.regular_min_queries -> retour False")
        return False
    ordered = sorted(timestamps)
    deltas = [b - a for a, b in zip(ordered, ordered[1:], strict=False)]
    avg = mean(deltas)
    logger.debug("_regular_timing: retour avg > 0 and pstdev(deltas) / avg <= t.regular_max…")
    return avg > 0 and pstdev(deltas) / avg <= t.regular_max_cv


def detect_dns_tunneling(
    packets: Iterable[Pkt], thresholds: DnsTunnelThresholds = DEFAULT_THRESHOLDS
) -> DnsTunnelResult:
    """Applique les signaux de la docstring du module a `packets`."""
    t = thresholds
    total_by_point: Counter[str] = Counter()
    dns_by_point: Counter[str] = Counter()
    queries_by_point: Counter[str] = Counter()
    domains: dict[tuple[str, str], _DomainState] = defaultdict(_DomainState)

    for pk in packets:
        total_by_point[pk.point] += 1
        if pk.dns_txn_id is None:
            continue
        dns_by_point[pk.point] += 1
        name = pk.dns_qry_name
        if not name or _is_ignored(name):
            continue
        domain, _sub = split_domain(name)
        state = domains[(pk.point, domain)]
        if pk.dns_is_response:
            if pk.length > t.large_response_bytes:
                state.large_responses.append(pk.frame_number)
        else:
            queries_by_point[pk.point] += 1
            state.queries.append((pk.ts, pk.frame_number, name.lower().strip(".")))

    result = DnsTunnelResult()
    logger.debug("dns_tunnel : {} domaine(s) a analyser", len(domains))
    for (point, domain), state in sorted(domains.items()):
        if not state.queries and not state.large_responses:
            continue
        names = [q[2] for q in state.queries]
        subs = {split_domain(n)[1] for n in names} - {""}
        entropies = [shannon_entropy(s.replace(".", "")) for s in subs]
        mean_entropy = mean(entropies) if entropies else 0.0
        mean_sub_len = mean(len(s.replace(".", "")) for s in subs) if subs else 0.0
        max_label = max((len(lb) for n in names for lb in n.split(".")), default=0)
        max_name = max((len(n) for n in names), default=0)
        result.domain_entropy.append(
            {
                "point": point,
                "domain": domain,
                "queries": len(names),
                "unique_subdomains": len(subs),
                "mean_entropy": round(mean_entropy, 3),
            }
        )

        signals: list[str] = []
        long_names = [q for q in state.queries if len(q[2]) > t.max_name_len]
        if max_label > t.max_label_len:
            signals.append(SIGNAL_LONG_LABEL)
        if len(long_names) >= t.long_name_min_queries:
            signals.append(SIGNAL_LONG_NAME)
        if (
            len(subs) >= t.entropy_min_unique
            and mean_entropy >= t.entropy_min_bits
            and mean_sub_len >= t.entropy_min_subdomain_len
        ):
            signals.append(SIGNAL_HIGH_ENTROPY)
        if not signals:
            continue  # aucun signal fort : les signaux faibles seuls ne levent rien
        if len(state.large_responses) >= t.large_response_min_count:
            signals.append(SIGNAL_LARGE_RESPONSE)
        total_q = queries_by_point[point]
        if total_q >= t.dominance_min_queries and len(names) / total_q > t.dominance_ratio:
            signals.append(SIGNAL_DOMINANT_DOMAIN)
        if _regular_timing([q[0] for q in state.queries], t):
            signals.append(SIGNAL_REGULAR_TIMING)

        weak = [s for s in signals if s in WEAK_SIGNALS]
        result.suspicions.append(
            {
                "kind": KIND_DOMAIN,
                "point": point,
                "domain": domain,
                "signals": signals,
                "severity": "elevee" if weak else "moyenne",
                "queries": len(names),
                "unique_subdomains": len(subs),
                "mean_entropy": round(mean_entropy, 3),
                "max_label_len": max_label,
                "max_name_len": max_name,
                "frames": _frames(q[1] for q in (long_names or state.queries)),
            }
        )

    for point, n_dns in sorted(dns_by_point.items()):
        total = total_by_point[point]
        if n_dns >= t.volume_min_packets and n_dns / total > t.volume_ratio:
            result.suspicions.append(
                {
                    "kind": KIND_VOLUME,
                    "point": point,
                    "signals": ["dns_volume"],
                    "severity": "faible",
                    "dns_packets": n_dns,
                    "total_packets": total,
                    "ratio": round(n_dns / total, 3),
                }
            )

    result.suspicions.sort(key=lambda d: (d["kind"], d["point"], d.get("domain", "")))
    result.domain_entropy.sort(key=lambda d: (-d["mean_entropy"], d["point"], d["domain"]))
    logger.info(
        "dns_tunnel : {} suspicion(s) levee(s), {} domaine(s) avec entropie",
        len(result.suspicions),
        len(result.domain_entropy),
    )
    logger.debug("detect_dns_tunneling: retour result={}", summarize(result, "result"))
    return result
