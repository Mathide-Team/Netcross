"""
netcross_core.security.dga -- issue #152 (SCENARIO-6, parent #141) :
detection de domaines generes algorithmiquement (DGA).

Un DGA produit des noms de domaine pseudo-aleatoires (xkqjfwbvt.com,
qjwvn3k1n2.org...) utilises par les botnets pour contacter leur C2.
Ces domaines ont des caracteristiques statistiques distinctes des
noms legitimes : haute entropie de Shannon, ratio consonnes/voyelles
anormal, bigrammes rares, longueur fixe atypique.

Le module reutilise ``shannon_entropy()`` et ``split_domain()`` de
``dns_tunnel.py`` (#144, FLOW-3) : pas de duplication de code.

Score DGA par domaine (0.0 a 1.0) :
- entropie de Shannon du sous-domaine (poids 0.35) ;
- ratio consonnes/voyelles (poids 0.20) ;
- bigrammes rares en anglais (poids 0.20) ;
- longueur du sous-domaine (poids 0.15) ;
- ratio NXDOMAIN pour ce domaine (poids 0.10).

Anti faux positifs :
- liste blanche de domaines legitimes (google.com, cloudflare.com...) ;
- domaines ignores (in-addr.arpa, ip6.arpa, local) -- reutilise dns_tunnel ;
- seuil de score configurable (defaut 0.6) ;
- un domaine en liste blanche n'est jamais signale, meme avec un score eleve.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt
from netcross_core.security.dns_tunnel import _is_ignored, shannon_entropy, split_domain

logger = get_logger(__name__)

# Bigrammes frequents en anglais (noms de domaine legitimes).
# Un domaine legitime a une proportion elevee de ces bigrammes.
_COMMON_BIGRAMS: frozenset[str] = frozenset(
    {
        "th",
        "he",
        "in",
        "er",
        "an",
        "re",
        "on",
        "at",
        "en",
        "nd",
        "ti",
        "es",
        "or",
        "te",
        "of",
        "ed",
        "is",
        "it",
        "al",
        "ar",
        "st",
        "to",
        "nt",
        "ng",
        "se",
        "ha",
        "as",
        "ou",
        "io",
        "le",
        "ve",
        "co",
        "me",
        "de",
        "hi",
        "ri",
        "ro",
        "ic",
        "ne",
        "ea",
    }
)

# Domaines legitimes connus (liste blanche). Le sous-domaine est compare.
_WHITELIST_DOMAINS: frozenset[str] = frozenset(
    {
        "google.com",
        "cloudflare.com",
        "amazonaws.com",
        "amazon.com",
        "microsoft.com",
        "github.com",
        "githubusercontent.com",
        "akamai.net",
        "akamaized.net",
        "cloudfront.net",
        "apple.com",
        "icloud.com",
        "yahoo.com",
        "bing.com",
        "wikipedia.org",
        "youtube.com",
        "facebook.com",
        "twitter.com",
        "linkedin.com",
        "instagram.com",
        "whatsapp.net",
        "office.com",
        "live.com",
        "outlook.com",
        "msn.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "google-analytics.com",
        "doubleclick.net",
        "windowsupdate.com",
        "msecnd.net",
        "azureedge.net",
        "azure.com",
        "azure-devices.net",
        "azure-devices-provisioning.net",
        "docker.com",
        "docker.io",
        "npmjs.org",
        "npmjs.com",
        "python.org",
        "pypi.org",
        "readthedocs.io",
        "stackoverflow.com",
        "serverfault.com",
        "superuser.com",
        "w3.org",
        "mozilla.org",
        "firefox.com",
        "opera.com",
        "edge.com",
        "spotify.com",
        "netflix.com",
        "twitch.tv",
        "steampowered.com",
        "steamcommunity.com",
        "dropbox.com",
        "box.com",
        "zoom.us",
        "slack.com",
        "discord.com",
        "discordapp.com",
        "salesforce.com",
        "force.com",
        "zendesk.com",
        "intercom.io",
        "stripe.com",
        "paypal.com",
        "akamaihd.net",
        "edgesuite.net",
        "cloudflareinsights.com",
        "cloudflareclient.com",
        "cf-analytics.com",
        "workers.dev",
        "fastly.net",
        "fastlycdn.com",
        "innovation.gov",
        "data.gov",
        "amazoncrl.com",
        "1e100.net",
        "gvt1.com",
        "gvt2.com",
        "schema.org",
        "jsonld.com",
        "gravatar.com",
        "wp.com",
        "wordpress.com",
        "medium.com",
        "substack.com",
        "notion.so",
        "airtable.com",
        "figma.com",
        "cloudflarestream.com",
        "cloudflare-video.com",
    }
)

# Seuil par defaut pour le score DGA.
_DGA_SCORE_THRESHOLD: float = 0.6


@dataclass
class DgaThresholds:
    """Seuils de detection DGA (tous configurables)."""

    # Score minimum pour lever une alerte (0.0 a 1.0).
    score_threshold: float = _DGA_SCORE_THRESHOLD
    # Longueur minimum du sous-domaine pour evaluer (ignorer les TLD courts).
    min_subdomain_len: int = 6
    # Entropie de Shannon minimale (bits/caractere) pour le signal entropie.
    entropy_min_bits: float = 2.5
    # Ratio consonnes/voyelles minimal pour le signal consonnes.
    consonant_ratio_min: float = 0.65
    # Proportion minimale de bigrammes rares pour le signal n-grams.
    rare_bigram_ratio_min: float = 0.5
    # Longueur du sous-domaine consideree comme suspecte (>= cette valeur).
    suspicious_length: int = 10
    # Ratio NXDOMAIN minimum pour le signal NXDOMAIN.
    nxdomain_ratio_min: float = 0.5
    # Nombre maximum de sous-domaines uniques par domaine enregistre.
    # Au-dela, on considere qu'il s'agit de tunneling DNS (exfiltration
    # par labels), pas de DGA (un domaine DGA = un nom par domaine).
    max_unique_queries_per_domain: int = 5


@dataclass
class DgaAlert:
    """Une alerte DGA pour un domaine suspect.

    Issue #343 : un domaine DGA vu depuis plusieurs points de capture est
    UN evenement, pas un par point -- `points` liste tous les points ou
    il a ete observe (`point` reste expose comme alias retro-compatible :
    le premier point trie, ou None si `points` est vide)."""

    domain: str
    score: float  # 0.0 a 1.0
    reason: str
    points: tuple[str, ...] = ()
    entropy: float = 0.0
    consonant_ratio: float = 0.0
    rare_bigram_ratio: float = 0.0
    length: int = 0
    nxdomain_ratio: float = 0.0

    @property
    def point(self) -> str | None:
        return self.points[0] if self.points else None


@dataclass
class DgaResult:
    """Resultat de la detection DGA."""

    alerts: list[DgaAlert] = field(default_factory=list)
    domain_scores: list[dict] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return bool(self.alerts)


def _is_vowel(c: str) -> bool:
    return c in "aeiou"


def _consonant_ratio(text: str) -> float:
    """Ratio consonnes/(consonnes+voyelles) sur un texte alpha."""
    consonants = 0
    vowels = 0
    for c in text.lower():
        if c.isalpha():
            if _is_vowel(c):
                vowels += 1
            else:
                consonants += 1
    total = consonants + vowels
    if total == 0:
        return 0.0
    return consonants / total


def _rare_bigram_ratio(text: str) -> float:
    """Proportion de bigrammes rares (non frequents en anglais)."""
    text = text.lower()
    bigrams = [text[i : i + 2] for i in range(len(text) - 1) if text[i : i + 2].isalpha()]
    if not bigrams:
        return 0.0
    rare = sum(1 for bg in bigrams if bg not in _COMMON_BIGRAMS)
    return rare / len(bigrams)


def _compute_dga_score(
    subdomain: str,
    entropy: float,
    nxdomain_ratio: float,
    thresholds: DgaThresholds,
) -> tuple[float, str]:
    """Calcule le score DGA (0.0 a 1.0) et la raison principale."""
    reasons: list[str] = []

    # Signal 1 : entropie de Shannon (poids 0.35)
    entropy_score = 0.0
    if entropy >= thresholds.entropy_min_bits:
        entropy_score = min(1.0, (entropy - thresholds.entropy_min_bits) / 1.0)
        reasons.append(f"entropie {entropy:.2f}")

    # Signal 2 : ratio consonnes/voyelles (poids 0.20)
    c_ratio = _consonant_ratio(subdomain)
    consonant_score = 0.0
    if c_ratio >= thresholds.consonant_ratio_min:
        consonant_score = min(1.0, (c_ratio - thresholds.consonant_ratio_min) / 0.25)
        reasons.append(f"consonnes {c_ratio:.2f}")

    # Signal 3 : bigrammes rares (poids 0.20)
    rare_ratio = _rare_bigram_ratio(subdomain)
    bigram_score = 0.0
    if rare_ratio >= thresholds.rare_bigram_ratio_min:
        bigram_score = min(1.0, (rare_ratio - thresholds.rare_bigram_ratio_min) / 0.3)
        reasons.append(f"bigrammes rares {rare_ratio:.2f}")

    # Signal 4 : longueur du sous-domaine (poids 0.15)
    length_score = 0.0
    if len(subdomain) >= thresholds.suspicious_length:
        length_score = min(1.0, (len(subdomain) - thresholds.suspicious_length) / 8)
        reasons.append(f"longueur {len(subdomain)}")

    # Signal 5 : ratio NXDOMAIN (poids 0.10)
    nxdomain_score = 0.0
    if nxdomain_ratio >= thresholds.nxdomain_ratio_min:
        nxdomain_score = min(1.0, (nxdomain_ratio - thresholds.nxdomain_ratio_min) / 0.4)
        reasons.append(f"NXDOMAIN {nxdomain_ratio:.2f}")

    total = (
        0.35 * entropy_score
        + 0.20 * consonant_score
        + 0.20 * bigram_score
        + 0.15 * length_score
        + 0.10 * nxdomain_score
    )

    reason = ", ".join(reasons) if reasons else "score insuffisant"
    return round(total, 3), reason


def detect_dga(
    packets: Iterable[Pkt],
    thresholds: DgaThresholds | None = None,
) -> DgaResult:
    """Detection de domaines DGA dans les paquets DNS.

    Parcourt les requetes DNS (``dns_qry_name`` non nul), calcule un
    score DGA par domaine et le compare au seuil. Les domaines en liste
    blanche ou ignores (in-addr.arpa, local...) sont exclus.

    Le ratio NXDOMAIN est calcule par domaine : nombre de reponses
    NXDOMAIN (rcode=3) / nombre total de reponses pour ce domaine.
    """
    if thresholds is None:
        thresholds = DgaThresholds()

    packets = list(packets)

    # Domaine -> (point, nb_queries, nb_nxdomain, nb_responses, unique_names)
    domain_stats: dict[str, dict] = {}
    # Domaine -> set de points
    domain_points: dict[str, set[str]] = {}
    # Domaine -> sous-domaine representatif (pour le score)
    domain_sub: dict[str, str] = {}

    for pkt in packets:
        if not pkt.dns_qry_name:
            continue
        name = pkt.dns_qry_name.lower().strip(".")
        if _is_ignored(name):
            continue

        domain, sub = split_domain(name)
        if not domain:
            continue
        if domain in _WHITELIST_DOMAINS:
            continue

        # Pour le score DGA, utiliser le sous-domaine s'il existe,
        # sinon le premier label du domaine (la partie avant le TLD).
        # Les domaines DGA sont souvent courts : xkqjfwbvt.com -> "xkqjfwbvt"
        score_name = sub if sub else name.split(".")[0]
        if len(score_name) < thresholds.min_subdomain_len:
            continue

        if domain not in domain_stats:
            domain_stats[domain] = {"queries": 0, "nxdomain": 0, "responses": 0, "unique_names": set()}
            domain_points[domain] = set()
            domain_sub[domain] = score_name

        domain_stats[domain]["queries"] += 1
        domain_stats[domain]["unique_names"].add(name)
        domain_points[domain].add(pkt.point)

        if pkt.dns_is_response:
            domain_stats[domain]["responses"] += 1
            if pkt.dns_rcode == 3:  # NXDOMAIN
                domain_stats[domain]["nxdomain"] += 1

    # Calcul du score par domaine
    alerts: list[DgaAlert] = []
    domain_scores: list[dict] = []

    for domain, stats in domain_stats.items():
        # Filtrer les domaines avec trop de sous-domaines uniques :
        # c'est du tunneling DNS (exfiltration par labels), pas du DGA.
        if len(stats["unique_names"]) > thresholds.max_unique_queries_per_domain:
            continue

        sub = domain_sub[domain]

        entropy = shannon_entropy(sub.replace(".", ""))
        c_ratio = _consonant_ratio(sub)
        rare_ratio = _rare_bigram_ratio(sub)

        nxdomain_ratio = 0.0
        if stats["responses"] > 0:
            nxdomain_ratio = stats["nxdomain"] / stats["responses"]

        score, reason = _compute_dga_score(sub, entropy, nxdomain_ratio, thresholds)

        domain_scores.append(
            {
                "domain": domain,
                "score": score,
                "entropy": round(entropy, 3),
                "consonant_ratio": round(c_ratio, 3),
                "rare_bigram_ratio": round(rare_ratio, 3),
                "length": len(sub),
                "nxdomain_ratio": round(nxdomain_ratio, 3),
                "queries": stats["queries"],
            }
        )

        if score >= thresholds.score_threshold:
            alerts.append(
                DgaAlert(
                    domain=domain,
                    score=score,
                    reason=reason,
                    points=tuple(sorted(domain_points[domain])),
                    entropy=round(entropy, 3),
                    consonant_ratio=round(c_ratio, 3),
                    rare_bigram_ratio=round(rare_ratio, 3),
                    length=len(sub),
                    nxdomain_ratio=round(nxdomain_ratio, 3),
                )
            )

    domain_scores.sort(key=lambda d: (-d["score"], d["domain"]))

    logger.debug("detect_dga: {} domaine(s) évalués, {} alerte(s)", len(domain_scores), len(alerts))
    return DgaResult(alerts=alerts, domain_scores=domain_scores)
