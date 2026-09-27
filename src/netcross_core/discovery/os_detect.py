"""
netcross_core.discovery.os_detect -- identification passive de systeme
d'exploitation par TTL et options TCP (empreinte type p0f), SCENARIO-5
(issue #151, parent #141).

Approche 100% passive : aucune sonde n'est emise, seuls des paquets deja
captures sont observes -- meme discipline que le reste de netcross_core
(voir docstring du package netcross_core.discovery).

Deux signaux exploites, tous deux deja portes par Pkt (aucune extraction
de paquet supplementaire necessaire, voir netcross_core.models) :

- `ttl` : la valeur RECUE (post-decrement par chaque routeur traverse)
  est comparee aux valeurs INITIALES standard, bien connues et
  publiques (aucun defaut n'est fixe par le RFC IP, mais l'usage s'est
  stabilise, documente notamment par p0f/nmap, autour de trois valeurs :
  64 -- Linux/BSD/macOS, 128 -- Windows, 255 -- equipement reseau/Solaris
  ancien). On retient la plus petite valeur standard superieure ou
  egale au TTL observe comme hypothese de TTL initial (le nombre de
  sauts reels n'est jamais connu avec certitude cote capture passive),
  puis on en deduit le nombre de sauts estime.
- options TCP du handshake (`wscale_shift`, `sack_permitted`,
  `mss_val`) : disponibles uniquement sur un paquet SYN ou SYN-ACK
  (meme filtre "S" in flags que netcross_core.analysis.
  _analyse_tcp_options) -- une combinaison Window Scale + SACK Permis
  CORROBORE une hypothese TTL deja posee (piles modernes quasi
  universelles), sans jamais suffire seule ni la contredire.

Comme netcross_core.security.expert_correlation (issue #137) : une
hypothese, JAMAIS un diagnostic certain -- deux systemes distincts
peuvent partager le meme TTL initial standard et les memes options ;
seule une empreinte ACTIVE (nmap -O) ou une source hors-bande confirme
un OS reel.
"""

from __future__ import annotations

from dataclasses import dataclass

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

# Valeurs de TTL initial standard, triees croissant -- voir docstring
# du module pour la source (usage documente par p0f/nmap, pas une
# empreinte precise de version d'OS).
_STANDARD_INITIAL_TTLS: tuple[int, ...] = (64, 128, 255)

_TTL_FAMILY = {
    64: "Linux/BSD/macOS",
    128: "Windows",
    255: "equipement reseau (Cisco IOS, Solaris ancien) ou saut initial direct",
}

CONFIDENCE_LOW = "faible"
CONFIDENCE_MEDIUM = "moyenne"


@dataclass(frozen=True, slots=True)
class OsGuess:
    """Hypothese d'OS pour un hote -- jamais un diagnostic certain (voir
    docstring du module). `confidence` vaut CONFIDENCE_LOW (TTL seul)
    ou CONFIDENCE_MEDIUM (TTL + options TCP de handshake coherentes)."""

    family: str
    guessed_initial_ttl: int
    observed_ttl: int
    hop_estimate: int
    confidence: str
    evidence: str


def guess_initial_ttl(observed_ttl: int) -> int:
    """Plus petite valeur standard >= observed_ttl. Si observed_ttl
    depasse la plus grande valeur standard (255 -- plafond du champ TTL
    sur 8 bits, jamais depasse par un paquet IPv4/IPv6 valide), retombe
    sur 255."""
    for standard in _STANDARD_INITIAL_TTLS:
        if observed_ttl <= standard:
            logger.debug(
                "guess_initial_ttl: si observed_ttl <= standard -> retour standard={}", summarize(standard, "standard")
            )
            return standard
    logger.debug("guess_initial_ttl: retour _STANDARD_INITIAL_TTLS[-1]")
    return _STANDARD_INITIAL_TTLS[-1]


def guess_os_from_ttl(observed_ttl: int) -> OsGuess:
    """Hypothese initiale a partir du seul TTL observe -- confiance
    CONFIDENCE_LOW, voir `refine_with_tcp_options` pour l'affiner."""
    initial = guess_initial_ttl(observed_ttl)
    hops = initial - observed_ttl
    logger.debug("guess_os_from_ttl: retour OsGuess(…)")
    return OsGuess(
        family=_TTL_FAMILY[initial],
        guessed_initial_ttl=initial,
        observed_ttl=observed_ttl,
        hop_estimate=hops,
        confidence=CONFIDENCE_LOW,
        evidence=(f"TTL observe {observed_ttl} <= TTL initial standard {initial} ({hops} saut(s) estime(s))"),
    )


def refine_with_tcp_options(
    guess: OsGuess,
    *,
    wscale_shift: int | None,
    sack_permitted: bool,
    mss_val: int | None,
) -> OsGuess:
    """Affine (ne contredit jamais) une hypothese TTL avec les options
    TCP d'un handshake observe pour ce meme hote. Confiance relevee a
    CONFIDENCE_MEDIUM uniquement quand Window Scale ET SACK Permis sont
    tous deux presents -- combinaison universelle chez les piles TCP
    modernes, donc peu discriminante seule : elle sert uniquement a
    CORROBORER l'hypothese TTL deja posee, jamais a reclasser vers une
    autre famille. N'a aucun effet si `guess` porte deja une confiance
    superieure a CONFIDENCE_LOW (idempotent, plusieurs appels
    successifs ne degradent jamais la confiance)."""
    if guess.confidence != CONFIDENCE_LOW:
        logger.debug(
            "refine_with_tcp_options: si guess.confidence != CONFIDENCE_LOW -> retour guess={}",
            summarize(guess, "guess"),
        )
        return guess
    if wscale_shift is None or not sack_permitted:
        logger.debug(
            "refine_with_tcp_options: si wscale_shift is None or not sack_permitted -> retour guess={}",
            summarize(guess, "guess"),
        )
        return guess
    logger.debug("refine_with_tcp_options: retour OsGuess(…)")
    return OsGuess(
        family=guess.family,
        guessed_initial_ttl=guess.guessed_initial_ttl,
        observed_ttl=guess.observed_ttl,
        hop_estimate=guess.hop_estimate,
        confidence=CONFIDENCE_MEDIUM,
        evidence=(
            guess.evidence + f" ; options handshake coherentes (wscale={wscale_shift}, SACK permis, MSS={mss_val})"
        ),
    )
