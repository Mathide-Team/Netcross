"""
netcross_core.security.fast_flux -- issue #152 (SCENARIO-6, parent #141) :
detection d'infrastructures a flux rapide (fast flux) utilisees par les
botnets et C2.

Le fast flux consiste a faire resoudre un meme domaine vers de
nombreuses IP differentes en peu de temps (rotation d'IPs), rendant
le blocage par IP inefficace.

Deux signaux :

- **ip_rotation** : les reponses DNS d'un domaine, vues a un meme point,
  annoncent >= ``min_ips`` adresses A/AAAA differentes dans une fenetre
  glissante de ``window_seconds`` (defaut : 5 IPs en 600 s), reparties
  sur au moins ``min_responses`` reponses. Signal central.
- **high_nxdomain** : un domaine a un ratio NXDOMAIN >=
  ``nxdomain_ratio_min`` (defaut : 0.7). Signal faible.

Issue #344 (audit 2026-09) : la premiere version correlait « une source
resout un nom » avec « cette source ouvre des connexions TCP » et comptait
TOUTES les destinations TCP de la source dans la fenetre, sans lien avec
les reponses DNS. Un poste qui resolvait un nom puis scannait son reseau
declenchait une alerte par domaine resolu (198 alertes ip_rotation sur le
scenario de l'audit, zero fast flux reel). Le calcul repose maintenant
uniquement sur les adresses reellement annoncees par les reponses DNS
(``Pkt.dns_answers``, lu depuis ``dns.a``/``dns.aaaa``).

Anti faux positifs :
- liste blanche des memes domaines legitimes que dga.py (CDN, cloud...) ;
- domaines ignores (in-addr.arpa, local...) ;
- une seule reponse, meme avec beaucoup d'enregistrements (round-robin
  classique), ne suffit pas : il faut une rotation entre reponses ;
- minimum de ``min_ips`` IPs differentes (2-3 est normal pour un CDN).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt
from netcross_core.security.dga import _WHITELIST_DOMAINS
from netcross_core.security.dns_tunnel import _is_ignored, split_domain

logger = get_logger(__name__)


@dataclass
class FastFluxThresholds:
    """Seuils de detection fast flux (tous configurables)."""

    # IP rotation
    min_ips: int = 5  # minimum d'IPs differentes annoncees
    window_seconds: float = 600.0  # fenetre glissante (10 min)
    min_responses: int = 2  # une rotation suppose au moins deux reponses
    # NXDOMAIN
    nxdomain_ratio_min: float = 0.7
    nxdomain_min_responses: int = 5  # minimum de reponses pour evaluer le ratio


@dataclass
class FastFluxAlert:
    """Une alerte fast flux pour un domaine suspect.

    Issue #343 : un domaine suspect vu depuis plusieurs points de capture
    est UN evenement -- `points` liste tous les points ou il a ete
    observe (`point` reste un alias retro-compatible : premier point
    trie, ou None si `points` est vide)."""

    domain: str
    alert_type: str  # ip_rotation | high_nxdomain
    score: float  # 0.0 a 1.0
    reason: str
    points: tuple[str, ...] = ()
    ips: list[str] = field(default_factory=list)
    nxdomain_ratio: float = 0.0

    @property
    def point(self) -> str | None:
        return self.points[0] if self.points else None


@dataclass
class FastFluxResult:
    """Resultat de la detection fast flux."""

    alerts: list[FastFluxAlert] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return bool(self.alerts)


def detect_fast_flux(
    packets: Iterable[Pkt],
    thresholds: FastFluxThresholds | None = None,
) -> FastFluxResult:
    """Detection fast flux a partir des reponses DNS (issue #344).

    Pour chaque couple (point, nom complet) :

    1. collecte les adresses A/AAAA de chaque reponse DNS reussie ;
    2. cherche la fenetre de ``window_seconds`` contenant le plus
       d'adresses distinctes ; alerte ``ip_rotation`` si ce nombre atteint
       ``min_ips`` sur au moins ``min_responses`` reponses ;
    3. calcule le ratio NXDOMAIN (signal faible ``high_nxdomain``).

    Les connexions TCP ne sont plus utilisees : une destination contactee
    n'est pas une preuve de resolution.
    """
    if thresholds is None:
        thresholds = FastFluxThresholds()

    # (point, nom) -> compteurs et reponses horodatees
    per_key: dict[tuple[str, str], dict] = defaultdict(lambda: {"nxdomain": 0, "responses": 0, "answers": []})

    for pkt in packets:
        if not pkt.dns_qry_name or not pkt.dns_is_response:
            continue
        name = pkt.dns_qry_name.lower().strip(".")
        if _is_ignored(name):
            continue
        registered, _sub = split_domain(name)
        if not registered or registered in _WHITELIST_DOMAINS:
            continue

        info = per_key[(pkt.point, name)]
        info["responses"] += 1
        if pkt.dns_rcode == 3:
            info["nxdomain"] += 1
        answers = getattr(pkt, "dns_answers", ()) or ()
        if answers and pkt.dns_rcode in (0, None):
            info["answers"].append((pkt.ts, tuple(answers)))

    alerts: list[FastFluxAlert] = []
    for (point, name), info in sorted(per_key.items()):
        # Signal 1 : rotation d'IPs dans les reponses
        best_ips, best_n_resp = _best_window(info["answers"], thresholds.window_seconds)
        if len(best_ips) >= thresholds.min_ips and best_n_resp >= thresholds.min_responses:
            score = min(1.0, len(best_ips) / (thresholds.min_ips * 2))
            alerts.append(
                FastFluxAlert(
                    points=(point,),
                    domain=name,
                    alert_type="ip_rotation",
                    score=round(score, 3),
                    reason=(
                        f"rotation d'IPs : {len(best_ips)} adresses differentes annoncees "
                        f"par {best_n_resp} reponses DNS en {thresholds.window_seconds:.0f}s"
                    ),
                    ips=sorted(best_ips)[:20],
                )
            )

        # Signal 2 : ratio NXDOMAIN eleve
        if info["responses"] >= thresholds.nxdomain_min_responses:
            nxdomain_ratio = info["nxdomain"] / info["responses"]
            if nxdomain_ratio >= thresholds.nxdomain_ratio_min:
                alerts.append(
                    FastFluxAlert(
                        points=(point,),
                        domain=name,
                        alert_type="high_nxdomain",
                        score=round(min(1.0, nxdomain_ratio), 3),
                        reason=(
                            f"ratio NXDOMAIN eleve : {info['nxdomain']}/{info['responses']} ({nxdomain_ratio:.2f})"
                        ),
                        nxdomain_ratio=round(nxdomain_ratio, 3),
                    )
                )

    logger.debug("detect_fast_flux: {} alerte(s)", len(alerts))
    return FastFluxResult(alerts=alerts)


def _best_window(answers: list[tuple[float, tuple[str, ...]]], window: float) -> tuple[set[str], int]:
    """Fenetre glissante : ensemble d'IPs distinctes le plus grand, et le
    nombre de reponses qui le composent. ``answers`` = (ts, adresses)."""
    answers = sorted(answers, key=lambda a: a[0])
    best: set[str] = set()
    best_n = 0
    start = 0
    for end in range(len(answers)):
        while answers[end][0] - answers[start][0] > window:
            start += 1
        ips = {ip for _, group in answers[start : end + 1] for ip in group}
        if len(ips) > len(best):
            best, best_n = ips, end - start + 1
    return best, best_n
