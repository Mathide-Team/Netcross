"""
netcross_core.security -- detection passive de vulnerabilites (CVE) sur
traces reseau (issue #133, sous-tache CVE-4 / issue #138).

Ce sous-package regroupe :
- cve_db.py    : base SQLite locale des CVE (import NVD, requetes par
                 produit/vendor), aucune dependance reseau au runtime.
- expert_correlation.py : correlation des alertes Expert Info (_ws.expert,
                 applicatives) en signaux d'attaque -- fuzzing, overflow,
                 deni de service (issue #137, sous-tache CVE-3).
- cpe_match.py : conversion d'une banniere de service ("Apache/2.4.41")
                 en identifiant CPE 2.3 et comparaison de versions
                 (gestion des ranges NVD : versionStart/EndIncluding/
                 Excluding).

Dependance amont (documentee par #133) : CVE-4 (#138) est cense
consommer les versions extraites par CVE-1 (#135, "extraction des
bannieres de versions, fingerprinting passif"), qui n'est pas encore
mergee au moment de cette PR (toujours ouverte). La correlation
ci-dessous n'est donc PAS encore cablee sur le pipeline d'analyse
(Pkt/Flow) : elle accepte directement des chaines "produit/version"
(le format que donne l'exemple des criteres d'acceptation de #138,
"Apache/2.4.41") en entree. Une fois #135 mergee, il suffira d'appeler
correlate_versions() avec les bannieres qu'elle extrait -- aucun
changement de signature attendu, seulement un nouvel appelant.
"""

from __future__ import annotations

from dataclasses import dataclass

from netcross_core.logging_config import get_logger
from netcross_core.security.cpe_match import ParsedBanner, parse_all_banners, parse_banner, vendor_candidates
from netcross_core.security.cve_db import (
    AffectedProduct,
    CveEntry,
    close_db,
    connect_cve_db,
    count_cves,
    get_cve,
    init_db,
    query_by_product,
    upsert_cve,
)

logger = get_logger(__name__)

__all__ = [
    "AffectedProduct",
    "CveEntry",
    "CveMatch",
    "ParsedBanner",
    "close_db",
    "connect_cve_db",
    "correlate_banner",
    "correlate_versions",
    "count_cves",
    "get_cve",
    "init_db",
    "parse_all_banners",
    "parse_banner",
    "query_by_product",
    "upsert_cve",
]


@dataclass(frozen=True, slots=True)
class CveMatch:
    """
    Une CVE corrélée avec une bannière observée -- ce que #138 attend en
    sortie ("Apache/2.4.41 -> CVE-2021-41773, CVE-2021-42013, etc.",
    "Score CVSS affiché pour chaque vulnérabilité détectée").
    """

    cve_id: str
    cvss_score: float | None
    cvss_severity: str | None
    description: str
    matched_cpe: str
    banner: str


def correlate_banner(conn, banner: str) -> list[CveMatch]:
    """
    Corrèle une seule bannière de service ("Apache/2.4.41", "OpenSSH_8.2p1",
    "nginx/1.18.0", ...) avec la base CVE locale `conn`. Renvoie une liste
    triée par score CVSS décroissant (les plus critiques d'abord), vide si
    la bannière n'est pas reconnue (produit non catalogué dans
    cpe_match.PRODUCT_ALIASES) ou si aucune CVE ne s'applique à cette
    version précise.
    """
    parsed = parse_banner(banner)
    if parsed is None:
        logger.debug("correlate_banner: bannière sans produit reconnu")
        return []

    matches: list[CveMatch] = []
    entries: dict[str, CveEntry] = {}
    for vendor in vendor_candidates(parsed.vendor, parsed.product):
        for entry in query_by_product(conn, vendor, parsed.product):
            entries.setdefault(entry.cve_id, entry)  # une CVE listee sous deux vendeurs
    for entry in entries.values():
        matched = entry.matching_cpe(parsed.version)
        if matched is None:
            continue
        matches.append(
            CveMatch(
                cve_id=entry.cve_id,
                cvss_score=entry.cvss_score,
                cvss_severity=entry.cvss_severity,
                description=entry.description,
                matched_cpe=matched,
                banner=banner,
            )
        )

    matches.sort(key=lambda m: (m.cvss_score is None, -(m.cvss_score or 0.0), m.cve_id))
    logger.debug("correlate_banner: {} CVE candidate(s)", len(matches))
    return matches


def correlate_versions(conn, banners) -> dict[str, list[CveMatch]]:
    """
    Corrèle plusieurs bannières en une passe (une connexion SQLite
    ouverte une seule fois plutôt qu'à chaque appel). `banners` est
    n'importe quel itérable de chaînes -- typiquement les valeurs
    dédupliquées d'un futur `ServiceBanner.raw` (#135) une fois cette
    issue mergée ; en attendant, un simple `list[str]` construit par
    l'appelant suffit (voir docstring de module).

    Renvoie un dict {banniere: [CveMatch, ...]} qui omet les bannières
    sans aucune correspondance, pour que `len(resultat)` donne
    directement le nombre de services vulnérables plutôt que le nombre
    de bannières testées.
    """
    result: dict[str, list[CveMatch]] = {}
    for banner in banners:
        matches = correlate_banner(conn, banner)
        if matches:
            result[banner] = matches
    logger.debug("correlate_versions: {} bannière(s) avec CVE", len(result))
    return result
