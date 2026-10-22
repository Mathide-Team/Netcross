#!/usr/bin/env python3
"""
scripts/import_nvd.py -- import (periodique) du flux NVD dans la base
CVE locale SQLite (netcross_core.security.cve_db), issue #138 (CVE-4).

Ce script est la SEULE piece de la fonctionnalite CVE-4 qui touche le
reseau -- volontairement isole de netcross_core.security (voir la
docstring de ce package) pour que la correlation elle-meme reste
utilisable hors-ligne, sur une base deja peuplee (critere d'acceptation
#138 : "Aucune dependance reseau au runtime").

Deux modes d'entree, non exclusifs (le fichier local est toujours
prioritaire s'il est fourni, pour permettre un import reproductible en
CI/tests sans reseau) :

    --input CHEMIN.json   charge un export local de l'API NVD 2.0
                          (https://services.nvd.nist.gov/rest/json/cves/2.0),
                          au format {"vulnerabilities": [{"cve": {...}}, ...]}

    --fetch               interroge directement l'API NVD 2.0 en paginant
                          (parametre --results-per-page, 2000 par defaut,
                          plafond impose par l'API elle-meme), avec une
                          pause entre pages (--delay, defaut 6s) pour
                          respecter la limite de debit publique du NVD
                          (5 requetes / 30s sans cle d'API).

Usage :
    python3 scripts/import_nvd.py --db data/cve.db --input nvd-export.json
    python3 scripts/import_nvd.py --db data/cve.db --fetch --keyword apache

Non execute dans cet environnement de developpement (pas d'acces reseau
sortant vers nvd.nist.gov depuis ce conteneur -- meme situation que
celle documentee dans la PR #122, "Job 25", pour les tests non executes
faute d'environnement reseau) : la logique de parsing est validee par
tests/test_cve_correlation.py contre une fixture locale au format NVD
reel, sans dependre du mode --fetch.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

try:
    from loguru import logger
except ImportError:  # invoqué par la CI avec le python système, sans loguru
    class _logger:  # noqa: N801 -- repli muet, mêmes méthodes que loguru
        def _mute(self, *_args, **_kwargs):
            pass

        trace = debug = info = success = warning = error = exception = critical = log = _mute

    logger = _logger()

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from netcross_core.security.cve_db import AffectedProduct, CveEntry, connect_cve_db, upsert_cve  # noqa: E402

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Ordre de preference des metriques CVSS : la plus recente version du
# standard d'abord (V3.1 remplace V3.0 depuis 2019 ; V2 reste le seul
# score present sur les CVE anciennes que le NVD n'a jamais re-notees).
_CVSS_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def iter_nvd_items(payload: dict) -> Iterator[dict]:
    """Itere les objets `cve` (un par CVE) d'une reponse API NVD 2.0 deja chargee en memoire."""
    for vuln in payload.get("vulnerabilities", []):
        cve = vuln.get("cve")
        if cve is not None:
            yield cve


def _extract_description(cve: dict) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    descriptions = cve.get("descriptions", [])
    return descriptions[0].get("value", "") if descriptions else ""


def _extract_cvss(cve: dict) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics", {})
    for key in _CVSS_METRIC_KEYS:
        entries = metrics.get(key)
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        score = data.get("baseScore")
        # V2 ne porte pas baseSeverity dans cvssData mais a cote, sur l'entree elle-meme.
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
        return score, severity
    return None, None


def _extract_affected(cve: dict) -> list[AffectedProduct]:
    """
    Aplati `configurations[].nodes[].cpeMatch[]` (vulnerable=true
    uniquement) en AffectedProduct(vendor, product, ranges). Le CPE 2.3
    ("criteria") est de la forme cpe:2.3:a:vendor:product:version:... --
    seuls les champs 4 (vendor) et 5 (product) sont utilises pour le
    matching ; la version du criteria elle-meme (champ 6) sert de
    version exacte quand aucun versionStart/End n'est fourni.
    """
    affected: list[AffectedProduct] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", True):
                    continue
                criteria = cpe_match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) < 6 or parts[2] != "a":
                    continue  # ignore les CPE materiels ("h") / OS ("o") -- hors perimetre #138
                vendor, product, version = parts[3], parts[4], parts[5]
                affected.append(
                    AffectedProduct(
                        vendor=vendor,
                        product=product,
                        version=None if version == "*" else version,
                        version_start_including=cpe_match.get("versionStartIncluding"),
                        version_start_excluding=cpe_match.get("versionStartExcluding"),
                        version_end_including=cpe_match.get("versionEndIncluding"),
                        version_end_excluding=cpe_match.get("versionEndExcluding"),
                    )
                )
    return affected


def parse_nvd_item(cve: dict) -> CveEntry:
    """Convertit un objet `cve` brut (API NVD 2.0) en CveEntry pret pour cve_db.upsert_cve()."""
    score, severity = _extract_cvss(cve)
    return CveEntry(
        cve_id=cve["id"],
        description=_extract_description(cve),
        cvss_score=score,
        cvss_severity=severity,
        published=cve.get("published"),
        affected=_extract_affected(cve),
    )


def import_from_file(path, db_path) -> int:
    """Charge un export NVD local (--input) dans la base `db_path`. Renvoie le nombre de CVE importees."""
    with open(path, encoding="utf-8") as f:
        payload = json.load(f)
    conn = connect_cve_db(db_path)
    count = 0
    try:
        for item in iter_nvd_items(payload):
            upsert_cve(conn, parse_nvd_item(item))
            count += 1
    finally:
        conn.close()
    return count


def _fetch_page_once(params: dict[str, Any]) -> dict:
    url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
    request = urllib.request.Request(url, headers={"User-Agent": "netcross-cve-import/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 -- URL fixe, hote NVD officiel
        return json.load(response)


def _is_throttled(payload: dict) -> bool:
    """Le NVD limite le debit SANS code d'erreur : HTTP 200, `totalResults`
    renseigne mais `resultsPerPage` a 0 et aucune vulnerabilite (constate
    en 2026, issue #353). Une telle page n'est pas une fin de resultats."""
    start = payload.get("startIndex", 0)
    return not payload.get("vulnerabilities") and payload.get("totalResults", 0) > start


def _fetch_page(params: dict[str, Any], *, retries: int = 4, backoff: float = 10.0) -> dict:
    """Une page de l'API, en reessayant (pause `backoff` croissante) tant
    que le NVD renvoie une page vide de limitation de debit. Leve
    RuntimeError si la limitation persiste, plutot que tronquer l'import
    en silence."""
    page_size = int(params.get("resultsPerPage", 2000))
    for attempt in range(retries + 1):
        # une page vide de limitation semble mise en cache par URL : faire
        # varier resultsPerPage (sans effet sur le contenu, l'appelant avance
        # de la taille reellement recue) change la cle de cache.
        payload = _fetch_page_once({**params, "resultsPerPage": max(1, page_size - attempt)} if attempt else params)
        if not _is_throttled(payload):
            return payload
        if attempt < retries:
            time.sleep(backoff * (attempt + 1))
    raise RuntimeError(
        f"Le NVD limite le debit (page vide malgre totalResults={payload.get('totalResults')}, "
        f"parametres {params}) : relancer plus tard ou augmenter --delay."
    )


def import_from_api(db_path, *, keyword: str | None, results_per_page: int, delay: float) -> int:
    """
    Pagine sur l'API NVD 2.0 (max `results_per_page` resultats par
    requete, defaut 2000) jusqu'a epuisement, avec `delay` secondes
    entre deux requetes (limite de debit publique du NVD sans cle
    d'API : 5 requetes / 30s). Chaque page importee immediatement
    (upsert) plutot qu'accumulee : un import interrompu au milieu
    conserve les CVE deja recuperees.
    """
    conn = connect_cve_db(db_path)
    total = 0
    start_index = 0
    try:
        while True:
            params: dict[str, Any] = {"startIndex": start_index, "resultsPerPage": results_per_page}
            if keyword:
                params["keywordSearch"] = keyword
            try:
                payload = _fetch_page(params)
            except urllib.error.URLError as exc:
                logger.error("requete NVD en echec (startIndex={}) : {}", start_index, exc)
                raise RuntimeError(
                    f"Echec de la requete NVD (startIndex={start_index}) : {exc}. "
                    "Verifier l'acces reseau sortant vers services.nvd.nist.gov."
                ) from exc

            page_count = 0
            for item in iter_nvd_items(payload):
                upsert_cve(conn, parse_nvd_item(item))
                page_count += 1
                total += 1

            total_results = payload.get("totalResults", total)
            start_index += page_count
            if page_count == 0 or start_index >= total_results:
                break
            time.sleep(delay)
    finally:
        conn.close()
    return total


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", required=True, help="chemin de la base SQLite CVE (cree si absente)")
    parser.add_argument("--input", help="fichier JSON local au format API NVD 2.0 (mode hors-ligne, prioritaire)")
    parser.add_argument("--fetch", action="store_true", help="interroger directement l'API NVD 2.0")
    parser.add_argument("--keyword", help="filtre keywordSearch de l'API NVD (--fetch uniquement)")
    parser.add_argument("--results-per-page", type=int, default=2000, help="taille de page (--fetch), defaut 2000")
    parser.add_argument("--delay", type=float, default=6.0, help="secondes entre deux pages (--fetch), defaut 6.0")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.input:
        count = import_from_file(args.input, args.db)
        print(f"{count} CVE importees depuis {args.input} vers {args.db}")
        return 0

    if args.fetch:
        count = import_from_api(args.db, keyword=args.keyword, results_per_page=args.results_per_page, delay=args.delay)
        print(f"{count} CVE importees depuis l'API NVD vers {args.db}")
        return 0

    print("Aucune source fournie : utiliser --input FICHIER.json ou --fetch.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
