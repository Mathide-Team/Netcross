"""
Base CVE minimale embarquee (issue #353).

Sans `--cve-db`, aucune correlation CVE n'etait faite : un Apache 2.4.49
n'etait pas qualifie vulnerable. `open_seed_db()` charge en memoire une
courte selection de CVE critiques (`data/cve_seed.json`, extraite de
l'API NVD 2.0 par `scripts/build_cve_seed.py`) sur les produits
catalogues dans `cpe_match.PRODUCT_ALIASES`.

C'est un filet de securite, pas une base complete : une version absente
de la selection n'est PAS pour autant non vulnerable. Le CLI le rappelle
et `--cve-db` (base importee par `scripts/import_nvd.py`) reste la voie
normale. Aucun acces reseau au runtime : le fichier est livre avec le
paquet.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from netcross_core.logging_config import get_logger
from netcross_core.security.cve_db import AffectedProduct, CveEntry, connect_cve_db, upsert_cve

logger = get_logger(__name__)

SEED_FORMAT_VERSION = 1
DEFAULT_SEED_PATH = Path(__file__).resolve().parent.parent / "data" / "cve_seed.json"


@dataclass(frozen=True, slots=True)
class CveSeed:
    """Contenu de la base embarquee : entrees + provenance."""

    entries: tuple[CveEntry, ...]
    source: str
    generated: str


def load_seed(path: Path | str = DEFAULT_SEED_PATH) -> CveSeed:
    """Lit et valide le fichier de base embarquee (ValueError si le format est inattendu)."""
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict) or raw.get("version") != SEED_FORMAT_VERSION:
        raise ValueError(f"{path} : format de base CVE embarquee inattendu (version {SEED_FORMAT_VERSION} attendue)")
    entries = []
    for item in raw.get("cves", []):
        affected = [AffectedProduct(**product) for product in item.get("affected", [])]
        entries.append(
            CveEntry(
                cve_id=item["cve_id"],
                description=item["description"],
                cvss_score=item.get("cvss_score"),
                cvss_severity=item.get("cvss_severity"),
                published=item.get("published"),
                affected=affected,
            )
        )
    logger.debug("load_seed: {} entrée(s) depuis {}", len(entries), path)
    return CveSeed(entries=tuple(entries), source=str(raw.get("source", "")), generated=str(raw.get("generated", "")))


def open_seed_db(path: Path | str = DEFAULT_SEED_PATH) -> tuple[sqlite3.Connection, CveSeed]:
    """Base SQLite EN MEMOIRE peuplee depuis la base embarquee (meme schema que --cve-db)."""
    seed = load_seed(path)
    conn = connect_cve_db(":memory:")
    for entry in seed.entries:
        upsert_cve(conn, entry)
    conn.commit()
    logger.debug("base CVE embarquee chargee : %d CVE (%s)", len(seed.entries), seed.generated)
    return conn, seed
