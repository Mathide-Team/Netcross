"""
netcross_core.security.cve_db -- base SQLite locale des CVE, peuplee par
scripts/import_nvd.py depuis le flux NVD (voir ce script pour le format
JSON attendu, API NVD 2.0).

sqlite3 est dans la bibliotheque standard, meme convention que
netcross_report.history/netcross_core.baseline_profile : aucune
dependance supplementaire, connexion locale a un fichier .db.
"AUCUNE dependance reseau au runtime" (critere d'acceptation #138) :
toutes les fonctions de ce module lisent/ecrivent uniquement dans le
fichier SQLite local -- l'import (reseau) est un script separe,
execute periodiquement, jamais appele depuis le chemin d'analyse.

Deux tables : `cves` (une ligne par CVE : id, description, score CVSS)
et `cve_products` (N lignes par CVE, une par produit/range affecte --
une CVE Apache peut viser plusieurs ranges de versions selon la branche
2.2/2.4). Correspond a la structure `configurations[].nodes[].cpeMatch[]`
du JSON NVD, aplatie pour etre interrogeable par (vendor, product) sans
reparser le JSON a chaque correlation.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger
from netcross_core.security.cpe_match import build_cpe23, version_in_range

logger = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    cvss_score REAL,
    cvss_severity TEXT,
    published TEXT
);
CREATE TABLE IF NOT EXISTS cve_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL REFERENCES cves(cve_id),
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT
);
CREATE INDEX IF NOT EXISTS idx_cve_products_vendor_product
    ON cve_products(vendor, product);
CREATE INDEX IF NOT EXISTS idx_cve_products_cve_id
    ON cve_products(cve_id);
"""


@dataclass(frozen=True, slots=True)
class AffectedProduct:
    """
    Un couple (produit, range de versions affectees) rattache a une
    CVE -- correspond a une entree `cpeMatch` du JSON NVD. `version`
    porte la version exacte quand la CVE ne precise aucun range (voir
    cpe_match.version_in_range).
    """

    vendor: str
    product: str
    version: str | None = None
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None

    def matches(self, vendor: str, product: str, version: str) -> bool:
        if self.vendor.lower() != vendor.lower() or self.product.lower() != product.lower():
            return False
        return version_in_range(
            version,
            exact=self.version,
            start_including=self.version_start_including,
            start_excluding=self.version_start_excluding,
            end_including=self.version_end_including,
            end_excluding=self.version_end_excluding,
        )


@dataclass(frozen=True, slots=True)
class CveEntry:
    """Une CVE complete : identifiant, description, score CVSS, et tous les produits/ranges qu'elle affecte."""

    cve_id: str
    description: str
    cvss_score: float | None
    cvss_severity: str | None
    published: str | None
    affected: list[AffectedProduct] = field(default_factory=list)

    def matching_cpe(self, version: str) -> str | None:
        """
        Renvoie le CPE 2.3 du premier produit affecte dont le range
        couvre `version`, ou None si aucun ne correspond. `affected` ne
        contient ici que des entrees deja filtrees par (vendor, product)
        par query_by_product() : seule la version reste a comparer.
        """
        for product in self.affected:
            if version_in_range(
                version,
                exact=product.version,
                start_including=product.version_start_including,
                start_excluding=product.version_start_excluding,
                end_including=product.version_end_including,
                end_excluding=product.version_end_excluding,
            ):
                return build_cpe23(product.vendor, product.product, product.version or version)
        return None


def connect_cve_db(db_path) -> sqlite3.Connection:
    """Ouvre (et cree si absent) la base SQLite `db_path`, schema applique."""
    logger.debug("connect_cve_db: {}", db_path)
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA)
    return conn


def init_db(db_path) -> sqlite3.Connection:
    """Alias explicite de connect_cve_db() pour les appelants qui ne font que creer la base (scripts/import_nvd.py)."""
    return connect_cve_db(db_path)


def close_db(conn: sqlite3.Connection) -> None:
    conn.close()


def upsert_cve(conn: sqlite3.Connection, entry: CveEntry) -> None:
    """
    Insere ou remplace une CveEntry (et tous ses produits affectes) --
    idempotent, pour que des imports NVD periodiques successifs sur la
    meme base ne dupliquent jamais une CVE deja connue (une CVE peut
    voir son score CVSS ou sa description revisee par le NVD apres
    publication initiale).
    """
    logger.debug("upsert_cve: {}", entry.cve_id)
    conn.execute(
        "INSERT INTO cves (cve_id, description, cvss_score, cvss_severity, published) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(cve_id) DO UPDATE SET description=excluded.description, "
        "cvss_score=excluded.cvss_score, cvss_severity=excluded.cvss_severity, "
        "published=excluded.published",
        (entry.cve_id, entry.description, entry.cvss_score, entry.cvss_severity, entry.published),
    )
    conn.execute("DELETE FROM cve_products WHERE cve_id = ?", (entry.cve_id,))
    conn.executemany(
        "INSERT INTO cve_products (cve_id, vendor, product, version, version_start_including, "
        "version_start_excluding, version_end_including, version_end_excluding) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                entry.cve_id,
                p.vendor,
                p.product,
                p.version,
                p.version_start_including,
                p.version_start_excluding,
                p.version_end_including,
                p.version_end_excluding,
            )
            for p in entry.affected
        ],
    )
    conn.commit()


def get_cve(conn: sqlite3.Connection, cve_id: str) -> CveEntry | None:
    """Recupere une CVE par identifiant, avec tous ses produits affectes (sans filtre)."""
    row = conn.execute(
        "SELECT cve_id, description, cvss_score, cvss_severity, published FROM cves WHERE cve_id = ?",
        (cve_id,),
    ).fetchone()
    if row is None:
        logger.debug("get_cve: {} absente de la base", cve_id)
        return None
    products = conn.execute(
        "SELECT vendor, product, version, version_start_including, version_start_excluding, "
        "version_end_including, version_end_excluding FROM cve_products WHERE cve_id = ?",
        (cve_id,),
    ).fetchall()
    return CveEntry(
        cve_id=row[0],
        description=row[1],
        cvss_score=row[2],
        cvss_severity=row[3],
        published=row[4],
        affected=[AffectedProduct(*p) for p in products],
    )


def query_by_product(conn: sqlite3.Connection, vendor: str, product: str) -> list[CveEntry]:
    """
    Renvoie toutes les CveEntry qui affectent (vendor, product) --
    insensible a la casse. Chaque CveEntry.affected ne contient QUE les
    ranges de ce produit (pas les autres produits que la meme CVE peut
    par ailleurs affecter) : c'est le pre-filtrage qui rend
    CveEntry.matching_cpe() utilisable directement par correlate_banner()
    sans reparcourir tous les produits d'une CVE multi-produits.
    """
    cve_ids = [
        row[0]
        for row in conn.execute(
            "SELECT DISTINCT cve_id FROM cve_products WHERE lower(vendor) = ? AND lower(product) = ?",
            (vendor.lower(), product.lower()),
        ).fetchall()
    ]
    if not cve_ids:
        logger.debug("query_by_product: aucun CVE pour {}/{}", vendor, product)
        return []

    placeholders = ",".join("?" * len(cve_ids))
    cve_rows = conn.execute(
        f"SELECT cve_id, description, cvss_score, cvss_severity, published FROM cves WHERE cve_id IN ({placeholders})",
        cve_ids,
    ).fetchall()

    product_rows = conn.execute(
        f"SELECT cve_id, vendor, product, version, version_start_including, version_start_excluding, "
        f"version_end_including, version_end_excluding FROM cve_products "
        f"WHERE cve_id IN ({placeholders}) AND lower(vendor) = ? AND lower(product) = ?",
        [*cve_ids, vendor.lower(), product.lower()],
    ).fetchall()

    by_cve: dict[str, list[AffectedProduct]] = {}
    for row in product_rows:
        by_cve.setdefault(row[0], []).append(AffectedProduct(*row[1:]))

    return [
        CveEntry(
            cve_id=row[0],
            description=row[1],
            cvss_score=row[2],
            cvss_severity=row[3],
            published=row[4],
            affected=by_cve.get(row[0], []),
        )
        for row in cve_rows
    ]


def count_cves(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
