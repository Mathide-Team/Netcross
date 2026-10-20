"""
netcross_core.lua_dissectors -- catalogue des dissecteurs Wireshark écrits en
Lua, dans la banque Lua (issue #917).

Source : le recensement du dépôt Mathilde-Team/wireshark-lua (une issue par
dissecteur, CSV complet joint à l'issue #559), versionné dans
``data/lua_dissectors.csv`` (``scripts/import_lua_dissectors.py`` le
normalise). Chargé dans la même base SQLite que la documentation de l'API
Lua (``netcross_core.lua_doc``), tables ``dissecteurs`` et index plein texte
``recherche_dissecteurs`` (empreinte dans ``meta_dissecteurs``, à part de la
``meta`` de l'API) ; rechargé quand l'empreinte du CSV change, sans
accès réseau au runtime.

Seules les métadonnées sont gardées (dépôt, domaine, protocole, licence,
popularité, présence d'un dissecteur natif dans Wireshark) : le code des
dissecteurs reste dans leurs dépôts, sous leur propre licence.
"""

from __future__ import annotations

import csv
import hashlib
import io
import os
import sqlite3
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

#: variable d'environnement pour pointer un autre CSV que ceux de csv_candidates()
ENV_CSV = "NETCROSS_LUA_DISSECTORS_CSV"

#: colonnes attendues du CSV (en-tête du recensement wireshark-lua)
COLONNES = (
    "url",
    "domaine",
    "protocole",
    "etoiles",
    "forks",
    "derniere_maj",
    "date_creation",
    "licence",
    "archive",
    "topics",
    "langage_confirme",
    "natif_wireshark_4_6_4",
    "ajout",
)

_META_SHA = "dissecteurs_sha256"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS dissecteurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    depot TEXT NOT NULL,
    hebergeur TEXT NOT NULL,
    domaine TEXT NOT NULL DEFAULT '',
    protocole TEXT NOT NULL DEFAULT '',
    etoiles INTEGER NOT NULL DEFAULT 0,
    forks INTEGER NOT NULL DEFAULT 0,
    derniere_maj TEXT NOT NULL DEFAULT '',
    date_creation TEXT NOT NULL DEFAULT '',
    licence TEXT NOT NULL DEFAULT '',
    archive INTEGER NOT NULL DEFAULT 0,
    topics TEXT NOT NULL DEFAULT '',
    langage TEXT NOT NULL DEFAULT '',
    natif INTEGER NOT NULL DEFAULT 0,
    natif_protocole TEXT NOT NULL DEFAULT '',
    ajout TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_dissecteurs_domaine ON dissecteurs(domaine);
CREATE VIRTUAL TABLE IF NOT EXISTS recherche_dissecteurs USING fts5(
    depot, domaine, protocole, topics,
    ref_id UNINDEXED,
    tokenize = 'unicode61 remove_diacritics 2'
);
CREATE TABLE IF NOT EXISTS meta_dissecteurs (
    cle TEXT PRIMARY KEY,
    valeur TEXT NOT NULL
);
"""


@dataclass
class Dissecteur:
    url: str
    depot: str
    hebergeur: str
    domaine: str
    protocole: str
    etoiles: int
    forks: int
    derniere_maj: str
    date_creation: str
    licence: str
    archive: bool
    topics: str
    langage: str
    natif: bool
    natif_protocole: str
    ajout: str


class CatalogueError(ValueError):
    """CSV du catalogue illisible (en-tête ou ligne invalide)."""


def _entier(valeur: str) -> int:
    valeur = (valeur or "").strip()
    return int(valeur) if valeur.isdigit() else 0


def parse_row(row: dict[str, str]) -> dict[str, Any]:
    """Ligne du CSV -> colonnes de la table ``dissecteurs``."""
    url = (row.get("url") or "").strip().rstrip("/")
    morceaux = url.split("/")
    if len(morceaux) < 5 or not url.startswith("https://"):
        logger.debug("parse_row: url invalide {}", url)
        raise CatalogueError(f"URL de dépôt invalide : {url!r}")
    natif_brut = (row.get("natif_wireshark_4_6_4") or "").strip()
    natif = natif_brut.lower().startswith("oui")
    return {
        "url": url,
        "depot": "/".join(morceaux[3:5]),
        "hebergeur": morceaux[2],
        "domaine": (row.get("domaine") or "").strip(),
        "protocole": (row.get("protocole") or "").strip(),
        "etoiles": _entier(row.get("etoiles", "")),
        "forks": _entier(row.get("forks", "")),
        "derniere_maj": (row.get("derniere_maj") or "").strip(),
        "date_creation": (row.get("date_creation") or "").strip(),
        "licence": (row.get("licence") or "").strip(),
        "archive": (row.get("archive") or "").strip().lower() == "oui",
        "topics": (row.get("topics") or "").strip(),
        "langage": (row.get("langage_confirme") or "").strip(),
        "natif": natif,
        "natif_protocole": natif_brut.split(":", 1)[1].strip() if natif and ":" in natif_brut else "",
        "ajout": (row.get("ajout") or "").strip(),
    }


def read_csv(texte: str) -> list[dict[str, Any]]:
    """Lit le CSV du recensement ; une URL en double garde sa première ligne."""
    lecteur = csv.DictReader(io.StringIO(texte.lstrip("\ufeff")))
    manquantes = [c for c in ("url", "domaine", "protocole") if c not in (lecteur.fieldnames or [])]
    if manquantes:
        logger.debug("read_csv: colonnes manquantes {}", manquantes)
        raise CatalogueError(f"colonnes manquantes dans le CSV : {', '.join(manquantes)}")
    lignes: dict[str, dict[str, Any]] = {}
    for numero, row in enumerate(lecteur, start=2):
        try:
            ligne = parse_row(row)
        except CatalogueError as exc:
            logger.debug("read_csv: ligne {} invalide", numero)
            raise CatalogueError(f"ligne {numero} : {exc}") from exc
        lignes.setdefault(ligne["url"].lower(), ligne)
    return list(lignes.values())


def load_csv(conn: sqlite3.Connection, texte: str) -> int:
    """Remplace le catalogue par le contenu du CSV ; retourne le nombre de dissecteurs."""
    lignes = read_csv(texte)
    with conn:
        conn.executescript(_SCHEMA)
        conn.execute("DELETE FROM recherche_dissecteurs")
        conn.execute("DELETE FROM dissecteurs")
        for ligne in lignes:
            cur = conn.execute(
                f"INSERT INTO dissecteurs({', '.join(ligne)}) VALUES ({', '.join('?' * len(ligne))})",  # noqa: S608 -- colonnes constantes
                tuple(ligne.values()),
            )
            conn.execute(
                "INSERT INTO recherche_dissecteurs(depot, domaine, protocole, topics, ref_id) VALUES (?, ?, ?, ?, ?)",
                (
                    ligne["depot"].replace("/", " "),
                    ligne["domaine"],
                    ligne["protocole"],
                    ligne["topics"],
                    cur.lastrowid,
                ),
            )
        conn.execute(
            "INSERT OR REPLACE INTO meta_dissecteurs(cle, valeur) VALUES (?, ?)",
            (_META_SHA, hashlib.sha256(texte.encode("utf-8")).hexdigest()),
        )
    logger.info("catalogue des dissecteurs Lua : {} entrées chargées", len(lignes))
    return len(lignes)


def csv_candidates() -> list[Path]:
    """Emplacements du CSV, par priorité : $NETCROSS_LUA_DISSECTORS_CSV, dépôt, paquet deb/rpm."""
    here = Path(__file__).resolve()
    candidats = [
        here.parents[2] / "data" / "lua_dissectors.csv",
        here.parents[1] / "data" / "lua_dissectors.csv",
    ]
    env = os.environ.get(ENV_CSV)
    logger.debug("csv_candidates: env={}", env)
    return [Path(env).expanduser(), *candidats] if env else candidats


def find_csv() -> Path | None:
    logger.debug("find_csv()")
    return next((p for p in csv_candidates() if p.is_file()), None)


def ensure_catalogue(conn: sqlite3.Connection, csv_path: str | Path | None = None) -> bool:
    """Charge le catalogue si le CSV a changé (empreinte sha256). Retourne
    False si aucun CSV n'est disponible (catalogue vide)."""
    chemin = Path(csv_path) if csv_path else find_csv()
    conn.executescript(_SCHEMA)
    if chemin is None or not chemin.is_file():
        logger.warning("catalogue des dissecteurs Lua : CSV introuvable ({})", ", ".join(map(str, csv_candidates())))
        return False
    texte = chemin.read_text(encoding="utf-8")
    attendu = hashlib.sha256(texte.encode("utf-8")).hexdigest()
    actuel = conn.execute("SELECT valeur FROM meta_dissecteurs WHERE cle = ?", (_META_SHA,)).fetchone()
    if actuel is None or actuel[0] != attendu:
        load_csv(conn, texte)
    logger.debug("ensure_catalogue: {} prêt", chemin)
    return True


def _depuis_ligne(row: sqlite3.Row | tuple) -> Dissecteur:
    d = Dissecteur(*row)
    d.archive, d.natif = bool(d.archive), bool(d.natif)
    return d


_CHAMPS = (
    "url, depot, hebergeur, domaine, protocole, etoiles, forks, derniere_maj, date_creation, "
    "licence, archive, topics, langage, natif, natif_protocole, ajout"
)


def _plier(texte: str) -> str:
    """Minuscules sans accents (``Énergie`` -> ``energie``)."""
    decompose = unicodedata.normalize("NFKD", texte.casefold())
    return "".join(c for c in decompose if not unicodedata.combining(c))


def _fts(terme: str) -> str:
    mots = [m.replace('"', "") for m in terme.split() if m.replace('"', "")]
    return " ".join(f'"{m}"*' for m in mots)


def search(
    conn: sqlite3.Connection,
    terme: str = "",
    domaine: str | None = None,
    non_natif: bool = False,
    limit: int = 20,
) -> tuple[int, list[Dissecteur]]:
    """(nombre total de correspondances, ``limit`` premiers dissecteurs).

    ``terme`` : recherche plein texte (dépôt, domaine, protocole, topics ; tous
    les mots, préfixes acceptés, sans accents). ``domaine`` : sous-chaîne du
    domaine, insensible à la casse. ``non_natif`` : seulement les protocoles
    sans dissecteur natif dans Wireshark. Tri : étoiles décroissantes (les
    dépôts les plus suivis d'abord), puis nom du dépôt."""
    logger.debug(
        "lua_dissectors.search: terme={} domaine={} non_natif={} limit={}",
        summarize(terme, "terme"),
        domaine,
        non_natif,
        limit,
    )
    clauses, params = [], []
    ordre = "d.etoiles DESC, d.depot"
    jointure = ""
    if terme.strip() and _fts(terme):
        jointure = "JOIN recherche_dissecteurs r ON r.ref_id = d.id AND recherche_dissecteurs MATCH ?"
        params.append(_fts(terme))
    if domaine and domaine.strip():
        # comparaison sans accents ni casse côté Python (lower() de SQLite ignore É, À...)
        voulus = [d for d, _n in domains(conn) if _plier(domaine.strip()) in _plier(d)]
        clauses.append(f"d.domaine IN ({', '.join('?' * len(voulus))})" if voulus else "0")
        params.extend(voulus)
    if non_natif:
        clauses.append("d.natif = 0")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    base = f"FROM dissecteurs d {jointure} {where}"  # noqa: S608 -- fragments constants, valeurs en paramètres
    total = conn.execute(f"SELECT count(*) {base}", params).fetchone()[0]  # noqa: S608
    champs = ", ".join(f"d.{c.strip()}" for c in _CHAMPS.split(","))
    rows = conn.execute(f"SELECT {champs} {base} ORDER BY {ordre} LIMIT ?", [*params, limit]).fetchall()  # noqa: S608
    return total, [_depuis_ligne(r) for r in rows]


def domains(conn: sqlite3.Connection) -> list[tuple[str, int]]:
    """Domaines du catalogue avec leur nombre de dissecteurs, du plus fourni au moins fourni."""
    logger.debug("lua_dissectors.domains()")
    return [
        (d, n)
        for d, n in conn.execute(
            "SELECT domaine, count(*) FROM dissecteurs GROUP BY domaine ORDER BY count(*) DESC, domaine"
        ).fetchall()
    ]


def count(conn: sqlite3.Connection) -> int:
    logger.debug("lua_dissectors.count()")
    return int(conn.execute("SELECT count(*) FROM dissecteurs").fetchone()[0])


def search_document(
    conn: sqlite3.Connection, terme: str = "", domaine: str | None = None, non_natif: bool = False, limit: int = 20
) -> dict[str, Any]:
    """Document JSON commun à ``netcross-lua-doc --dissectors --json``, à
    ``GET /lua-doc/dissectors`` et à la GUI."""
    total, res = search(conn, terme, domaine, non_natif, limit)
    logger.debug("lua_dissectors.search_document: {} / {}", len(res), total)
    return {
        "terme": terme,
        "domaine": domaine or "",
        "non_natif": non_natif,
        "total": total,
        "catalogue": count(conn),
        "dissecteurs": [asdict(d) for d in res],
    }


def domains_document(conn: sqlite3.Connection) -> dict[str, Any]:
    logger.debug("lua_dissectors.domains_document()")
    return {"catalogue": count(conn), "domaines": [{"domaine": d, "dissecteurs": n} for d, n in domains(conn)]}
