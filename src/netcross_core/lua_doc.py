"""
netcross_core.lua_doc -- banque SQLite locale de l'API Lua Wireshark
(issue #387, rattachee a #331).

Chargee depuis le JSON produit par tools/extract_lua_api.py (#386) via
scripts/build_lua_db.py. Meme convention que netcross_core.security.cve_db :
sqlite3 de la bibliotheque standard, aucune dependance reseau au runtime,
un fichier .db local.

Schema :
- ``meta(cle, valeur)`` : version_wireshark, date_generation, source,
  schema_version -- permet de savoir a quelle release correspond la banque ;
- ``classes(id, nom, module, description)`` + ``exemples_classe`` ;
- ``methodes(id, classe_id, nom, genre, signature, description, depuis_version)``
  (genre : constructeur, methode, metamethode, fonction) ;
- ``parametres(id, methode_id, nom, type, optionnel, description, ordre)`` ;
- ``retours(id, methode_id, type, description)`` ;
- ``erreurs(id, methode_id, description)`` ;
- ``exemples(id, methode_id, code)`` ;
- ``attributs(id, classe_id, nom, nom_complet, mode, description, depuis_version)``
  (mode : RO, WO, RW) ;
- ``recherche`` : index FTS5 (classe, nom, signature, description) sur les
  methodes et les attributs, pour la recherche libre.

Le chargement est idempotent : la base est videe puis rechargee, ce qui
permet de la regenerer proprement a chaque nouvelle version de Wireshark.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

SCHEMA_VERSION = 2

#: base par defaut, reconstruite a la volee depuis le JSON (voir ensure_db)
DEFAULT_DB_PATH = Path.home() / ".cache" / "netcross" / "lua_api.db"

#: variable d'environnement pour pointer un autre JSON que ceux de json_candidates()
ENV_JSON = "NETCROSS_LUA_API_JSON"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    cle TEXT PRIMARY KEY,
    valeur TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS classes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT NOT NULL UNIQUE,
    module TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS exemples_classe (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    classe_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    code TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS methodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    classe_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    nom TEXT NOT NULL,
    genre TEXT NOT NULL DEFAULT 'methode',
    signature TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    depuis_version TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS parametres (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    methode_id INTEGER NOT NULL REFERENCES methodes(id) ON DELETE CASCADE,
    nom TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT '',
    optionnel INTEGER NOT NULL DEFAULT 0,
    description TEXT NOT NULL DEFAULT '',
    ordre INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS retours (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    methode_id INTEGER NOT NULL REFERENCES methodes(id) ON DELETE CASCADE,
    type TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS erreurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    methode_id INTEGER NOT NULL REFERENCES methodes(id) ON DELETE CASCADE,
    description TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exemples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    methode_id INTEGER NOT NULL REFERENCES methodes(id) ON DELETE CASCADE,
    code TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attributs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    classe_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    nom TEXT NOT NULL,
    nom_complet TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    depuis_version TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_methodes_classe ON methodes(classe_id);
CREATE INDEX IF NOT EXISTS idx_methodes_nom ON methodes(nom);
CREATE INDEX IF NOT EXISTS idx_parametres_methode ON parametres(methode_id, ordre);
CREATE INDEX IF NOT EXISTS idx_retours_methode ON retours(methode_id);
CREATE INDEX IF NOT EXISTS idx_erreurs_methode ON erreurs(methode_id);
CREATE INDEX IF NOT EXISTS idx_exemples_methode ON exemples(methode_id);
CREATE INDEX IF NOT EXISTS idx_attributs_classe ON attributs(classe_id);
CREATE VIRTUAL TABLE IF NOT EXISTS recherche USING fts5(
    classe, nom, signature, description,
    genre UNINDEXED,
    ref_id UNINDEXED,
    tokenize = 'unicode61 remove_diacritics 2'
);
"""

_TABLES = (
    "recherche",
    "attributs",
    "exemples",
    "erreurs",
    "retours",
    "parametres",
    "methodes",
    "exemples_classe",
    "classes",
    "meta",
)

_FTS_INSERT = "INSERT INTO recherche(classe, nom, signature, description, genre, ref_id) VALUES (?, ?, ?, ?, ?, ?)"

#: genre des entrees de ``recherche`` qui designent un attribut (les autres sont des methodes)
GENRE_ATTRIBUT = "attribut"


@dataclass(frozen=True, slots=True)
class Parametre:
    """Un argument de methode."""

    nom: str
    type: str
    optionnel: bool
    description: str


@dataclass(frozen=True, slots=True)
class Methode:
    """Fiche complete d'une methode, d'un constructeur ou d'une fonction globale."""

    classe: str
    nom: str
    genre: str
    signature: str
    description: str
    depuis_version: str
    parametres: list[Parametre] = field(default_factory=list)
    retours: list[str] = field(default_factory=list)
    erreurs: list[str] = field(default_factory=list)
    exemples: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class Attribut:
    """Attribut d'une classe (ex. ``pinfo.src``), mode RO / WO / RW."""

    classe: str
    nom: str
    nom_complet: str
    mode: str
    description: str
    depuis_version: str


@dataclass(frozen=True, slots=True)
class FicheClasse:
    """Fiche complete d'une classe : methodes, attributs, exemples."""

    nom: str
    module: str
    description: str
    exemples: list[str]
    methodes: list[Methode]
    attributs: list[Attribut]


@dataclass(frozen=True, slots=True)
class ResultatRecherche:
    """Une reponse de la recherche plein texte (methode ou attribut)."""

    classe: str
    nom: str
    signature: str
    description: str
    genre: str
    ref_id: int

    @property
    def est_attribut(self) -> bool:
        return self.genre == GENRE_ATTRIBUT


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Ouvre (et cree si besoin) la banque Lua.

    Une base creee avec un autre schema (``PRAGMA user_version``) est
    videe et recreee : son contenu est de toute facon regenerable.
    """
    logger.debug("connect: db_path={}", summarize(db_path, "db_path"))
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version != SCHEMA_VERSION:
        for table in _TABLES:
            conn.execute(f"DROP TABLE IF EXISTS {table}")  # noqa: S608 -- noms de tables constants
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.executescript(_SCHEMA)
    return conn


def _insert_methode(conn: sqlite3.Connection, classe_id: int, cls_name: str, m: dict[str, Any], counts: dict) -> None:
    genre = m.get("genre", "methode")
    cur = conn.execute(
        "INSERT INTO methodes(classe_id, nom, genre, signature, description, depuis_version) VALUES (?, ?, ?, ?, ?, ?)",
        (
            classe_id,
            m.get("nom", ""),
            genre,
            m.get("signature", ""),
            m.get("description", ""),
            m.get("depuis_version", ""),
        ),
    )
    methode_id = cur.lastrowid
    counts["methodes"] += 1
    params = [
        (
            methode_id,
            a.get("nom", ""),
            a.get("type", ""),
            int(bool(a.get("optionnel", False))),
            a.get("description", ""),
            ordre,
        )
        for ordre, a in enumerate(m.get("arguments", []))
    ]
    conn.executemany(
        "INSERT INTO parametres(methode_id, nom, type, optionnel, description, ordre) VALUES (?, ?, ?, ?, ?, ?)",
        params,
    )
    counts["parametres"] += len(params)
    for table, colonne, cle in (
        ("retours", "description", "retours"),
        ("erreurs", "description", "erreurs"),
        ("exemples", "code", "exemples"),
    ):
        valeurs = [(methode_id, v) for v in m.get(cle, [])]
        conn.executemany(f"INSERT INTO {table}(methode_id, {colonne}) VALUES (?, ?)", valeurs)  # noqa: S608
        counts[table] += len(valeurs)
    conn.execute(
        _FTS_INSERT,
        (cls_name, m.get("nom", ""), m.get("signature", ""), m.get("description", ""), genre, methode_id),
    )


def load_json(conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, int]:
    """Charge le JSON de #386 dans la base (remplace le contenu existant).

    Retourne les compteurs inseres par table.
    """
    counts = dict.fromkeys(("classes", "methodes", "parametres", "retours", "erreurs", "exemples", "attributs"), 0)
    with conn:
        for table in _TABLES:
            conn.execute(f"DELETE FROM {table}")  # noqa: S608 -- noms de tables constants

        meta = {
            "version_wireshark": str(data.get("version_wireshark", "")),
            "date_generation": str(data.get("date_generation", "")),
            "source": str(data.get("source", "")),
            "schema_version": str(SCHEMA_VERSION),
        }
        conn.executemany("INSERT INTO meta(cle, valeur) VALUES (?, ?)", meta.items())

        for cls_name, cls_info in sorted(data.get("classes", {}).items()):
            cur = conn.execute(
                "INSERT INTO classes(nom, module, description) VALUES (?, ?, ?)",
                (cls_name, cls_info.get("module", ""), cls_info.get("description", "")),
            )
            classe_id = int(cur.lastrowid or 0)
            counts["classes"] += 1
            conn.executemany(
                "INSERT INTO exemples_classe(classe_id, code) VALUES (?, ?)",
                [(classe_id, code) for code in cls_info.get("exemples", [])],
            )
            for m in cls_info.get("methodes", []):
                _insert_methode(conn, classe_id, cls_name, m, counts)
            for a in cls_info.get("attributs", []):
                cur = conn.execute(
                    "INSERT INTO attributs(classe_id, nom, nom_complet, mode, description, depuis_version) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        classe_id,
                        a.get("nom", ""),
                        a.get("nom_complet", a.get("nom", "")),
                        a.get("mode", ""),
                        a.get("description", ""),
                        a.get("depuis_version", ""),
                    ),
                )
                counts["attributs"] += 1
                conn.execute(
                    _FTS_INSERT,
                    (
                        cls_name,
                        a.get("nom", ""),
                        a.get("nom_complet", ""),
                        a.get("description", ""),
                        GENRE_ATTRIBUT,
                        cur.lastrowid,
                    ),
                )
    logger.info(
        "Banque Lua chargee : {} classes, {} methodes, {} attributs (Wireshark {})",
        counts["classes"],
        counts["methodes"],
        counts["attributs"],
        meta["version_wireshark"],
    )
    return counts


def load_json_file(conn: sqlite3.Connection, json_path: str | Path) -> dict[str, int]:
    """Charge un fichier JSON produit par tools/extract_lua_api.py.

    L'empreinte sha256 du fichier est gardee dans ``meta.json_sha256``
    pour que :func:`ensure_db` sache quand reconstruire la base.
    """
    logger.debug("load_json_file: conn={} json_path={}", summarize(conn, "conn"), summarize(json_path, "json_path"))
    raw = Path(json_path).read_bytes()
    counts = load_json(conn, json.loads(raw))
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO meta(cle, valeur) VALUES ('json_sha256', ?)", (hashlib.sha256(raw).hexdigest(),)
        )
    return counts


def json_candidates() -> list[Path]:
    """Emplacements du JSON, par priorite : $NETCROSS_LUA_API_JSON, depot, paquet deb/rpm."""
    logger.debug("json_candidates()")
    here = Path(__file__).resolve()
    candidats = [
        here.parents[2] / "data" / "lua_api.json",  # depot : src/netcross_core/lua_doc.py -> data/
        here.parents[1] / "data" / "lua_api.json",  # paquet : /usr/share/netcross/data/
    ]
    env = os.environ.get(ENV_JSON)
    return [Path(env).expanduser(), *candidats] if env else candidats


def find_json() -> Path | None:
    """Premier JSON existant parmi :func:`json_candidates`, ou None."""
    return next((p for p in json_candidates() if p.is_file()), None)


def ensure_db(db_path: str | Path, json_path: str | Path) -> sqlite3.Connection:
    """Ouvre la banque, en la (re)construisant si le JSON a change.

    La comparaison porte sur l'empreinte sha256 du JSON : regenerer
    ``data/lua_api.json`` pour une nouvelle version de Wireshark suffit,
    la base suit au prochain appel.
    """
    db_path, json_path = Path(db_path), Path(json_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    attendu = hashlib.sha256(json_path.read_bytes()).hexdigest()
    if get_meta(conn).get("json_sha256") != attendu:
        logger.debug("Construction de la banque Lua {} depuis {}", db_path, json_path)
        load_json_file(conn, json_path)
    return conn


def get_meta(conn: sqlite3.Connection) -> dict[str, str]:
    """Retourne les metadonnees (version Wireshark, date de generation...)."""
    return dict(conn.execute("SELECT cle, valeur FROM meta").fetchall())


def list_classes(conn: sqlite3.Connection) -> list[str]:
    """Liste les noms de classes, tries."""
    return [r[0] for r in conn.execute("SELECT nom FROM classes ORDER BY nom")]


def _fts_query(terme: str, operateur: str = " ") -> str:
    """Transforme un texte libre en requete FTS5 sure (prefixe sur chaque mot)."""
    mots = [m.replace('"', "") for m in terme.split()]
    return operateur.join(f'"{m}"*' for m in mots if m)


def search(conn: sqlite3.Connection, terme: str, limit: int = 20) -> list[ResultatRecherche]:
    """Recherche plein texte (FTS5) sur classe, nom, signature et description.

    Tous les mots sont d'abord exiges ; a defaut de resultat, n'importe
    lequel suffit. Les correspondances sur le nom pesent plus que sur la
    description.
    """
    logger.debug(
        "search: conn={} terme={} limit={}",
        summarize(conn, "conn"),
        summarize(terme, "terme"),
        summarize(limit, "limit"),
    )
    query = _fts_query(terme)
    if not query:
        return []
    mots = [m.lower() for m in terme.split()]
    marques = ", ".join("?" for _ in mots)
    # nom (ou classe) exactement egal a un des mots d'abord, puis pertinence bm25
    sql = (
        "SELECT classe, nom, signature, description, genre, ref_id FROM recherche "  # noqa: S608 -- placeholders
        f"WHERE recherche MATCH ? ORDER BY (lower(nom) IN ({marques})) + (lower(classe) IN ({marques})) DESC, "
        "bm25(recherche, 5.0, 10.0, 3.0, 1.0) LIMIT ?"
    )
    rows = conn.execute(sql, (query, *mots, *mots, limit)).fetchall()
    if not rows and len(mots) > 1:
        rows = conn.execute(sql, (_fts_query(terme, " OR "), *mots, *mots, limit)).fetchall()
    return [ResultatRecherche(r[0], r[1], r[2], r[3], r[4], int(r[5])) for r in rows]


def _load_methode(conn: sqlite3.Connection, row: tuple[Any, ...]) -> Methode:
    methode_id, classe, nom, genre, signature, description, depuis = row
    params = [
        Parametre(r[0], r[1], bool(r[2]), r[3])
        for r in conn.execute(
            "SELECT nom, type, optionnel, description FROM parametres WHERE methode_id = ? ORDER BY ordre",
            (methode_id,),
        )
    ]

    def _col(table: str, colonne: str) -> list[str]:
        sql = f"SELECT {colonne} FROM {table} WHERE methode_id = ? ORDER BY id"  # noqa: S608 -- constantes
        return [r[0] for r in conn.execute(sql, (methode_id,))]

    return Methode(
        classe,
        nom,
        genre,
        signature,
        description,
        depuis,
        params,
        _col("retours", "description"),
        _col("erreurs", "description"),
        _col("exemples", "code"),
    )


_METHODE_SELECT = (
    "SELECT m.id, c.nom, m.nom, m.genre, m.signature, m.description, m.depuis_version "
    "FROM methodes m JOIN classes c ON c.id = m.classe_id "
)
_ATTRIBUT_SELECT = (
    "SELECT c.nom, a.nom, a.nom_complet, a.mode, a.description, a.depuis_version "
    "FROM attributs a JOIN classes c ON c.id = a.classe_id "
)


def get_class(conn: sqlite3.Connection, nom: str) -> FicheClasse | None:
    """Fiche complete d'une classe (insensible a la casse), ou None si inconnue."""
    logger.debug("get_class: conn={} nom={}", summarize(conn, "conn"), summarize(nom, "nom"))
    row = conn.execute(
        "SELECT id, nom, module, description FROM classes WHERE nom = ? COLLATE NOCASE", (nom,)
    ).fetchone()
    if row is None:
        return None
    classe_id, nom_reel, module, description = row
    methodes = [
        _load_methode(conn, r)
        for r in conn.execute(_METHODE_SELECT + "WHERE m.classe_id = ? ORDER BY m.id", (classe_id,)).fetchall()
    ]
    attributs = [
        Attribut(*r) for r in conn.execute(_ATTRIBUT_SELECT + "WHERE a.classe_id = ? ORDER BY a.id", (classe_id,))
    ]
    exemples = [
        r[0] for r in conn.execute("SELECT code FROM exemples_classe WHERE classe_id = ? ORDER BY id", (classe_id,))
    ]
    return FicheClasse(nom_reel, module, description, exemples, methodes, attributs)


def get_methode(conn: sqlite3.Connection, methode_id: int) -> Methode | None:
    """Fiche complete d'une methode par identifiant."""
    row = conn.execute(_METHODE_SELECT + "WHERE m.id = ?", (methode_id,)).fetchone()
    return _load_methode(conn, row) if row else None


def get_attribut(conn: sqlite3.Connection, attribut_id: int) -> Attribut | None:
    """Attribut par identifiant."""
    row = conn.execute(_ATTRIBUT_SELECT + "WHERE a.id = ?", (attribut_id,)).fetchone()
    return Attribut(*row) if row else None
