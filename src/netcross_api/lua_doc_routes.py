"""netcross_api.lua_doc_routes -- documentation hors ligne de l'API Lua
Wireshark (issue #873), équivalent de ``netcross-lua-doc --json``.

``GET /lua-doc/classes``, ``GET /lua-doc/classes/{name}`` et
``GET /lua-doc/search`` rendent exactement les documents JSON de
``--classes``, ``--class NOM`` et ``TERME [--full] [--limit N]``. Même banque
SQLite (``~/.cache/netcross/lua_api.db`` du serveur, reconstruite quand
``data/lua_api.json`` ou ``$NETCROSS_LUA_API_JSON`` change), aucun accès
réseau.

Issue #917 : ``GET /lua-doc/dissectors`` et ``GET /lua-doc/dissectors/domains``
rendent le catalogue des dissecteurs Lua (``--dissectors``, ``--domains``),
chargé depuis ``data/lua_dissectors.csv`` ; ils ne dépendent pas du JSON de
l'API.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query

from netcross_core import lua_dissectors, lua_doc
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

_RESPONSES: dict[int | str, dict[str, Any]] = {
    404: {"description": "Classe inconnue (avec suggestions)"},
    503: {"description": "JSON de l'API Lua ou catalogue des dissecteurs introuvable sur le serveur"},
}


@contextmanager
def _connexion() -> Iterator[sqlite3.Connection]:
    source = lua_doc.find_json()
    if source is None or not source.is_file():
        emplacements = ", ".join(str(p) for p in lua_doc.json_candidates())
        logger.warning("lua-doc : JSON introuvable ({})", emplacements)
        raise HTTPException(
            status_code=503,
            detail=f"JSON de l'API Lua introuvable ({emplacements}) : "
            f"le generer avec tools/extract_lua_api.py ou definir ${lua_doc.ENV_JSON}",
        )
    conn = lua_doc.ensure_db(lua_doc.DEFAULT_DB_PATH, source)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def _catalogue() -> Iterator[sqlite3.Connection]:
    lua_doc.DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = lua_doc.connect(lua_doc.DEFAULT_DB_PATH)
    try:
        if not lua_dissectors.ensure_catalogue(conn):
            emplacements = ", ".join(str(p) for p in lua_dissectors.csv_candidates())
            logger.warning("lua-doc : catalogue des dissecteurs introuvable ({})", emplacements)
            raise HTTPException(
                status_code=503,
                detail=f"Catalogue des dissecteurs Lua introuvable ({emplacements}) : "
                f"le generer avec scripts/import_lua_dissectors.py ou definir ${lua_dissectors.ENV_CSV}",
            )
        yield conn
    finally:
        conn.close()


def get_lua_dissectors(
    q: str = Query("", description="Recherche plein texte : dépôt, protocole, domaine, topics (tous les mots)"),
    domain: str | None = Query(None, description="Domaine contenant ce texte, sans accents ni casse (--domain)"),
    non_native: bool = Query(False, description="Seulement sans dissecteur natif dans Wireshark (--non-native)"),
    limit: int = Query(20, ge=1, le=2000, description="Nombre maximal de résultats (--limit)"),
) -> dict[str, Any]:
    """Catalogue des dissecteurs Wireshark en Lua (équivalent de
    ``netcross-lua-doc --dissectors --json``), triés par étoiles ; ``total``
    compte toutes les correspondances. Aucun résultat : liste vide (200)."""
    with _catalogue() as conn:
        return lua_dissectors.search_document(conn, q.strip(), domain, non_native, limit)


def get_lua_dissector_domains() -> dict[str, Any]:
    """Domaines du catalogue et leur nombre de dissecteurs (``--domains --json``)."""
    with _catalogue() as conn:
        return lua_dissectors.domains_document(conn)


def get_lua_classes() -> dict[str, Any]:
    """Liste des classes (équivalent de ``netcross-lua-doc --classes --json``)."""
    with _connexion() as conn:
        return {"meta": lua_doc.get_meta(conn), "classes": lua_doc.list_classes(conn)}


def get_lua_class(name: str) -> dict[str, Any]:
    """Fiche complète d'une classe, insensible à la casse (équivalent de
    ``netcross-lua-doc --class NOM --json``)."""
    with _connexion() as conn:
        fiche = lua_doc.get_class(conn, name)
        if fiche is None:
            suggestion = lua_doc.suggest_classes(conn, name)
            detail = f"Classe inconnue : {name}" + (f" (voir : {', '.join(suggestion)})" if suggestion else "")
            logger.debug("get_lua_class: {}", detail)
            raise HTTPException(status_code=404, detail=detail)
        return {"meta": lua_doc.get_meta(conn), "classe": asdict(fiche)}


def search_lua_doc(
    q: str = Query(..., min_length=1, description="Terme de recherche (classes, méthodes, fonctions, attributs)"),
    limit: int = Query(20, ge=1, le=500, description="Nombre maximal de résultats (équivalent de --limit)"),
    full: bool = Query(False, description="Détail complet de chaque résultat (équivalent de --full)"),
) -> dict[str, Any]:
    """Recherche plein texte (équivalent de ``netcross-lua-doc --json TERME``).
    Aucun résultat : liste vide (code 200), comme le JSON de la CLI."""
    terme = q.strip()
    if not terme:
        raise HTTPException(status_code=422, detail="terme de recherche vide")
    with _connexion() as conn:
        return lua_doc.search_document(conn, terme, limit, full)


def register(app: FastAPI, verify: Callable[..., None]) -> None:
    """Déclare les routes sur ``app`` avec l'authentification ``verify``
    (routes à plat, comme les autres : ``include_router`` des versions
    récentes de FastAPI ne les rend plus comme ``APIRoute``)."""
    deps = [Depends(verify)]
    for path, endpoint in (
        ("/lua-doc/classes", get_lua_classes),
        ("/lua-doc/classes/{name}", get_lua_class),
        ("/lua-doc/search", search_lua_doc),
        ("/lua-doc/dissectors", get_lua_dissectors),
        ("/lua-doc/dissectors/domains", get_lua_dissector_domains),
    ):
        app.add_api_route(path, endpoint, methods=["GET"], tags=["lua-doc"], responses=_RESPONSES, dependencies=deps)
    logger.debug("lua_doc_routes.register: 5 routes")
