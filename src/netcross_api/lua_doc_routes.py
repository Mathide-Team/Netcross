"""netcross_api.lua_doc_routes -- documentation hors ligne de l'API Lua
Wireshark (issue #873), équivalent de ``netcross-lua-doc --json``.

``GET /lua-doc/classes``, ``GET /lua-doc/classes/{name}`` et
``GET /lua-doc/search`` rendent exactement les documents JSON de
``--classes``, ``--class NOM`` et ``TERME [--full] [--limit N]``. Même banque
SQLite (``~/.cache/netcross/lua_api.db`` du serveur, reconstruite quand
``data/lua_api.json`` ou ``$NETCROSS_LUA_API_JSON`` change), aucun accès
réseau.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query

from netcross_core import lua_doc
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

_RESPONSES: dict[int | str, dict[str, Any]] = {
    404: {"description": "Classe inconnue (avec suggestions)"},
    503: {"description": "JSON de l'API Lua introuvable sur le serveur"},
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
    ):
        app.add_api_route(path, endpoint, methods=["GET"], tags=["lua-doc"], responses=_RESPONSES, dependencies=deps)
    logger.debug("lua_doc_routes.register: 3 routes")
