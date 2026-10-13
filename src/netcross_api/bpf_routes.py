"""netcross_api.bpf_routes -- bibliothèque de filtres BPF enregistrés
(issue #906), équivalent API de ``--bpf-library NOM`` et des boutons
« Filtres… » / « Enregistrer » de la GUI.

``GET /bpf-filters`` liste le catalogue prédéfini puis les filtres
enregistrés, ``PUT /bpf-filters/{nom}`` crée ou remplace un filtre et
``DELETE /bpf-filters/{nom}`` le supprime. Même fichier et mêmes règles que
la CLI et la GUI (``netcross_core.bpf_filters``) : noms comparés sans tenir
compte de la casse ni des espaces de bordure, noms du catalogue réservés,
fichier illisible jamais écrasé. Comme la CLI, la syntaxe BPF n'est pas
compilée ici : tshark la rejettera au démarrage de la capture.

Le fichier est celui du serveur : ``$NETCROSS_API_BPF_FILTERS`` s'il est
défini (choisi par l'administrateur, jamais par le client), sinon
``~/.netcross/bpf_filters.json`` du compte qui exécute l'API.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from netcross_core import bpf_filters
from netcross_core.logging_config import get_logger
from netcross_core.models import BPFFilter

logger = get_logger(__name__)

#: Variable d'environnement : chemin du fichier de filtres côté serveur.
BPF_FILTERS_ENV = "NETCROSS_API_BPF_FILTERS"

_RESPONSES: dict[int | str, dict[str, Any]] = {
    409: {"description": "Nom réservé au catalogue prédéfini"},
    500: {"description": "Fichier de filtres illisible ou non inscriptible (il n'est pas modifié)"},
}


class BPFFilterBody(BaseModel):
    """Corps de ``PUT /bpf-filters/{nom}``."""

    expression: str = Field(..., description="Expression BPF (libpcap), transmise telle quelle à tshark (-f)")
    description: str = Field("", description="Description libre, facultative")


def filters_path() -> Path | None:
    """Fichier utilisé : ``$NETCROSS_API_BPF_FILTERS`` ou ``None`` (défaut du cœur)."""
    valeur = os.environ.get(BPF_FILTERS_ENV, "").strip()
    return Path(valeur).expanduser() if valeur else None


def _document(filtres: list[BPFFilter]) -> dict[str, Any]:
    reserves = {f.name for f in bpf_filters.PREDEFINED_BPF_FILTERS}
    return {
        "filters": [
            {
                "name": f.name,
                "expression": f.expression,
                "description": f.description,
                "predefined": f.name in reserves,
            }
            for f in filtres
        ]
    }


def _erreur_fichier(exc: Exception) -> HTTPException:
    logger.warning("bpf-filters : {}", exc)
    return HTTPException(status_code=500, detail=str(exc))


def list_bpf_filters() -> dict[str, Any]:
    """Catalogue prédéfini puis filtres enregistrés (la liste de la GUI)."""
    try:
        return _document(bpf_filters.available_bpf_filters(filters_path()))
    except (ValueError, OSError) as exc:
        logger.debug("list_bpf_filters: (ValueError, OSError) -> {}", exc)
        raise _erreur_fichier(exc) from exc


def put_bpf_filter(nom: str, body: BPFFilterBody) -> dict[str, Any]:
    """Crée ou remplace le filtre ``nom`` ; renvoie la liste à jour."""
    try:
        nouveau = BPFFilter(nom.strip(), body.expression.strip(), body.description.strip())
    except ValueError as exc:
        logger.debug("put_bpf_filter: ValueError -> {}", exc)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    cle = nom.strip().casefold()
    if any(f.name.casefold() == cle for f in bpf_filters.PREDEFINED_BPF_FILTERS):
        raise HTTPException(
            status_code=409,
            detail=f"le nom '{nom.strip()}' est reserve au catalogue predefini : choisir un autre nom",
        )
    try:
        return _document(bpf_filters.upsert_bpf_filter(nouveau, filters_path()))
    except (ValueError, OSError) as exc:
        logger.debug("put_bpf_filter: (ValueError, OSError) -> {}", exc)
        raise _erreur_fichier(exc) from exc


def delete_bpf_filter(nom: str) -> dict[str, Any]:
    """Supprime le filtre enregistré ``nom`` ; renvoie la liste à jour."""
    cle = nom.strip().casefold()
    if any(f.name.casefold() == cle for f in bpf_filters.PREDEFINED_BPF_FILTERS):
        raise HTTPException(
            status_code=409,
            detail=f"le nom '{nom.strip()}' appartient au catalogue predefini : il ne peut pas etre supprime",
        )
    try:
        return _document(bpf_filters.delete_bpf_filter(nom, filters_path()))
    except KeyError as exc:
        logger.debug("delete_bpf_filter: KeyError -> {}", exc)
        raise HTTPException(status_code=404, detail=f"Filtre BPF '{nom.strip()}' introuvable") from exc
    except (ValueError, OSError) as exc:
        logger.debug("delete_bpf_filter: (ValueError, OSError) -> {}", exc)
        raise _erreur_fichier(exc) from exc


def resolve_bpf_library(nom: str) -> str:
    """Expression du filtre ``nom`` (pour le champ ``bpf_library`` des points
    de capture en direct, #902) ; 400 s'il est introuvable, comme le refus
    de ``--bpf-library`` en CLI."""
    try:
        filtres = bpf_filters.available_bpf_filters(filters_path())
    except (ValueError, OSError) as exc:
        logger.debug("resolve_bpf_library: (ValueError, OSError) -> {}", exc)
        raise _erreur_fichier(exc) from exc
    cle = nom.strip().casefold()
    for f in filtres:
        if f.name.casefold() == cle:
            return f.expression
    disponibles = ", ".join(f.name for f in filtres)
    raise HTTPException(
        status_code=400,
        detail=f"Filtre BPF '{nom.strip()}' introuvable dans la bibliotheque (disponibles : {disponibles})",
    )


def register(app: FastAPI, verify: Callable[..., None]) -> None:
    """Déclare les routes sur ``app`` avec l'authentification ``verify``."""
    deps = [Depends(verify)]
    app.add_api_route(
        "/bpf-filters",
        list_bpf_filters,
        methods=["GET"],
        tags=["bpf-filters"],
        responses={500: _RESPONSES[500]},
        dependencies=deps,
    )
    app.add_api_route(
        "/bpf-filters/{nom}",
        put_bpf_filter,
        methods=["PUT"],
        tags=["bpf-filters"],
        responses=_RESPONSES,
        dependencies=deps,
    )
    app.add_api_route(
        "/bpf-filters/{nom}",
        delete_bpf_filter,
        methods=["DELETE"],
        tags=["bpf-filters"],
        responses={404: {"description": "Filtre enregistré introuvable"}, **_RESPONSES},
        dependencies=deps,
    )
    logger.debug("bpf_routes.register: 3 routes")
