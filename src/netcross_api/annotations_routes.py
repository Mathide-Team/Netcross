"""netcross_api.annotations_routes -- annotations (etiquettes / signets sur
des trames) d'une analyse (issue #910), équivalent API du panneau
« Annotations / signets » de la GUI et de ``netcross annotations``.

L'API supprime les captures téléversées une fois l'analyse terminée : il
n'y a donc pas de sidecar ``<capture>.annotations.json`` côté serveur. Les
annotations sont rangées dans l'analyse elle-même, par point
(``metadata["annotations"]``, persistées en SQLite avec ``NETCROSS_DB_PATH``),
au même format JSON que le sidecar : un client peut les réécrire telles
quelles à côté de sa capture pour les retrouver dans la GUI et la CLI.

- ``GET /analyses/{id}/annotations[?point=&tag=]`` : ``{"annotations": {point: [...]}}`` ;
- ``POST /analyses/{id}/annotations`` : ajoute ou met à jour une annotation
  (même paire trame / étiquette = mise à jour) ;
- ``DELETE /analyses/{id}/annotations?point=&frame_number=&tag=`` : 404 si absente.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from netcross_core.annotations import (
    add_annotation,
    annotation_from_dict,
    annotation_to_dict,
    make_annotation,
    remove_annotation,
    sort_annotations,
)
from netcross_core.logging_config import get_logger
from netcross_core.models import PacketAnnotation

logger = get_logger(__name__)

#: Clé des annotations dans ``metadata`` de l'analyse.
METADATA_KEY = "annotations"

_RESPONSES: dict[int | str, dict[str, Any]] = {
    404: {"description": "Analyse, point ou annotation introuvable"},
    409: {"description": "Analyse en cours ou en échec"},
}


class AnnotationBody(BaseModel):
    """Corps de ``POST /analyses/{analysis_id}/annotations``."""

    point: str = Field(..., description="Point de capture annoté (un des points de l'analyse)")
    frame_number: int = Field(..., description="Numéro de trame (>= 1, celui de Wireshark)")
    tag: str = Field(..., description="Étiquette")
    comment: str = Field("", description="Commentaire libre")
    color: str | None = Field(None, description="Couleur d'affichage (ex. #ff0000)")


class _Routes:
    def __init__(self, completed_entry: Callable[[str], dict], get_store: Callable[[], Any]) -> None:
        self._completed_entry = completed_entry
        self._get_store = get_store

    def _load(self, analysis_id: str) -> tuple[list[str], dict[str, list[PacketAnnotation]]]:
        entry = self._completed_entry(analysis_id)
        points = [str(p) for p in (entry.get("document") or {}).get("points", [])]
        brut = (entry.get("metadata") or {}).get(METADATA_KEY) or {}
        by_point = {p: [annotation_from_dict(i) for i in items] for p, items in brut.items()}
        return points, by_point

    def _save(self, analysis_id: str, by_point: dict[str, list[PacketAnnotation]]) -> None:
        doc = {p: [annotation_to_dict(a) for a in sort_annotations(lst)] for p, lst in by_point.items() if lst}
        self._get_store().set_metadata(analysis_id, METADATA_KEY, doc)

    @staticmethod
    def _check_point(points: list[str], point: str) -> str:
        point = point.strip()
        if point not in points:
            logger.debug("annotations: point {} inconnu -> 404", point)
            raise HTTPException(
                status_code=404, detail=f"Point {point!r} absent de l'analyse (points : {', '.join(points)})"
            )
        return point

    @staticmethod
    def _document(by_point: dict[str, list[PacketAnnotation]]) -> dict[str, Any]:
        return {
            "annotations": {
                p: [annotation_to_dict(a) for a in sort_annotations(lst)] for p, lst in sorted(by_point.items()) if lst
            }
        }

    def list(
        self,
        analysis_id: str,
        point: str | None = Query(None, description="Seulement ce point"),
        tag: str | None = Query(None, description="Seulement cette étiquette"),
    ) -> dict[str, Any]:
        """Annotations de l'analyse, par point (format du sidecar de la GUI)."""
        points, by_point = self._load(analysis_id)
        if point is not None:
            cle = self._check_point(points, point)
            by_point = {cle: by_point.get(cle, [])}
        if tag is not None:
            by_point = {p: [a for a in lst if a.tag == tag.strip()] for p, lst in by_point.items()}
        return self._document(by_point)

    def add(self, analysis_id: str, body: AnnotationBody) -> dict[str, Any]:
        """Ajoute une annotation ; la même paire trame / étiquette est mise à jour."""
        points, by_point = self._load(analysis_id)
        point = self._check_point(points, body.point)
        try:
            nouvelle = make_annotation(body.frame_number, body.tag, body.comment, body.color)
        except ValueError as exc:
            logger.debug("annotations.add: saisie invalide ({})", exc)
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        by_point[point] = add_annotation(by_point.get(point, []), nouvelle)
        self._save(analysis_id, by_point)
        return self._document(by_point)

    def delete(
        self,
        analysis_id: str,
        point: str = Query(..., description="Point de capture"),
        frame_number: int = Query(..., description="Numéro de trame"),
        tag: str = Query(..., description="Étiquette"),
    ) -> dict[str, Any]:
        """Supprime l'annotation (point, trame, étiquette) ; 404 si absente."""
        points, by_point = self._load(analysis_id)
        cle = self._check_point(points, point)
        try:
            by_point[cle] = remove_annotation(by_point.get(cle, []), frame_number, tag)
        except ValueError as exc:
            logger.debug("annotations.delete: saisie invalide ({})", exc)
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except KeyError as exc:
            logger.debug("annotations.delete: absente ({})", exc)
            raise HTTPException(status_code=404, detail=f"Annotation introuvable : {exc.args[0]}") from exc
        self._save(analysis_id, by_point)
        return self._document(by_point)


def register(
    app: FastAPI, verify: Callable[..., None], completed_entry: Callable[[str], dict], get_store: Callable[[], Any]
) -> None:
    """Déclare les routes sur ``app`` (même authentification que les autres) ;
    ``get_store`` est relu à chaque requête, comme ``completed_entry``."""
    routes = _Routes(completed_entry, get_store)
    deps = [Depends(verify)]
    chemin = "/analyses/{analysis_id}/annotations"
    for methode, endpoint in (("GET", routes.list), ("POST", routes.add), ("DELETE", routes.delete)):
        app.add_api_route(
            chemin, endpoint, methods=[methode], tags=["annotations"], responses=_RESPONSES, dependencies=deps
        )
    logger.debug("annotations_routes.register: 3 routes")
