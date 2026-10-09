"""netcross_api.history_routes -- historique SQLite des runs (issue #874).

Équivalent de ``--history-db`` / ``netcross-history`` : la base est fixée
par l'administrateur (``NETCROSS_HISTORY_DB``), jamais par le client. Sans
cette variable, l'enregistrement (``history=true``) est refusé (400) et
``GET /history`` répond 503.

- ``GET /history`` : ``run_type`` (``analyse`` ou ``diff``), ``label``,
  ``limit`` -- mêmes filtres que ``cross_history_cli.py`` ;
- ``POST /comparisons`` : ``history``, ``history_label`` (voir app.py).
"""

from __future__ import annotations

import dataclasses
import os
from collections.abc import Callable
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

HISTORY_DB_ENV = "NETCROSS_HISTORY_DB"
RUN_TYPES = ("analyse", "diff")


def history_db_path() -> str | None:
    """Base d'historique du serveur, ou None si non configurée."""
    path = os.environ.get(HISTORY_DB_ENV, "").strip() or None
    logger.debug("history_db_path: {}", path)
    return path


def require_history_db() -> str:
    """Base configurée, sinon 400 (demande d'enregistrement refusée)."""
    path = history_db_path()
    if path is None:
        raise HTTPException(
            status_code=400,
            detail=f"historique desactive sur ce serveur : {HISTORY_DB_ENV} non defini",
        )
    return path


def record_comparison(findings, baseline_report, current_report, label: str | None, redact: bool) -> dict[str, Any]:
    """``record_diff_run`` dans la base du serveur ; renvoie ``history_id``
    ou ``history_error`` (base illisible : la comparaison reste valable)."""
    from netcross_report import HistoryDatabaseError, record_diff_run

    path = history_db_path()
    if path is None:
        return {}
    try:
        run_id = record_diff_run(
            findings,
            baseline_report,
            current_report,
            path,
            meta={"Anonymisation": "adresses IP/MAC anonymisees (--redact)"} if redact else None,
            label=label,
        )
    except HistoryDatabaseError as exc:
        logger.warning("historique : enregistrement impossible ({})", exc)
        return {"history_error": str(exc)}
    logger.info("comparaison enregistree dans l'historique (id {}, etiquette {})", run_id, label)
    return {"history_id": run_id}


def register(app: FastAPI, verify: Callable[..., None]) -> None:
    @app.get("/history", tags=["history"], dependencies=[Depends(verify)])
    async def list_history_route(
        run_type: str | None = Query(None, description="analyse ou diff (équivalent de --run-type)"),
        label: str | None = Query(None, description="Étiquette exacte (équivalent de --label)"),
        limit: int | None = Query(None, ge=1, description="Nombre maximal de runs (équivalent de --limit)"),
    ) -> dict:
        """Runs de l'historique du serveur, du plus récent au plus ancien
        (équivalent de ``netcross-history --db ...``)."""
        from netcross_report import HistoryDatabaseError, list_history

        path = history_db_path()
        if path is None:
            raise HTTPException(status_code=503, detail=f"historique non configure ({HISTORY_DB_ENV})")
        if run_type is not None and run_type not in RUN_TYPES:
            raise HTTPException(status_code=400, detail=f"run_type : analyse ou diff (recu {run_type!r})")
        try:
            entries = list_history(path, limit=limit, label=label, run_type=run_type)
        except HistoryDatabaseError as exc:
            logger.warning("historique illisible : {}", exc)
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"entries": [dataclasses.asdict(e) for e in entries]}

    logger.debug("history_routes.register: 1 route")
