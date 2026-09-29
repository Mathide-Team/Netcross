"""
netcross_api.store -- analyses de l'API : statut, document JSON, persistance.

Issue #356 : chaque analyse passe par ``pending`` puis ``completed`` ou
``failed``. Le store ne garde pas l'objet ``Report`` mais son **document
JSON** (``report_document``), qui est ce que servent les routes GET. Ce
document peut donc être relu tel quel depuis SQLite après un redémarrage.

Issue #330 : à côté de ce document brut, le store garde le **rapport
structuré** (``report``), le même document que ``--json-report`` de la CLI
et l'export JSON de la GUI (constats, triage, score de santé), servi par
``GET /analyses/{id}/report``. Les analyses enregistrées avant #330 n'en
ont pas (``report`` à ``None``).

Sans ``NETCROSS_DB_PATH``, tout reste en mémoire (mode MVP, perdu au
redémarrage). Avec ``NETCROSS_DB_PATH=/chemin/netcross-api.db``, chaque
changement d'état est écrit dans SQLite et les analyses sont rechargées au
démarrage. Une analyse encore ``pending`` au rechargement a été interrompue
avec le service : elle passe en ``failed`` plutôt que de rester en attente
pour toujours.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import closing
from dataclasses import fields, is_dataclass
from typing import Any

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

PENDING = "pending"
COMPLETED = "completed"
FAILED = "failed"
STATUTS = (PENDING, COMPLETED, FAILED)

ERREUR_INTERROMPUE = "analyse interrompue par un redemarrage du service"


def jsonable(value: Any) -> Any:
    """Rend une valeur de ``Report`` sérialisable en JSON.

    Les dictionnaires par segment (``latency``, ``qos_change``...) ont des
    clés tuple (amont, aval), refusées par JSON : elles deviennent
    « amont -> aval », le libellé des constats et des segments (#354).
    """
    if hasattr(value, "items"):
        logger.debug("jsonable: si hasattr(value, 'items') -> retour dictionnaire")
        return {(" -> ".join(map(str, k)) if isinstance(k, tuple) else str(k)): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        logger.debug("jsonable: si isinstance(value, (list, tuple, set, frozenset)) -> retour liste")
        return [jsonable(v) for v in value]
    if is_dataclass(value) and not isinstance(value, type):
        logger.debug("jsonable: si is_dataclass(value) and (not isinstance(value, type)) -> retour dictionnaire")
        return {f.name: jsonable(getattr(value, f.name)) for f in fields(value)}
    if value is None or isinstance(value, (str, int, float, bool)):
        logger.debug(
            "jsonable: si value is None or isinstance(value, (str, int, float, bool)) -> retour value={}",
            summarize(value, "value"),
        )
        return value
    logger.debug("jsonable: retour str(…)")
    return str(value)


def report_document(report: Any) -> dict[str, Any]:
    """Document JSON complet d'un ``Report`` (servi par GET /analyses/{id})."""
    logger.debug("report_document: retour dictionnaire")
    return {f.name: jsonable(getattr(report, f.name)) for f in fields(report)}


_COLONNES = {
    "status": "TEXT NOT NULL DEFAULT 'completed'",
    "metadata": "TEXT NOT NULL DEFAULT '{}'",
    "document_json": "TEXT",
    "structured_json": "TEXT",
    "summary_json": "TEXT",
    "error": "TEXT",
    "created_at": "TEXT NOT NULL DEFAULT (datetime('now'))",
}


class AnalysesStore:
    """Analyses indexées par ID : statut, métadonnées, résumé, document."""

    def __init__(self, db_path: str | None = None) -> None:
        logger.debug("AnalysesStore.__init__: db_path={}", summarize(db_path, "db_path"))
        self._store: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._db_path = db_path if db_path is not None else os.environ.get("NETCROSS_DB_PATH")
        if self._db_path:
            self._init_db()
            self._load()
        logger.debug("AnalysesStore.__init__: fin")

    @property
    def persistent(self) -> bool:
        logger.debug("AnalysesStore.persistent: retour bool(…)")
        return bool(self._db_path)

    # -- cycle de vie ------------------------------------------------------

    def create_pending(self, metadata: dict | None = None) -> str:
        """Crée une analyse ``pending`` et retourne son ID."""
        logger.debug("AnalysesStore.create_pending: metadata={}", summarize(metadata, "metadata"))
        analysis_id = uuid.uuid4().hex[:12]
        entry = {
            "status": PENDING,
            "metadata": dict(metadata or {}),
            "document": None,
            "report": None,
            "summary": None,
            "error": None,
            "report_obj": None,
            "flows": None,
            "findings": None,
            "security_report_obj": None,
            "tls_findings": None,
            "quic_findings": None,
        }
        with self._lock:
            self._store[analysis_id] = entry
            self._persist(analysis_id, entry)
        logger.debug("AnalysesStore.create_pending: retour analysis_id={}", summarize(analysis_id, "analysis_id"))
        return analysis_id

    def complete(
        self,
        analysis_id: str,
        document: dict,
        summary: dict,
        report: dict | None = None,
        report_obj: Any = None,
        flows: Any = None,
        findings: Any = None,
        security_report_obj: Any = None,
        tls_findings: Any = None,
        quic_findings: Any = None,
    ) -> None:
        """Passe l'analyse en ``completed`` avec son document brut, son
        résumé et son rapport structuré (celui de ``--json-report``).

        Issue #670 : ``report_obj``, ``flows``, ``findings``,
        ``security_report_obj``, ``tls_findings`` et ``quic_findings`` sont
        les objets Python vivants conservés en mémoire pour générer les
        exports texte, PDF et CSV à la demande. Ils ne sont pas persistés
        en SQLite (ce sont des objets complexes non sérialisables tels
        quels) : une analyse relue depuis SQLite après redémarrage ne
        pourra pas les régénérer (409, comme une analyse antérieure à
        #330 sans rapport structuré)."""
        self._update(
            analysis_id,
            status=COMPLETED,
            document=document,
            report=report,
            summary=summary,
            error=None,
            report_obj=report_obj,
            flows=flows,
            findings=findings,
            security_report_obj=security_report_obj,
            tls_findings=tls_findings,
            quic_findings=quic_findings,
        )
        logger.debug("AnalysesStore.complete: fin")

    def fail(self, analysis_id: str, error: str) -> None:
        """Passe l'analyse en ``failed`` ; ``error`` est rendu au client."""
        self._update(analysis_id, status=FAILED, error=error)
        logger.debug("AnalysesStore.fail: fin")

    def _update(self, analysis_id: str, **changes: Any) -> None:
        with self._lock:
            entry = self._store.get(analysis_id)
            if entry is None:
                logger.warning("analyse {} inconnue, mise a jour ignoree", analysis_id)
                logger.debug("AnalysesStore._update: si entry is None -> retour")
                return
            entry.update(changes)
            self._persist(analysis_id, entry)
        logger.debug("AnalysesStore._update: fin")

    # -- lecture -----------------------------------------------------------

    def get(self, analysis_id: str) -> dict | None:
        """Copie de l'entrée (status, metadata, summary, document, error)."""
        with self._lock:
            entry = self._store.get(analysis_id)
            logger.debug("AnalysesStore.get: retour dict(entry) if entry else None")
            return dict(entry) if entry else None

    def get_status(self, analysis_id: str) -> str | None:
        with self._lock:
            entry = self._store.get(analysis_id)
            logger.debug("AnalysesStore.get_status: retour entry['status'] if entry else None")
            return entry["status"] if entry else None

    def list_ids(self) -> list[str]:
        with self._lock:
            logger.debug("AnalysesStore.list_ids: retour list(…)")
            return list(self._store.keys())

    def clear(self) -> None:
        """Vide la mémoire (tests) ; la base SQLite n'est pas touchée."""
        with self._lock:
            self._store.clear()
        logger.debug("AnalysesStore.clear: fin")

    # -- SQLite ------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        assert self._db_path is not None
        logger.debug("AnalysesStore._connect: retour sqlite3.connect(…)")
        return sqlite3.connect(self._db_path)

    def _init_db(self) -> None:
        logger.debug("AnalysesStore._init_db()")
        with closing(self._connect()) as conn, conn:
            conn.execute("CREATE TABLE IF NOT EXISTS analyses (id TEXT PRIMARY KEY)")
            existantes = {row[1] for row in conn.execute("PRAGMA table_info(analyses)")}
            # Migration douce : la première version (#381) n'avait ni
            # document_json ni summary_json ni error.
            for nom, definition in _COLONNES.items():
                if nom not in existantes:
                    conn.execute(f"ALTER TABLE analyses ADD COLUMN {nom} {definition}")
        logger.debug("AnalysesStore._init_db: fin")

    def _load(self) -> None:
        interrompues = []
        with closing(self._connect()) as conn, conn:
            rows = conn.execute(
                "SELECT id, status, metadata, document_json, structured_json, summary_json, error"
                " FROM analyses ORDER BY created_at"
            ).fetchall()
        for analysis_id, status, metadata, document_json, structured_json, summary_json, error in rows:
            entry = {
                "status": status if status in STATUTS else FAILED,
                "metadata": json.loads(metadata or "{}"),
                "document": json.loads(document_json) if document_json else None,
                "report": json.loads(structured_json) if structured_json else None,
                "summary": json.loads(summary_json) if summary_json else None,
                "error": error,
                # Issue #670 : les objets vivants ne sont pas persistés en
                # SQLite. Les exports texte/PDF/CSV nécessitent une analyse
                # en mémoire (relancer si besoin).
                "report_obj": None,
                "flows": None,
                "findings": None,
                "security_report_obj": None,
                "tls_findings": None,
                "quic_findings": None,
            }
            if entry["status"] == PENDING:
                entry.update(status=FAILED, error=ERREUR_INTERROMPUE)
                interrompues.append(analysis_id)
            elif entry["status"] == COMPLETED and entry["document"] is None:
                # ligne de l'ancien format (rapport str(), non relisible)
                entry.update(status=FAILED, error="rapport enregistre dans un ancien format, non relisible")
            self._store[analysis_id] = entry
        for analysis_id in interrompues:
            self._persist(analysis_id, self._store[analysis_id])
        logger.info("{} analyse(s) rechargee(s) depuis {}", len(rows), self._db_path)
        logger.debug("AnalysesStore._load: fin")

    def _persist(self, analysis_id: str, entry: dict) -> None:
        """Écrit l'entrée si la persistance est active (appelé sous verrou)."""
        if not self._db_path:
            logger.debug("AnalysesStore._persist: si not self._db_path -> retour")
            return
        with closing(self._connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO analyses (id, status, metadata, document_json, structured_json, summary_json, error)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET status = excluded.status, metadata = excluded.metadata,
                    document_json = excluded.document_json, structured_json = excluded.structured_json,
                    summary_json = excluded.summary_json, error = excluded.error
                """,
                (
                    analysis_id,
                    entry["status"],
                    json.dumps(entry["metadata"], ensure_ascii=False, default=str),
                    json.dumps(entry["document"], ensure_ascii=False) if entry["document"] is not None else None,
                    json.dumps(entry["report"], ensure_ascii=False) if entry.get("report") is not None else None,
                    json.dumps(entry["summary"], ensure_ascii=False) if entry["summary"] is not None else None,
                    entry["error"],
                ),
            )
        logger.debug("AnalysesStore._persist: fin")


# Singleton global partagé entre les endpoints.
store = AnalysesStore()
