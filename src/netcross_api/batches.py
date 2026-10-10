"""
netcross_api.batches -- lots de captures de l'API (issue #872).

Équivalent REST de ``cross_capture_batch_cli.py`` : ``POST /batches`` reçoit
plusieurs captures ou une archive ZIP, le moteur commun
(``netcross_report.batch_runner``) inventorie, regroupe et analyse, puis
``GET /batches/{id}`` donne l'avancement et le résultat.

Les lots vivent en mémoire (comme les comparaisons) : chaque lot a son
répertoire de travail (captures reçues + rapports), supprimé quand le lot
est évincé (au-delà de ``NETCROSS_API_MAX_BATCHES``, défaut 20, les plus
anciens lots terminés partent en premier) ou à l'arrêt du service.
"""

from __future__ import annotations

import atexit
import os
import re
import shutil
import tempfile
import threading
import uuid
import zipfile
from collections import OrderedDict
from pathlib import Path

from netcross_core.logging_config import get_logger, summarize
from netcross_report.batch_runner import CAPTURE_EXTENSIONS, BatchOptions, run_batch

logger = get_logger(__name__)

PENDING = "pending"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"

MAX_BATCHES = int(os.environ.get("NETCROSS_API_MAX_BATCHES", "20"))
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]")


class BatchInputError(ValueError):
    """Envoi refusé (archive invalide, trop volumineuse, sans capture)."""


def safe_name(name: str) -> str:
    """Nom de fichier sans chemin ni caractère exotique (jamais ``..``)."""
    base = os.path.basename(name.replace("\\", "/")) or "capture"
    cleaned = _SAFE_NAME.sub("_", base).lstrip(".") or "capture"
    logger.debug("safe_name: {} -> {}", summarize(name, "name"), cleaned)
    return cleaned


def unique_path(directory: str, name: str) -> str:
    """Chemin libre dans ``directory`` : ``nom``, ``nom_2.ext``, ``nom_3.ext``..."""
    path = os.path.join(directory, name)
    stem, dot, ext = name.partition(".")
    n = 2
    while os.path.exists(path):
        path = os.path.join(directory, f"{stem}_{n}{dot}{ext}")
        n += 1
    return path


def extract_archive(archive: str, directory: str, max_bytes: int) -> list[str]:
    """Extrait les captures d'une archive ZIP à plat dans ``directory``.

    Défenses : aucun chemin de l'archive n'est réutilisé (noms nettoyés,
    jamais d'écriture hors ``directory``), taille décompressée totale bornée
    par ``max_bytes`` (bombe ZIP), seules les extensions de capture sont
    extraites ; les autres membres sont renvoyés comme ignorés.
    """
    ignored: list[str] = []
    try:
        with zipfile.ZipFile(archive) as zf:
            members = [m for m in zf.infolist() if not m.is_dir()]
            total = sum(m.file_size for m in members)
            if total > max_bytes:
                raise BatchInputError(
                    f"archive trop volumineuse une fois décompressée ({total // 1024 // 1024} Mo, "
                    f"max {max_bytes // 1024 // 1024} Mo)"
                )
            for member in members:
                name = safe_name(member.filename)
                if not name.lower().endswith(CAPTURE_EXTENSIONS):
                    ignored.append(member.filename)
                    continue
                with zf.open(member) as src, open(unique_path(directory, name), "wb") as dst:
                    shutil.copyfileobj(src, dst)
    except zipfile.BadZipFile as exc:
        logger.warning("extract_archive: archive illisible ({})", exc)
        raise BatchInputError(f"archive ZIP illisible : {exc}") from exc
    logger.debug("extract_archive: {} membre(s) ignoré(s)", len(ignored))
    return ignored


class BatchStore:
    """Lots en mémoire, bornés à ``MAX_BATCHES`` (thread-safe)."""

    def __init__(self, max_batches: int = MAX_BATCHES) -> None:
        self._lock = threading.Lock()
        self._batches: OrderedDict[str, dict] = OrderedDict()
        self.max_batches = max(1, max_batches)

    def create(self, options: BatchOptions, files: list[str], workdir: str) -> str:
        batch_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._batches[batch_id] = {
                "batch_id": batch_id,
                "status": PENDING,
                "options": {
                    "recursive": options.recursive,
                    "group": options.group,
                    "group_window": options.group_window,
                    "min_overlap": options.min_overlap,
                    "min_common_ips": options.min_common_ips,
                    "jobs": options.jobs,
                    "security_report": options.security_report,
                },
                "files": files,
                "progress": [],
                "result": None,
                "index": None,
                "error": None,
                "workdir": workdir,
            }
            self._evict()
        logger.debug("BatchStore.create: lot {} ({} fichier(s))", batch_id, len(files))
        return batch_id

    def _evict(self) -> None:
        """Supprime les plus anciens lots terminés au-delà de la limite."""
        while len(self._batches) > self.max_batches:
            victim = next(
                (k for k, v in self._batches.items() if v["status"] in (COMPLETED, FAILED)),
                None,
            )
            if victim is None:
                break
            entry = self._batches.pop(victim)
            shutil.rmtree(entry["workdir"], ignore_errors=True)
            logger.debug("BatchStore._evict: lot {} évincé", victim)

    def get(self, batch_id: str) -> dict | None:
        with self._lock:
            entry = self._batches.get(batch_id)
            return dict(entry, progress=list(entry["progress"])) if entry else None

    def update(self, batch_id: str, **changes) -> None:
        with self._lock:
            if batch_id in self._batches:
                self._batches[batch_id].update(changes)

    def progress(self, batch_id: str, message: str) -> None:
        with self._lock:
            if batch_id in self._batches:
                self._batches[batch_id]["progress"].append(message)

    def list(self) -> list[dict]:
        with self._lock:
            return [{"batch_id": k, "status": v["status"], "files": len(v["files"])} for k, v in self._batches.items()]

    def clear(self) -> None:
        with self._lock:
            for entry in self._batches.values():
                shutil.rmtree(entry["workdir"], ignore_errors=True)
            self._batches.clear()


batch_store = BatchStore()
atexit.register(batch_store.clear)


def run_batch_job(batch_id: str, options: BatchOptions, ignored: list[str]) -> None:
    """Tâche de fond : lot complet, puis completed/failed. Ne lève jamais."""
    entry = batch_store.get(batch_id)
    if entry is None:
        return
    workdir = entry["workdir"]
    input_dir = os.path.join(workdir, "captures")
    output_dir = os.path.join(workdir, "rapports")
    batch_store.update(batch_id, status=RUNNING)
    try:
        from netcross_report.batch_runner import list_captures

        captures, more_ignored = list_captures(input_dir, options.recursive)
        if not captures:
            raise BatchInputError(f"aucune capture ({', '.join(CAPTURE_EXTENSIONS)}) reçue")
        result = run_batch(
            captures,
            ignored + more_ignored,
            output_dir,
            options,
            "lot API",
            lambda msg: batch_store.progress(batch_id, msg),
        )
    except Exception as exc:  # noqa: BLE001 -- un lot ne doit jamais rester running
        logger.exception("lot {} en échec", batch_id)
        batch_store.update(batch_id, status=FAILED, error=str(exc) or type(exc).__name__)
        return
    batch_store.update(
        batch_id,
        status=COMPLETED,
        result={**result.to_dict(), "has_failures": result.has_failures},
        index=result.index,
    )
    logger.debug("run_batch_job: lot {} terminé", batch_id)


def report_path(entry: dict, name: str) -> Path | None:
    """Chemin d'un rapport produit par le lot, ou None (jamais hors du lot)."""
    result = entry.get("result") or {}
    known = set((result.get("capture_reports") or {}).values())
    known |= {g["report"] for g in result.get("groups", []) if g.get("report")}
    if name not in known:
        return None
    path = Path(entry["workdir"]) / "rapports" / name
    return path if path.is_file() else None


def new_workdir() -> tuple[str, str]:
    """(répertoire du lot, sous-répertoire des captures reçues)."""
    workdir = tempfile.mkdtemp(prefix="netcross-api-batch-")
    captures = os.path.join(workdir, "captures")
    os.makedirs(captures)
    return workdir, captures
