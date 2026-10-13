"""netcross_api.live_routes -- capture en direct sur des interfaces du
serveur, puis analyse (issue #902), équivalent API de ``--live`` et de la
case « Capture en direct » de la GUI.

Chaque point enregistre son interface dans un fichier temporaire (un
``tshark`` d'enregistrement par point, filtre BPF propre au point, comme
``--live NOM:INTERFACE:FILTRE``) pendant ``duration`` secondes au plus ;
les fichiers passent ensuite par la même chaîne d'analyse que
``POST /captures`` / ``POST /captures/multi`` -- mêmes options, même
résultat consultable sous ``/analyses/{analysis_id}``.

- ``POST /live-captures`` : démarre (202) ;
- ``GET /live-captures/{capture_id}`` : état (``capturing``, ``analysing``,
  ``completed``, ``failed``), octets enregistrés par point, durée écoulée,
  ``analysis_id`` une fois l'analyse lancée ;
- ``POST /live-captures/{capture_id}/stop`` : arrêt anticipé (l'analyse
  porte alors sur ce qui a été capturé) ; la réponse donne l'``analysis_id``
  (issue #904) ;
- ``DELETE /live-captures/{capture_id}`` : abandon sans analyse, fichiers
  supprimés, statut ``cancelled`` (issue #904) ;
- ``ring_buffer`` (``files``, ``seconds``, issue #905, équiv. ``--ring-buffer
  N:SECONDES``) : en plus de l'analyse, un second enregistreur par point
  garde la capture brute en pcapng tournants ; ces fichiers survivent à
  l'analyse : ``GET /live-captures/{capture_id}/files`` les liste,
  ``GET .../files/{point}/{filename}`` les télécharge,
  ``DELETE .../files`` les supprime.

Sécurité : capturer demande des privilèges (``CAP_NET_RAW``) sur le
serveur. Désactivé par défaut (``NETCROSS_API_LIVE=1`` pour l'activer),
interfaces en liste blanche (``NETCROSS_API_LIVE_INTERFACES``), durée
bornée (``NETCROSS_API_LIVE_MAX_DURATION``, 300 s par défaut), réservé au
détenteur de la clé API : refusé si ``NETCROSS_API_TOKEN`` n'est pas
défini. Une seule capture à la fois par serveur.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from netcross_core.logging_config import get_logger
from pcap_parser.capture import start_ring_recorder, stop_ring_recorder

logger = get_logger(__name__)

LIVE_ENV = "NETCROSS_API_LIVE"
INTERFACES_ENV = "NETCROSS_API_LIVE_INTERFACES"
MAX_DURATION_ENV = "NETCROSS_API_LIVE_MAX_DURATION"
DEFAULT_MAX_DURATION = 300.0

CAPTURING, ANALYSING, COMPLETED, FAILED = "capturing", "analysing", "completed", "failed"
CANCELLED = "cancelled"  # DELETE /live-captures/{id} (issue #904) : abandon sans analyse
# Attente maximale de /stop et DELETE : le temps d'arrêter tshark et de créer
# l'analyse (issue #904 : /stop renvoie l'analysis_id).
STOP_WAIT_SECONDS = 15.0

#: Options de ``_options`` sans objet ici (fichiers téléversés, séparation
#: des interfaces d'un pcapng : un point = une interface).
_EXCLUDED_OPTIONS = frozenset({"known_destinations", "known_hosts", "names_path", "split_interfaces"})

_RESPONSES: dict[int | str, dict[str, Any]] = {
    403: {
        "description": f"Capture en direct désactivée ({LIVE_ENV}), interface hors de {INTERFACES_ENV}, "
        "ou NETCROSS_API_TOKEN non défini"
    },
    404: {"description": "Capture inconnue"},
    409: {"description": "Une capture est déjà en cours, ou abandon d'une capture déjà terminée"},
}


class LivePoint(BaseModel):
    """Un point de capture : nom, interface du serveur, filtre BPF propre."""

    name: str = Field(..., description="Nom du point (devient le point de capture de l'analyse)")
    interface: str = Field(..., description=f"Interface du serveur (autorisée par {INTERFACES_ENV})")
    bpf: str | None = Field(None, description="Filtre BPF de capture de ce point (ex. 'tcp port 443')")
    bpf_library: str | None = Field(
        None,
        description="Nom d'un filtre de la bibliothèque (GET /bpf-filters) à la place de bpf "
        "(équiv. --bpf-library ; exclusif avec bpf)",
    )


class RingBuffer(BaseModel):
    """Rotation de la capture brute (équiv. ``--ring-buffer N:SECONDES``)."""

    files: int = Field(..., ge=1, description="Nombre de fichiers gardés par point (N)")
    seconds: float = Field(..., gt=0, description="Durée maximale d'un fichier, en secondes")


class LiveCaptureRequest(BaseModel):
    """Corps de ``POST /live-captures``."""

    points: list[LivePoint] = Field(..., description="Points à capturer simultanément (au moins 1)")
    duration: float = Field(..., gt=0, description=f"Durée de capture en secondes (bornée par {MAX_DURATION_ENV})")
    points_order: list[str] | None = Field(None, description="Ordre amont -> aval (sinon déduit du trafic)")
    ring_buffer: RingBuffer | None = Field(
        None,
        description="Garde aussi la capture brute de chaque point en pcapng tournants, téléchargeables "
        "après l'analyse (GET /live-captures/{capture_id}/files) ; incompatible avec pipe://",
    )
    options: dict[str, Any] = Field(
        default_factory=dict,
        description="Options d'analyse de POST /captures/multi (mêmes noms : tls, nat_tolerant, max_packets...)",
    )


def live_enabled(environ: dict[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    return env.get(LIVE_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def allowed_interfaces(environ: dict[str, str] | None = None) -> frozenset[str]:
    env = os.environ if environ is None else environ
    return frozenset(i.strip() for i in env.get(INTERFACES_ENV, "").split(",") if i.strip())


def max_duration(environ: dict[str, str] | None = None) -> float:
    env = os.environ if environ is None else environ
    brut = env.get(MAX_DURATION_ENV, "").strip()
    try:
        valeur = float(brut) if brut else DEFAULT_MAX_DURATION
    except ValueError:
        logger.warning("{}={!r} invalide : {} s par défaut", MAX_DURATION_ENV, brut, DEFAULT_MAX_DURATION)
        return DEFAULT_MAX_DURATION
    return valeur if valeur > 0 else DEFAULT_MAX_DURATION


def _size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError as exc:  # fichier supprimé entre glob et stat
        logger.debug("live: taille de {} illisible ({})", path, exc)
        return 0


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "point"


class _LiveCaptures:
    """Captures en cours ou terminées (mémoire du processus)."""

    def __init__(self, deps: dict[str, Callable[..., Any]]) -> None:
        self._deps = deps
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}

    # -- validation ------------------------------------------------------------------

    def _check_security(self, req: LiveCaptureRequest) -> None:
        if not live_enabled():
            logger.debug("live: désactivée -> 403")
            raise HTTPException(status_code=403, detail=f"capture en direct désactivée sur ce serveur ({LIVE_ENV}=1)")
        if not self._deps["token"]():
            logger.debug("live: pas de NETCROSS_API_TOKEN -> 403")
            raise HTTPException(
                status_code=403,
                detail="capture en direct réservée au détenteur de la clé API : définir NETCROSS_API_TOKEN",
            )
        autorisees = allowed_interfaces()
        for point in req.points:
            if point.interface.strip() not in autorisees:
                logger.debug("live: interface {} hors liste blanche -> 403", point.interface)
                raise HTTPException(
                    status_code=403,
                    detail=f"interface {point.interface!r} non autorisée par {INTERFACES_ENV}"
                    + ("" if autorisees else " (vide)"),
                )

    def _check_request(self, req: LiveCaptureRequest) -> tuple[list[str], list[str] | None, Any]:
        if not req.points:
            raise HTTPException(status_code=400, detail="au moins un point est requis")
        if len(req.points) > self._deps["max_files"]():
            raise HTTPException(status_code=400, detail=f"au plus {self._deps['max_files']()} points par capture")
        noms = [p.name.strip() for p in req.points]
        if any(not n for n in noms) or len(set(noms)) != len(noms):
            raise HTTPException(status_code=400, detail="chaque point doit avoir un nom non vide et distinct")
        if any(not p.interface.strip() for p in req.points):
            raise HTTPException(status_code=400, detail="interface manquante")
        for p in req.points:
            if p.bpf_library is not None:
                if p.bpf:
                    raise HTTPException(status_code=400, detail=f"{p.name} : bpf et bpf_library sont exclusifs")
                p.bpf = self._deps["resolve_bpf_library"](p.bpf_library)
                logger.debug("live: point {} : filtre {!r} de la bibliothèque", p.name, p.bpf_library)
        if req.ring_buffer is not None:
            for p in req.points:
                if p.interface.strip().startswith("pipe://"):
                    raise HTTPException(
                        status_code=400, detail=f"{p.name} : ring_buffer incompatible avec une source pipe://"
                    )
        borne = max_duration()
        if req.duration > borne:
            raise HTTPException(status_code=400, detail=f"duration : {borne:g} s au plus ({MAX_DURATION_ENV})")
        order = None
        if req.points_order:
            order = self._deps["parse_points_order"](",".join(req.points_order), noms)
        inconnues = sorted(set(req.options) - self._deps["option_names"]())
        if inconnues:
            raise HTTPException(status_code=422, detail=f"options inconnues : {', '.join(inconnues)}")
        try:
            options = self._deps["make_options"](**req.options)
        except TypeError as exc:
            logger.debug("live: options invalides ({})", exc)
            raise HTTPException(status_code=422, detail=f"options invalides : {exc}") from exc
        return noms, order, options

    # -- cycle de vie ------------------------------------------------------------------

    def start(self, req: LiveCaptureRequest) -> dict[str, Any]:
        self._check_security(req)
        noms, order, options = self._check_request(req)
        with self._lock:
            if any(e["status"] == CAPTURING for e in self._entries.values()):
                logger.debug("live: capture déjà en cours -> 409")
                raise HTTPException(status_code=409, detail="une capture en direct est déjà en cours sur ce serveur")
            capture_id = uuid.uuid4().hex
            workdir = tempfile.mkdtemp(prefix="netcross-live-")
            ringdir = tempfile.mkdtemp(prefix="netcross-live-ring-") if req.ring_buffer is not None else None
            entry: dict[str, Any] = {
                "capture_id": capture_id,
                "status": CAPTURING,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "_t0": time.monotonic(),
                "_t1": None,
                "duration": req.duration,
                "points": [
                    {
                        "name": n,
                        "interface": p.interface.strip(),
                        "bpf": p.bpf or None,
                        "_dir": f"{workdir}/{i}",
                        "_ring": f"{ringdir}/{_safe_name(n)}" if ringdir else None,
                    }
                    for i, (n, p) in enumerate(zip(noms, req.points, strict=True))
                ],
                "analysis_id": None,
                "error": None,
                "_stop": threading.Event(),
                # posé quand la phase de capture est finie : analyse créée, échec ou abandon
                "_handoff": threading.Event(),
                "_abort": False,
                "_workdir": workdir,
                "_ringdir": ringdir,
                "ring_buffer": req.ring_buffer.model_dump() if req.ring_buffer is not None else None,
            }
            self._entries[capture_id] = entry
        threading.Thread(target=self._run, args=(entry, order, options), daemon=True).start()
        logger.info("capture en direct {} démarrée : {} point(s), {} s", capture_id, len(noms), req.duration)
        return self.public(entry)

    def _run(self, entry: dict[str, Any], order: list[str] | None, options: Any) -> None:
        recorders: list[tuple[dict[str, Any], Any]] = []
        try:
            for point in entry["points"]:
                proc = self._deps["start_recorder"](
                    point["interface"],
                    point["_dir"],
                    max_files=2,
                    # rotation jamais atteinte : l'arrêt vient de la durée ou de /stop
                    max_duration_per_file=entry["duration"] + 3600,
                    prefix=_safe_name(point["name"]),
                    bpf_filter=point["bpf"],
                )
                recorders.append((point, proc))
                if point["_ring"] is not None:
                    ring = self._deps["start_recorder"](
                        point["interface"],
                        point["_ring"],
                        max_files=entry["ring_buffer"]["files"],
                        max_duration_per_file=entry["ring_buffer"]["seconds"],
                        prefix=_safe_name(point["name"]),
                        bpf_filter=point["bpf"],
                    )
                    recorders.append(({**point, "_dir": point["_ring"], "_is_ring": True}, ring))
            entry["_stop"].wait(entry["duration"])
        except Exception as exc:  # noqa: BLE001 -- tâche de fond : l'erreur va dans l'état
            logger.exception("capture en direct {} : démarrage impossible", entry["capture_id"])
            entry["error"] = f"capture impossible : {exc}"
        erreurs = []
        for point, proc in recorders:
            err = self._deps["stop_recorder"](proc)
            if err and not point.get("_is_ring") and not self._files(point):
                erreurs.append(f"{point['name']} : {err}")
        entry["_t1"] = time.monotonic()
        for point in entry["points"]:  # figé : les fichiers sont supprimés après l'analyse
            point["_bytes"] = sum(_size(f) for f in self._files(point))
        captures = [(p["name"], f) for p in entry["points"] for f in self._files(p)]
        if entry["_abort"]:
            logger.info("capture en direct {} abandonnée sans analyse", entry["capture_id"])
            entry["status"] = CANCELLED
            shutil.rmtree(entry["_workdir"], ignore_errors=True)
            self._purge_ring(entry)
            entry["_handoff"].set()
            return
        if entry["error"] is None and erreurs:
            entry["error"] = "; ".join(erreurs)
        if entry["error"] is None and {n for n, _ in captures} != {p["name"] for p in entry["points"]}:
            manquants = sorted({p["name"] for p in entry["points"]} - {n for n, _ in captures})
            entry["error"] = f"aucun fichier enregistré pour : {', '.join(manquants)}"
        if entry["error"] is not None:
            logger.warning("capture en direct {} en échec : {}", entry["capture_id"], entry["error"])
            entry["status"] = FAILED
            shutil.rmtree(entry["_workdir"], ignore_errors=True)
            entry["_handoff"].set()
            return
        multi = len(entry["points"]) > 1
        metadata = {
            "live_capture_id": entry["capture_id"],
            "labels": [p["name"] for p in entry["points"]],
            "interfaces": {p["name"]: p["interface"] for p in entry["points"]},
            "points_order": order,
        }
        entry["analysis_id"] = self._deps["create_pending"](metadata, options)
        entry["status"] = ANALYSING
        entry["_handoff"].set()
        try:
            self._deps["run_job"](entry["analysis_id"], captures, order, multi, options)
        finally:
            shutil.rmtree(entry["_workdir"], ignore_errors=True)
        analyse = self._deps["get_analysis"](entry["analysis_id"]) or {}
        if analyse.get("status") == COMPLETED:
            entry["status"] = COMPLETED
        else:
            entry["status"] = FAILED
            entry["error"] = analyse.get("error") or "analyse en échec"
        logger.info("capture en direct {} : {}", entry["capture_id"], entry["status"])

    # -- fichiers du ring buffer (issue #905) --------------------------------------------

    @staticmethod
    def _purge_ring(entry: dict[str, Any]) -> None:
        if entry.get("_ringdir"):
            shutil.rmtree(entry["_ringdir"], ignore_errors=True)
            entry["_ring_purged"] = True

    def ring_files(self, capture_id: str) -> dict[str, Any]:
        entry = self.get(capture_id)
        if entry.get("ring_buffer") is None:
            logger.debug("live: {} sans ring_buffer -> 404", capture_id)
            raise HTTPException(status_code=404, detail=f"Capture en direct {capture_id} lancée sans ring_buffer")
        points = []
        for p in entry["points"]:
            fichiers = [Path(f) for f in self._files({"_dir": p["_ring"]})]
            points.append(
                {
                    "name": p["name"],
                    "files": [
                        {
                            "filename": f.name,
                            "bytes": _size(str(f)),
                            "url": f"/live-captures/{capture_id}/files/{p['name']}/{f.name}",
                        }
                        for f in fichiers
                    ],
                }
            )
        return {
            "capture_id": capture_id,
            "status": entry["status"],
            "ring_buffer": entry["ring_buffer"],
            "purged": bool(entry.get("_ring_purged")),
            "points": points,
        }

    def ring_file(self, capture_id: str, point: str, filename: str) -> Path:
        """Chemin d'un fichier listé par ``ring_files`` : seuls ces noms sont
        servis (aucun chemin construit depuis la requête)."""
        doc = self.ring_files(capture_id)
        entry = self.get(capture_id)
        for p, desc in zip(entry["points"], doc["points"], strict=True):
            if desc["name"] == point:
                for f in desc["files"]:
                    if f["filename"] == filename:
                        return Path(p["_ring"]) / f["filename"]
        logger.debug("live: fichier {}/{} absent de {} -> 404", point, filename, capture_id)
        raise HTTPException(status_code=404, detail=f"Fichier {point}/{filename} introuvable")

    def purge_ring(self, capture_id: str) -> dict[str, Any]:
        entry = self.get(capture_id)
        self.ring_files(capture_id)  # 404 sans ring_buffer
        if entry["status"] == CAPTURING:
            logger.debug("live: purge de {} pendant la capture -> 409", capture_id)
            raise HTTPException(status_code=409, detail="capture en cours : l'arrêter avant de supprimer ses fichiers")
        self._purge_ring(entry)
        logger.info("capture en direct {} : fichiers du ring buffer supprimés", capture_id)
        return self.ring_files(capture_id)

    @staticmethod
    def _files(point: dict[str, Any]) -> list[str]:
        dossier = Path(point["_dir"])
        return sorted(str(p) for p in dossier.glob("*.pcap*")) if dossier.is_dir() else []

    def get(self, capture_id: str) -> dict[str, Any]:
        entry = self._entries.get(capture_id)
        if entry is None:
            logger.debug("live: capture {} inconnue -> 404", capture_id)
            raise HTTPException(status_code=404, detail=f"Capture en direct {capture_id} introuvable")
        return entry

    def stop(self, capture_id: str) -> dict[str, Any]:
        """Arrêt anticipé (issue #904) : attend que l'analyse soit créée pour
        renvoyer son ``analysis_id``. Sans effet si la capture est finie."""
        entry = self.get(capture_id)
        if entry["status"] == CAPTURING:
            entry["_stop"].set()
            if not entry["_handoff"].wait(STOP_WAIT_SECONDS):
                logger.warning("capture en direct {} : arrêt plus long que {} s", capture_id, STOP_WAIT_SECONDS)
        return self.public(entry)

    def cancel(self, capture_id: str) -> dict[str, Any]:
        """Abandon sans analyse (issue #904) : arrête tshark, supprime les
        fichiers, statut ``cancelled``. 409 si la capture est déjà finie."""
        entry = self.get(capture_id)
        if entry["status"] != CAPTURING:
            logger.debug("live: abandon de {} au statut {} -> 409", capture_id, entry["status"])
            raise HTTPException(
                status_code=409,
                detail=f"capture en direct {capture_id} déjà terminée ({entry['status']}) : rien à abandonner",
            )
        entry["_abort"] = True
        entry["_stop"].set()
        if not entry["_handoff"].wait(STOP_WAIT_SECONDS):
            logger.warning("capture en direct {} : abandon plus long que {} s", capture_id, STOP_WAIT_SECONDS)
        return self.public(entry)

    def public(self, entry: dict[str, Any]) -> dict[str, Any]:
        fin = entry["_t1"] if entry["_t1"] is not None else time.monotonic()
        points = []
        for p in entry["points"]:
            taille = p["_bytes"] if "_bytes" in p else sum(_size(f) for f in self._files(p))
            points.append({"name": p["name"], "interface": p["interface"], "bpf": p["bpf"], "bytes_captured": taille})
        analyse = self._deps["get_analysis"](entry["analysis_id"]) if entry["analysis_id"] else None
        summary = (analyse or {}).get("summary") or {}
        return {
            "capture_id": entry["capture_id"],
            "status": entry["status"],
            "started_at": entry["started_at"],
            "duration": entry["duration"],
            "elapsed_seconds": round(fin - entry["_t0"], 3),
            "points": points,
            "packet_count": summary.get("packet_count"),
            "analysis_id": entry["analysis_id"],
            "analysis_url": f"/analyses/{entry['analysis_id']}" if entry["analysis_id"] else None,
            "error": entry["error"],
            "ring_buffer": entry.get("ring_buffer"),
            "files_url": f"/live-captures/{entry['capture_id']}/files" if entry.get("ring_buffer") else None,
        }


def register(app: FastAPI, verify: Callable[..., None], deps: dict[str, Callable[..., Any]]) -> _LiveCaptures:
    """Déclare les routes. ``deps`` : fonctions de ``netcross_api.app``
    (``token``, ``max_files``, ``parse_points_order``, ``option_names``,
    ``make_options``, ``create_pending``, ``run_job``, ``get_analysis``) et
    l'enregistreur (``start_recorder``, ``stop_recorder``)."""
    from netcross_api.bpf_routes import resolve_bpf_library

    deps = {
        "start_recorder": start_ring_recorder,
        "stop_recorder": stop_ring_recorder,
        "resolve_bpf_library": resolve_bpf_library,
        **deps,
    }
    live = _LiveCaptures(deps)
    auth = [Depends(verify)]

    @app.post("/live-captures", status_code=202, tags=["live"], responses=_RESPONSES, dependencies=auth)
    def start_live_capture(body: LiveCaptureRequest) -> JSONResponse:
        """Démarre une capture en direct puis son analyse (équiv. ``--live`` + ``--live-duration``)."""
        etat = live.start(body)
        url = f"/live-captures/{etat['capture_id']}"
        return JSONResponse(status_code=202, content=etat, headers={"Location": url})

    @app.get("/live-captures/{capture_id}", tags=["live"], responses=_RESPONSES, dependencies=auth)
    def get_live_capture(capture_id: str) -> dict[str, Any]:
        """État : capturing, analysing, completed ou failed ; octets par point ; analysis_id."""
        return live.public(live.get(capture_id))

    @app.post("/live-captures/{capture_id}/stop", tags=["live"], responses=_RESPONSES, dependencies=auth)
    def stop_live_capture(capture_id: str) -> dict[str, Any]:
        """Arrête la capture avant la fin de ``duration`` (équiv. Ctrl+C / « Arreter et analyser ») ;
        l'analyse porte sur ce qui a été capturé et la réponse donne son ``analysis_id``."""
        return live.stop(capture_id)

    @app.delete("/live-captures/{capture_id}", tags=["live"], responses=_RESPONSES, dependencies=auth)
    def cancel_live_capture(capture_id: str) -> dict[str, Any]:
        """Abandonne une capture en cours sans l'analyser (fichiers supprimés, statut ``cancelled``) ;
        409 si elle est déjà terminée."""
        return live.cancel(capture_id)

    @app.get("/live-captures/{capture_id}/files", tags=["live"], responses=_RESPONSES, dependencies=auth)
    def list_live_capture_files(capture_id: str) -> dict[str, Any]:
        """Fichiers pcapng conservés par le ``ring_buffer`` (équiv. ``--ring-buffer``), par point ;
        404 si la capture a été lancée sans ``ring_buffer``."""
        return live.ring_files(capture_id)

    @app.get(
        "/live-captures/{capture_id}/files/{point}/{filename}",
        tags=["live"],
        responses={**_RESPONSES, 200: {"content": {"application/vnd.tcpdump.pcap": {}}}},
        dependencies=auth,
    )
    def download_live_capture_file(capture_id: str, point: str, filename: str) -> FileResponse:
        """Télécharge un fichier du ``ring_buffer`` (nom donné par ``GET .../files``)."""
        chemin = live.ring_file(capture_id, point, filename)
        return FileResponse(chemin, media_type="application/vnd.tcpdump.pcap", filename=chemin.name)

    @app.delete("/live-captures/{capture_id}/files", tags=["live"], responses=_RESPONSES, dependencies=auth)
    def purge_live_capture_files(capture_id: str) -> dict[str, Any]:
        """Supprime les fichiers du ``ring_buffer`` ; 409 pendant la capture."""
        return live.purge_ring(capture_id)

    logger.debug("live_routes.register: 7 routes")
    return live
