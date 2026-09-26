"""
netcross_api.app -- application FastAPI pour exposer les analyses Netcross
(issues #209, #354, #356).

Endpoints :
    POST /captures              — upload d'un pcap, analyse en tâche de fond
    POST /captures/multi        — plusieurs pcaps étiquetés, analyse croisée (#354)
    GET  /analyses              — IDs des analyses connues
    GET  /analyses/{id}/status  — pending / completed / failed (+ résumé)
    GET  /analyses/{id}         — rapport complet (JSON)
    GET  /analyses/{id}/security — constats de sécurité
    GET  /health                — health check (jamais authentifié)

Déploiement (#356), par variables d'environnement lues au démarrage :
    NETCROSS_API_TOKEN      jeton exigé dans l'en-tête X-API-Key (sinon
                            authentification désactivée : usage local)
    NETCROSS_MAX_UPLOAD_MB  taille maximale d'un fichier (défaut 100)
    NETCROSS_API_MAX_FILES  nombre maximal de fichiers par requête (défaut 16)
    NETCROSS_API_WORKERS    analyses simultanées en tâche de fond (défaut 2)
    NETCROSS_DB_PATH        base SQLite : analyses conservées au redémarrage

Le service dépend de netcross_core (analyse). FastAPI/uvicorn sont en
dépendance optionnelle (extra ``api``).
"""

from __future__ import annotations

import hmac
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader

from netcross_api.models import (
    AnalysisAccepted,
    AnalysisStatus,
    AnalysisSummary,
    ErrorResponse,
    HealthResponse,
    MultiAnalysisSummary,
    SecurityFinding,
    SecurityReport,
    SegmentLoss,
)
from netcross_api.store import COMPLETED, FAILED, PENDING, report_document, store
from netcross_core import analyse, correlate, parse_capture
from netcross_core.logging_config import get_logger
from netcross_core.security.findings import apply_security_findings, scan_capture_exploits

logger = get_logger(__name__)
# Singleton pour éviter B008 (File() in argument defaults).
_FILE_REQUIRED = File(default=..., description="Fichier pcap/pcapng à analyser")
_FILES_REQUIRED = File(default=..., description="Fichiers pcap/pcapng à analyser")
_LABEL_FORM = Form(default="capture", description="Étiquette du point de capture (ex: lan)")
_LABELS_FORM = Form(default="", description="Étiquettes séparées par virgule (ex: lan,wan,dc)")
_POINTS_ORDER_FORM = Form(default="", description="Ordre des points séparé par virgule (ex: lan,wan,dc)")
_WAIT_QUERY = Query(
    default=False,
    description="true : attendre la fin de l'analyse (201 + résumé) au lieu de 202 + statut pending",
)

# Issue #356 : authentification par jeton configurable via env var.
# Si NETCROSS_API_TOKEN n'est pas défini, l'authentification est désactivée
# (mode développement local).
_API_TOKEN = os.environ.get("NETCROSS_API_TOKEN")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

_MAX_UPLOAD_BYTES = int(os.environ.get("NETCROSS_MAX_UPLOAD_MB", "100")) * 1024 * 1024
_MAX_FILES = int(os.environ.get("NETCROSS_API_MAX_FILES", "16"))
_WORKERS = int(os.environ.get("NETCROSS_API_WORKERS", "2"))
_CHUNK_BYTES = 1024 * 1024
# Marge multipart (en-têtes de parties, champs labels/points_order) tolérée
# au-delà de la somme des fichiers dans le contrôle Content-Length.
_MULTIPART_MARGIN = 1024 * 1024

_executor: ThreadPoolExecutor | None = None


def _get_executor() -> ThreadPoolExecutor:
    """Pool des analyses en tâche de fond, créé à la première demande."""
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=max(1, _WORKERS), thread_name_prefix="netcross-api")
    return _executor


def _verify_api_key(api_key: str | None = Depends(_api_key_header)) -> None:
    """Dépendance FastAPI : vérifie le jeton d'authentification.

    Issue #356 : si NETCROSS_API_TOKEN est défini, toutes les routes sauf
    /health exigent l'en-tête X-API-Key (comparaison à temps constant).
    Sinon, l'authentification est désactivée (mode développement local).
    """
    if _API_TOKEN and not (api_key and hmac.compare_digest(api_key.encode(), _API_TOKEN.encode())):
        raise HTTPException(status_code=401, detail="Jeton d'authentification invalide ou manquant")


app = FastAPI(
    title="Netcross API",
    description="Analyse croisée de captures réseau — service REST",
    version="1.0.0",
)


def _max_mb() -> int:
    return _MAX_UPLOAD_BYTES // 1024 // 1024


@app.middleware("http")
async def _refuser_corps_trop_gros(request: Request, call_next):
    """413 avant lecture du corps quand Content-Length dépasse déjà ce que
    la route acceptera (issue #356). Starlette met le multipart en tampon
    avant d'appeler la route : sans ce contrôle, un envoi énorme serait
    reçu en entier avant d'être refusé. Un envoi sans Content-Length
    (chunked) reste borné fichier par fichier par ``_save_upload``."""
    if request.method == "POST" and request.url.path.startswith("/captures"):
        longueur = request.headers.get("content-length", "")
        if longueur.isdigit() and int(longueur) > _MAX_UPLOAD_BYTES * _MAX_FILES + _MULTIPART_MARGIN:
            return JSONResponse(
                status_code=413, content={"detail": f"Requête trop volumineuse (max {_max_mb()} Mo par fichier)"}
            )
    return await call_next(request)


@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    """Health check du service."""
    logger.debug("health()")
    return HealthResponse()


async def _save_upload(file: UploadFile, label: str) -> str:
    """Copie l'upload sur disque par blocs, 413 dès que la limite est
    dépassée (issue #356) : le fichier n'est jamais chargé en mémoire."""
    total = 0
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)  # noqa: SIM115 -- fermé ci-dessous
    try:
        with tmp:
            while chunk := await file.read(_CHUNK_BYTES):
                total += len(chunk)
                if total > _MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail=f"Fichier {label} trop volumineux (max {_max_mb()} Mo)")
                tmp.write(chunk)
    except BaseException:
        logger.debug("_save_upload: échec pour {}, fichier temporaire {} supprimé", label, tmp.name)
        Path(tmp.name).unlink(missing_ok=True)
        raise
    return tmp.name


class AnalysisError(Exception):
    """Échec d'analyse attribuable aux captures ; le message est rendu tel
    quel au client (statut failed, ou 400 avec ?wait=true)."""


def _analyse_captures(captures: list[tuple[str, str]], order_list: list[str] | None, multi: bool) -> tuple[dict, dict]:
    """Analyse complète (corrélation, sécurité) ; retourne le document JSON
    du rapport et le résumé. Exécuté hors de la boucle asyncio."""
    all_packets = []
    for label, path in captures:
        try:
            pkts = parse_capture(label, path)
        except Exception as exc:
            logger.warning("parsing de la capture {} impossible : {}", label, exc)
            raise AnalysisError(f"Erreur de parsing pour {label}: {exc}") from exc
        if not pkts:
            raise AnalysisError(f"Aucun paquet trouvé dans la capture {label}")
        all_packets.extend(pkts)
    try:
        flows = correlate(all_packets)
        points_order = order_list if multi else [captures[0][0]]
        report = analyse(flows, points_order=points_order, all_packets=all_packets)
        # CVE-2 : scanner les exploits sur chaque fichier
        detections = []
        for label, path in captures:
            detections.extend(scan_capture_exploits(label, path))
        apply_security_findings(report, all_packets, detections=detections)
    except Exception as exc:
        logger.exception("échec de l'analyse des captures")
        raise AnalysisError(f"Erreur d'analyse: {exc}") from exc

    summary: dict = {
        "point_count": len(report.points),
        "packet_count": len(all_packets),
        "security_finding_count": len(report.security_findings),
    }
    if multi:
        summary["points"] = list(report.points)
        summary["order_source"] = "points_order" if order_list else "auto"
        summary["segments"] = [seg.model_dump() for seg in segment_losses(report)]
    return report_document(report), summary


def _run_job(analysis_id: str, captures: list[tuple[str, str]], order_list: list[str] | None, multi: bool) -> None:
    """Tâche de fond : analyse puis completed/failed ; supprime les fichiers."""
    try:
        document, summary = _analyse_captures(captures, order_list, multi)
    except AnalysisError as exc:
        logger.warning("analyse {} en échec : {}", analysis_id, exc)
        store.fail(analysis_id, str(exc))
    except Exception as exc:  # défense : une tâche ne doit jamais rester pending
        logger.exception("analyse {} : erreur interne", analysis_id)
        store.fail(analysis_id, f"Erreur interne: {exc}")
    else:
        store.complete(analysis_id, document, summary)
    finally:
        for _label, path in captures:
            Path(path).unlink(missing_ok=True)


async def _dispatch(
    captures: list[tuple[str, str]], metadata: dict, order_list: list[str] | None, multi: bool, wait: bool
) -> JSONResponse:
    """Enregistre l'analyse en pending puis l'exécute : en tâche de fond
    (202) ou, avec ``wait``, dans le pool de threads de la requête (201)."""
    analysis_id = store.create_pending(metadata)
    status_url = f"/analyses/{analysis_id}/status"
    if not wait:
        _get_executor().submit(_run_job, analysis_id, captures, order_list, multi)
        accepted = AnalysisAccepted(analysis_id=analysis_id, status=PENDING, status_url=status_url)
        return JSONResponse(status_code=202, content=accepted.model_dump(), headers={"Location": status_url})
    await run_in_threadpool(_run_job, analysis_id, captures, order_list, multi)
    entry = store.get(analysis_id)
    assert entry is not None
    if entry["status"] == FAILED:
        raise HTTPException(status_code=400, detail=entry["error"])
    model = MultiAnalysisSummary if multi else AnalysisSummary
    summary = model(analysis_id=analysis_id, status=COMPLETED, **entry["summary"])
    return JSONResponse(status_code=201, content=summary.model_dump(), headers={"Location": f"/analyses/{analysis_id}"})


_UPLOAD_RESPONSES: dict = {
    201: {"model": AnalysisSummary, "description": "Analyse terminée (?wait=true)"},
    400: {"model": ErrorResponse},
    401: {"model": ErrorResponse},
    413: {"model": ErrorResponse},
}


@app.post(
    "/captures",
    response_model=AnalysisAccepted,
    status_code=202,
    tags=["captures"],
    responses=_UPLOAD_RESPONSES,
)
async def upload_capture(
    file: UploadFile = _FILE_REQUIRED,
    label: str = _LABEL_FORM,
    wait: bool = _WAIT_QUERY,
    _auth: None = Depends(_verify_api_key),
) -> JSONResponse:
    """Upload d'un fichier pcap, analyse en tâche de fond.

    Réponse 202 ``{"status": "pending"}`` : suivre ``status_url`` jusqu'à
    ``completed`` (ou ``failed`` avec ``error``). ``?wait=true`` attend la
    fin et retourne directement le résumé (201).
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Nom de fichier manquant")
    path = await _save_upload(file, label)
    metadata = {"filename": file.filename, "label": label}
    return await _dispatch([(label, path)], metadata, None, multi=False, wait=wait)


def _parse_labels(labels: str, file_count: int) -> list[str]:
    """Étiquettes des captures, une par fichier, dans l'ordre des fichiers.

    Issue #354 : une étiquette manquante ou dupliquée est refusée (400)
    plutôt que remplacée en silence par ``point-N`` -- l'ordre des points et
    les segments de la réponse en dépendent.
    """
    label_list = [lbl.strip() for lbl in labels.split(",")] if labels.strip() else []
    if len(label_list) != file_count or not all(label_list):
        raise HTTPException(
            status_code=400,
            detail=f"labels doit donner une étiquette non vide par fichier ({file_count} attendue(s), "
            f"{len([lbl for lbl in label_list if lbl])} reçue(s))",
        )
    doublons = sorted({lbl for lbl in label_list if label_list.count(lbl) > 1})
    if doublons:
        raise HTTPException(status_code=400, detail=f"Étiquettes dupliquées : {', '.join(doublons)}")
    return label_list


def _parse_points_order(points_order: str, label_list: list[str]) -> list[str] | None:
    """Ordre amont -> aval des points, ou None pour le déduire (comme la CLI
    sans ``--order``). S'il est fourni, il doit citer chaque étiquette une
    fois et une seule : un point inconnu ou oublié fausserait les segments."""
    if not points_order.strip():
        return None
    order = [p.strip() for p in points_order.split(",") if p.strip()]
    inconnus = [p for p in order if p not in label_list]
    manquants = [lbl for lbl in label_list if lbl not in order]
    if inconnus or manquants or len(order) != len(set(order)):
        detail = "points_order doit citer chaque étiquette exactement une fois"
        if inconnus:
            detail += f" ; inconnue(s) : {', '.join(inconnus)}"
        if manquants:
            detail += f" ; absente(s) : {', '.join(manquants)}"
        raise HTTPException(status_code=400, detail=detail)
    return order


def segment_losses(report) -> list[SegmentLoss]:
    """Pertes et délai par segment de ``report.pairs`` (issue #354).

    Même définition que ``netcross_report.path_metrics`` (pertes au point
    aval, taux = pertes / paquets vus à ce point), recalculée ici parce que
    la couche API ne dépend pas de netcross_report (contrat import-linter).
    """
    segments = []
    for upstream, downstream in report.pairs:
        loss = int(report.loss_count.get(downstream, 0))
        seen = int(report.seen_count.get(downstream, 0))
        lat = report.latency.get((upstream, downstream), [])
        segments.append(
            SegmentLoss(
                segment=f"{upstream} -> {downstream}",
                upstream=upstream,
                downstream=downstream,
                loss_count=loss,
                loss_pct=round(100.0 * loss / seen, 3) if seen else None,
                seen_downstream=seen,
                off_path_count=int(report.off_path_count.get(downstream, 0)),
                latency_samples=len(lat),
                latency_avg_ms=round(sum(lat) / len(lat), 3) if lat else None,
            )
        )
    return segments


@app.post(
    "/captures/multi",
    response_model=AnalysisAccepted,
    status_code=202,
    tags=["captures"],
    responses={
        **_UPLOAD_RESPONSES,
        201: {"model": MultiAnalysisSummary, "description": "Analyse terminée (?wait=true)"},
    },
)
async def upload_multi_capture(
    files: list[UploadFile] = _FILES_REQUIRED,
    labels: str = _LABELS_FORM,
    points_order: str = _POINTS_ORDER_FORM,
    wait: bool = _WAIT_QUERY,
    _auth: None = Depends(_verify_api_key),
) -> JSONResponse:
    """Upload de plusieurs captures étiquetées, analyse croisée entre points.

    Issue #354 : équivalent de ``netcross -f LAN=lan.pcap -f DC=dc.pcap
    --order LAN,DC``. ``labels`` donne une étiquette par fichier (dans
    l'ordre des fichiers) ; ``points_order`` (facultatif) fixe l'ordre
    amont -> aval, sinon il est déduit du trafic. Le résumé (``?wait=true``
    ou ``/status``) détaille les pertes et le délai de chaque segment.
    """
    if not files or len(files) < 2:
        raise HTTPException(status_code=400, detail="Au moins 2 fichiers sont requis pour l'analyse multi-points")
    if len(files) > _MAX_FILES:
        raise HTTPException(status_code=400, detail=f"Au plus {_MAX_FILES} fichiers par requête")
    label_list = _parse_labels(labels, len(files))
    order_list = _parse_points_order(points_order, label_list)

    captures: list[tuple[str, str]] = []
    try:
        for file, label in zip(files, label_list, strict=True):
            if not file.filename:
                raise HTTPException(status_code=400, detail=f"Nom de fichier manquant pour {label}")
            captures.append((label, await _save_upload(file, label)))
    except BaseException:
        logger.debug("upload interrompu : {} fichier(s) temporaire(s) supprimé(s)", len(captures))
        for _label, path in captures:
            Path(path).unlink(missing_ok=True)
        raise

    metadata = {"files": [f.filename for f in files], "labels": label_list, "points_order": order_list}
    return await _dispatch(captures, metadata, order_list, multi=True, wait=wait)


def _completed_document(analysis_id: str) -> dict:
    """Document d'une analyse terminée ; 404 inconnue, 409 pending/failed."""
    entry = store.get(analysis_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Analyse {analysis_id} introuvable")
    if entry["status"] == PENDING:
        raise HTTPException(
            status_code=409, detail=f"Analyse {analysis_id} en cours (pending) : suivre /analyses/{analysis_id}/status"
        )
    if entry["status"] == FAILED:
        raise HTTPException(status_code=409, detail=f"Analyse {analysis_id} en echec : {entry['error']}")
    return entry["document"]


_ANALYSIS_RESPONSES: dict = {
    401: {"model": ErrorResponse},
    404: {"model": ErrorResponse},
    409: {"model": ErrorResponse},
}


@app.get("/analyses/{analysis_id}", tags=["analyses"], responses=_ANALYSIS_RESPONSES)
async def get_analysis(analysis_id: str, _auth: None = Depends(_verify_api_key)) -> JSONResponse:
    """Récupère le rapport complet d'une analyse terminée (JSON).

    Les clés par segment sont « amont -> aval » (voir ``store.jsonable``).
    """
    logger.debug("get_analysis(analysis_id={})", analysis_id)
    doc = dict(_completed_document(analysis_id))
    doc["_analysis_id"] = analysis_id
    return JSONResponse(content=doc)


@app.get(
    "/analyses/{analysis_id}/security",
    response_model=SecurityReport,
    tags=["analyses"],
    responses=_ANALYSIS_RESPONSES,
)
async def get_security_report(analysis_id: str, _auth: None = Depends(_verify_api_key)) -> SecurityReport:
    """Récupère les constats de sécurité d'une analyse terminée."""
    logger.debug("get_security_report(analysis_id={})", analysis_id)
    doc = _completed_document(analysis_id)
    findings = [
        SecurityFinding(
            severity=f.get("severity", ""),
            category=f.get("category", ""),
            detail=f.get("detail", ""),
            point=f.get("point"),
        )
        for f in doc.get("security_findings", [])
    ]
    return SecurityReport(
        analysis_id=analysis_id,
        findings=findings,
        service_fingerprints=doc.get("service_fingerprints", []),
        lateral_movement_events=doc.get("lateral_movement_events", []),
        dga_alerts=doc.get("dga_alerts", []),
        fast_flux_alerts=doc.get("fast_flux_alerts", []),
    )


@app.get("/analyses", tags=["analyses"], responses={401: {"model": ErrorResponse}})
async def list_analyses(_auth: None = Depends(_verify_api_key)) -> dict:
    """Liste les IDs d'analyses disponibles (tous statuts)."""
    logger.debug("list_analyses()")
    return {"analyses": store.list_ids()}


@app.get(
    "/analyses/{analysis_id}/status",
    response_model=AnalysisStatus,
    tags=["analyses"],
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def get_analysis_status(analysis_id: str, _auth: None = Depends(_verify_api_key)) -> AnalysisStatus:
    """Statut d'une analyse (issue #356) : ``pending``, ``completed`` (avec
    le résumé, segments compris en multi-points) ou ``failed`` (``error``)."""
    entry = store.get(analysis_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Analyse {analysis_id} introuvable")
    return AnalysisStatus(
        analysis_id=analysis_id,
        status=entry["status"],
        error=entry["error"],
        summary=entry["summary"],
    )
