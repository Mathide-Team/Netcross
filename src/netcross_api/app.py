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

import contextlib
import hmac
import io
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
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
from netcross_core.logging_config import get_logger, summarize
from netcross_core.security.findings import apply_security_findings, scan_capture_exploits
from netcross_report.json_report import build_json_report_document
from netcross_report.security_report import build_security_report
from netcross_report.synthesis import build_findings

logger = get_logger(__name__)
# Singleton pour éviter B008 (File() in argument defaults).
_FILE_REQUIRED = File(default=..., description="Fichier pcap/pcapng à analyser")
_FILES_REQUIRED = File(default=..., description="Fichiers pcap/pcapng à analyser")
_LABEL_FORM = Form(default="capture", description="Étiquette du point de capture (ex: lan)")
_LABELS_FORM = Form(default="", description="Étiquettes séparées par virgule (ex: lan,wan,dc)")
_POINTS_ORDER_FORM = Form(default="", description="Ordre des points séparé par virgule (ex: lan,wan,dc)")
# Issue #330 (écart 2) : options d'analyse, mêmes noms et même sens que la CLI.
_NAT_TOLERANT_FORM = Form(
    default=False, description="true : corrélation tolérante au NAT (équivalent de --nat-tolerant)"
)
_NAT_WINDOW_FORM = Form(
    default=200.0,
    gt=0,
    description="Fenêtre de corrélation NAT en ms, avec nat_tolerant (équivalent de --nat-window-ms)",
)
_TLS_FORM = Form(default=False, description="true : diagnostic TLS (équivalent de --tls)")
_QUIC_FORM = Form(default=False, description="true : diagnostic QUIC/HTTP3 (équivalent de --quic)")
_REDACT_FORM = Form(
    default=False,
    description="true : anonymise les adresses IP/MAC avant analyse (équivalent de --redact) ; "
    "incompatible avec tls/quic, et le rapport de sécurité n'est alors pas calculé",
)
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
    logger.debug("_get_executor()")
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=max(1, _WORKERS), thread_name_prefix="netcross-api")
    logger.debug("_get_executor: retour _executor={}", summarize(_executor, "_executor"))
    return _executor


def _verify_api_key(api_key: str | None = Depends(_api_key_header)) -> None:
    """Dépendance FastAPI : vérifie le jeton d'authentification.

    Issue #356 : si NETCROSS_API_TOKEN est défini, toutes les routes sauf
    /health exigent l'en-tête X-API-Key (comparaison à temps constant).
    Sinon, l'authentification est désactivée (mode développement local).
    """
    if _API_TOKEN and not (api_key and hmac.compare_digest(api_key.encode(), _API_TOKEN.encode())):
        logger.trace("_verify_api_key: refus, HTTPException")
        logger.debug(
            "_verify_api_key: si _API_TOKEN and (not (api_key and hmac.compare_digest(api_ke… -> levée HTTPException"
        )
        raise HTTPException(status_code=401, detail="Jeton d'authentification invalide ou manquant")
    logger.debug("_verify_api_key: fin")


app = FastAPI(
    title="Netcross API",
    description="Analyse croisée de captures réseau — service REST",
    version="1.0.0",
)


def _max_mb() -> int:
    logger.debug("_max_mb: retour _MAX_UPLOAD_BYTES // 1024 // 1024")
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
            logger.debug(
                "_refuser_corps_trop_gros: si longueur.isdigit() and int(longueur) > _MAX_UPLOAD_BYTES * … -> retour…"
            )
            return JSONResponse(
                status_code=413, content={"detail": f"Requête trop volumineuse (max {_max_mb()} Mo par fichier)"}
            )
    logger.debug("_refuser_corps_trop_gros: retour await call_next(request)")
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
                    logger.debug("_save_upload: si total > _MAX_UPLOAD_BYTES -> levée HTTPException")
                    raise HTTPException(status_code=413, detail=f"Fichier {label} trop volumineux (max {_max_mb()} Mo)")
                tmp.write(chunk)
    except BaseException:
        logger.debug("_save_upload: échec pour {}, fichier temporaire {} supprimé", label, tmp.name)
        Path(tmp.name).unlink(missing_ok=True)
        logger.debug("_save_upload: except BaseException -> relance de l'exception en cours")
        raise
    logger.debug("_save_upload: retour tmp.name={}", summarize(tmp.name, "name"))
    return tmp.name


@dataclass(frozen=True)
class ApiAnalysisOptions:
    """Options d'analyse de l'API (issue #330), miroir des options de la CLI."""

    nat_tolerant: bool = False
    nat_window_ms: float = 200.0
    tls: bool = False
    quic: bool = False
    redact: bool = False


def _options(nat_tolerant: bool, nat_window_ms: float, tls: bool, quic: bool, redact: bool) -> ApiAnalysisOptions:
    """Valide les options comme la CLI : ``redact`` exclut ``tls``/``quic``,
    qui relisent les fichiers d'origine (adresses réelles)."""
    if redact and (tls or quic):
        logger.debug("_options: si redact and (tls or quic) -> levée HTTPException")
        raise HTTPException(
            status_code=400,
            detail="redact n'est pas disponible avec tls/quic : ces diagnostics relisent les fichiers "
            "d'origine, avec les adresses réelles (même règle que la CLI)",
        )
    options = ApiAnalysisOptions(nat_tolerant, nat_window_ms, tls, quic, redact)
    logger.debug("_options: retour options={}", summarize(options, "options"))
    return options


class AnalysisError(Exception):
    """Échec d'analyse attribuable aux captures ; le message est rendu tel
    quel au client (statut failed, ou 400 avec ?wait=true)."""


def _tls_quic_findings(
    captures: list[tuple[str, str]], points: list[str], options: ApiAnalysisOptions
) -> tuple[list | None, list | None]:
    """Diagnostics TLS / QUIC demandés, relus sur les fichiers comme
    ``--tls`` / ``--quic`` ; ``None`` pour un diagnostic non demandé."""
    tls_findings = quic_findings = None
    if options.tls:
        from netcross_core.tls_diagnostics import build_handshake_status, diagnose_tls, parse_tls_capture

        tls_events = []
        for label, path in captures:
            tls_events.extend(parse_tls_capture(label, path))
        tls_findings = diagnose_tls(build_handshake_status(tls_events), points)
    if options.quic:
        try:
            from netcross_core.quic_diagnostics import diagnose_quic, parse_quic_capture
        except ImportError as exc:
            logger.debug("_tls_quic_findings: except ImportError -> levée AnalysisError")
            raise AnalysisError("quic nécessite le paquet cryptography (pip install cryptography)") from exc
        quic_events = []
        for label, path in captures:
            quic_events.extend(parse_quic_capture(label, path))
        quic_findings = diagnose_quic(quic_events, points)
    logger.debug(
        "_tls_quic_findings: retour tls={} quic={}",
        summarize(tls_findings, "tls_findings"),
        summarize(quic_findings, "quic_findings"),
    )
    return tls_findings, quic_findings


def _analyse_captures(
    captures: list[tuple[str, str]],
    order_list: list[str] | None,
    multi: bool,
    options: ApiAnalysisOptions | None = None,
) -> tuple[dict, dict, dict, Any, Any, list, Any, Any, list | None, list | None]:
    """Analyse complète (corrélation, sécurité) ; retourne le document brut,
    le résumé, le rapport structuré (celui de ``--json-report``, issue
    #330), l'objet Report vivant, les flows, les findings, le
    security_report_obj et les diagnostics TLS/QUIC — conservés en
    mémoire pour les exports texte/PDF/CSV de l'issue #670.
    Exécuté hors de la boucle asyncio."""
    options = options or ApiAnalysisOptions()
    all_packets = []
    for label, path in captures:
        try:
            pkts = parse_capture(label, path)
        except Exception as exc:
            logger.warning("parsing de la capture {} impossible : {}", label, exc)
            raise AnalysisError(f"Erreur de parsing pour {label}: {exc}") from exc
        if not pkts:
            logger.debug("_analyse_captures: si not pkts -> levée AnalysisError")
            raise AnalysisError(f"Aucun paquet trouvé dans la capture {label}")
        all_packets.extend(pkts)
    try:
        if options.redact:
            from netcross_core.redact import redact_packets

            redact_packets(all_packets)
        flows = correlate(all_packets, options.nat_tolerant, options.nat_window_ms)
        points_order = order_list if multi else [captures[0][0]]
        report = analyse(flows, points_order=points_order, all_packets=all_packets, nat_tolerant=options.nat_tolerant)
        security_report = None
        if not options.redact:
            # CVE-2 : scanner les exploits sur chaque fichier. Pas avec redact :
            # les signatures lisent la charge utile brute des fichiers (même
            # refus que --security-report --redact).
            detections = []
            for label, path in captures:
                detections.extend(scan_capture_exploits(label, path))
            apply_security_findings(report, all_packets, detections=detections)
            security_report = build_security_report(report)
        tls_findings, quic_findings = _tls_quic_findings(captures, list(report.points), options)
        # Issue #330 : même document que `netcross --json-report
        # --security-report` (constats, triage, score de santé).
        # Issue #670 : findings calculés une fois, partagés entre le JSON
        # structuré et les exports texte/PDF/CSV ultérieurs.
        findings = build_findings(report)
        meta = {"Source": "API REST"}
        if options.redact:
            meta["Anonymisation"] = "adresses IP/MAC anonymisees (redact)"
        structured = build_json_report_document(
            report,
            findings=findings,
            security_report=security_report,
            tls_findings=tls_findings,
            quic_findings=quic_findings,
            meta=meta,
        )
        if options.redact:
            structured["security_report_absent"] = "non disponible avec l'anonymisation (redact=true)"
    except AnalysisError:
        logger.debug("_analyse_captures: except AnalysisError -> relance de l'exception en cours")
        raise
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
    logger.debug("_analyse_captures: retour tuple de 10")
    return (
        report_document(report),
        summary,
        structured,
        report,
        flows,
        findings,
        security_report,
        tls_findings,
        quic_findings,
        all_packets,
    )


def _run_job(
    analysis_id: str,
    captures: list[tuple[str, str]],
    order_list: list[str] | None,
    multi: bool,
    options: ApiAnalysisOptions | None = None,
) -> None:
    """Tâche de fond : analyse puis completed/failed ; supprime les fichiers."""
    try:
        (
            document,
            summary,
            structured,
            report_obj,
            flows,
            findings,
            security_report_obj,
            tls_findings,
            quic_findings,
            _all_packets,
        ) = _analyse_captures(captures, order_list, multi, options)
    except AnalysisError as exc:
        logger.warning("analyse {} en échec : {}", analysis_id, exc)
        store.fail(analysis_id, str(exc))
    except Exception as exc:  # défense : une tâche ne doit jamais rester pending
        logger.exception("analyse {} : erreur interne", analysis_id)
        store.fail(analysis_id, f"Erreur interne: {exc}")
    else:
        store.complete(
            analysis_id,
            document,
            summary,
            report=structured,
            report_obj=report_obj,
            flows=flows,
            findings=findings,
            security_report_obj=security_report_obj,
            tls_findings=tls_findings,
            quic_findings=quic_findings,
        )
    finally:
        for _label, path in captures:
            Path(path).unlink(missing_ok=True)
    logger.debug("_run_job: fin")


async def _dispatch(
    captures: list[tuple[str, str]],
    metadata: dict,
    order_list: list[str] | None,
    multi: bool,
    wait: bool,
    options: ApiAnalysisOptions | None = None,
) -> JSONResponse:
    """Enregistre l'analyse en pending puis l'exécute : en tâche de fond
    (202) ou, avec ``wait``, dans le pool de threads de la requête (201)."""
    logger.debug(
        "_dispatch: captures={} metadata={} order_list={} multi={} wait={}",
        summarize(captures, "captures"),
        summarize(metadata, "metadata"),
        summarize(order_list, "order_list"),
        summarize(multi, "multi"),
        summarize(wait, "wait"),
    )
    options = options or ApiAnalysisOptions()
    analysis_id = store.create_pending({**metadata, "options": asdict(options)})
    status_url = f"/analyses/{analysis_id}/status"
    if not wait:
        _get_executor().submit(_run_job, analysis_id, captures, order_list, multi, options)
        accepted = AnalysisAccepted(analysis_id=analysis_id, status=PENDING, status_url=status_url)
        logger.debug("_dispatch: si not wait -> retour JSONResponse(…)")
        return JSONResponse(status_code=202, content=accepted.model_dump(), headers={"Location": status_url})
    await run_in_threadpool(_run_job, analysis_id, captures, order_list, multi, options)
    entry = store.get(analysis_id)
    assert entry is not None
    if entry["status"] == FAILED:
        logger.debug("_dispatch: refus, HTTPException")
        raise HTTPException(status_code=400, detail=entry["error"])
    model = MultiAnalysisSummary if multi else AnalysisSummary
    summary = model(analysis_id=analysis_id, status=COMPLETED, **entry["summary"])
    logger.debug("_dispatch: retour JSONResponse(…)")
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
    nat_tolerant: bool = _NAT_TOLERANT_FORM,
    nat_window_ms: float = _NAT_WINDOW_FORM,
    tls: bool = _TLS_FORM,
    quic: bool = _QUIC_FORM,
    redact: bool = _REDACT_FORM,
    wait: bool = _WAIT_QUERY,
    _auth: None = Depends(_verify_api_key),
) -> JSONResponse:
    """Upload d'un fichier pcap, analyse en tâche de fond.

    Réponse 202 ``{"status": "pending"}`` : suivre ``status_url`` jusqu'à
    ``completed`` (ou ``failed`` avec ``error``). ``?wait=true`` attend la
    fin et retourne directement le résumé (201). ``nat_tolerant``,
    ``nat_window_ms``, ``tls``, ``quic`` et ``redact`` ont le sens des
    options de même nom de la CLI (issue #330).
    """
    options = _options(nat_tolerant, nat_window_ms, tls, quic, redact)
    if not file.filename:
        logger.debug("upload_capture: si not file.filename -> levée HTTPException")
        raise HTTPException(status_code=400, detail="Nom de fichier manquant")
    path = await _save_upload(file, label)
    metadata = {"filename": file.filename, "label": label}
    logger.debug("upload_capture: retour await _dispatch([(label, path)], metadata, None, …")
    return await _dispatch([(label, path)], metadata, None, multi=False, wait=wait, options=options)


def _parse_labels(labels: str, file_count: int) -> list[str]:
    """Étiquettes des captures, une par fichier, dans l'ordre des fichiers.

    Issue #354 : une étiquette manquante ou dupliquée est refusée (400)
    plutôt que remplacée en silence par ``point-N`` -- l'ordre des points et
    les segments de la réponse en dépendent.
    """
    logger.debug(
        "_parse_labels: labels={} file_count={}",
        summarize(labels, "labels"),
        summarize(file_count, "file_count"),
    )
    label_list = [lbl.strip() for lbl in labels.split(",")] if labels.strip() else []
    if len(label_list) != file_count or not all(label_list):
        logger.debug("_parse_labels: refus, HTTPException")
        raise HTTPException(
            status_code=400,
            detail=f"labels doit donner une étiquette non vide par fichier ({file_count} attendue(s), "
            f"{len([lbl for lbl in label_list if lbl])} reçue(s))",
        )
    doublons = sorted({lbl for lbl in label_list if label_list.count(lbl) > 1})
    if doublons:
        logger.debug("_parse_labels: refus, HTTPException")
        raise HTTPException(status_code=400, detail=f"Étiquettes dupliquées : {', '.join(doublons)}")
    logger.debug("_parse_labels: retour label_list={}", summarize(label_list, "label_list"))
    return label_list


def _parse_points_order(points_order: str, label_list: list[str]) -> list[str] | None:
    """Ordre amont -> aval des points, ou None pour le déduire (comme la CLI
    sans ``--order``). S'il est fourni, il doit citer chaque étiquette une
    fois et une seule : un point inconnu ou oublié fausserait les segments."""
    logger.debug(
        "_parse_points_order: points_order={} label_list={}",
        summarize(points_order, "points_order"),
        summarize(label_list, "label_list"),
    )
    if not points_order.strip():
        logger.debug("_parse_points_order: si not points_order.strip() -> retour None")
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
        logger.debug("_parse_points_order: refus, HTTPException")
        raise HTTPException(status_code=400, detail=detail)
    logger.debug("_parse_points_order: retour order={}", summarize(order, "order"))
    return order


def segment_losses(report) -> list[SegmentLoss]:
    """Pertes et délai par segment de ``report.pairs`` (issue #354).

    Même définition que ``netcross_report.path_metrics`` (pertes au point
    aval, taux = pertes / paquets vus à ce point), au format ``SegmentLoss``
    propre au résumé de l'API.
    """
    logger.debug("segment_losses: report={}", summarize(report, "report"))
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
    logger.debug("segment_losses: retour segments={}", summarize(segments, "segments"))
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
    nat_tolerant: bool = _NAT_TOLERANT_FORM,
    nat_window_ms: float = _NAT_WINDOW_FORM,
    tls: bool = _TLS_FORM,
    quic: bool = _QUIC_FORM,
    redact: bool = _REDACT_FORM,
    wait: bool = _WAIT_QUERY,
    _auth: None = Depends(_verify_api_key),
) -> JSONResponse:
    """Upload de plusieurs captures étiquetées, analyse croisée entre points.

    Issue #354 : équivalent de ``netcross -f LAN=lan.pcap -f DC=dc.pcap
    --order LAN,DC``. ``labels`` donne une étiquette par fichier (dans
    l'ordre des fichiers) ; ``points_order`` (facultatif) fixe l'ordre
    amont -> aval, sinon il est déduit du trafic. Le résumé (``?wait=true``
    ou ``/status``) détaille les pertes et le délai de chaque segment.
    Options d'analyse : comme ``POST /captures`` (issue #330).
    """
    options = _options(nat_tolerant, nat_window_ms, tls, quic, redact)
    if not files or len(files) < 2:
        logger.debug("upload_multi_capture: si not files or len(files) < 2 -> levée HTTPException")
        raise HTTPException(status_code=400, detail="Au moins 2 fichiers sont requis pour l'analyse multi-points")
    if len(files) > _MAX_FILES:
        logger.debug("upload_multi_capture: si len(files) > _MAX_FILES -> levée HTTPException")
        raise HTTPException(status_code=400, detail=f"Au plus {_MAX_FILES} fichiers par requête")
    label_list = _parse_labels(labels, len(files))
    order_list = _parse_points_order(points_order, label_list)

    captures: list[tuple[str, str]] = []
    try:
        for file, label in zip(files, label_list, strict=True):
            if not file.filename:
                logger.debug("upload_multi_capture: si not file.filename -> levée HTTPException")
                raise HTTPException(status_code=400, detail=f"Nom de fichier manquant pour {label}")
            captures.append((label, await _save_upload(file, label)))
    except BaseException:
        logger.debug("upload interrompu : {} fichier(s) temporaire(s) supprimé(s)", len(captures))
        for _label, path in captures:
            Path(path).unlink(missing_ok=True)
        logger.debug("upload_multi_capture: except BaseException -> relance de l'exception en cours")
        raise

    metadata = {"files": [f.filename for f in files], "labels": label_list, "points_order": order_list}
    logger.debug("upload_multi_capture: retour await _dispatch(captures, metadata, order_list, m…")
    return await _dispatch(captures, metadata, order_list, multi=True, wait=wait, options=options)


def _completed_entry(analysis_id: str) -> dict:
    """Entrée d'une analyse terminée ; 404 inconnue, 409 pending/failed."""
    logger.debug("_completed_entry: analysis_id={}", summarize(analysis_id, "analysis_id"))
    entry = store.get(analysis_id)
    if entry is None:
        logger.debug("_completed_entry: refus, HTTPException")
        raise HTTPException(status_code=404, detail=f"Analyse {analysis_id} introuvable")
    if entry["status"] == PENDING:
        logger.debug("_completed_entry: refus, HTTPException")
        raise HTTPException(
            status_code=409, detail=f"Analyse {analysis_id} en cours (pending) : suivre /analyses/{analysis_id}/status"
        )
    if entry["status"] == FAILED:
        logger.debug("_completed_entry: refus, HTTPException")
        raise HTTPException(status_code=409, detail=f"Analyse {analysis_id} en echec : {entry['error']}")
    logger.debug("_completed_entry: retour entry={}", summarize(entry, "entry"))
    return entry


def _completed_document(analysis_id: str) -> dict:
    """Document brut d'une analyse terminée (voir ``_completed_entry``)."""
    entry = _completed_entry(analysis_id)
    logger.debug("_completed_document: retour entry['document']")
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
    logger.debug("get_analysis: retour JSONResponse(…)")
    return JSONResponse(content=doc)


@app.get("/analyses/{analysis_id}/report", tags=["analyses"], responses=_ANALYSIS_RESPONSES)
async def get_analysis_report(analysis_id: str, _auth: None = Depends(_verify_api_key)) -> JSONResponse:
    """Rapport structuré d'une analyse terminée : le même document que
    ``netcross --json-report --security-report`` et que l'export JSON de la
    GUI (``findings``, ``triage``, ``health_score``, ``security_report``...).

    Issue #330 : ``GET /analyses/{analysis_id}`` sert la copie brute des
    mesures ; cette route sert les constats et le score de santé. 409 pour
    une analyse enregistrée avant l'ajout de cette route (à relancer).
    """
    logger.debug("get_analysis_report(analysis_id={})", analysis_id)
    entry = _completed_entry(analysis_id)
    if entry.get("report") is None:
        logger.debug("get_analysis_report: si rapport absent -> levée HTTPException")
        raise HTTPException(
            status_code=409,
            detail=f"Analyse {analysis_id} enregistree sans rapport structure (version anterieure) : la relancer",
        )
    doc = dict(entry["report"])
    doc["_analysis_id"] = analysis_id
    logger.debug("get_analysis_report: retour JSONResponse(…)")
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
    logger.debug("get_security_report: retour SecurityReport(…)")
    return SecurityReport(
        analysis_id=analysis_id,
        findings=findings,
        service_fingerprints=doc.get("service_fingerprints", []),
        lateral_movement_events=doc.get("lateral_movement_events", []),
        dga_alerts=doc.get("dga_alerts", []),
        fast_flux_alerts=doc.get("fast_flux_alerts", []),
    )


# -- Issue #670 : exports texte, PDF et CSV du détail -----------------------


def _live_objects(analysis_id: str) -> dict:
    """Entrée d'une analyse terminée, avec garantie que les objets vivants
    (report_obj, flows, findings) sont disponibles. 409 si l'analyse a été
    relue depuis SQLite après un redémarrage : ces objets ne sont pas
    persistés (voir store.complete)."""
    entry = _completed_entry(analysis_id)
    if entry.get("report_obj") is None:
        logger.debug("_live_objects: refus, HTTPException")
        raise HTTPException(
            status_code=409,
            detail=f"Analyse {analysis_id} sans objets vivants en memoire "
            "(relue depuis SQLite ou version anterieure) : la relancer pour generer cet export",
        )
    return entry


@app.get(
    "/analyses/{analysis_id}/text",
    tags=["analyses"],
    responses={**_ANALYSIS_RESPONSES, 200: {"content": {"text/plain": {}}}},
)
async def get_analysis_text(
    analysis_id: str,
    _auth: None = Depends(_verify_api_key),
) -> PlainTextResponse:
    """Rapport texte d'une analyse terminée (équivalent de la sortie console
    de la CLI, issue #670).

    409 si l'analyse a été relue depuis SQLite après un redémarrage
    (les objets vivants nécessaires ne sont pas persistés).
    """
    logger.debug("get_analysis_text(analysis_id={})", analysis_id)
    entry = _live_objects(analysis_id)
    report = entry["report_obj"]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        from netcross_core.report_text import print_report

        print_report(report)
    logger.debug("get_analysis_text: retour PlainTextResponse(…)")
    return PlainTextResponse(buf.getvalue())


@app.get(
    "/analyses/{analysis_id}/pdf",
    tags=["analyses"],
    responses={**_ANALYSIS_RESPONSES, 200: {"content": {"application/pdf": {}}}},
)
async def get_analysis_pdf(
    analysis_id: str,
    topn: int = Query(default=5, ge=1, le=50, description="Nombre de catégories par graphique Top-N"),
    _auth: None = Depends(_verify_api_key),
) -> StreamingResponse:
    """Rapport PDF d'une analyse terminée (équivalent de ``--pdf-report``,
    issue #670).

    ``topn`` contrôle le nombre de catégories affichées par graphique
    temporel Top-N (équivalent de ``--topn-charts``, défaut 5).

    409 si l'analyse a été relue depuis SQLite après un redémarrage.
    """
    logger.debug("get_analysis_pdf(analysis_id={}, topn={})", analysis_id, topn)
    entry = _live_objects(analysis_id)
    report = entry["report_obj"]
    findings = entry.get("findings")
    security_report = entry.get("security_report_obj")
    tls_findings = entry.get("tls_findings")
    quic_findings = entry.get("quic_findings")

    from netcross_report.pdf import generate_pdf

    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)  # noqa: SIM115
    try:
        with tmp:
            # Le paramètre topn est accepté pour la parité avec --topn-charts
            # mais le PDF utilise le topn fixé au moment de analyse() (défaut 5).
            generate_pdf(
                report,
                tmp.name,
                findings=findings,
                security_report=security_report,
                tls_findings=tls_findings,
                quic_findings=quic_findings,
                meta={"Source": "API REST"},
            )
        data = Path(tmp.name).read_bytes()
    finally:
        Path(tmp.name).unlink(missing_ok=True)
    logger.debug("get_analysis_pdf: retour StreamingResponse(…)")
    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="netcross-{analysis_id}.pdf"'},
    )


@app.get(
    "/analyses/{analysis_id}/detail.csv",
    tags=["analyses"],
    responses={**_ANALYSIS_RESPONSES, 200: {"content": {"text/csv": {}}}},
)
async def get_analysis_csv(
    analysis_id: str,
    _auth: None = Depends(_verify_api_key),
) -> PlainTextResponse:
    """CSV du détail par flux d'une analyse terminée (équivalent de
    ``--detail-csv``, issue #670).

    409 si l'analyse a été relue depuis SQLite après un redémarrage.
    """
    logger.debug("get_analysis_csv(analysis_id={})", analysis_id)
    entry = _live_objects(analysis_id)
    report = entry["report_obj"]
    flows = entry.get("flows")

    from netcross_core.report_text import write_detail_csv

    tmp = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)  # noqa: SIM115
    try:
        with tmp:
            write_detail_csv(tmp.name, flows, report.points)
        data = Path(tmp.name).read_text(encoding="utf-8")
    finally:
        Path(tmp.name).unlink(missing_ok=True)
    logger.debug("get_analysis_csv: retour PlainTextResponse(…)")
    return PlainTextResponse(
        data,
        headers={"Content-Disposition": f'attachment; filename="netcross-{analysis_id}-detail.csv"'},
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
        logger.debug("get_analysis_status: si entry is None -> levée HTTPException")
        raise HTTPException(status_code=404, detail=f"Analyse {analysis_id} introuvable")
    logger.debug("get_analysis_status: retour AnalysisStatus(…)")
    return AnalysisStatus(
        analysis_id=analysis_id,
        status=entry["status"],
        error=entry["error"],
        summary=entry["summary"],
    )
