"""netcross_api.tools_routes -- manipulation de captures (issues #868,
#869, #870, #886, #887), équivalents des modes utilitaires de la CLI :

- ``POST /tools/merge`` : ``--merge``, ``--merge-dedup`` ;
- ``POST /tools/split`` : ``--split MODE:VALEUR`` (archive zip des morceaux) ;
- ``POST /tools/convert`` : ``--convert``, ``--convert-format`` ;
- ``POST /tools/export`` : ``--export-pcap`` et ses filtres ;
- ``POST /tools/adjust-time`` : ``--adjust-time-output`` et ses modes ;
- ``POST /tools/replay`` : ``--replay`` (issue #871), seulement sur les
  interfaces listees par l'administrateur dans ``NETCROSS_REPLAY_INTERFACES``
  (vide par defaut : rejeu refuse, 403).

Même validation et mêmes messages que la CLI (``netcross_core.capture_tools``) ;
aucune analyse. Fichiers temporaires supprimés après la réponse.
"""

from __future__ import annotations

import shutil
import tempfile
import zipfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

from netcross_core import capture_tools
from netcross_core.logging_config import get_logger
from pcap_parser.capture import TcpreplayNotFoundError, TsharkNotFoundError

logger = get_logger(__name__)

_CAPTURE_FORMATS = ("pcapng", "pcap")
_MEDIA = {
    "pcap": "application/vnd.tcpdump.pcap",
    "pcapng": "application/octet-stream",
    "erf": "application/octet-stream",
    "csv": "text/csv",
    "json": "application/json",
    "zip": "application/zip",
}
_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {"content": {"application/octet-stream": {}}},
    400: {"description": "Paramètres refusés (mêmes messages que la CLI)"},
    413: {"description": "Fichier trop volumineux"},
    422: {"description": "Échec de l'outil Wireshark (capture illisible...)"},
    503: {"description": "Outils Wireshark (tshark, editcap, mergecap) absents du serveur"},
}

# Singletons pour éviter B008 (File() en valeur par défaut), comme app.py.
_MERGE_FILES = File(..., description="Captures à fusionner (pcap/pcapng, formats mélangeables)")
_SPLIT_FILE = File(..., description="Capture à découper")
_CONVERT_FILE = File(..., description="Capture à convertir")
_EXPORT_FILE = File(..., description="Capture source")
_ADJUST_FILE = File(..., description="Capture à recaler")
_REPLAY_FILE = File(..., description="Capture à rejouer")
_ALIGN_FILE = File(None, description="Capture de référence (équivalent de --align-to)")

_REPLAY_RESPONSES: dict[int | str, dict[str, Any]] = {
    **{k: v for k, v in _RESPONSES.items() if k != 200},
    403: {"description": "Interface non autorisée par NETCROSS_REPLAY_INTERFACES (rejeu désactivé par défaut)"},
    503: {"description": "tcpreplay absent du serveur"},
}

SaveUpload = Callable[[UploadFile, str], Awaitable[str]]


async def _run(work: Callable[[], Any]) -> Any:
    """Exécute l'outil hors de la boucle ; erreurs -> codes HTTP."""
    try:
        return await run_in_threadpool(work)
    except (TsharkNotFoundError, TcpreplayNotFoundError) as exc:
        logger.warning("outils de capture : {}", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (ValueError, FileNotFoundError) as exc:
        logger.info("outils de capture : refus ({})", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (OSError, RuntimeError) as exc:  # TsharkError hérite de RuntimeError
        logger.warning("outils de capture : échec ({})", exc)
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _check_format(fmt: str, allowed: tuple[str, ...]) -> str:
    fmt = fmt.strip().lower()
    if fmt not in allowed:
        raise HTTPException(status_code=400, detail=f"format inconnu : {fmt} (attendu : {', '.join(allowed)})")
    return fmt


def _file_response(workdir: str, path: str, filename: str, fmt: str, message: str) -> FileResponse:
    return FileResponse(
        path,
        media_type=_MEDIA.get(fmt, "application/octet-stream"),
        filename=filename,
        headers={"X-Netcross-Message": message.encode("ascii", "replace").decode("ascii")},
        background=BackgroundTask(shutil.rmtree, workdir, True),
    )


def register(app: FastAPI, verify: Callable[..., None], save_upload: SaveUpload, max_files: Callable[[], int]) -> None:
    """Déclare les routes ``/tools/*`` sur ``app`` (authentification ``verify``,
    copie bornée des fichiers ``save_upload``, au plus ``max_files()``)."""
    deps = [Depends(verify)]

    async def _saved(workdir: str, upload: UploadFile, label: str) -> str:
        tmp = await save_upload(upload, label)
        name = Path(upload.filename or label).name or label
        dest = Path(workdir) / "in" / f"{len(list((Path(workdir) / 'in').glob('*')))}-{name}"
        shutil.move(tmp, dest)
        return str(dest)

    def _workdir() -> str:
        workdir = tempfile.mkdtemp(prefix="netcross-tools-")
        (Path(workdir) / "in").mkdir()
        return workdir

    @app.post("/tools/merge", tags=["tools"], responses=_RESPONSES, dependencies=deps)
    async def merge_captures_route(
        files: list[UploadFile] = _MERGE_FILES,
        dedup: bool = Form(False, description="Supprimer les paquets identiques (équivalent de --merge-dedup)"),
        format: str = Form("pcapng", description="Format de sortie : pcapng (défaut de mergecap) ou pcap"),  # noqa: A002
    ) -> FileResponse:
        """Fusion ordonnée par horodatage (équivalent de ``--merge``)."""
        fmt = _check_format(format, _CAPTURE_FORMATS)
        if len(files) > max_files():
            raise HTTPException(status_code=413, detail=f"Trop de fichiers (max {max_files()})")
        workdir = _workdir()
        try:
            paths = [await _saved(workdir, f, f"capture {i + 1}") for i, f in enumerate(files)]
            out = str(Path(workdir) / f"netcross-merge.{fmt}")
            message = await _run(lambda: capture_tools.merge(paths, out, dedup=dedup))
        except BaseException:
            logger.debug("outils de capture : echec, {} supprime", workdir)
            shutil.rmtree(workdir, True)
            raise
        return _file_response(workdir, out, f"netcross-merge.{fmt}", fmt, message)

    @app.post("/tools/split", tags=["tools"], responses=_RESPONSES, dependencies=deps)
    async def split_capture_route(
        file: UploadFile = _SPLIT_FILE,
        split: str = Form(..., description="MODE:VALEUR : time:60, count:10000 ou size:100M (équivalent de --split)"),
    ) -> FileResponse:
        """Découpage ; réponse = archive zip des morceaux, dans l'ordre
        (équivalent de ``--split`` / ``--split-output-dir``)."""
        try:
            capture_tools.parse_split_spec(split)
        except ValueError as exc:
            logger.info("split refuse : {}", exc)
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        workdir = _workdir()
        try:
            path = await _saved(workdir, file, "capture")
            segdir = str(Path(workdir) / "segments")
            segments = await _run(lambda: capture_tools.split(path, segdir, split))
            if not segments:
                raise HTTPException(status_code=422, detail="aucun paquet a decouper -- aucun segment cree")
            archive = str(Path(workdir) / "netcross-split.zip")
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
                for seg in segments:
                    zf.write(seg, Path(seg).name)
        except BaseException:
            logger.debug("outils de capture : echec, {} supprime", workdir)
            shutil.rmtree(workdir, True)
            raise
        return _file_response(workdir, archive, "netcross-split.zip", "zip", f"{len(segments)} segment(s)")

    @app.post("/tools/convert", tags=["tools"], responses=_RESPONSES, dependencies=deps)
    async def convert_capture_route(
        file: UploadFile = _CONVERT_FILE,
        format: str = Form("pcapng", description="pcap, pcapng, erf, csv ou json (équivalent de --convert-format)"),  # noqa: A002
    ) -> FileResponse:
        """Conversion de format ou export structuré (équivalent de ``--convert``)."""
        fmt = _check_format(format, capture_tools.CONVERT_FORMATS)
        workdir = _workdir()
        try:
            path = await _saved(workdir, file, "capture")
            out = str(Path(workdir) / f"netcross-convert.{capture_tools.CONVERT_EXTENSIONS[fmt]}")
            message = await _run(lambda: capture_tools.convert(path, out, fmt))
        except BaseException:
            logger.debug("outils de capture : echec, {} supprime", workdir)
            shutil.rmtree(workdir, True)
            raise
        return _file_response(workdir, out, Path(out).name, fmt, message)

    @app.post("/tools/export", tags=["tools"], responses=_RESPONSES, dependencies=deps)
    async def export_subset_route(
        file: UploadFile = _EXPORT_FILE,
        bpf: str | None = Form(None, description="Filtre d'affichage Wireshark (équivalent de --export-bpf)"),
        time_start: float | None = Form(None, description="Début, secondes après le 1er paquet (--export-time-start)"),
        time_end: float | None = Form(None, description="Fin, secondes après le 1er paquet (--export-time-end)"),
        endpoints: str | None = Form(None, description="IP1,IP2,... en source ou destination (--export-endpoints)"),
        format: str = Form("pcapng", description="Format de sortie : pcapng ou pcap"),  # noqa: A002
    ) -> FileResponse:
        """Sous-ensemble filtré (équivalent de ``--export-pcap``)."""
        fmt = _check_format(format, _CAPTURE_FORMATS)
        workdir = _workdir()
        try:
            path = await _saved(workdir, file, "capture")
            out = str(Path(workdir) / f"netcross-export.{fmt}")
            ips = capture_tools.parse_endpoints(endpoints)
            message = await _run(
                lambda: capture_tools.export_subset(
                    path, out, bpf_filter=bpf, time_start=time_start, time_end=time_end, endpoints=ips
                )
            )
        except BaseException:
            logger.debug("outils de capture : echec, {} supprime", workdir)
            shutil.rmtree(workdir, True)
            raise
        return _file_response(workdir, out, f"netcross-export.{fmt}", fmt, message)

    @app.post("/tools/adjust-time", tags=["tools"], responses=_RESPONSES, dependencies=deps)
    async def adjust_time_route(
        file: UploadFile = _ADJUST_FILE,
        time_offset: float | None = Form(None, description="Décalage en secondes (équivalent de --time-offset)"),
        normalize: bool = Form(False, description="Premier paquet à t=0 (équivalent de --normalize-time)"),
        align_to: UploadFile | None = _ALIGN_FILE,
        format: str = Form("pcapng", description="Format de sortie : pcapng ou pcap"),  # noqa: A002
    ) -> FileResponse:
        """Recalage des horodatages (équivalent de ``--adjust-time-output``) ;
        un seul mode parmi ``time_offset``, ``normalize``, ``align_to``."""
        fmt = _check_format(format, _CAPTURE_FORMATS)
        workdir = _workdir()
        try:
            path = await _saved(workdir, file, "capture")
            ref = await _saved(workdir, align_to, "reference") if align_to is not None else None
            out = str(Path(workdir) / f"netcross-adjust.{fmt}")
            message = await _run(
                lambda: capture_tools.adjust_time(path, out, offset=time_offset, normalize=normalize, align_to=ref)
            )
        except BaseException:
            logger.debug("outils de capture : echec, {} supprime", workdir)
            shutil.rmtree(workdir, True)
            raise
        return _file_response(workdir, out, f"netcross-adjust.{fmt}", fmt, message)

    @app.post("/tools/replay", tags=["tools"], responses=_REPLAY_RESPONSES, dependencies=deps)
    async def replay_capture_route(
        file: UploadFile = _REPLAY_FILE,
        interface: str = Form(..., description="Interface d'émission (équivalent de --replay)"),
        speed: str = Form("1.0", description="Multiplicateur ou topspeed (équivalent de --replay-speed)"),
        loop: int = Form(1, description="Nombre de passes, >= 1 (équivalent de --replay-loop)"),
    ) -> dict[str, str]:
        """Rejeu sur une interface réseau via tcpreplay (équivalent de
        ``--replay``) : ÉMET du trafic réel. Refusé (403) si ``interface``
        n'est pas autorisée par ``NETCROSS_REPLAY_INTERFACES`` côté serveur.
        Réponse à la fin du rejeu."""
        allowed = capture_tools.allowed_replay_interfaces()
        if interface not in allowed:
            logger.warning("rejeu refuse sur {} (autorisees : {})", interface, sorted(allowed))
            detail = (
                f"rejeu refuse sur {interface} : interface non autorisee par {capture_tools.REPLAY_INTERFACES_ENV}"
                if allowed
                else f"rejeu desactive sur ce serveur ({capture_tools.REPLAY_INTERFACES_ENV} vide)"
            )
            raise HTTPException(status_code=403, detail=detail)
        workdir = _workdir()
        try:
            path = await _saved(workdir, file, "capture")
            name = Path(file.filename or "capture").name
            await _run(lambda: capture_tools.replay(path, interface, speed=speed, loop=loop))
        finally:
            shutil.rmtree(workdir, True)
        logger.info("rejeu de {} sur {} (speed={}, loop={})", name, interface, speed, loop)
        return {"message": capture_tools.replay_message(name, interface, speed, loop)}

    logger.debug("tools_routes.register: 6 routes")
