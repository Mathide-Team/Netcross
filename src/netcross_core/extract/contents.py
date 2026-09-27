"""
netcross_core.extract.contents -- issue #278 : extraction des contenus
(audio, video, documents) a titre d'analyse qualitative, avec rappel de
l'usage raisonne.

Les documents sont extraits par ``tshark --export-objects`` (HTTP, SMB,
IMF/courriel, TFTP, FTP-DATA) : c'est le reassemblage de Wireshark, pas
un decodage maison. L'audio et la video passent par
:mod:`netcross_core.extract.media`.

Tout est ecrit sous un repertoire dedie, cree en 0700 (fichiers 0600),
accompagne d'un ``manifest.json`` (empreintes SHA-256, flux d'origine,
note de degradation) et d'un ``LISEZ-MOI.txt`` portant le rappel d'usage.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from netcross_core.extract.carver import detect_file_type
from netcross_core.extract.media import KINDS, RtpStream, StreamQuality, analyse_stream, collect_streams, export_stream
from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

DOCUMENT_PROTOCOLS = ("http", "smb", "imf", "tftp", "ftp-data")

USAGE_REMINDER = (
    "Rappel d'usage raisonne : les contenus extraits (voix, video, documents, courriels) sont des "
    "correspondances et des donnees personnelles. Leur extraction ne se justifie que sur un reseau "
    "dont vous avez la charge, pour un diagnostic ou une investigation de securite, les personnes "
    "concernees ayant ete informees (RGPD art. 5 et 6 ; secret des correspondances, art. 226-15 du "
    "Code penal ; information prealable des salaries, art. L1222-4 du Code du travail). Limitez-vous "
    "au strict necessaire (--extract-kinds, --media-quality suffit souvent), ne diffusez pas les "
    "fichiers et supprimez-les une fois l'analyse terminee."
)


@dataclass
class ExtractedDocument:
    point: str
    protocol: str
    path: str
    size: int
    sha256: str
    detected_type: str | None

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class ContentExtraction:
    """Resultat d'une extraction (ou d'une simple analyse qualitative)."""

    out_dir: str | None
    kinds: tuple[str, ...]
    media: list[StreamQuality] = field(default_factory=list)
    documents: list[ExtractedDocument] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "usage_reminder": USAGE_REMINDER,
            "out_dir": self.out_dir,
            "kinds": list(self.kinds),
            "media": [m.to_dict() for m in self.media],
            "documents": [d.to_dict() for d in self.documents],
            "errors": list(self.errors),
        }


def parse_kinds(spec: str | None) -> tuple[str, ...]:
    """``audio,video`` -> ('audio', 'video') ; ValueError sur un type inconnu."""
    logger.debug("parse_kinds: spec={}", summarize(spec, "spec"))
    if not spec:
        return KINDS
    kinds = tuple(dict.fromkeys(k.strip() for k in spec.split(",") if k.strip()))
    unknown = [k for k in kinds if k not in KINDS]
    if unknown or not kinds:
        logger.debug("parse_kinds: refus, ValueError")
        raise ValueError(f"type(s) inconnu(s) : {', '.join(unknown) or spec!r} (attendu : {', '.join(KINDS)})")
    return kinds


def prepare_out_dir(path: str) -> Path:
    """Cree le repertoire de sortie (0700). Refuse un repertoire non vide :
    melanger deux extractions rendrait le manifeste trompeur."""
    logger.debug("prepare_out_dir: path={}", summarize(path, "path"))
    out = Path(path)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        logger.debug("prepare_out_dir: refus, ValueError")
        raise ValueError(f"{path} existe deja et n'est pas un repertoire vide")
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    out.chmod(0o700)
    return out


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def inventory_documents(point: str, protocol: str, directory: Path) -> list[ExtractedDocument]:
    logger.debug(
        "inventory_documents: point={} protocol={} directory={}",
        summarize(point, "point"),
        summarize(protocol, "protocol"),
        summarize(directory, "directory"),
    )
    docs = []
    for p in sorted(directory.iterdir()) if directory.is_dir() else []:
        if not p.is_file():
            continue
        p.chmod(0o600)
        with p.open("rb") as f:
            head = f.read(16)
        docs.append(ExtractedDocument(point, protocol, str(p), p.stat().st_size, _sha256(p), detect_file_type(head)))
    return docs


def export_documents(
    captures: Sequence[tuple[str, str]],
    out_dir: Path,
    *,
    protocols: Sequence[str] = DOCUMENT_PROTOCOLS,
    tshark_bin: str = "tshark",
    timeout: float = 600.0,
) -> tuple[list[ExtractedDocument], list[str]]:
    """``tshark --export-objects`` pour chaque capture et protocole."""
    docs: list[ExtractedDocument] = []
    errors: list[str] = []
    for label, path in captures:
        for proto in protocols:
            target = out_dir / "documents" / _safe(label) / proto
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            cmd = [tshark_bin, "-Q", "-n", "-r", path, "--export-objects", f"{proto},{target}"]
            try:
                done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            except FileNotFoundError:
                logger.exception("échec dans export_documents")
                errors.append("documents : tshark introuvable, aucun document extrait")
                return docs, errors
            except subprocess.TimeoutExpired:
                logger.exception("échec dans export_documents")
                errors.append(f"documents [{label}] {proto} : delai depasse ({timeout:.0f} s)")
                continue
            if done.returncode != 0:
                reason = (done.stderr.strip().splitlines() or ["code " + str(done.returncode)])[-1]
                errors.append(f"documents [{label}] {proto} : {reason}")
            found = inventory_documents(label, proto, target)
            docs.extend(found)
            if not found:
                target.rmdir()
        with_docs = out_dir / "documents" / _safe(label)
        if with_docs.is_dir() and not any(with_docs.iterdir()):
            with_docs.rmdir()
    return docs, errors


def _safe(label: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "-" for c in label) or "point"


def datagrams_from_raw(label: str, raw_packets: Iterable) -> Iterable[tuple]:
    """Adapte des ``pcap_parser.RawPacket`` au format de collect_streams."""
    logger.debug(
        "datagrams_from_raw: label={} raw_packets={}",
        summarize(label, "label"),
        summarize(raw_packets, "raw_packets"),
    )
    for raw in raw_packets:
        # TCP : seulement pour le SDP d'un SIP sur TCP (le RTP, lui, est sur UDP)
        if raw.payload and (raw.proto == "UDP" or (raw.proto == "TCP" and b"a=rtpmap:" in raw.payload)):
            yield (label, raw.ts, raw.src, raw.sport, raw.dst, raw.dport, raw.payload)


def analyse_media(datagrams: Iterable[tuple]) -> tuple[list[RtpStream], list[StreamQuality]]:
    streams = collect_streams(datagrams)
    return streams, [analyse_stream(s) for s in streams]


def run_extraction(
    captures: Sequence[tuple[str, str]],
    *,
    out_dir: str | None,
    kinds: Sequence[str] = KINDS,
    read_capture=None,
    tshark_bin: str = "tshark",
) -> ContentExtraction:
    """Analyse qualitative des flux RTP de ``captures`` et, si ``out_dir``
    est donne, extraction des contenus des types ``kinds``.

    ``read_capture(path) -> list[RawPacket]`` : injectable pour les tests
    (par defaut ``pcap_parser.parse_capture``)."""
    if read_capture is None:
        import pcap_parser

        def read_capture(path: str):
            return pcap_parser.parse_capture(path, raise_on_error=False)

    out = prepare_out_dir(out_dir) if out_dir else None
    result = ContentExtraction(str(out) if out else None, tuple(kinds))
    media_kinds = {k for k in kinds if k in ("audio", "video")}
    if media_kinds or out is None:
        datagrams = (d for label, path in captures for d in datagrams_from_raw(label, read_capture(path)))
        streams, qualities = analyse_media(datagrams)
        for st, q in zip(streams, qualities):
            if out is not None and st.kind in media_kinds:
                try:
                    q.exported = str(export_stream(st, out))
                except ValueError as exc:
                    logger.exception(f"échec dans read_capture: {exc}")
                    q.note = f"{q.note} ; {exc}" if q.note else str(exc)
            result.media.append(q)
    if out is not None and "documents" in kinds:
        result.documents, result.errors = export_documents(captures, out, tshark_bin=tshark_bin)
    if out is not None:
        write_manifest(result, out)
    return result


def write_manifest(result: ContentExtraction, out: Path) -> None:
    logger.debug("write_manifest: result={} out={}", summarize(result, "result"), summarize(out, "out"))
    manifest = out / "manifest.json"
    manifest.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    readme = out / "LISEZ-MOI.txt"
    readme.write_text(
        "Contenus extraits par Netcross (issue #278).\n\n" + USAGE_REMINDER + "\n\n"
        "manifest.json : origine de chaque fichier, empreinte SHA-256, note de degradation du transport.\n",
        encoding="utf-8",
    )
    for p in (manifest, readme):
        os.chmod(p, 0o600)


def format_extraction(result: ContentExtraction) -> list[str]:
    """Lignes de sortie texte (CLI)."""
    logger.debug("format_extraction: result={}", summarize(result, "result"))
    lines = []
    if not result.media:
        lines.append("Aucun flux RTP audio/video identifie.")
    for q in result.media:
        head = f"{q.label} -- {q.kind} {q.codec or '?'} : degradation "
        head += f"{q.degradation}/100 ({q.verdict})" if q.degradation is not None else q.verdict
        lines.append(head)
        detail = (
            f"    {q.received} paquet(s) recu(s) / {q.expected} attendu(s), pertes {q.loss_pct:.1f} % "
            f"(rafale max {q.max_burst}), doublons {q.duplicates}, desordre {q.reordered}"
        )
        if q.jitter_ms is not None:
            detail += f", gigue {q.jitter_ms:.1f} ms"
        lines.append(detail)
        if q.mos is not None:
            lines.append(f"    MOS estime {q.mos:.2f} (R-factor {q.r_factor:.0f})")
        if q.frames is not None:
            lines.append(f"    images : {q.frames}, dont {q.damaged_frames} endommagee(s)")
        if q.note:
            lines.append(f"    ({q.note})")
        if q.exported:
            lines.append(f"    -> {q.exported}")
    if result.out_dir is not None and "documents" in result.kinds:
        lines.append(f"Documents extraits : {len(result.documents)}")
        lines.extend(
            f"    [{d.point}] {d.protocol} {Path(d.path).name} ({d.size} o, {d.detected_type or 'type inconnu'}) "
            f"sha256={d.sha256[:16]}..."
            for d in result.documents
        )
    lines.extend(f"  ! {e}" for e in result.errors)
    if result.out_dir is not None:
        lines.append(f"Manifeste : {Path(result.out_dir) / 'manifest.json'}")
    return lines
