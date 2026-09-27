"""
netcross_core.extract.carver -- issue #150 (SCENARIO-4, parent #141) :
extraction et reconstruction de fichiers depuis les traces réseau.

Le module travaille sur les métadonnées déjà décodées par tshark dans
``Pkt`` (``http_content_type``, ``http_content_length``, ``http_uri``,
``payload_hash``, ``service_banners``, ports/protocoles). Pkt ne
retient pas le payload brut (par design -- voir ``content.py``) :
l'extraction est donc au niveau métadonnées (type, taille, hash,
horodatage, protocole source), pas au niveau contenu binaire.

Le carving générique par magic bytes est implémenté comme un utilitaire
réutilisable : ``detect_file_type(data: bytes) -> str | None``. Il sera
utilisable quand le payload brut sera disponible (relecture pcap).

Quatre sources d'extraction :

- **HTTP** : réponses HTTP avec Content-Type/Content-Length → fichiers
  téléchargés (PDF, images, archives, exécutables...).
- **Email** : SMTP (port 25), IMAP (143/993), POP3 (110/995) avec
  pièces jointes détectées via Content-Type multipart ou bannière MIME.
- **SMB** : transferts SMB2/3 (port 445) -- détection par port.
- **FTP** : transferts FTP (ports 20/21) -- détection par port.

Anti faux positifs :
- seules les réponses HTTP avec Content-Length > 0 sont extraites ;
- les réponses 3xx/4xx/5xx sans corps sont ignorées ;
- les requêtes DNS, NTP, etc. ne produisent jamais d'extraction.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Pkt

logger = get_logger(__name__)

# Magic bytes pour la détection de type de fichier.
_MAGIC_BYTES: list[tuple[bytes, str]] = [
    (b"\x50\x4b\x03\x04", "zip"),  # PK\x03\x04 (ZIP)
    (b"\x1f\x8b", "gzip"),  # GZIP
    (b"\x25\x50\x44\x46", "pdf"),  # %PDF
    (b"\x89\x50\x4e\x47", "png"),  # PNG
    (b"\xff\xd8\xff", "jpeg"),  # JPEG
    (b"\x47\x49\x46\x38", "gif"),  # GIF8
    (b"\x4d\x5a", "exe"),  # MZ (PE/EXE)
    (b"\x7f\x45\x4c\x46", "elf"),  # ELF
    (b"\x42\x5a\x68", "bzip2"),  # BZh (BZIP2)
    (b"\x52\x61\x72\x21", "rar"),  # Rar!
    (b"\x37\x7a\xbc\xaf", "7z"),  # 7z
    (b"\x00\x00\x01\x00", "ico"),  # ICO
    (b"\x49\x49\x2a\x00", "tiff"),  # TIFF (LE)
    (b"\x4d\x4d\x00\x2a", "tiff"),  # TIFF (BE)
    (b"\x00\x00\x01\xba", "mpeg"),  # MPEG PS
    (b"\x1a\x45\xdf\xa3", "mkv"),  # Matroska/WebM
]

# Ports d'email (SMTP, IMAP, POP3 et leurs variantes TLS).
_EMAIL_PORTS: frozenset[int] = frozenset({25, 587, 465, 143, 993, 110, 995})

# Ports de transfert de fichiers.
_SMB_PORTS: frozenset[int] = frozenset({445})
_FTP_PORTS: frozenset[int] = frozenset({20, 21})

# Types MIME courants -> type détecté simplifié.
_MIME_TO_TYPE: dict[str, str] = {
    "application/pdf": "pdf",
    "application/zip": "zip",
    "application/x-gzip": "gzip",
    "application/x-tar": "tar",
    "application/x-bzip2": "bzip2",
    "application/x-rar-compressed": "rar",
    "application/x-7z-compressed": "7z",
    "application/octet-stream": "binary",
    "application/x-msdownload": "exe",
    "application/x-executable": "elf",
    "application/json": "json",
    "application/xml": "xml",
    "text/html": "html",
    "text/plain": "text",
    "text/css": "css",
    "text/javascript": "javascript",
    "image/png": "png",
    "image/jpeg": "jpeg",
    "image/gif": "gif",
    "image/svg+xml": "svg",
    "image/x-icon": "ico",
    "image/tiff": "tiff",
    "video/mp4": "mp4",
    "video/x-msvideo": "avi",
    "audio/mpeg": "mp3",
    "font/woff": "woff",
    "font/woff2": "woff2",
}


def detect_file_type(data: bytes) -> str | None:
    """Détecte le type d'un fichier à partir de ses magic bytes.

    Retourne le type simplifié (``zip``, ``pdf``, ``png``...) ou ``None``
    si aucun magic byte connu n'est reconnu.
    """
    for magic, ftype in _MAGIC_BYTES:
        if data[: len(magic)] == magic:
            logger.debug("detect_file_type: retour ftype")
            return ftype
    logger.debug("detect_file_type: retour None")
    return None


def _mime_to_type(content_type: str | None) -> str | None:
    """Convertit un Content-Type MIME en type simplifié."""
    if not content_type:
        logger.debug("_mime_to_type: retour None")
        return None
    # Enlever les paramètres (charset, boundary...)
    mime = content_type.split(";")[0].strip().lower()
    logger.debug("_mime_to_type: retour get(...)")
    return _MIME_TO_TYPE.get(mime, mime.split("/")[-1] if "/" in mime else mime)


def _hash_payload(payload_hash: str | None) -> tuple[str | None, str | None]:
    """Retourne (hash_md5, hash_sha256) depuis le payload_hash de Pkt.

    Pkt.payload_hash est un hash SHA256 calculé par le parseur. Si le
    payload_hash est un hex SHA256, on l'utilise directement et on
    calcule le MD5 depuis les données brutes si disponibles. Sinon, on
    utilise le hash tel quel pour les deux champs.
    """
    if not payload_hash:
        logger.debug("_hash_payload: retour tuple")
        return None, None
    # payload_hash est un SHA256 hex (64 chars) -- on le reporte tel quel.
    if len(payload_hash) == 64:
        logger.debug("_hash_payload: retour tuple")
        return None, payload_hash
    # Sinon, on ne sait pas quel algo c'est -- on le met dans md5.
    logger.debug("_hash_payload: retour tuple")
    return payload_hash, None


@dataclass
class ExtractedFile:
    """Un fichier extrait d'un flux réseau, avec métadonnées."""

    point: str
    proto_source: str  # http | email | smb | ftp | carve
    src: str
    dst: str
    ts: float
    uri: str | None = None
    content_type: str | None = None
    size: int | None = None
    hash_md5: str | None = None
    hash_sha256: str | None = None
    type_detected: str = "unknown"
    frame_number: int | None = None


@dataclass
class ExtractionResult:
    """Résultat de l'extraction de fichiers."""

    files: list[ExtractedFile] = field(default_factory=list)

    @property
    def has_files(self) -> bool:
        logger.debug("has_files: retour bool(...)")
        return bool(self.files)

    @property
    def files_by_type(self) -> dict[str, list[ExtractedFile]]:
        grouped: dict[str, list[ExtractedFile]] = {}
        for f in self.files:
            grouped.setdefault(f.type_detected, []).append(f)
        logger.debug("files_by_type: retour grouped")
        return grouped


def _extract_http(packets: list[Pkt]) -> list[ExtractedFile]:
    """Extrait les fichiers des réponses HTTP (Content-Type, Content-Length)."""
    logger.debug("_extract_http: packets={}", summarize(packets, "packets"))
    files: list[ExtractedFile] = []
    for pkt in packets:
        if not pkt.http_is_response:
            continue
        # Ignorer les réponses sans corps (3xx redirect, 4xx/5xx sans Content-Length)
        if pkt.http_content_length is None or pkt.http_content_length <= 0:
            continue
        # Ignorer les réponses d'erreur sans contenu
        if pkt.http_status_code is not None and pkt.http_status_code >= 400:
            continue

        type_detected = _mime_to_type(pkt.http_content_type) or "unknown"
        hash_md5, hash_sha256 = _hash_payload(pkt.payload_hash)

        files.append(
            ExtractedFile(
                point=pkt.point,
                proto_source="http",
                src=pkt.dst,  # serveur -> client : src du fichier = dst du paquet
                dst=pkt.src,  # client qui reçoit
                ts=pkt.ts,
                uri=pkt.http_uri,
                content_type=pkt.http_content_type,
                size=pkt.http_content_length,
                hash_md5=hash_md5,
                hash_sha256=hash_sha256,
                type_detected=type_detected,
                frame_number=pkt.frame_number,
            )
        )
    logger.debug("_extract_http: retour files")
    return files


def _extract_email(packets: list[Pkt]) -> list[ExtractedFile]:
    """Extrait les pièces jointes email (SMTP/IMAP/POP3).

    Détection par port + bannières MIME dans service_banners. Les emails
    avec Content-Type multipart ou application/* sont considérés comme
    contenant des pièces jointes.
    """
    logger.debug("_extract_email: packets={}", summarize(packets, "packets"))
    files: list[ExtractedFile] = []
    for pkt in packets:
        if pkt.dport not in _EMAIL_PORTS and pkt.sport not in _EMAIL_PORTS:
            continue
        if pkt.proto != "TCP":
            continue

        # Détecter les pièces jointes via les bannières de service
        # (MIME Content-Type dans le payload identifié par tshark).
        has_attachment = False
        for banner in pkt.service_banners:
            if banner.protocol not in ("smtp", "imap", "pop3"):
                continue
            raw = banner.raw or ""
            if "multipart/" in raw or "application/" in raw:
                has_attachment = True
                break

        if not has_attachment:
            continue

        hash_md5, hash_sha256 = _hash_payload(pkt.payload_hash)
        files.append(
            ExtractedFile(
                point=pkt.point,
                proto_source="email",
                src=pkt.src,
                dst=pkt.dst,
                ts=pkt.ts,
                content_type="message/rfc822",
                size=pkt.length,
                hash_md5=hash_md5,
                hash_sha256=hash_sha256,
                type_detected="email-attachment",
                frame_number=pkt.frame_number,
            )
        )
    logger.debug("_extract_email: retour files")
    return files


def _extract_smb(packets: list[Pkt]) -> list[ExtractedFile]:
    """Extrait les transferts de fichiers SMB2/3 (port 445)."""
    logger.debug("_extract_smb: packets={}", summarize(packets, "packets"))
    files: list[ExtractedFile] = []
    for pkt in packets:
        if pkt.dport not in _SMB_PORTS and pkt.sport not in _SMB_PORTS:
            continue
        if pkt.proto != "TCP":
            continue
        # SMB a un protocole spécifique dans les bannières
        is_smb = False
        for banner in pkt.service_banners:
            if banner.protocol == "smb":
                is_smb = True
                break
        if not is_smb:
            continue

        hash_md5, hash_sha256 = _hash_payload(pkt.payload_hash)
        files.append(
            ExtractedFile(
                point=pkt.point,
                proto_source="smb",
                src=pkt.src,
                dst=pkt.dst,
                ts=pkt.ts,
                size=pkt.length,
                hash_md5=hash_md5,
                hash_sha256=hash_sha256,
                type_detected="smb-transfer",
                frame_number=pkt.frame_number,
            )
        )
    logger.debug("_extract_smb: retour files")
    return files


def _extract_ftp(packets: list[Pkt]) -> list[ExtractedFile]:
    """Extrait les transferts de fichiers FTP (ports 20/21)."""
    logger.debug("_extract_ftp: packets={}", summarize(packets, "packets"))
    files: list[ExtractedFile] = []
    for pkt in packets:
        if pkt.dport not in _FTP_PORTS and pkt.sport not in _FTP_PORTS:
            continue
        if pkt.proto != "TCP":
            continue
        # FTP est identifié par bannière ou par port
        is_ftp = bool(pkt.service_banners) and any(b.protocol == "ftp" for b in pkt.service_banners)
        if not is_ftp and pkt.dport not in (20, 21) and pkt.sport not in (20, 21):
            continue

        hash_md5, hash_sha256 = _hash_payload(pkt.payload_hash)
        files.append(
            ExtractedFile(
                point=pkt.point,
                proto_source="ftp",
                src=pkt.src,
                dst=pkt.dst,
                ts=pkt.ts,
                size=pkt.length,
                hash_md5=hash_md5,
                hash_sha256=hash_sha256,
                type_detected="ftp-transfer",
                frame_number=pkt.frame_number,
            )
        )
    logger.debug("_extract_ftp: retour files")
    return files


def detect_extracted_files(
    packets: Iterable[Pkt],
    *,
    extract_dir: str | None = None,
) -> ExtractionResult:
    """Extrait les fichiers transmis dans les flux réseau.

    Parcourt les paquets et identifie les transferts de fichiers par
    protocole (HTTP, email, SMB, FTP). Retourne un :class:`ExtractionResult`
    avec les métadonnées de chaque fichier extrait.

    ``extract_dir`` : répertoire de sortie (non utilisé pour l'instant,
    réservé pour une future écriture sur disque des payloads extraits).
    """
    logger.debug(
        "detect_extracted_files: packets={} extract_dir={}",
        summarize(packets, "packets"),
        summarize(extract_dir, "extract_dir"),
    )
    packets = list(packets)
    files: list[ExtractedFile] = []
    files.extend(_extract_http(packets))
    files.extend(_extract_email(packets))
    files.extend(_extract_smb(packets))
    files.extend(_extract_ftp(packets))

    # Si extract_dir est fourni, on pourrait écrire les payloads sur disque.
    # Pkt ne retient pas le payload brut, donc on ne fait que les métadonnées.
    # L'écriture sur disque nécessiterait de relire le pcap avec tshark.

    logger.debug("detect_extracted_files: retour ExtractionResult(...)")
    return ExtractionResult(files=files)
