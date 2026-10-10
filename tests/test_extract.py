"""
netcross_core.extract.carver -- tests (issue #150, SCENARIO-4).

Couvre :
- Extraction HTTP (Content-Type, Content-Length, hash)
- Extraction email (SMTP/IMAP/POP3)
- Extraction SMB (port 445)
- Extraction FTP (ports 20/21)
- Carving générique : magic bytes (ZIP, PDF, PNG, JPEG, EXE, ELF, GZIP)
- Anti faux positifs : trafic sans fichier, erreurs HTTP ignorées
- Hash MD5/SHA256 depuis payload_hash
"""

from __future__ import annotations

from netcross_core.extract.carver import (
    ExtractedFile,
    detect_extracted_files,
    detect_file_type,
)
from netcross_core.models import Banner
from tests.conftest import make_pkt

# --- Helpers ---------------------------------------------------------------


def _http_response(
    *,
    content_type: str | None = "application/pdf",
    content_length: int = 1024,
    status_code: int = 200,
    uri: str = "/download/doc.pdf",
    src: str = "93.184.216.34",
    dst: str = "192.168.1.50",
    ts: float = 1000.0,
    payload_hash: str | None = None,
    frame: int | None = 42,
) -> object:
    return make_pkt(
        proto="TCP",
        src=src,
        dst=dst,
        sport=80,
        dport=50000,
        ts=ts,
        http_is_response=True,
        http_content_type=content_type,
        http_content_length=content_length,
        http_status_code=status_code,
        http_uri=uri,
        payload_hash=payload_hash,
        frame_number=frame,
    )


def _smtp_packet(
    *,
    src: str = "192.168.1.50",
    dst: str = "10.0.0.1",
    ts: float = 1000.0,
    payload_hash: str | None = None,
    raw: str = "Content-Type: multipart/mixed; boundary=boundary123",
    frame: int | None = 10,
) -> object:
    banner = Banner(protocol="smtp", service="Postfix", version="3.5", raw=raw, role="server")
    return make_pkt(
        proto="TCP",
        src=src,
        dst=dst,
        sport=50000,
        dport=25,
        ts=ts,
        service_banners=(banner,),
        payload_hash=payload_hash,
        frame_number=frame,
    )


def _smb_packet(
    *,
    src: str = "192.168.1.50",
    dst: str = "10.0.0.2",
    ts: float = 1000.0,
    payload_hash: str | None = None,
    frame: int | None = 20,
) -> object:
    banner = Banner(protocol="smb", service="Samba", version="4.13", raw="", role="server")
    return make_pkt(
        proto="TCP",
        src=src,
        dst=dst,
        sport=50000,
        dport=445,
        ts=ts,
        service_banners=(banner,),
        payload_hash=payload_hash,
        frame_number=frame,
    )


def _ftp_packet(
    *,
    src: str = "192.168.1.50",
    dst: str = "10.0.0.3",
    ts: float = 1000.0,
    payload_hash: str | None = None,
    frame: int | None = 30,
) -> object:
    banner = Banner(protocol="ftp", service="vsftpd", version="3.0", raw="", role="server")
    return make_pkt(
        proto="TCP",
        src=src,
        dst=dst,
        sport=50000,
        dport=21,
        ts=ts,
        service_banners=(banner,),
        payload_hash=payload_hash,
        frame_number=frame,
    )


# --- Magic bytes / detect_file_type ----------------------------------------


def test_detect_file_type_zip():
    assert detect_file_type(b"\x50\x4b\x03\x04" + b"\x00" * 100) == "zip"


def test_detect_file_type_pdf():
    assert detect_file_type(b"\x25\x50\x44\x46\x2d" + b"\x00" * 100) == "pdf"


def test_detect_file_type_png():
    assert detect_file_type(b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a" + b"\x00" * 100) == "png"


def test_detect_file_type_jpeg():
    assert detect_file_type(b"\xff\xd8\xff\xe0" + b"\x00" * 100) == "jpeg"


def test_detect_file_type_exe():
    assert detect_file_type(b"\x4d\x5a\x90\x00" + b"\x00" * 100) == "exe"


def test_detect_file_type_elf():
    assert detect_file_type(b"\x7f\x45\x4c\x46\x01\x01\x01" + b"\x00" * 100) == "elf"


def test_detect_file_type_gzip():
    assert detect_file_type(b"\x1f\x8b\x08\x00" + b"\x00" * 100) == "gzip"


def test_detect_file_type_unknown():
    assert detect_file_type(b"\x00\x00\x00\x00") is None
    assert detect_file_type(b"") is None
    assert detect_file_type(b"Hello World") is None


# --- HTTP extraction -------------------------------------------------------


def test_http_extraction_pdf():
    """Extraction d'un fichier PDF depuis une réponse HTTP."""
    pkts = [_http_response(content_type="application/pdf", content_length=2048)]
    result = detect_extracted_files(pkts)
    assert len(result.files) == 1
    f = result.files[0]
    assert f.proto_source == "http"
    assert f.type_detected == "pdf"
    assert f.size == 2048
    assert f.uri == "/download/doc.pdf"
    assert f.content_type == "application/pdf"


def test_http_extraction_png():
    """Extraction d'une image PNG."""
    pkts = [_http_response(content_type="image/png", content_length=512)]
    result = detect_extracted_files(pkts)
    assert len(result.files) == 1
    assert result.files[0].type_detected == "png"


def test_http_extraction_json():
    """Extraction d'un fichier JSON."""
    pkts = [_http_response(content_type="application/json", content_length=256)]
    result = detect_extracted_files(pkts)
    assert len(result.files) == 1
    assert result.files[0].type_detected == "json"


def test_http_extraction_ignore_erreur_404():
    """Les réponses 404 sans Content-Length ne doivent pas être extraites."""
    pkts = [_http_response(status_code=404, content_length=None)]
    result = detect_extracted_files(pkts)
    assert len(result.files) == 0


def test_http_extraction_ignore_redirection_302():
    """Les redirections 302 sans Content-Length ne doivent pas être extraites."""
    pkts = [_http_response(status_code=302, content_length=None)]
    result = detect_extracted_files(pkts)
    assert len(result.files) == 0


def test_http_extraction_ignore_content_length_zero():
    """Les réponses avec Content-Length=0 ne doivent pas être extraites."""
    pkts = [_http_response(content_length=0)]
    result = detect_extracted_files(pkts)
    assert len(result.files) == 0


def test_http_extraction_hash_payload():
    """Le hash SHA256 du payload doit être reporté."""
    sha256 = "a" * 64  # SHA256 hex (64 chars)
    pkts = [_http_response(payload_hash=sha256)]
    result = detect_extracted_files(pkts)
    assert len(result.files) == 1
    assert result.files[0].hash_sha256 == sha256


# --- Email extraction ------------------------------------------------------


def test_email_extraction_smtp_attachment():
    """Extraction d'une pièce jointe email SMTP."""
    pkts = [_smtp_packet(raw="Content-Type: multipart/mixed; boundary=boundary123")]
    result = detect_extracted_files(pkts)
    assert len(result.files) >= 1
    f = result.files[0]
    assert f.proto_source == "email"
    assert f.type_detected == "email-attachment"


def test_email_extraction_imap():
    """Extraction d'un email IMAP (port 143)."""
    banner = Banner(protocol="imap", service="Dovecot", version="2.3", raw="multipart/mixed", role="server")
    pkts = [
        make_pkt(
            proto="TCP",
            src="192.168.1.50",
            dst="10.0.0.1",
            sport=50000,
            dport=143,
            ts=1000.0,
            service_banners=(banner,),
        )
    ]
    result = detect_extracted_files(pkts)
    assert len(result.files) >= 1
    assert result.files[0].proto_source == "email"


def test_email_extraction_ignore_smtp_sans_piece_jointe():
    """SMTP sans multipart ne doit pas être extrait."""
    banner = Banner(protocol="smtp", service="Postfix", version="3.5", raw="220 OK", role="server")
    pkts = [
        make_pkt(
            proto="TCP", src="192.168.1.50", dst="10.0.0.1", sport=50000, dport=25, ts=1000.0, service_banners=(banner,)
        )
    ]
    result = detect_extracted_files(pkts)
    assert len(result.files) == 0


# --- SMB extraction --------------------------------------------------------


def test_smb_extraction():
    """Extraction d'un transfert SMB2/3 (port 445)."""
    pkts = [_smb_packet()]
    result = detect_extracted_files(pkts)
    assert len(result.files) == 1
    assert result.files[0].proto_source == "smb"
    assert result.files[0].type_detected == "smb-transfer"


def test_smb_extraction_hash():
    """Le hash du payload doit être reporté pour SMB."""
    sha256 = "b" * 64
    pkts = [_smb_packet(payload_hash=sha256)]
    result = detect_extracted_files(pkts)
    assert result.files[0].hash_sha256 == sha256


# --- FTP extraction --------------------------------------------------------


def test_ftp_extraction():
    """Extraction d'un transfert FTP (port 21)."""
    pkts = [_ftp_packet()]
    result = detect_extracted_files(pkts)
    assert len(result.files) == 1
    assert result.files[0].proto_source == "ftp"
    assert result.files[0].type_detected == "ftp-transfer"


# --- Anti faux positifs ----------------------------------------------------


def test_aucun_fichier_sur_trafic_dns():
    """Le trafic DNS ne doit pas produire d'extraction."""
    pkts = [make_pkt(proto="UDP", dns_qry_name="example.com", dport=53, ts=1000.0)]
    result = detect_extracted_files(pkts)
    assert len(result.files) == 0


def test_aucun_fichier_sur_trafic_tcp_normal():
    """Le trafic TCP sans protocole applicatif ne doit pas produire d'extraction."""
    pkts = [make_pkt(proto="TCP", src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=8080, ts=1000.0)]
    result = detect_extracted_files(pkts)
    assert len(result.files) == 0


def test_aucun_fichier_sur_requete_http():
    """Les requêtes HTTP (pas les réponses) ne doivent pas être extraites."""
    pkts = [make_pkt(proto="TCP", http_is_request=True, http_method="GET", http_uri="/index.html", dport=80, ts=1000.0)]
    result = detect_extracted_files(pkts)
    assert len(result.files) == 0


def test_aucun_fichier_sur_liste_vide():
    """Une liste vide de paquets ne doit pas produire d'extraction."""
    result = detect_extracted_files([])
    assert len(result.files) == 0
    assert result.has_files is False


# --- ExtractionResult ------------------------------------------------------


def test_extraction_result_files_by_type():
    """files_by_type groupe correctement les fichiers par type."""
    pkts = [
        _http_response(content_type="application/pdf", content_length=100),
        _http_response(content_type="image/png", content_length=200),
        _smb_packet(),
    ]
    result = detect_extracted_files(pkts)
    by_type = result.files_by_type
    assert "pdf" in by_type
    assert "png" in by_type
    assert "smb-transfer" in by_type
    assert len(by_type["pdf"]) == 1


def test_extraction_result_has_files():
    """has_files est True quand il y a des fichiers, False sinon."""
    assert detect_extracted_files([]).has_files is False
    assert detect_extracted_files([_http_response()]).has_files is True


def test_extracted_file_dataclass():
    """La dataclass ExtractedFile sérialise correctement."""
    f = ExtractedFile(
        point="A",
        proto_source="http",
        src="93.184.216.34",
        dst="192.168.1.50",
        ts=1000.0,
        uri="/doc.pdf",
        content_type="application/pdf",
        size=1024,
        hash_md5=None,
        hash_sha256="a" * 64,
        type_detected="pdf",
        frame_number=42,
    )
    assert f.proto_source == "http"
    assert f.size == 1024
    assert f.type_detected == "pdf"


# --- Issue #708 : branches restantes du carver ---------------------------------


def test_mime_absent_et_hash_non_sha256():
    """Lignes 119-120 : Content-Type absent ; lignes 143-144 : empreinte de
    longueur inconnue rangee en MD5."""
    from netcross_core.extract.carver import _hash_payload, _mime_to_type

    assert _mime_to_type(None) is None
    assert _mime_to_type("") is None
    assert _hash_payload("abc123") == ("abc123", None)


def test_http_reponse_d_erreur_ignoree():
    """Ligne 197 : une reponse >= 400 n'est pas un fichier extrait."""
    from netcross_core.extract.carver import _extract_http

    assert _extract_http([_http_response(status_code=404)]) == []


def test_email_smb_ftp_hors_tcp_ignores_et_banniere_non_mail_sautee():
    """Lignes 235, 279, 316 : ports connus mais UDP -> ignores ; ligne 242 :
    une banniere d'un autre protocole est sautee avant la banniere SMTP."""
    from netcross_core.extract.carver import _extract_email, _extract_ftp, _extract_smb

    udp = {"proto": "UDP", "src": "192.168.1.50", "dst": "10.0.0.9", "sport": 50000}
    assert _extract_email([make_pkt(dport=25, **udp)]) == []
    assert _extract_smb([make_pkt(dport=445, **udp)]) == []
    assert _extract_ftp([make_pkt(dport=21, **udp)]) == []

    http = Banner(protocol="http", service="nginx", version="1.25", raw="application/json", role="server")
    smtp = Banner(protocol="smtp", service="Postfix", version="3.5", raw="multipart/mixed", role="server")
    pkt = make_pkt(proto="TCP", sport=50000, dport=25, service_banners=(http, smtp))
    (fichier,) = _extract_email([pkt])
    assert fichier.proto_source == "email"


def test_smb_sans_banniere_smb_ignore():
    """Ligne 287 : port 445 en TCP mais aucune banniere SMB."""
    from netcross_core.extract.carver import _extract_smb

    assert _extract_smb([make_pkt(proto="TCP", sport=50000, dport=445)]) == []


def test_smb_banniere_non_smb_sautee_avant_la_banniere_smb():
    """Branche 283->282 (issue #708) : une banniere d'un autre protocole est
    sautee, la boucle continue et trouve la banniere SMB suivante."""
    from netcross_core.extract.carver import _extract_smb

    http = Banner(protocol="http", service="nginx", version="1.25", raw="", role="server")
    smb = Banner(protocol="smb", service="Samba", version="4.13", raw="", role="server")
    pkt = make_pkt(proto="TCP", sport=50000, dport=445, service_banners=(http, smb))
    (fichier,) = _extract_smb([pkt])
    assert fichier.proto_source == "smb"
    assert fichier.type_detected == "smb-transfer"
    # Seulement des bannieres non SMB : la boucle s'epuise -> ignore.
    assert _extract_smb([make_pkt(proto="TCP", sport=50000, dport=445, service_banners=(http,))]) == []
