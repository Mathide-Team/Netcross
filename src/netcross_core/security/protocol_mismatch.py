"""
netcross_core.security.protocol_mismatch -- issue #142 (FLOW-1, parent
#141) : detection des flux cachés où un protocole utilise un port non
standard (SSH sur 443, DNS sur 443, HTTP sur 22, etc.).

Contrairement à la proposition initiale (qui lisait le payload brut),
ce module exploite les champs **déjà décodés** de `Pkt` :
- `http_method`, `http_is_request`, `http_is_response` (HTTP)
- `dns_qry_name`, `dns_txn_id` (DNS)
- `tls_client_hello`, `tls_server_hello`, `tls_application_data` (TLS/HTTPS)
- `sip_msg_type`, `sip_call_id` (SIP)
- `service_banners` (SSH, FTP, SMTP, IMAP, POP3 — via `Banner.protocol`)

Aucune nouvelle dissection tshark : on réutilise les champs existants.
"""

from __future__ import annotations

from typing import Any

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt

logger = get_logger(__name__)

# -- Tables de référence ------------------------------------------------------

# Ports standards et protocole attendu (nom interne, pas le proto L3/L4)
STANDARD_PORTS: dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MS-SQL",
    1521: "ORACLE",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

# Correspondance protocole détecté -> nom affichable
# (les noms internes de Banner.protocol sont en minuscules)
_DETECTED_PROTO_LABEL: dict[str, str] = {
    "ssh": "SSH",
    "http": "HTTP",
    "dns": "DNS",
    "ftp": "FTP",
    "smtp": "SMTP",
    "imap": "IMAP",
    "pop3": "POP3",
    "smb": "SMB",
    "tls": "HTTPS",
    "sip": "SIP",
}

# Protocoles attendus qui sont compatibles (HTTPS est du TLS, HTTP-ALT est
# du HTTP, etc.) — on ne signale pas un mismatch si le protocole détecté
# est légitimement attendu sur ce port.
_COMPATIBLE_EXPECTED: dict[str, set[str]] = {
    "HTTPS": {"HTTP", "HTTPS", "TLS"},
    "HTTP-ALT": {"HTTP", "HTTPS"},
    "HTTPS-ALT": {"HTTP", "HTTPS", "TLS"},
    "SMTPS": {"SMTP", "SMTPS"},
    "IMAPS": {"IMAP", "IMAPS"},
    "POP3S": {"POP3", "POP3S"},
    "FTP-DATA": {"FTP"},
}


def _pkt_detected_protos(pkt: Pkt) -> set[str]:
    """Retourne l'ensemble des protocoles applicatifs détectés sur ce
    paquet, en utilisant les champs déjà décodés de `Pkt`.

    Les noms retournés sont les labels majuscules (SSH, HTTP, DNS, HTTPS,
    FTP, SMTP, IMAP, POP3, SMB, SIP)."""
    detected: set[str] = set()

    # HTTP
    if pkt.http_method is not None or pkt.http_is_request or pkt.http_is_response:
        detected.add("HTTP")

    # DNS
    if pkt.dns_qry_name is not None or pkt.dns_txn_id is not None:
        detected.add("DNS")

    # TLS / HTTPS
    if pkt.tls_client_hello or pkt.tls_server_hello or pkt.tls_application_data:
        detected.add("HTTPS")

    # SIP
    if pkt.sip_msg_type is not None or pkt.sip_call_id is not None:
        detected.add("SIP")

    # Bannières de service (SSH, FTP, SMTP, IMAP, POP3, SMB)
    for banner in pkt.service_banners:
        label = _DETECTED_PROTO_LABEL.get(banner.protocol)
        if label is not None:
            detected.add(label)

    return detected


def _check_port_for_mismatch(
    port: int | None,
    detected_protos: set[str],
    proto_l3: str,
) -> tuple[str, str] | None:
    """Vérifie un port contre les protocoles détectés.

    Retourne (protocole_détecté, description) si mismatch, sinon None.
    """
    if port is None or port not in STANDARD_PORTS:
        return None
    expected = STANDARD_PORTS[port]
    compatible = _COMPATIBLE_EXPECTED.get(expected, set())
    compatible.add(expected)

    for detected in detected_protos:
        if detected in compatible:
            continue
        return (
            detected,
            f"{detected} détecté sur port {port} (attendu : {expected})",
        )
    return None


def detect_protocol_mismatch(pkt: Pkt) -> tuple[str, str] | None:
    """Détecte si un paquet utilise un protocole non standard pour son port.

    Utilise les champs déjà décodés de `Pkt` (http_*, dns_*, tls_*,
    service_banners) — aucune dissection tshark supplémentaire.

    Args:
        pkt: Paquet normalisé (Pkt).

    Returns:
        (nom_protocole, description) si mismatch, sinon None.
    """
    detected = _pkt_detected_protos(pkt)
    if not detected:
        return None

    # Vérifier le port destination d'abord, puis le port source
    mismatch = _check_port_for_mismatch(pkt.dport, detected, pkt.proto)
    if mismatch is not None:
        return mismatch
    mismatch = _check_port_for_mismatch(pkt.sport, detected, pkt.proto)
    if mismatch is not None:
        return mismatch

    # Détection ICMP tunneling : un paquet ICMP ne devrait porter AUCUN
    # protocole applicatif (HTTP, DNS, SSH, etc.). Si un champ applicatif
    # est peuplé sur un paquet ICMP, c'est suspect.
    if pkt.proto.upper() in ("ICMP", "ICMPV6") and detected:
        proto_name = next(iter(detected))
        return (
            "ICMP_TUNNEL",
            f"Payload {proto_name} dans paquet ICMP (tunneling suspect)",
        )

    return None


def detect_protocol_mismatches(packets: list[Pkt]) -> list[dict[str, Any]]:
    """Détecte tous les mismatches de protocole dans une liste de paquets.

    Args:
        packets: Liste de paquets (Pkt).

    Returns:
        Liste de dictionnaires avec les détails de chaque mismatch :
        ``{"frame_number", "point", "proto", "src", "dst", "sport", "dport",
        "detected_proto", "description"}``.
    """
    details: list[dict[str, Any]] = []
    logger.debug("protocol_mismatch : analyse de {} paquet(s)", len(packets))
    for pkt in packets:
        mismatch = detect_protocol_mismatch(pkt)
        if mismatch is not None:
            proto_name, description = mismatch
            details.append(
                {
                    "frame_number": pkt.frame_number,
                    "proto": pkt.proto,
                    "src": pkt.src,
                    "dst": pkt.dst,
                    "sport": pkt.sport,
                    "dport": pkt.dport,
                    "detected_proto": proto_name,
                    "description": description,
                    "point": pkt.point or None,
                }
            )
    logger.info("protocol_mismatch : {} mismatch(es) detecte(s) sur {} paquet(s)", len(details), len(packets))
    return details


def count_protocol_mismatches(packets: list[Pkt]) -> dict[str, dict[str, int]]:
    """Compte les mismatches de protocole par type et par description.

    Returns:
        ``{"SSH": {"SSH détecté sur port 443 ...": 5}, ...}``
    """
    counts: dict[str, dict[str, int]] = {}
    for pkt in packets:
        mismatch = detect_protocol_mismatch(pkt)
        if mismatch is not None:
            proto_name, description = mismatch
            if proto_name not in counts:
                counts[proto_name] = {}
            counts[proto_name][description] = counts[proto_name].get(description, 0) + 1
    logger.debug("count_protocol_mismatches: {} protocole(s) concerné(s)", len(counts))
    return counts


def protocol_mismatch_findings(
    mismatches: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convertit les détails de mismatch en findings de sécurité
    (compatible avec `Report.security_findings`).

    Severity : ``"elevee"`` pour ICMP tunneling, ``"moyenne"`` sinon.
    """
    findings: list[dict[str, Any]] = []
    for detail in mismatches:
        severity = "elevee" if detail["detected_proto"] == "ICMP_TUNNEL" else "moyenne"
        src, dst = detail.get("src"), detail.get("dst")
        sport, dport = detail.get("sport"), detail.get("dport")
        flow = ""
        if src or dst:
            flow = f" -- {src or '?'}{f':{sport}' if sport is not None else ''} -> {dst or '?'}"
            flow += f":{dport}" if dport is not None else ""
        frame = detail.get("frame_number")
        text = f"incoherence de protocole : {detail['description']}{flow}"
        if frame is not None:
            text += f" -- trame {frame}"
        findings.append(
            {
                # format commun des constats (category/severity/detail/point),
                # celui que lisent build_security_report, le JSON, le HTML,
                # le PDF et les exports SIEM. Les cles historiques ci-dessous
                # (type/description/frame_number...) etaient les seules
                # produites : chaque constat sortait avec un texte vide dans
                # tous les rendus (audit du 23/09/2026, issues #329/#345).
                "category": "anomalie",
                "detector": "protocol_mismatch",
                "severity": severity,
                "detail": text,
                "point": detail.get("point") or None,
                "host": dst,
                "port": dport,
                "type": "protocol_mismatch",
                "detected_proto": detail["detected_proto"],
                "description": detail["description"],
                "frame_number": frame,
                "sport": sport,
                "dport": dport,
                "proto": detail.get("proto"),
            }
        )
    logger.debug("protocol_mismatch_findings: {} constat(s)", len(findings))
    return findings
