"""
netcross_core.fingerprint.report -- consolidation des empreintes JA4/
HASSH vues par paquet en entrees pretes pour `Report.service_fingerprints`
(issue #143, integration demandee avec CVE-1 #135).

Meme esprit que `application.banners.build_service_fingerprints` (memes
cles `service`/`version`/`host`/`port`/`point`, pour que
`netcross_report.security_report` -- qui ne fait qu'AFFICHER cette liste
sans rien y detecter -- n'ait rien de plus a connaitre) : une entree par
empreinte distincte vue a un point de capture, `service` valant
"TLS/JA4" ou "SSH/HASSH" plutot qu'un nom de logiciel (l'empreinte
n'identifie l'outil que quand elle correspond a une entree de
`fingerprint.known` -- sinon `version` reste None, comme un service
"banners" sans version connue)."""

from __future__ import annotations

from collections.abc import Iterable

from netcross_core.fingerprint import ssh_hassh, tls_ja4
from netcross_core.fingerprint.known import identify_tool, load_known_fingerprints
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import ROLE_CLIENT, ROLE_SERVER, Pkt

logger = get_logger(__name__)


def build_fingerprint_records(packets: Iterable[Pkt], known: dict | None = None) -> list[dict]:
    """Liste dedupliquee des empreintes JA4/HASSH, une entree par
    (point, hote, type d'empreinte, valeur). `known` : base de
    correspondances de `fingerprint.known.load_known_fingerprints` (la
    base livree par defaut si None -- chargee une seule fois ici, pas par
    paquet)."""
    known = known if known is not None else load_known_fingerprints()
    found: dict[tuple, dict] = {}
    for pk in packets:
        # JA4 provient toujours du ClientHello -- l'emetteur est
        # necessairement le client TLS, pas de port serveur a rattacher
        # (comme un User-Agent HTTP dans application.banners).
        if pk.tls_ja4:
            _add(
                found,
                pk.point,
                pk.src,
                None,
                ROLE_CLIENT,
                "TLS/JA4",
                pk.tls_ja4,
                pk.tls_ja4_readable,
                identify_tool("ja4", pk.tls_ja4, known),
            )
        if pk.ssh_hassh:
            port = pk.sport if pk.ssh_hassh_role == ROLE_SERVER else None
            _add(
                found,
                pk.point,
                pk.src,
                port,
                pk.ssh_hassh_role,
                "SSH/HASSH",
                pk.ssh_hassh,
                pk.ssh_hassh_readable,
                identify_tool("hassh", pk.ssh_hassh, known),
            )
    logger.debug("build_fingerprint_records: retour sorted(…)")
    return sorted(found.values(), key=lambda e: (e["point"], e["host"], e["port"] or 0, e["fingerprint"]))


def _add(
    found: dict,
    point: str,
    host: str,
    port: int | None,
    role: str | None,
    service: str,
    fingerprint: str,
    banner: str | None,
    tool: str | None,
) -> None:
    key = (point, host, port, service, fingerprint)
    if key in found:
        logger.debug("_add: si key in found -> retour")
        return
    found[key] = {
        "service": service,
        "version": tool,
        "host": host,
        "port": port,
        "point": point,
        "protocol": "tls" if service == "TLS/JA4" else "ssh",
        "role": role,
        "banner": banner or "",
        "fingerprint": fingerprint,
    }
    logger.debug("_add: fin")


def compute_pkt_fingerprints(proto: str, sport: int | None, dport: int | None, payload: bytes | None) -> dict:
    """Point d'entree pour `netcross_core.parsing._to_pkt` : calcule les
    champs `tls_ja4*`/`ssh_hassh*` d'un `Pkt` depuis la charge utile brute
    d'un `RawPacket` (les octets ne sont plus disponibles ensuite -- meme
    contrainte que `service_banners`, voir `models.Pkt.service_banners`).

    Renvoie un dict pret a etre eclate en kwargs de `Pkt(...)` ; toutes
    les valeurs sont None quand `proto` n'est pas TCP ou que rien n'est
    decodable (charge utile absente, tronquee, ou ne portant ni
    ClientHello TLS ni SSH_MSG_KEXINIT)."""
    empty: dict[str, str | None] = {
        "tls_ja4": None,
        "tls_ja4_readable": None,
        "ssh_hassh": None,
        "ssh_hassh_role": None,
        "ssh_hassh_readable": None,
    }
    if not payload or proto != "TCP":
        logger.debug(
            "compute_pkt_fingerprints: si not payload or proto != 'TCP' -> retour empty={}", summarize(empty, "empty")
        )
        return empty
    ja4 = tls_ja4.identify(payload)
    if ja4 is not None:
        empty["tls_ja4"], empty["tls_ja4_readable"] = ja4
        logger.debug("compute_pkt_fingerprints: si ja4 is not None -> retour empty={}", summarize(empty, "empty"))
        return empty
    hassh = ssh_hassh.identify(payload, sport, dport)
    if hassh is not None:
        empty["ssh_hassh"], empty["ssh_hassh_role"], empty["ssh_hassh_readable"] = hassh
    logger.debug("compute_pkt_fingerprints: retour empty={}", summarize(empty, "empty"))
    return empty
