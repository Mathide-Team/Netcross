"""
netcross_core.application.banners -- extraction passive des bannieres de
versions logicielles et construction de `Report.service_fingerprints`
(CVE-1, issue #135, parent #133).

Deux niveaux :

- `extract_banners(proto, sport, dport, payload)` : pur, lit UNE charge
  utile TCP/UDP (`RawPacket.payload`) et renvoie les `Banner` reconnues.
  Appele par `netcross_core.parsing` au moment de la conversion
  RawPacket -> Pkt (seul endroit ou les octets sur le fil sont encore
  disponibles : `Pkt` ne garde que `payload_hash`).
- `build_service_fingerprints(packets)` : consolide les `Pkt.service_banners`
  en une liste de dicts par (point, hote, port, logiciel, version), le
  format lu par `netcross_report.security_report`.

Pourquoi le payload brut plutot que les champs EK de tshark : la plupart
des champs utiles (`ssh.protocol`, `smtp.rsp.parameter`, `dns.txt`,
`smb.native_os`...) n'ont pas ete verifies empiriquement sur ce projet
(pas de tshark disponible pour ecrire ce module), alors que
`tcp.payload`/`udp.payload` sont deja lus et exploites ailleurs
(RTP/SIP/hash). Les formats parses ici sont des formats sur le fil
stables et documentes (RFC 9110 en-tetes HTTP, RFC 4253 §4.2 bannière
SSH, RFC 5321/959/3501/1939 salutations, RFC 1035 DNS, MS-CIFS/MS-SMB2).

Ce module ne fait AUCUNE hypothese sur l'obsolescence ou la
vulnerabilite d'une version : il ne fait que lire ce que le service dit
de lui-meme. Une banniere peut etre falsifiee ou masquee (ServerTokens
Prod, `version.bind` desactive) ; l'absence de banniere n'est donc pas
une information.

Aucune exception ne sort de `extract_banners` : une charge utile
tronquee ou malformee donne simplement aucun resultat.

Contrat de couches : stdlib et netcross_core.models uniquement.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Iterable

from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import ROLE_CLIENT, ROLE_SERVER, Banner, Pkt

logger = get_logger(__name__)

# Nombre maximal de bannieres retournees pour un seul paquet (garde-fou
# contre un en-tete Server: pathologique, pas une limite fonctionnelle).
MAX_BANNERS_PER_PACKET = 8

# Taille maximale de charge utile examinee : les en-tetes HTTP et les
# salutations tiennent largement dans le premier segment TCP.
_MAX_SCAN = 8192

# -- utilitaires -----------------------------------------------------------

_VERSION_RE = re.compile(r"\d+(?:\.\d+)*")


def _leading_version(text: str) -> str | None:
    m = _VERSION_RE.match(text.strip())
    logger.debug("_leading_version: retour m.group(0) if m else None")
    return m.group(0) if m else None


def _first_line(data: bytes, limit: int = 512) -> str:
    end = len(data)
    for sep in (b"\r\n", b"\n"):
        i = data.find(sep, 0, limit)
        if i != -1:
            end = min(end, i)
    logger.debug("_first_line: retour data[:min(end, limit)].decode('latin-1'…(…)")
    return data[: min(end, limit)].decode("latin-1").strip()


def _find_products(text: str, products: tuple[str, ...]) -> list[tuple[str, str | None]]:
    """Produits connus cites dans `text`, avec la version qui suit
    immediatement le nom quand il y en a une. Un nom n'est reconnu que
    comme mot entier et pas comme debut d'un nom d'hote ("postfix.
    example.com" n'est pas Postfix)."""
    found: list[tuple[str, str | None]] = []
    for name in products:
        pattern = (
            r"(?<![\w.-])" + re.escape(name) + r"(?!\w)(?!-[A-Za-z])(?!\.\w)(?:[\s/_-]+v?(\d+(?:\.\d+)*[A-Za-z0-9]*))?"
        )
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            found.append((name, m.group(1)))
    logger.debug("_find_products: retour found={}", summarize(found, "found"))
    return found


# -- HTTP ----------------------------------------------------------------

_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")
_TOKEN_RE = re.compile(r"^([A-Za-z][\w.+-]*)/(\d[\w.+~-]*)$")
_COMMENT_RE = re.compile(r"\([^)]*\)")

# Jetons de User-Agent qui ne designent pas un logiciel (compatibilite
# historique des navigateurs) : les ecarter evite de "detecter" Mozilla/5.0
# sur tout le trafic web.
_UA_NOISE = frozenset({"mozilla", "applewebkit", "khtml", "gecko", "safari", "mobile", "version"})


def _header_value(head: bytes, name: bytes) -> str | None:
    m = re.search(rb"(?im)^" + re.escape(name) + rb"[ \t]*:[ \t]*(.*?)[ \t]*\r?$", head)
    logger.debug("_header_value: retour m.group(1).decode('latin-1') if m else None")
    return m.group(1).decode("latin-1") if m else None


def _http_head(payload: bytes) -> bytes:
    """Bloc d'en-tetes (jusqu'a la ligne vide, ou toute la charge utile
    si le segment est tronque)."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = payload.find(sep)
        if i != -1:
            logger.debug("_http_head: si i != -1 -> retour payload[:i]")
            return payload[:i]
    logger.debug("_http_head: retour payload={}", summarize(payload, "payload"))
    return payload


def _versioned_tokens(value: str) -> list[tuple[str, str]]:
    tokens = []
    for tok in _COMMENT_RE.sub(" ", value).split():
        m = _TOKEN_RE.match(tok)
        if m:
            tokens.append((m.group(1), m.group(2)))
    logger.debug("_versioned_tokens: retour tokens={}", summarize(tokens, "tokens"))
    return tokens


def _http_banners(payload: bytes) -> list[Banner]:
    head = _http_head(payload[:_MAX_SCAN])
    if payload.startswith(b"HTTP/1."):
        value = _header_value(head, b"Server")
        if not value:
            logger.debug("_http_banners: si not value -> retour liste vide")
            return []
        tokens = _versioned_tokens(value)
        if tokens:
            logger.debug("_http_banners: si tokens -> retour liste")
            return [Banner("http", name, ver, value) for name, ver in tokens]
        # "Server: nginx", "Server: cloudflare" : pas de version mais le
        # logiciel est identifie.
        bare = _COMMENT_RE.sub(" ", value).strip()
        logger.debug(
            "_http_banners: si payload.startswith(b'HTTP/1.') -> retour [Banner('http', bare, None, value)] if bare e…"
        )
        return [Banner("http", bare, None, value)] if bare else []
    if payload.startswith(_HTTP_METHODS):
        value = _header_value(head, b"User-Agent")
        if not value:
            logger.debug("_http_banners: si not value -> retour liste vide")
            return []
        logger.debug("_http_banners: si payload.startswith(_HTTP_METHODS) -> retour liste")
        return [
            Banner("http", name, ver, value, ROLE_CLIENT)
            for name, ver in _versioned_tokens(value)
            if name.lower() not in _UA_NOISE
        ]
    logger.debug("_http_banners: retour liste vide")
    return []


# -- SSH (RFC 4253 §4.2) ---------------------------------------------------

_SSH_RE = re.compile(r"^SSH-(\d\.\d+)-(\S+)")
_SSH_SOFTWARE_RE = re.compile(r"^(.+?)[_-](\d[\w.+~-]*)$")


def _ssh_banners(payload: bytes, sport: int | None, dport: int | None) -> list[Banner]:
    line = _first_line(payload)
    m = _SSH_RE.match(line)
    if not m:
        logger.debug("_ssh_banners: si not m -> retour liste vide")
        return []
    software = m.group(2)
    sm = _SSH_SOFTWARE_RE.match(software)
    name, version = (sm.group(1).replace("_", " "), sm.group(2)) if sm else (software.replace("_", " "), None)
    # Les deux extremites envoient une banniere. Sur le port standard on
    # sait laquelle est le serveur ; hors port standard on suppose que
    # l'emetteur est le serveur (il parle en premier en pratique).
    role = ROLE_CLIENT if dport == 22 and sport != 22 else ROLE_SERVER
    logger.debug("_ssh_banners: retour liste")
    return [Banner("ssh", name, version, line, role)]


# -- SMTP / FTP / IMAP / POP3 : salutations serveur ------------------------

_SMTP_PRODUCTS = ("Postfix", "Exim", "Sendmail", "OpenSMTPD")
_FTP_PRODUCTS = ("vsftpd", "ProFTPD", "Pure-FTPd", "FileZilla Server")
_IMAP_POP_PRODUCTS = ("Dovecot", "Courier-IMAP", "Courier-POP3", "Cyrus IMAP")

# port serveur -> (protocole, prefixe de salutation, produits connus)
_GREETINGS: dict[int, tuple[str, bytes, tuple[str, ...]]] = {
    21: ("ftp", b"220", _FTP_PRODUCTS),
    25: ("smtp", b"220", _SMTP_PRODUCTS),
    587: ("smtp", b"220", _SMTP_PRODUCTS),
    2525: ("smtp", b"220", _SMTP_PRODUCTS),
    110: ("pop3", b"+OK", _IMAP_POP_PRODUCTS),
    143: ("imap", b"* OK", _IMAP_POP_PRODUCTS),
}


def _greeting_banners(payload: bytes, sport: int | None) -> list[Banner]:
    spec = _GREETINGS.get(sport) if sport is not None else None
    if spec is None:
        logger.debug("_greeting_banners: si spec is None -> retour liste vide")
        return []
    protocol, prefix, products = spec
    if not payload.startswith(prefix):
        logger.debug("_greeting_banners: si not payload.startswith(prefix) -> retour liste vide")
        return []
    line = _first_line(payload)
    logger.debug("_greeting_banners: retour liste")
    return [Banner(protocol, _canonical(products, name), ver, line) for name, ver in _find_products(line, products)]


def _canonical(products: tuple[str, ...], name: str) -> str:
    logger.debug("_canonical: retour next(…)")
    return next((p for p in products if p.lower() == name.lower()), name)


# -- DNS : version.bind (CHAOS TXT) ------------------------------------------

_DNS_PRODUCTS = ("dnsmasq", "Unbound", "PowerDNS", "Knot")
_DNS_CHAOS = 3
_DNS_TXT = 16


def _dns_name(msg: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    end: int | None = None
    hops = 0
    while True:
        if off >= len(msg):
            logger.trace("_dns_name: refus, ValueError")
            logger.debug("_dns_name: si off >= len(msg) -> levée ValueError")
            raise ValueError("nom DNS tronque")
        length = msg[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                logger.trace("_dns_name: refus, ValueError")
                logger.debug("_dns_name: si off + 1 >= len(msg) -> levée ValueError")
                raise ValueError("pointeur DNS tronque")
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | msg[off + 1]
            hops += 1
            if hops > 16:
                logger.trace("_dns_name: refus, ValueError")
                logger.debug("_dns_name: si hops > 16 -> levée ValueError")
                raise ValueError("boucle de compression DNS")
            continue
        if length & 0xC0:
            logger.trace("_dns_name: refus, ValueError")
            logger.debug("_dns_name: si length & 192 -> levée ValueError")
            raise ValueError("etiquette DNS invalide")
        off += 1
        labels.append(msg[off : off + length].decode("ascii", "replace"))
        off += length
    logger.debug("_dns_name: retour tuple de 2")
    return ".".join(labels), (end if end is not None else off)


def _version_bind_txt(msg: bytes) -> str | None:
    """Texte de la reponse TXT a une requete CHAOS `version.bind`, None si
    ce n'est pas une telle reponse."""
    if len(msg) < 12:
        logger.debug("_version_bind_txt: si len(msg) < 12 -> retour None")
        return None
    flags = struct.unpack_from("!H", msg, 2)[0]
    qdcount, ancount = struct.unpack_from("!HH", msg, 4)
    if not flags & 0x8000:  # reponses uniquement
        logger.debug("_version_bind_txt: si not flags & 32768 -> retour None")
        return None
    off = 12
    asked = False
    for _ in range(qdcount):
        name, off = _dns_name(msg, off)
        qtype, qclass = struct.unpack_from("!HH", msg, off)
        off += 4
        if name.lower() == "version.bind" and qclass == _DNS_CHAOS and qtype == _DNS_TXT:
            asked = True
    if not asked:
        logger.debug("_version_bind_txt: si not asked -> retour None")
        return None
    for _ in range(ancount):
        _name, off = _dns_name(msg, off)
        rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", msg, off)
        off += 10
        rdata = msg[off : off + rdlen]
        off += rdlen
        if rtype == _DNS_TXT and rdata:
            logger.debug("_version_bind_txt: si rtype == _DNS_TXT and rdata -> retour rdata[1:1 + rdata[0]].decode(…)")
            return rdata[1 : 1 + rdata[0]].decode("utf-8", "replace")
    logger.debug("_version_bind_txt: retour None")
    return None


def _dns_banners(payload: bytes, proto: str) -> list[Banner]:
    msg = payload
    if proto == "TCP":  # RFC 1035 §4.2.2 : prefixe de longueur sur 2 octets
        if len(msg) < 2 or struct.unpack_from("!H", msg, 0)[0] != len(msg) - 2:
            logger.debug(
                "_dns_banners: si len(msg) < 2 or struct.unpack_from('!H', msg, 0)[0] != len(… -> retour liste vide"
            )
            return []
        msg = msg[2:]
    txt = _version_bind_txt(msg)
    if not txt:
        logger.debug("_dns_banners: si not txt -> retour liste vide")
        return []
    known = _find_products(txt, _DNS_PRODUCTS)
    if known:
        name, ver = known[0]
        logger.debug("_dns_banners: si known -> retour liste")
        return [Banner("dns", _canonical(_DNS_PRODUCTS, name), ver, txt)]
    # Convention BIND : `version.bind` renvoie la version brute ("9.16.1-Ubuntu").
    ver = _leading_version(txt)
    logger.debug("_dns_banners: retour [Banner('dns', 'BIND', ver, txt)] if ver else []")
    return [Banner("dns", "BIND", ver, txt)] if ver else []


# -- SMB -----------------------------------------------------------------

_SMB2_DIALECTS = {
    0x0202: "2.0.2",
    0x0210: "2.1",
    0x02FF: "2.x",
    0x0300: "3.0",
    0x0302: "3.0.2",
    0x0311: "3.1.1",
}
_SMB1_NEGOTIATE = 0x72
_SMB1_SESSION_SETUP = 0x73
_SAMBA_RE = re.compile(r"Samba\s+(\S+)", re.IGNORECASE)


def _smb_cstring(msg: bytes, pos: int, unicode_: bool) -> tuple[str, int]:
    if unicode_:
        for i in range(pos, len(msg) - 1, 2):
            if msg[i : i + 2] == b"\x00\x00":
                logger.debug("_smb_cstring: si msg[i:i + 2] == b'\\x00\\x00' -> retour tuple de 2")
                return msg[pos:i].decode("utf-16-le", "replace"), i + 2
        logger.trace("_smb_cstring: refus, ValueError")
        logger.debug("_smb_cstring: si unicode_ -> levée ValueError")
        raise ValueError("chaine SMB tronquee")
    end = msg.find(b"\x00", pos)
    if end == -1:
        logger.trace("_smb_cstring: refus, ValueError")
        logger.debug("_smb_cstring: si end == -1 -> levée ValueError")
        raise ValueError("chaine SMB tronquee")
    logger.debug("_smb_cstring: retour tuple de 2")
    return msg[pos:end].decode("latin-1"), end + 1


def _smb1_banners(msg: bytes) -> list[Banner]:
    if len(msg) < 33 or not msg[9] & 0x80:  # reponses uniquement
        logger.debug("_smb1_banners: si len(msg) < 33 or not msg[9] & 128 -> retour liste vide")
        return []
    command = msg[4]
    if command == _SMB1_NEGOTIATE:
        logger.debug("_smb1_banners: si command == _SMB1_NEGOTIATE -> retour liste")
        return [Banner("smb", "SMB", "1.0", "SMB1 negotiate response")]
    if command != _SMB1_SESSION_SETUP:
        logger.debug("_smb1_banners: si command != _SMB1_SESSION_SETUP -> retour liste vide")
        return []
    unicode_ = bool(struct.unpack_from("<H", msg, 10)[0] & 0x8000)
    word_count = msg[32]
    pos = 33 + 2 * word_count + 2  # apres WordCount, les mots et ByteCount
    if word_count == 4:  # securite etendue : un blob precede les chaines
        pos += struct.unpack_from("<H", msg, 33 + 6)[0]
    if unicode_ and pos % 2:
        pos += 1
    native_os, pos = _smb_cstring(msg, pos, unicode_)
    native_lm, pos = _smb_cstring(msg, pos, unicode_)
    banners = [Banner("smb", "SMB", "1.0", f"SMB1 NativeOS={native_os}; NativeLanMan={native_lm}")]
    m = _SAMBA_RE.match(native_lm)
    if m:
        banners.append(Banner("smb", "Samba", _leading_version(m.group(1)), native_lm))
    logger.debug("_smb1_banners: retour banners={}", summarize(banners, "banners"))
    return banners


def _smb2_banners(msg: bytes) -> list[Banner]:
    if len(msg) < 70:
        logger.debug("_smb2_banners: si len(msg) < 70 -> retour liste vide")
        return []
    command = struct.unpack_from("<H", msg, 12)[0]
    flags = struct.unpack_from("<I", msg, 16)[0]
    if command != 0 or not flags & 1:  # NEGOTIATE, reponse serveur
        logger.debug("_smb2_banners: si command != 0 or not flags & 1 -> retour liste vide")
        return []
    dialect = struct.unpack_from("<H", msg, 68)[0]
    version = _SMB2_DIALECTS.get(dialect, f"0x{dialect:04x}")
    logger.debug("_smb2_banners: retour liste")
    return [Banner("smb", "SMB", version, f"SMB2 negotiate response, dialect 0x{dialect:04x}")]


def _smb_banners(payload: bytes) -> list[Banner]:
    # En-tete NetBIOS Session Service : type 0x00 + longueur sur 3 octets.
    if len(payload) < 8 or payload[0] != 0:
        logger.debug("_smb_banners: si len(payload) < 8 or payload[0] != 0 -> retour liste vide")
        return []
    msg = payload[4:]
    if msg[:4] == b"\xffSMB":
        logger.debug("_smb_banners: si msg[:4] == b'\\xffSMB' -> retour _smb1_banners(…)")
        return _smb1_banners(msg)
    if msg[:4] == b"\xfeSMB":
        logger.debug("_smb_banners: si msg[:4] == b'\\xfeSMB' -> retour _smb2_banners(…)")
        return _smb2_banners(msg)
    logger.debug("_smb_banners: retour liste vide")
    return []


# -- point d'entree ------------------------------------------------------------


def extract_banners(proto: str, sport: int | None, dport: int | None, payload: bytes) -> tuple[Banner, ...]:
    """Bannieres de logiciels lisibles dans la charge utile d'un paquet.

    `proto` vaut "TCP" ou "UDP" (toute autre valeur donne ()). Le
    protocole applicatif est reconnu au contenu (HTTP, SSH, SMB) ou au
    port serveur (salutations SMTP/FTP/IMAP/POP3, DNS). Tuple vide si
    rien n'est reconnu ou si la charge utile est malformee."""
    if not payload or proto not in ("TCP", "UDP"):
        logger.debug("extract_banners: si not payload or proto not in ('TCP', 'UDP') -> retour tuple de 0")
        return ()
    try:
        banners: list[Banner] = []
        if proto == "TCP":
            if payload.startswith((b"HTTP/1.", *_HTTP_METHODS)):
                banners = _http_banners(payload)
            elif payload.startswith(b"SSH-"):
                banners = _ssh_banners(payload, sport, dport)
            elif sport in (445, 139):
                banners = _smb_banners(payload)
            elif sport == 53:
                banners = _dns_banners(payload, proto)
            else:
                banners = _greeting_banners(payload, sport)
        elif sport == 53:
            banners = _dns_banners(payload, proto)
        if banners:
            logger.trace(
                "extract_banners: {} banniere(s) {} (port source {}){}",
                len(banners),
                "/".join(sorted({b.protocol for b in banners})),
                sport,
                ", tronque a " + str(MAX_BANNERS_PER_PACKET) if len(banners) > MAX_BANNERS_PER_PACKET else "",
            )
        logger.debug("extract_banners: retour tuple(…)")
        return tuple(banners[:MAX_BANNERS_PER_PACKET])
    except (ValueError, IndexError, struct.error, UnicodeError) as exc:
        # charge utile malformee : resultat attendu, a chaque paquet -> TRACE sans traceback
        logger.trace("extract_banners: charge utile {} malformee ({} octets) : {!r}", proto, len(payload), exc)
        logger.debug("extract_banners: except (ValueError, IndexError, struct.error, … -> retour tuple de 0")
        return ()


# -- consolidation : Pkt.service_banners -> Report.service_fingerprints -----------


def build_service_fingerprints(packets: Iterable[Pkt]) -> list[dict]:
    """Liste dedupliquee des logiciels identifies, un dict par (point,
    hote, port, logiciel, version, role) -- format lu par
    `netcross_report.security_report` (cles `service`, `version`, `host`,
    `port`, `point`) plus `protocol`, `role` et `banner` (texte source).

    `host` est l'emetteur du paquet (le logiciel tourne chez l'emetteur,
    y compris pour un User-Agent : c'est le client) ; `port` est son port
    source pour un serveur, None pour un client (port ephemere, sans
    interet). Deux vues du meme logiciel a des points de capture
    differents restent deux entrees (le champ `point` les distingue,
    `security_report` les fusionne).

    Si le meme logiciel est vu plusieurs fois, on garde le texte source le
    plus long (ex: SMB1, ou la reponse Session Setup porte le systeme
    d'exploitation et pas la reponse Negotiate)."""
    found: dict[tuple, dict] = {}
    for pk in packets:
        for b in pk.service_banners:
            port = pk.sport if b.role == ROLE_SERVER else None
            key = (pk.point, pk.src, port, b.service.lower(), b.version, b.role)
            entry = found.get(key)
            if entry is None:
                found[key] = {
                    "service": b.service,
                    "version": b.version,
                    "host": pk.src,
                    "port": port,
                    "point": pk.point,
                    "protocol": b.protocol,
                    "role": b.role,
                    "banner": b.raw,
                }
            elif len(b.raw) > len(entry["banner"]):
                entry["banner"] = b.raw
    logger.debug(
        "build_service_fingerprints: {} logiciel(s) identifie(s) sur {} hote(s)",
        len(found),
        len({(e["point"], e["host"]) for e in found.values()}),
    )
    return sorted(
        found.values(),
        key=lambda e: (e["point"], e["host"], e["port"] or 0, e["service"].lower(), e["version"] or "", e["role"]),
    )
