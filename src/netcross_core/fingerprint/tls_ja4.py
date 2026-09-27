"""
netcross_core.fingerprint.tls_ja4 -- empreinte JA4 d'un ClientHello TLS
(issue #143, FLOW-2).

JA4 identifie le CLIENT TLS (curl, un navigateur, un malware...) a la
combinaison version/ciphers/extensions/ALPN/signature algorithms qu'il
propose dans son ClientHello -- ordre normalement stable pour une meme
version d'un meme outil, y compris quand le trafic est achemine sur un
port non standard.

Lecture directe de la charge utile TCP (record layer + handshake TLS en
clair -- le ClientHello n'est JAMAIS chiffre, meme en TLS 1.3), pas des
champs EK tshark : meme discipline que `application.banners`, voir sa
docstring pour la justification (pas de tshark disponible pour ecrire ni
valider ce module empiriquement).

Reference : specification JA4 publique (FoxIO / John Althouse, "JA4+
Network Fingerprinting", 2023). Ecrit depuis la description publique de
l'algorithme. Verifie depuis (issue #259, voir
`scripts/capture_reference_fingerprints.py` et
`fingerprint/known_fingerprints.json`) : empreintes calculees ici
comparees octet-pres a celles de l'implementation de reference
Wireshark (`tls.handshake.ja4`) sur du trafic TLS reel (curl, wget,
openssl s_client, python ssl -- TLS 1.2 et 1.3) -- concordance exacte
dans tous les cas testes, y compris l'hypothese JA4_c ci-dessous.
Limite : verifie sur les outils/versions listes dans
known_fingerprints.json, pas une preuve pour toute implementation TLS
existante.
"""

from __future__ import annotations

import hashlib
import struct

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

_TLS_HANDSHAKE_CONTENT_TYPE = 0x16
_CLIENT_HELLO_TYPE = 0x01

_EXT_SERVER_NAME = 0x0000
_EXT_ALPN = 0x0010
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_SIGNATURE_ALGORITHMS = 0x000D

# RFC 8701 -- 16 valeurs GREASE reservees (memes deux octets repetes),
# a ecarter des listes de ciphers/extensions/versions : un client qui en
# emet le fait pour forcer l'interoperabilite (RFC "GREASE"), ce n'est
# jamais un choix reel qui distingue un outil d'un autre -- les inclure
# ferait varier l'empreinte a chaque connexion du MEME outil (GREASE est
# choisi aleatoirement par le client a chaque handshake).
_GREASE = frozenset(0x0A0A + 0x1010 * i for i in range(16))

# Version TLS (record ou legacy_version du ClientHello) -> code JA4_a
# deux caracteres. Valeurs de la spec JA4 publique.
_VERSION_CODES = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
}


def _is_grease(value: int) -> bool:
    logger.debug("_is_grease: retour booleen")
    return value in _GREASE


def _read_u8(data: bytes, off: int) -> tuple[int, int]:
    logger.debug("_read_u8: retour tuple")
    return data[off], off + 1


def _read_u16(data: bytes, off: int) -> tuple[int, int]:
    logger.debug("_read_u16: retour tuple")
    return struct.unpack_from(">H", data, off)[0], off + 2


def _read_u24(data: bytes, off: int) -> tuple[int, int]:
    logger.debug("_read_u24: retour tuple")
    return int.from_bytes(data[off : off + 3], "big"), off + 3


def parse_client_hello(payload: bytes) -> dict | None:
    """Decode le ClientHello TLS porte par `payload` (charge utile TCP
    brute, un ou plusieurs enregistrements TLS coalesces admis -- seul le
    premier ClientHello trouve est utilise).

    Renvoie None si `payload` ne porte pas de ClientHello TLS complet
    (paquet TLS d'un autre type, handshake fragmente sur plusieurs
    segments TCP -- non recompose ici, ou charge utile non-TLS) ou si le
    decodage echoue (paquet tronque/malforme).

    Champs renvoyes (bruts, GREASE deja ecarte des listes) :
    `record_version`, `legacy_version` (uint16 tels que sur le fil),
    `cipher_suites` (list[int], ordre d'origine), `extensions`
    (list[int], ordre d'origine), `sni` (bool), `alpn` (list[str]),
    `signature_algorithms` (list[int], ordre d'origine),
    `supported_versions` (list[int], ordre d'origine).
    """
    try:
        logger.debug("parse_client_hello: retour _parse_client_hello(...)")
        return _parse_client_hello(payload)
    except (IndexError, struct.error, UnicodeError):
        logger.exception("échec dans parse_client_hello")
        return None


def _parse_client_hello(payload: bytes) -> dict | None:
    off = 0
    n = len(payload)
    while off + 5 <= n:
        content_type = payload[off]
        record_version, _ = _read_u16(payload, off + 1)
        record_length, _ = _read_u16(payload, off + 3)
        body_start = off + 5
        body_end = body_start + record_length
        if content_type != _TLS_HANDSHAKE_CONTENT_TYPE or body_end > n:
            off = body_end if body_end > off else n
            continue
        body = payload[body_start:body_end]
        if body and body[0] == _CLIENT_HELLO_TYPE:
            hs = _parse_client_hello_body(body, record_version)
            if hs is not None:
                logger.debug("_parse_client_hello: retour hs")
                return hs
        off = body_end
    logger.debug("_parse_client_hello: retour None")
    return None


def _parse_client_hello_body(body: bytes, record_version: int) -> dict | None:
    if len(body) < 4:
        logger.debug("_parse_client_hello_body: retour None")
        return None
    _hs_type, off = _read_u8(body, 0)
    _hs_len, off = _read_u24(body, off)
    legacy_version, off = _read_u16(body, off)
    off += 32  # random
    session_id_len, off = _read_u8(body, off)
    off += session_id_len

    cs_len, off = _read_u16(body, off)
    cipher_suites = [
        struct.unpack_from(">H", body, off + i)[0] for i in range(0, cs_len, 2) if not _is_grease_at(body, off + i)
    ]
    off += cs_len

    comp_len, off = _read_u8(body, off)
    off += comp_len

    sni = False
    alpn: list[str] = []
    signature_algorithms: list[int] = []
    supported_versions: list[int] = []
    extensions: list[int] = []

    if off < len(body):
        ext_total_len, off = _read_u16(body, off)
        ext_end = off + ext_total_len
        while off + 4 <= ext_end:
            ext_type, off = _read_u16(body, off)
            ext_len, off = _read_u16(body, off)
            ext_data = body[off : off + ext_len]
            off += ext_len
            if not _is_grease(ext_type):
                extensions.append(ext_type)
            if ext_type == _EXT_SERVER_NAME:
                sni = True
            elif ext_type == _EXT_ALPN:
                alpn = _parse_alpn(ext_data)
            elif ext_type == _EXT_SIGNATURE_ALGORITHMS:
                signature_algorithms = _parse_u16_list(ext_data[2:]) if len(ext_data) >= 2 else []
            elif ext_type == _EXT_SUPPORTED_VERSIONS:
                supported_versions = _parse_supported_versions(ext_data)

    logger.debug("_parse_client_hello_body: retour dict")
    return {
        "record_version": record_version,
        "legacy_version": legacy_version,
        "cipher_suites": cipher_suites,
        "extensions": extensions,
        "sni": sni,
        "alpn": alpn,
        "signature_algorithms": signature_algorithms,
        "supported_versions": supported_versions,
    }


def _is_grease_at(data: bytes, off: int) -> bool:
    logger.debug("_is_grease_at: retour _is_grease(...)")
    return _is_grease(struct.unpack_from(">H", data, off)[0])


def _parse_u16_list(data: bytes) -> list[int]:
    logger.debug("_parse_u16_list: retour liste")
    return [struct.unpack_from(">H", data, i)[0] for i in range(0, len(data) - 1, 2) if not _is_grease_at(data, i)]


def _parse_alpn(ext_data: bytes) -> list[str]:
    if len(ext_data) < 2:
        logger.debug("_parse_alpn: retour liste")
        return []
    protocols: list[str] = []
    off = 2  # ALPN protocol_name_list length (redondant avec ext_len - 2)
    while off < len(ext_data):
        plen = ext_data[off]
        off += 1
        protocols.append(ext_data[off : off + plen].decode("ascii", errors="replace"))
        off += plen
    logger.debug("_parse_alpn: retour protocols")
    return protocols


def _parse_supported_versions(ext_data: bytes) -> list[int]:
    if not ext_data:
        logger.debug("_parse_supported_versions: retour liste")
        return []
    n = ext_data[0]  # liste (client) prefixee par sa longueur en 1 octet
    logger.debug("_parse_supported_versions: retour _parse_u16_list(...)")
    return _parse_u16_list(ext_data[1 : 1 + n])


def _ja4_version_code(client_hello: dict) -> str:
    """La version JA4 est la plus haute annonce dans l'extension
    supported_versions (TLS 1.3+) quand elle est presente -- le
    legacy_version du ClientHello reste fige a 0x0303 (TLS 1.2) par
    compatibilite descendante des lors que supported_versions existe -- et
    le legacy_version sinon (TLS 1.2 et anterieur, ou client qui n'envoie
    pas cette extension)."""
    versions = [v for v in client_hello["supported_versions"] if v in _VERSION_CODES]
    chosen = max(versions) if versions else client_hello["legacy_version"]
    logger.debug("_ja4_version_code: retour get(...)")
    return _VERSION_CODES.get(chosen, "00")


def _ja4_alpn_code(alpn: list[str]) -> str:
    """Deux caracteres : premier et dernier caractere de la premiere
    valeur ALPN proposee ("h2" -> "h2", "http/1.1" -> "h1"), "00" si
    aucune extension ALPN."""
    if not alpn or not alpn[0]:
        logger.debug("_ja4_alpn_code: retour '00'")
        return "00"
    first = alpn[0]
    logger.debug("_ja4_alpn_code: retour conditionnel")
    return f"{first[0]}{first[-1]}" if len(first) > 1 else f"{first[0]}{first[0]}"


def _truncated_sha256(text: str) -> str:
    logger.debug("_truncated_sha256: retour element")
    return hashlib.sha256(text.encode("ascii", errors="replace")).hexdigest()[:12]


def compute_ja4(client_hello: dict, *, transport: str = "t") -> str:
    """Calcule JA4 depuis le dict renvoye par `parse_client_hello`.

    `transport` : "t" (TCP, valeur normale ici -- ce module ne lit que du
    payload TCP) ou "q" (QUIC), premier caractere de JA4_a.

    Format (spec JA4) : JA4_a "_" JA4_b "_" JA4_c ou :
    - JA4_a = transport + version(2) + "d"/"i" (SNI present/absent) +
      nb_ciphers(2, plafonne a 99) + nb_extensions(2, plafonne a 99,
      GREASE deja exclu des deux comptes) + code ALPN(2) ;
    - JA4_b = SHA256 tronque (12 hex) de la liste des ciphers, TRIEE
      (hexadecimal, 4 chiffres, virgule) -- JA4 trie les ciphers,
      contrairement a JA3 qui gardait l'ordre d'emission ;
    - JA4_c = SHA256 tronque (12 hex) de la liste des extensions TRIEE
      (SNI et ALPN exclues du calcul -- deja representees dans JA4_a) ET,
      SI l'extension signature_algorithms est presente, de la liste des
      signature algorithms dans leur ORDRE D'EMISSION (celle-la n'est
      pas triee), les deux jointes par "_" avant hachage -- SANS le "_"
      quand signature_algorithms est absente (pas de suffixe vide) ;
      "000000000000" (sentinelle, pas de hachage) si la liste a hacher
      est totalement vide (aucune extension hors SNI/ALPN/GREASE ET pas
      de signature_algorithms). Meme sentinelle pour JA4_b si la liste
      de ciphers est vide.

    Format de JA4_c confirme empiriquement (voir docstring du module,
    issue #259) : le separateur "_" entre extensions triees et signature
    algorithms, contre l'implementation de reference Wireshark, sur du
    trafic TLS 1.2 et 1.3 reel.

    Les cas limites ci-dessus (signature_algorithms absente, liste a
    hacher vide, ciphers vides) ne sont PAS exerces par les 4 vecteurs
    de reference reels de tests/data/reference_fingerprints.json (issue
    #259) : tous viennent d'outils (curl, OpenSSH) qui envoient
    systematiquement signature_algorithms. Valides en complement contre
    `ja4plus` (implementation Python tierce, validee contre les vecteurs
    de test officiels FoxIO) sur 13 ClientHello synthetiques couvrant
    ces cas limites -- resultats identiques.
    """
    ciphers = [c for c in client_hello["cipher_suites"] if not _is_grease(c)]
    extensions = [e for e in client_hello["extensions"] if not _is_grease(e)]
    ext_for_hash = [e for e in extensions if e not in (_EXT_SERVER_NAME, _EXT_ALPN)]
    sigalgs = client_hello["signature_algorithms"]

    a = (
        f"{transport}"
        f"{_ja4_version_code(client_hello)}"
        f"{'d' if client_hello['sni'] else 'i'}"
        f"{min(len(ciphers), 99):02d}"
        f"{min(len(extensions), 99):02d}"
        f"{_ja4_alpn_code(client_hello['alpn'])}"
    )
    b = _truncated_sha256(",".join(f"{c:04x}" for c in sorted(ciphers))) if ciphers else "0" * 12

    ext_part = ",".join(f"{e:04x}" for e in sorted(ext_for_hash))
    sigalg_part = ",".join(f"{s:04x}" for s in sigalgs)
    c_input = f"{ext_part}_{sigalg_part}" if sigalg_part else ext_part
    c = _truncated_sha256(c_input) if c_input else "0" * 12

    logger.debug("compute_ja4: retour valeur")
    return f"{a}_{b}_{c}"


def readable_client_hello(client_hello: dict) -> str:
    """Chaine lisible pour un analyste (ciphers/extensions en clair,
    complement du hash JA4 opaque) -- pas une norme, format propre a ce
    projet."""
    ciphers = ",".join(f"{c:#06x}" for c in client_hello["cipher_suites"])
    extensions = ",".join(f"{e:#06x}" for e in client_hello["extensions"])
    alpn = ",".join(client_hello["alpn"]) or "-"
    logger.debug("readable_client_hello: retour valeur")
    return f"ciphers=[{ciphers}] extensions=[{extensions}] alpn=[{alpn}] sni={client_hello['sni']}"


def identify(payload: bytes) -> tuple[str, str] | None:
    """Point d'entree pour `netcross_core.parsing` : (JA4, forme lisible)
    si `payload` porte un ClientHello TLS decodable, None sinon."""
    client_hello = parse_client_hello(payload)
    if client_hello is None:
        logger.debug("identify: retour None")
        return None
    logger.debug("identify: retour tuple")
    return compute_ja4(client_hello), readable_client_hello(client_hello)
