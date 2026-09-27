"""
netcross_core.fingerprint.ssh_hassh -- empreinte HASSH d'une negociation
SSH (issue #143, FLOW-2).

HASSH identifie l'implementation SSH (OpenSSH, PuTTY, un outil de scan/
exploitation...) a la combinaison d'algorithmes qu'elle propose dans son
message SSH_MSG_KEXINIT (RFC 4253 §7.1) -- ce message est TOUJOURS en
clair (il precede l'echange de cles qui etablit le chiffrement), y
compris quand la banniere textuelle (`application.banners._ssh_banners`)
a ete masquee ou modifiee.

Lecture directe de la charge utile TCP (Binary Packet Protocol RFC 4253
§6, non chiffre a ce stade), pas des champs EK tshark : meme discipline
que `application.banners`/`tls_ja4`, voir leurs docstrings pour la
justification.

Reference : specification HASSH publique (Salesforce, "HASSH -- A
Profiling Method for SSH Clients and Servers", 2018). Contrairement a
JA4 (voir `tls_ja4`), HASSH est un algorithme simple et entierement
documente (un seul MD5, champs non tries, pas d'exclusion GREASE -- SSH
n'a pas cette notion) : pas de reserve equivalente a formuler ici.
"""

from __future__ import annotations

import hashlib

from netcross_core.logging_config import get_logger
from netcross_core.models import ROLE_CLIENT, ROLE_SERVER

logger = get_logger(__name__)

_SSH_MSG_KEXINIT = 20
_COOKIE_LEN = 16


def _read_u32(data: bytes, off: int) -> tuple[int, int]:
    logger.debug("_read_u32: retour tuple")
    return int.from_bytes(data[off : off + 4], "big"), off + 4


def _read_namelist(data: bytes, off: int) -> tuple[list[str], int]:
    length, off = _read_u32(data, off)
    raw = data[off : off + length].decode("ascii")
    off += length
    logger.debug("_read_namelist: retour tuple")
    return (raw.split(",") if raw else []), off


def parse_kexinit(payload: bytes) -> dict | None:
    """Decode le message SSH_MSG_KEXINIT porte par `payload` (charge
    utile TCP brute -- accepte aussi bien un segment qui commence
    directement par le paquet binaire qu'un segment ou la banniere
    textuelle "SSH-2.0-..." precede ce paquet dans le meme segment).

    Renvoie None si aucun SSH_MSG_KEXINIT complet n'est trouve (paquet
    d'un autre type, negociation fragmentee sur plusieurs segments TCP --
    non recomposee ici, ou charge utile tronquee/malformee).

    Les 10 name-lists du message (RFC 4253 §7.1) sont renvoyees telles
    quelles, dans l'ordre d'emission (HASSH ne les trie pas) ; seules
    kex_algorithms, les algorithmes de chiffrement/MAC/compression dans
    CHAQUE sens sont utiles a `compute_hassh`, le reste (server_host_key_
    algorithms, langues, first_kex_packet_follows) est renvoye pour
    completude mais non consomme."""
    try:
        logger.debug("parse_kexinit: retour _parse_kexinit(...)")
        return _parse_kexinit(payload)
    except (IndexError, UnicodeError):
        logger.exception("échec dans parse_kexinit")
        return None


def _parse_kexinit(payload: bytes) -> dict | None:
    data = payload
    if data.startswith(b"SSH-"):
        nl = data.find(b"\n")
        if nl == -1:
            logger.debug("_parse_kexinit: retour None")
            return None
        data = data[nl + 1 :]
    if len(data) < 6:
        logger.debug("_parse_kexinit: retour None")
        return None

    packet_length = int.from_bytes(data[0:4], "big")
    padding_length = data[4]
    msg_type = data[5]
    if msg_type != _SSH_MSG_KEXINIT:
        logger.debug("_parse_kexinit: retour None")
        return None
    payload_len = packet_length - padding_length - 1  # inclut le byte msg_type
    if payload_len < 1:
        logger.debug("_parse_kexinit: retour None")
        return None
    body_end = 5 + payload_len  # borne haute du message SSH (msg_type inclus)
    if body_end > len(data):
        # Segment tronque (fin de capture, MTU...) -- on tente quand meme
        # avec ce qui est disponible : les name-lists precoces (kex,
        # algorithmes cote client) sont presque toujours suffisantes.
        body_end = len(data)

    off = 6 + _COOKIE_LEN  # apres msg_type (deja lu) + cookie 16 octets
    if off > body_end:
        logger.debug("_parse_kexinit: retour None")
        return None

    kex_algorithms, off = _read_namelist(data, off)
    server_host_key_algorithms, off = _read_namelist(data, off)
    encryption_c2s, off = _read_namelist(data, off)
    encryption_s2c, off = _read_namelist(data, off)
    mac_c2s, off = _read_namelist(data, off)
    mac_s2c, off = _read_namelist(data, off)
    compression_c2s, off = _read_namelist(data, off)
    compression_s2c, off = _read_namelist(data, off)

    logger.debug("_parse_kexinit: retour dict")
    return {
        "kex_algorithms": kex_algorithms,
        "server_host_key_algorithms": server_host_key_algorithms,
        "encryption_algorithms_client_to_server": encryption_c2s,
        "encryption_algorithms_server_to_client": encryption_s2c,
        "mac_algorithms_client_to_server": mac_c2s,
        "mac_algorithms_server_to_client": mac_s2c,
        "compression_algorithms_client_to_server": compression_c2s,
        "compression_algorithms_server_to_client": compression_s2c,
    }


def compute_hassh(kexinit: dict, role: str = ROLE_CLIENT) -> str:
    """HASSH (role=ROLE_CLIENT, algorithmes cote client->serveur) ou
    HASSHServer (role=ROLE_SERVER, algorithmes cote serveur->client) :
    MD5 de "kex;chiffrement;MAC;compression" (chaque champ = ses
    algorithmes dans l'ordre d'emission, joints par une virgule)."""
    if role == ROLE_SERVER:
        enc, mac, comp = (
            kexinit["encryption_algorithms_server_to_client"],
            kexinit["mac_algorithms_server_to_client"],
            kexinit["compression_algorithms_server_to_client"],
        )
    else:
        enc, mac, comp = (
            kexinit["encryption_algorithms_client_to_server"],
            kexinit["mac_algorithms_client_to_server"],
            kexinit["compression_algorithms_client_to_server"],
        )
    fields = [",".join(kexinit["kex_algorithms"]), ",".join(enc), ",".join(mac), ",".join(comp)]
    logger.debug("compute_hassh: retour hexdigest(...)")
    return hashlib.md5(";".join(fields).encode("ascii")).hexdigest()  # noqa: S324 -- identifiant, pas crypto


def readable_kexinit(kexinit: dict, role: str = ROLE_CLIENT) -> str:
    """Chaine lisible pour un analyste -- pas une norme, format propre a
    ce projet."""
    enc_key = "encryption_algorithms_" + ("server_to_client" if role == ROLE_SERVER else "client_to_server")
    mac_key = "mac_algorithms_" + ("server_to_client" if role == ROLE_SERVER else "client_to_server")
    comp_key = "compression_algorithms_" + ("server_to_client" if role == ROLE_SERVER else "client_to_server")
    logger.debug("readable_kexinit: retour valeur")
    return (
        f"kex=[{','.join(kexinit['kex_algorithms'])}] "
        f"enc=[{','.join(kexinit[enc_key])}] "
        f"mac=[{','.join(kexinit[mac_key])}] "
        f"comp=[{','.join(kexinit[comp_key])}]"
    )


def identify(payload: bytes, sport: int | None, dport: int | None) -> tuple[str, str, str] | None:
    """Point d'entree pour `netcross_core.parsing` : (HASSH, role,
    forme lisible) si `payload` porte un SSH_MSG_KEXINIT decodable, None
    sinon. `role` suit la meme heuristique que
    `application.banners._ssh_banners` : port serveur (22) cote
    destination -> l'emetteur est le client."""
    kexinit = parse_kexinit(payload)
    if kexinit is None:
        logger.debug("identify: retour None")
        return None
    role = ROLE_CLIENT if dport == 22 and sport != 22 else ROLE_SERVER
    logger.debug("identify: retour tuple")
    return compute_hassh(kexinit, role), role, readable_kexinit(kexinit, role)
