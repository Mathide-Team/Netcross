"""
pcap_parser.capfile -- couche 1 bis : cadrage binaire minimal des
fichiers pcap / pcapng. AUCUNE dissection : on ne lit que la structure
(enregistrements pcap, blocs pcapng), jamais le contenu des paquets --
la regle "pas de decodage a la main, c'est le role de tshark" du
package n'est donc pas remise en cause.

Pourquoi ce module existe : editcap sait decouper par duree (-i) et par
nombre de paquets (-c), mais PAS par taille, et `tshark -r ... -b
filesize:` refuse de decouper une lecture de fichier ("Multiple capture
files requested, but a capture isn't being done"). Le mode "taille
maximale" de capture.split_capture ne peut donc pas etre un simple
wrapper autour d'un outil Wireshark : il est realise ici, en une seule
passe en flux (memoire constante, quelle que soit la taille du fichier).

Second usage (Job 38/issue #158) : read_structure() lit la version du format,
la liste des interfaces et, en pcapng, les compteurs des Interface
Statistics Blocks (paquets recus/perdus). capinfos 4.2.2 n'expose PAS ces
compteurs (il n'indique que "Number of stat entries"), verifie
empiriquement sur un pcapng portant un ISB avec isb_ifdrop non nul.

Formats pris en charge : pcap (µs et ns, les deux endianness) et pcapng
(les deux endianness, plusieurs sections). Un fichier compresse (.gz)
n'est PAS reconnu -- detect_format() renvoie None.
"""

from __future__ import annotations

import contextlib
import os
import struct
from collections.abc import Iterator
from dataclasses import dataclass, replace
from typing import BinaryIO

from loguru import logger as _loguru_logger

# pcap_parser reste independant de netcross_core (contrat import-linter) :
# loguru directement, lie au nom du module.
logger = _loguru_logger.bind(name=__name__)

FORMAT_PCAP = "pcap"
FORMAT_NSECPCAP = "nsecpcap"
FORMAT_PCAPNG = "pcapng"

# Noms attendus par `editcap -F` -- d'ou les valeurs de FORMAT_*.
_FORMAT_EXTENSION = {FORMAT_PCAP: ".pcap", FORMAT_NSECPCAP: ".pcap", FORMAT_PCAPNG: ".pcapng"}

# Magic pcap tels qu'ils apparaissent dans les 4 premiers OCTETS du fichier
# -> (endianness struct, format). Le magic 0xa1b2c3d4 ecrit en little-endian
# donne les octets d4 c3 b2 a1, d'ou la table ci-dessous.
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", FORMAT_PCAP),
    b"\xa1\xb2\xc3\xd4": (">", FORMAT_PCAP),
    b"\x4d\x3c\xb2\xa1": ("<", FORMAT_NSECPCAP),
    b"\xa1\xb2\x3c\x4d": (">", FORMAT_NSECPCAP),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # type du Section Header Block (palindrome)

_PCAP_HEADER_LEN = 24
_PCAP_RECORD_HEADER_LEN = 16

# Blocs pcapng (RFC draft-ietf-opsawg-pcapng).
_BLOCK_IDB = 0x00000001  # Interface Description
_BLOCK_ISB = 0x00000005  # Interface Statistics
_BLOCK_PB = 0x00000002  # Packet (obsolete)
_BLOCK_SPB = 0x00000003  # Simple Packet
_BLOCK_EPB = 0x00000006  # Enhanced Packet
_BLOCK_DSB = 0x0000000A  # Decryption Secrets
_BLOCK_SHB = 0x0A0D0D0A  # Section Header
_PACKET_BLOCKS = frozenset({_BLOCK_PB, _BLOCK_SPB, _BLOCK_EPB})
_BOM_LE = b"\x4d\x3c\x2b\x1a"
_BOM_BE = b"\x1a\x2b\x3c\x4d"

# Garde-fou contre un champ longueur corrompu (sinon f.read(n) tenterait
# d'allouer n octets). 256 Mio depasse de tres loin tout paquet ou bloc reel.
_MAX_UNIT_LEN = 256 * 1024 * 1024

_READ_BUFFER = 1024 * 1024

# Codes d'options pcapng lus par read_structure(). Les codes 2 et 3 n'ont
# pas le meme sens dans un IDB (nom/description) et dans un ISB (debut/fin
# de la mesure) : la lecture est donc toujours faite bloc par bloc.
_OPT_ENDOFOPT = 0
_OPT_IF_NAME = 2  # IDB : nom de l'interface
_OPT_ISB_IFRECV = 4  # ISB : paquets recus par l'interface
_OPT_ISB_IFDROP = 5  # ISB : paquets perdus par l'interface (manque de ressources)
_OPT_ISB_OSDROP = 7  # ISB : paquets perdus par l'OS


def detect_format(path: str) -> str | None:
    """FORMAT_PCAP, FORMAT_NSECPCAP ou FORMAT_PCAPNG d'apres les octets
    magiques du fichier (pas son extension), ou None si non reconnu
    (fichier compresse, autre format, fichier vide/tronque)."""
    with open(path, "rb") as f:
        magic = f.read(4)
    logger.debug("detect_format: {} magic={}", path, magic.hex())
    if magic == _PCAPNG_MAGIC:
        return FORMAT_PCAPNG
    entry = _PCAP_MAGICS.get(magic)
    return entry[1] if entry else None


def format_extension(fmt: str | None) -> str:
    """Extension de sortie coherente avec `editcap -F <fmt>` ; pcapng par
    defaut (c'est aussi ce que produit editcap sans -F)."""
    return _FORMAT_EXTENSION.get(fmt or FORMAT_PCAPNG, ".pcapng")


def _read_exact_or_none(f: BinaryIO, n: int) -> bytes | None:
    """n octets, ou None si le fichier s'arrete avant (fin de fichier
    tronquee -- cas normal d'une capture interrompue en cours d'ecriture)."""
    data = f.read(n)
    return data if len(data) == n else None


def _iter_pcap_records(f: BinaryIO, endian: str) -> Iterator[bytes]:
    """Yield chaque enregistrement (en-tete de 16 octets + donnees) apres
    l'en-tete global deja consomme. S'arrete silencieusement sur un
    dernier enregistrement tronque ; leve ValueError sur une longueur
    aberrante (fichier corrompu -- ne pas le confondre avec une simple
    troncature, qui ne perd que la fin)."""
    while True:
        header = _read_exact_or_none(f, _PCAP_RECORD_HEADER_LEN)
        if header is None:
            return
        incl_len = struct.unpack_from(endian + "I", header, 8)[0]
        if incl_len > _MAX_UNIT_LEN:
            raise ValueError(f"enregistrement pcap corrompu (longueur capturee {incl_len} octets)")
        data = _read_exact_or_none(f, incl_len)
        if data is None:
            return
        yield header + data


def _iter_pcapng_blocks(f: BinaryIO) -> Iterator[tuple[int, bytes]]:
    """Yield (type, octets bruts du bloc complet) pour chaque bloc pcapng.
    L'endianness est relue a chaque Section Header Block (un fichier peut
    concatener plusieurs sections d'endianness differentes). Meme regle de
    troncature/corruption que _iter_pcap_records."""
    endian = "<"
    while True:
        head = _read_exact_or_none(f, 8)
        if head is None:
            return
        if head[:4] == _PCAPNG_MAGIC:
            bom = _read_exact_or_none(f, 4)
            if bom is None:
                return
            if bom == _BOM_LE:
                endian = "<"
            elif bom == _BOM_BE:
                endian = ">"
            else:
                raise ValueError("pcapng corrompu (byte-order magic invalide dans un Section Header Block)")
            head += bom
        block_type, total_len = struct.unpack_from(endian + "II", head, 0)
        if total_len < len(head) + 4 or total_len % 4 or total_len > _MAX_UNIT_LEN:
            raise ValueError(f"bloc pcapng corrompu (type {block_type:#x}, longueur {total_len} octets)")
        rest = _read_exact_or_none(f, total_len - len(head))
        if rest is None:
            return
        yield block_type, head + rest


def has_packets(path: str) -> bool:
    """True si le fichier contient au moins un paquet. Format non reconnu :
    True (on ne sait pas dire -- l'appelant ne doit pas jeter un fichier
    qu'il ne comprend pas)."""
    fmt = detect_format(path)
    with open(path, "rb", buffering=_READ_BUFFER) as f:
        if fmt is None:
            logger.debug("has_packets: {} format inconnu, supposé non vide", path)
            return True
        if fmt == FORMAT_PCAPNG:
            return any(block_type in _PACKET_BLOCKS for block_type, _raw in _iter_pcapng_blocks(f))
        header = _read_exact_or_none(f, _PCAP_HEADER_LEN)
        if header is None:
            return False
        endian = _PCAP_MAGICS[header[:4]][0]
        logger.debug("has_packets: {} (pcap)", path)
        return next(_iter_pcap_records(f, endian), None) is not None


@dataclass(frozen=True)
class InterfaceRecord:
    """Une interface de capture : l'unique interface implicite d'un pcap
    classique, ou un Interface Description Block pcapng (index = rang
    d'apparition dans le fichier, toutes sections confondues).

    snaplen == 0 signifie "pas de limite". received/dropped_by_interface/
    dropped_by_os valent None tant qu'aucun ISB ne les a renseignes -- ce
    qui n'est PAS la meme chose que 0 (voir CaptureInfo.has_drops)."""

    index: int
    linktype: int
    snaplen: int
    name: str | None = None
    received: int | None = None
    dropped_by_interface: int | None = None
    dropped_by_os: int | None = None


@dataclass(frozen=True)
class CaptureStructure:
    """Ce que le cadrage binaire seul permet de dire d'un fichier de
    capture : format, version ("2.4" pour un pcap, "1.0" pour un pcapng)
    et interfaces. Aucune donnee de paquet."""

    fmt: str
    version: str
    interfaces: tuple[InterfaceRecord, ...]


def _iter_options(data: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
    """Yield (code, valeur) pour chaque option pcapng de `data` (la zone
    d'options d'un bloc, sans l'octet de longueur finale). S'arrete a
    opt_endofopt ou sur une option tronquee -- on garde ce qui precede.

    Iterere sur les options TLV (type 2, length 2, value padded a 4
    octets) d'un bloc pcapng. Renvoie (code, value) pour chaque option."""
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, offset)
        if code == _OPT_ENDOFOPT:
            return
        offset += 4
        if offset + length > len(data):
            return
        value = data[offset : offset + length]
        yield code, value
        # padding a 4 octets (aligne sur 32 bits)
        offset += (length + 3) & ~3


def _read_pcapng_structure(f: BinaryIO) -> CaptureStructure | None:
    interfaces: list[InterfaceRecord] = []
    version: str | None = None
    endian = "<"
    section_base = 0  # les interface_id des ISB repartent de 0 a chaque section
    try:
        for block_type, raw in _iter_pcapng_blocks(f):
            if block_type == _BLOCK_SHB:
                endian = "<" if raw[8:12] == _BOM_LE else ">"
                major, minor = struct.unpack_from(endian + "HH", raw, 12)
                version = version or f"{major}.{minor}"
                section_base = len(interfaces)
            elif block_type == _BLOCK_IDB:
                linktype, _reserved, snaplen = struct.unpack_from(endian + "HHI", raw, 8)
                name = None
                for code, value in _iter_options(raw[16:-4], endian):
                    if code == _OPT_IF_NAME:
                        name = value.decode("utf-8", "replace") or None
                interfaces.append(InterfaceRecord(len(interfaces), linktype, snaplen, name))
            elif block_type == _BLOCK_ISB:
                slot = section_base + struct.unpack_from(endian + "I", raw, 8)[0]
                if slot >= len(interfaces):
                    continue  # ISB d'une interface inconnue : fichier incoherent, ignore
                fields: dict[str, int] = {}
                for code, value in _iter_options(raw[20:-4], endian):
                    if len(value) != 8:
                        continue
                    counter = struct.unpack(endian + "Q", value)[0]
                    if code == _OPT_ISB_IFRECV:
                        fields["received"] = counter
                    elif code == _OPT_ISB_IFDROP:
                        fields["dropped_by_interface"] = counter
                    elif code == _OPT_ISB_OSDROP:
                        fields["dropped_by_os"] = counter
                # Compteurs cumulatifs : le DERNIER ISB d'une interface donne les
                # totaux ; un ISB qui omet une option ne remet pas l'ancienne a None.
                interfaces[slot] = replace(interfaces[slot], **fields)
    except (ValueError, struct.error) as exc:
        logger.warning(
            "_read_pcapng_structure: bloc corrompu, lecture arrêtée après {} interface(s) ({})", len(interfaces), exc
        )
        # bloc corrompu : on garde les interfaces lues jusque-la (comme une troncature)
    logger.debug("_read_pcapng_structure: version={} {} interface(s)", version, len(interfaces))
    if version is None:
        return None
    return CaptureStructure(FORMAT_PCAPNG, version, tuple(interfaces))


def read_structure(path: str) -> CaptureStructure | None:
    """Format, version et interfaces de `path` d'apres le seul cadrage
    binaire, ou None si le format n'est pas reconnu (fichier compresse,
    autre format, vide, tronque avant son premier en-tete). Leve OSError
    si le fichier est illisible.

    Un pcap classique ne porte aucune statistique : ses compteurs restent
    None. Un pcapng en porte si l'outil de capture a ecrit des Interface
    Statistics Blocks (dumpcap/tshark le font, tcpdump et editcap non)."""
    fmt = detect_format(path)
    if fmt is None:
        logger.debug("read_structure: {} format non reconnu", path)
        return None
    with open(path, "rb", buffering=_READ_BUFFER) as f:
        if fmt == FORMAT_PCAPNG:
            return _read_pcapng_structure(f)
        header = _read_exact_or_none(f, _PCAP_HEADER_LEN)
        if header is None:
            return None
        endian = _PCAP_MAGICS[header[:4]][0]
        major, minor, _thiszone, _sigfigs, snaplen, linktype = struct.unpack_from(endian + "HHiIII", header, 4)
        logger.debug("read_structure: {} {} {}.{} linktype={}", path, fmt, major, minor, linktype)
        return CaptureStructure(fmt, f"{major}.{minor}", (InterfaceRecord(0, linktype, snaplen),))


class _SegmentSink:
    """Ecrit des blocs dans des fichiers successifs `<prefix>_NNNNN<ext>`.

    `preamble` = octets a recopier en tete de CHAQUE segment (en-tete
    global pcap ; SHB + IDB + DSB courants en pcapng) pour que chaque
    segment soit un fichier autonome lisible seul.

    Un segment contient toujours au moins un paquet : un paquet plus gros
    que la limite a donc son propre segment (qui depasse alors la limite --
    un paquet ne se coupe pas)."""

    def __init__(self, prefix: str, ext: str, max_bytes: int):
        self._prefix = prefix
        self._ext = ext
        self._max_bytes = max_bytes
        self.preamble: list[bytes] = []
        self.paths: list[str] = []
        self._file: BinaryIO | None = None
        self._size = 0
        self._packets = 0

    @property
    def is_open(self) -> bool:
        return self._file is not None

    def _roll(self) -> None:
        self._close_current()
        path = f"{self._prefix}_{len(self.paths):05d}{self._ext}"
        # "xb" : refuse d'ecraser un fichier existant (defense en profondeur,
        # split_capture verifie deja le repertoire en amont).
        self._file = open(path, "xb")  # noqa: SIM115 -- ferme par _close_current/close
        logger.debug("_SegmentSink: nouveau segment {}", path)
        self.paths.append(path)
        self._size = 0
        self._packets = 0
        for block in self.preamble:
            self._file.write(block)
            self._size += len(block)

    def _close_current(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def write(self, raw: bytes, *, is_packet: bool) -> None:
        overflow = self._size + len(raw) > self._max_bytes
        if self._file is None or (is_packet and self._packets > 0 and overflow):
            self._roll()
        assert self._file is not None  # garanti par _roll
        self._file.write(raw)
        self._size += len(raw)
        if is_packet:
            self._packets += 1

    def write_if_open(self, raw: bytes) -> None:
        """Pour un bloc de preambule (SHB/IDB/DSB) : s'il y a un segment en
        cours, le bloc y est ecrit aussi ; sinon il ne sera ecrit que dans le
        preambule du prochain segment."""
        if self._file is not None:
            self._file.write(raw)
            self._size += len(raw)

    def close(self) -> None:
        # Un dernier segment sans aucun paquet (ex : fichier qui ne contient
        # que des blocs de statistiques) n'a pas de raison d'exister.
        if self._file is not None and self._packets == 0:
            self._close_current()
            logger.debug("_SegmentSink.close: dernier segment vide supprimé ({})", self.paths[-1])
            os.remove(self.paths.pop())
        self._close_current()

    def abort(self) -> None:
        """Ferme et supprime tous les segments deja ecrits (echec en cours
        de route : un jeu de segments partiel serait trompeur)."""
        logger.debug("_SegmentSink.abort: {} segment(s) à supprimer", len(self.paths))
        self._close_current()
        for path in self.paths:
            with contextlib.suppress(OSError):
                os.remove(path)
        self.paths.clear()


def split_by_size(path: str, out_prefix: str, max_bytes: int) -> list[str]:
    """Decoupe `path` en segments `<out_prefix>_00000.<ext>`, `_00001`, ...
    de `max_bytes` octets au plus (taille du FICHIER segment, en-tetes
    recopies compris), dans l'ordre d'origine des paquets, et renvoie la
    liste des chemins crees, dans l'ordre.

    Exception unique a la limite : un segment contient toujours au moins un
    paquet, donc un paquet plus gros que `max_bytes` (a plus forte raison
    avec un `max_bytes` inferieur a un paquet + les en-tetes) produit un
    segment a lui seul, plus gros que la limite.

    Leve ValueError si `max_bytes` < 1, si le format n'est pas pcap/pcapng
    non compresse, ou si le fichier est corrompu (longueur aberrante) ; dans
    ce dernier cas les segments deja ecrits sont supprimes. Un fichier
    simplement TRONQUE (capture interrompue) n'est pas une erreur : le
    dernier enregistrement incomplet est ignore.
    """
    if max_bytes < 1:
        raise ValueError("max_bytes doit etre >= 1")
    fmt = detect_format(path)
    if fmt is None:
        raise ValueError(
            f"{path} : format non reconnu -- le decoupage par taille exige un fichier pcap/pcapng non compresse"
        )
    logger.debug("split_by_size: {} ({}) -> {}_*, {} octets max", path, fmt, out_prefix, max_bytes)
    sink = _SegmentSink(out_prefix, format_extension(fmt), max_bytes)
    try:
        with open(path, "rb", buffering=_READ_BUFFER) as f:
            if fmt == FORMAT_PCAPNG:
                _split_pcapng(f, sink)
            else:
                _split_pcap(f, sink)
        sink.close()
    except BaseException as exc:
        # l'appelant journalise l'erreur remontee ; ici on trace le nettoyage
        logger.warning(
            "split_by_size: {} interrompu ({}), {} segment(s) partiel(s) supprimé(s)",
            path,
            type(exc).__name__,
            len(sink.paths),
        )
        sink.abort()
        raise
    logger.debug("split_by_size: {} segment(s)", len(sink.paths))
    return sink.paths


def _split_pcap(f: BinaryIO, sink: _SegmentSink) -> None:
    header = _read_exact_or_none(f, _PCAP_HEADER_LEN)
    if header is None:
        return
    endian = _PCAP_MAGICS[header[:4]][0]
    sink.preamble = [header]
    for record in _iter_pcap_records(f, endian):
        sink.write(record, is_packet=True)


def _split_pcapng(f: BinaryIO, sink: _SegmentSink) -> None:
    for block_type, raw in _iter_pcapng_blocks(f):
        if block_type == _BLOCK_SHB:
            # Nouvelle section : les interfaces precedentes ne valent plus.
            sink.preamble = [raw]
            sink.write_if_open(raw)
        elif block_type in (_BLOCK_IDB, _BLOCK_DSB):
            # IDB : les paquets suivants y font reference par numero, chaque
            # segment doit donc les porter tous. DSB : secrets de dechiffrement,
            # utiles dans chaque segment pour qu'il reste lisible seul.
            sink.preamble.append(raw)
            sink.write_if_open(raw)
        else:
            sink.write(raw, is_packet=block_type in _PACKET_BLOCKS)


# -- first_timestamp --------------------------------------------------------


def first_timestamp(path: str) -> float:
    """Timestamp epoch du premier paquet de `path` (pcap, nsecpcap ou
    pcapng), lu directement du cadrage binaire sans tshark. Leve
    FileNotFoundError si le fichier est absent, ValueError si le format
    n'est pas reconnu ou si la capture ne contient aucun paquet."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"capture introuvable : {path}")
    fmt = detect_format(path)
    if fmt is None:
        raise ValueError(f"format non reconnu : {path}")
    logger.debug("first_timestamp: {} ({})", path, fmt)
    with open(path, "rb") as f:
        if fmt == FORMAT_PCAPNG:
            return _first_timestamp_pcapng(f)
        # pcap ou nsecpcap : lire l'en-tete global pour l'endianness
        header = f.read(_PCAP_HEADER_LEN)
        if len(header) < _PCAP_HEADER_LEN:
            raise ValueError("fichier pcap tronque (en-tete global incomplet)")
        endian, fmt_name = _PCAP_MAGICS[header[:4]]
        nsec = fmt_name == FORMAT_NSECPCAP
        return _first_timestamp_pcap(f, endian, nsec)


def _first_timestamp_pcap(f: BinaryIO, endian: str, nsec: bool) -> float:
    """Lit le timestamp du premier paquet d'un pcap classique. f est
    positionne juste apres l'en-tete global (24 octets). Renvoie un
    timestamp epoch en secondes (float)."""
    header = f.read(_PCAP_RECORD_HEADER_LEN)
    if len(header) < _PCAP_RECORD_HEADER_LEN:
        raise ValueError("pcap sans paquet (en-tete global seul)")
    ts_sec, ts_frac = struct.unpack_from(endian + "II", header, 0)
    divisor = 1e9 if nsec else 1e6
    return ts_sec + ts_frac / divisor


def _first_timestamp_pcapng(f: BinaryIO) -> float:
    """Lit le timestamp du premier paquet (Enhanced Packet Block) d'un
    pcapng. f est au debut du fichier. Renvoie un timestamp epoch en
    secondes (float). Leve ValueError si aucun paquet n'est trouve."""
    endian = "<"
    tsresol_shift = 6  # microsecondes par defaut (2^6 = 64)
    for block_type, raw in _iter_pcapng_blocks(f):
        if block_type == _BLOCK_SHB:
            bom = raw[8:12]
            endian = "<" if bom == _BOM_LE else ">"
        elif block_type == _BLOCK_IDB:
            # if_tsresol (option 9) : log2 du diviseur. Defaut : 6 (us).
            for code, value in _iter_options(raw[16:-4], endian):
                if code == 9 and len(value) >= 1:
                    tsresol_shift = value[0]
        elif block_type == _BLOCK_EPB:
            # EPB : ts_high (4) + ts_low (4) apres interface_id (4)
            if len(raw) < 20:
                continue
            ts_high, ts_low = struct.unpack_from(endian + "II", raw, 12)
            ts_64 = (ts_high << 32) | ts_low
            divisor = 2**tsresol_shift
            logger.debug("_first_timestamp_pcapng: résolution 2^-{} s", tsresol_shift)
            return ts_64 / divisor
    raise ValueError("pcapng sans paquet (aucun Enhanced Packet Block)")
