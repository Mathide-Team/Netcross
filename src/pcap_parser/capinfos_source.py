"""
pcap_parser.capinfos_source -- lecture du commentaire de SECTION pcapng
(Section Header Block, "capture comment") d'un fichier de capture, via
`capinfos -k`.

Ne pas confondre avec le commentaire de PAQUET (Enhanced Packet Block,
option opt_comment) -- celui-la est une donnee de paquet comme une
autre, deja lue par tshark -T ek et exposee via RawPacket.comment (voir
pcap_parser.packet.build_packet). Le commentaire de section est d'une
nature differente : une metadonnee du FICHIER/de la section pcapng
elle-meme, absente par construction du format pcap classique (qui ne
porte aucune notion de commentaire, section ou paquet), et surtout PAS
rattachee a un paquet precis -- rien a en tirer via le flux NDJSON de
ek_source.py, il faut interroger le fichier separement. capinfos (deja
présent dans toute installation tshark/wireshark-cli, meme suite que
tshark) fait exactement ce travail -- pas de raison de le reimplementer
via un post-dissecteur Lua tshark (l'autre piste envisagee par l'issue
#159/Job 39).

Meme discipline que ek_source.py pour le sous-processus (shutil.which,
timeout, jamais de -> texte brut suppose bien forme), mais avec une
tolerance plus large aux erreurs : un commentaire de section est une
annotation operateur FACULTATIVE, son absence ou l'echec de sa lecture
(capinfos non installe, fichier illisible, timeout) ne doit jamais
interrompre l'analyse -- contrairement a TsharkNotFoundError/TsharkError
cote ek_source.py (tshark, lui, est indispensable au coeur du pipeline),
read_capture_comment() ne leve donc jamais : absence de commentaire et
echec de lecture sont indiscernables pour l'appelant, None dans les deux
cas.

Job 38/issue #158 : read_capture_info() etend ce module aux metadonnees de
la capture elle-meme (format, snaplen, link type, nombre de paquets et
d'octets, duree, materiel/application de capture, interfaces et paquets
perdus). Deux ecarts assumes avec le texte de l'issue, verifies
empiriquement sur capinfos 4.2.2 : capinfos n'a AUCUNE sortie JSON (le `capinfos
-m -T json` de l'issue n'existe pas ; le rapport tabulaire `-T`, separe par
des TAB, est la seule sortie structuree) et n'affiche PAS les compteurs de paquets
perdus des Interface Statistics Blocks -- ceux-ci sont lus par
pcap_parser.capfile.read_structure(). Meme tolerance que
read_capture_comment() : jamais d'exception, None si rien de fiable.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from dataclasses import dataclass

from loguru import logger as _loguru_logger

from pcap_parser.capfile import CaptureStructure, InterfaceRecord, read_structure

# pcap_parser reste independant de netcross_core (contrat import-linter) :
# loguru directement, lie au nom du module.
logger = _loguru_logger.bind(name=__name__)

# Prefixe de la ligne portant le commentaire de section dans la sortie
# "long report" (par defaut) de `capinfos -k`. Verifie empiriquement
# (capinfos 4.2.2, pcapng synthetique commente via `editcap
# --capture-comment`, voir la PR de Job 39/issue #159) : absente du
# rapport si le fichier n'a pas de commentaire de section (pcap
# classique, ou pcapng qui n'en porte simplement pas) -- pas de ligne
# avec une valeur vide, la ligne elle-meme n'apparait pas. Un
# commentaire multi-ligne est deja aplati par capinfos sur une seule
# ligne (retours a la ligne internes remplaces par des espaces), donc
# un parsing ligne par ligne suffit, pas besoin de gerer une
# continuation.
_COMMENT_PREFIX = "Capture comment:"

# Le fichier peut etre volumineux (capinfos doit le parcourir pour
# construire son rapport, meme s'il n'a besoin ici que de -k) -- borne
# large mais finie, meme raisonnement que le reste de ce projet
# (jamais bloquer indefiniment sur un sous-processus externe).
_TIMEOUT_SECONDS = 30


def _capinfos_path() -> str | None:
    """Contrairement a pcap_parser.ek_source._tshark_path(), ne leve
    jamais si l'executable est absent -- capinfos n'est qu'un
    complement facultatif (commentaire de section), pas un composant
    central du pipeline comme tshark : son absence degrade simplement
    vers "pas de commentaire de section disponible", jamais une erreur
    remontee a l'appelant."""
    logger.debug("_capinfos_path: {}", shutil.which("capinfos") or "introuvable")
    return shutil.which("capinfos")


def _parse_capture_comment(stdout: str) -> str | None:
    """Fonction pure (aucun sous-processus) : extrait le commentaire de
    section du texte deja produit par `capinfos -k`, ou None si la
    ligne "Capture comment:" est absente. Separee de read_capture_comment()
    ci-dessous pour rester testable sans capinfos installe -- meme
    raison d'etre que _build_args()/_iter_ndjson_records() dans
    ek_source.py, testes independamment de tout sous-processus reel."""
    for line in stdout.splitlines():
        if line.startswith(_COMMENT_PREFIX):
            return line[len(_COMMENT_PREFIX) :].strip() or None
    logger.debug("_parse_capture_comment: aucun commentaire")
    return None


def read_capture_comment(path: str) -> str | None:
    """Lit le commentaire de section pcapng de `path` via `capinfos -k`.

    Renvoie None dans TOUS les cas ou aucun commentaire fiable n'est
    disponible : capinfos non installe, fichier introuvable/illisible/
    corrompu (capinfos sort alors en erreur sur stderr sans rien
    produire sur stdout concernant un commentaire -- verifie
    empiriquement, code de retour non nul mais jamais d'exception ici,
    voir la PR de Job 39), timeout, format pcap classique sans support
    des commentaires, ou pcapng sans commentaire de section. Ces cas ne
    sont volontairement pas distingues (pas de log, pas d'exception) :
    un commentaire de section est une simple annotation operateur, son
    absence est le cas normal, pas une erreur a signaler."""
    capinfos = _capinfos_path()
    if capinfos is None:
        logger.debug("read_capture_comment: capinfos absent, pas de commentaire lu")
        return None
    try:
        proc = subprocess.run(
            [capinfos, "-k", path],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("read_capture_comment: capinfos -k {} impossible ({})", path, exc)
        return None
    logger.debug("read_capture_comment: {} code {}", path, proc.returncode)
    return _parse_capture_comment(proc.stdout)


# -- Job 38/issue #158 : metadonnees de capture ---------------------------

# -T : rapport tabulaire (un en-tete + une ligne, separes par des TAB -- le
# separateur par defaut, choisi a dessein : avec `-m` (virgule) OU `-Q`
# (guillemets) un champ texte libre contenant une virgule ou un guillemet
# decalerait les colonnes ou casserait le csv, verifie sur un commentaire
# `sonde, "A" 1`) ; -S : dates en secondes depuis l'epoque (sinon capinfos
# les affiche en heure LOCALE, ambigue) ; -K : sans la colonne "Capture
# comment", texte libre deja couvert par read_capture_comment().
_TABLE_ARGS = ("-T", "-S", "-K")

# Valeurs par lesquelles capinfos dit "pas d'information" dans le rapport.
_NO_VALUE = frozenset({"", "n/a", "(not set)"})


@dataclass(frozen=True)
class CaptureInfo:
    """Metadonnees d'un fichier de capture (issue #158) -- qualite de la
    capture elle-meme, pas contenu du trafic. Tout champ inconnu vaut None.

    packet_count/byte_count : nombre de paquets et somme de leurs longueurs
    (capinfos "Data size"). snaplen : limite de capture, None si absente.
    start_time/end_time : secondes depuis l'epoque. interfaces : vide si le
    format du fichier n'a pas pu etre lu (ex. fichier compresse)."""

    path: str
    file_type: str | None = None
    version: str | None = None
    encapsulation: str | None = None
    timestamp_precision: str | None = None
    snaplen: int | None = None
    packet_count: int | None = None
    byte_count: int | None = None
    file_size: int | None = None
    duration_seconds: float | None = None
    start_time: float | None = None
    end_time: float | None = None
    strict_time_order: bool | None = None
    hardware: str | None = None
    operating_system: str | None = None
    application: str | None = None
    interfaces: tuple[InterfaceRecord, ...] = ()

    @property
    def dropped_by_interface(self) -> int | None:
        """Total des paquets perdus par les interfaces, ou None si la capture
        ne porte aucune statistique (pcap classique, pcapng sans ISB)."""
        values = [i.dropped_by_interface for i in self.interfaces if i.dropped_by_interface is not None]
        return sum(values) if values else None

    @property
    def dropped_by_os(self) -> int | None:
        """Idem pour les paquets perdus par le systeme d'exploitation."""
        values = [i.dropped_by_os for i in self.interfaces if i.dropped_by_os is not None]
        return sum(values) if values else None

    @property
    def has_drops(self) -> bool | None:
        """True si au moins un paquet a ete perdu (interface ou OS) ; False si
        des statistiques existent et sont toutes a zero ; None si la capture
        n'en embarque aucune -- absence d'INFORMATION, pas absence de perte :
        l'appelant ne doit jamais l'afficher comme 'aucune perte'."""
        counters = [self.dropped_by_interface, self.dropped_by_os]
        known = [c for c in counters if c is not None]
        if not known:
            return None
        return any(c > 0 for c in known)


def _parse_table_report(stdout: str) -> dict[str, str] | None:
    """Fonction pure : l'en-tete et la ligne de valeurs du rapport `-T`
    (colonnes separees par des TAB) sous forme de dict, ou None si la sortie
    n'a pas la forme attendue (vide -- capinfos en echec sur un fichier
    illisible --, ou nombre de colonnes different : on prefere ne rien dire
    que decaler les valeurs). Ne strip pas les lignes : les colonnes
    finales vides comptent."""
    lines = [line for line in stdout.split("\n") if line.strip()]
    logger.debug("_parse_table_report: {} ligne(s) non vide(s)", len(lines))
    if len(lines) < 2:
        return None
    header, row = lines[0].split("\t"), lines[1].split("\t")
    if len(header) != len(row):
        logger.debug("_parse_table_report: en-tête {} colonne(s) / ligne {} colonne(s)", len(header), len(row))
    if len(header) != len(row):
        return None
    return dict(zip(header, row, strict=True))


def _text(value: str | None) -> str | None:
    return None if value is None or value.strip() in _NO_VALUE else value.strip()


def _integer(value: str | None) -> int | None:
    text = _text(value)
    try:
        return int(text) if text is not None else None
    except ValueError:
        logger.debug("_integer: valeur capinfos non entière {!r}", text)
        return None


def _number(value: str | None) -> float | None:
    text = _text(value)
    try:
        return float(text) if text is not None else None
    except ValueError:
        logger.debug("_number: valeur capinfos non numérique {!r}", text)
        return None


def _boolean(value: str | None) -> bool | None:
    text = _text(value)
    return None if text is None else text.lower() == "true"


def _build_capture_info(path: str, fields: dict[str, str], structure: CaptureStructure | None) -> CaptureInfo:
    """Fonction pure : assemble le CaptureInfo depuis le rapport capinfos deja
    parse et, si lisible, le cadrage binaire du fichier."""
    interfaces = structure.interfaces if structure else ()
    snaplen = _integer(fields.get("Packet size limit")) or None  # 0 = pas de limite
    if snaplen is None:
        # pcapng : capinfos ne donne pas de limite au niveau du fichier ("(not
        # set)"), elle est portee par chaque interface.
        limits = [i.snaplen for i in interfaces if i.snaplen]
        snaplen = max(limits) if limits else None
    logger.debug("_build_capture_info: {} snaplen={} {} interface(s)", path, snaplen, len(interfaces))
    return CaptureInfo(
        path=path,
        file_type=_text(fields.get("File type")),
        version=structure.version if structure else None,
        encapsulation=_text(fields.get("File encapsulation")),
        timestamp_precision=_text(fields.get("File time precision")),
        snaplen=snaplen,
        packet_count=_integer(fields.get("Number of packets")),
        byte_count=_integer(fields.get("Data size (bytes)")),
        file_size=_integer(fields.get("File size (bytes)")),
        duration_seconds=_number(fields.get("Capture duration (seconds)")),
        start_time=_number(fields.get("Start time")),
        end_time=_number(fields.get("End time")),
        strict_time_order=_boolean(fields.get("Strict time order")),
        hardware=_text(fields.get("Capture hardware")),
        operating_system=_text(fields.get("Capture oper-sys")),
        application=_text(fields.get("Capture application")),
        interfaces=tuple(interfaces),
    )


def read_capture_info(path: str) -> CaptureInfo | None:
    """Metadonnees de la capture `path` via `capinfos -T` (+ interfaces et
    compteurs de paquets perdus lus par pcap_parser.capfile.read_structure).

    Ne leve jamais, comme read_capture_comment() : None si capinfos est
    absent, si le fichier est introuvable/illisible/dans un format que
    capinfos ne comprend pas, ou en cas de timeout. Si seul le cadrage
    binaire echoue (fichier compresse -- capinfos, lui, sait le lire), les
    champs de capinfos sont renvoyes et `interfaces` reste vide."""
    logger.debug("read_capture_info: {}", path)
    capinfos = _capinfos_path()
    if capinfos is None:
        return None
    try:
        proc = subprocess.run(
            [capinfos, *_TABLE_ARGS, path],
            capture_output=True,
            text=True,
            errors="replace",  # materiel/application de capture : texte libre, pas forcement UTF-8
            timeout=_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("read_capture_info: capinfos {} impossible ({})", path, exc)
        return None
    fields = _parse_table_report(proc.stdout)
    logger.debug("read_capture_info: capinfos code {}, rapport lisible={}", proc.returncode, fields is not None)
    if fields is None:
        return None
    try:
        structure = read_structure(path)
    except (OSError, ValueError, struct.error) as exc:
        logger.warning("read_capture_info: structure de {} illisible ({}), interfaces ignorées", path, exc)
        structure = None
    return _build_capture_info(path, fields, structure)
