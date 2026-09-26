"""
pcap_parser -- decodage de captures reseau via tshark -T ek (moteur
Wireshark en ligne de commande).

Package independant, sans dependance a netcross_core : reutilisable
tel quel dans n'importe quel projet ayant besoin de decoder des
paquets reseau (RTP/DHCP/SIP, tunnels VLAN/MPLS/GRE/VXLAN/GTP-U/
ERSPAN/CAPWAP) sans avoir a reimplementer les dissecteurs a la main.

Organisation en couches (bas en haut) :
    ek_source   -- E/S : subprocess tshark, flux NDJSON (fichier ou live)
    capfile     -- cadrage binaire pcap/pcapng (sans dissection), pour split_capture
    ek_fields   -- acces bas niveau aux champs EK (couches empilees, hex/int)
    tunnels     -- detection d'encapsulation + selection de la couche interne
    protocols   -- RTP / DHCP / SIP (lecture des champs deja disseques + repli heuristique)
    packet      -- assemblage du RawPacket normalise (dont RawPacket.comment,
                   commentaire de PAQUET pcapng -- Job 39)
    capinfos_source -- E/S separee : subprocess capinfos, commentaire de SECTION
                   pcapng (metadonnee de fichier, pas de paquet -- Job 39) et
                   metadonnees de capture : format, snaplen, paquets perdus (Job 38)
    capture     -- API publique : parse_capture / parse_captures_parallel / iter_live
                   (+ merge_captures : fusion de fichiers via mergecap, sans decodage
                   + replay_capture : rejeu de trafic via tcpreplay, sans decodage
                   + split_capture : decoupage par duree, nombre de paquets ou taille
                   + iter_live_multi : capture simultanee sur plusieurs interfaces)

Utilisation typique :

    from pcap_parser import parse_capture, iter_live

    packets = parse_capture("lan.pcapng")          # lecture d'un fichier
    for pkt in iter_live("eth0"):                    # capture en direct
        ...

    from pcap_parser import split_capture

    segments = split_capture("gros.pcapng", "segments/", by="time", value=60.0)

    from pcap_parser import iter_live_multi

    # capture simultanee sur plusieurs interfaces : (label, interface)
    for label, pkt in iter_live_multi([("LAN", "eth0"), ("WAN", "eth1")]):
        ...

Usage en tant que bibliotheque (issue #446)
-------------------------------------------

pcap_parser est silencieux par defaut (loguru desactive pour ce package),
warnings et erreurs compris. Pour voir ses logs, au choix :

    from netcross_core.logging_config import configure_logging
    configure_logging()           # active aussi pcap_parser

    # ou directement via loguru, APRES l'import de pcap_parser (sinon le
    # disable ci-dessous annule le enable) :
    import pcap_parser
    from loguru import logger
    logger.enable("pcap_parser")

Voir docs/journalisation.md.
"""

from loguru import logger as _loguru_logger

from pcap_parser.capfile import first_timestamp
from pcap_parser.capinfos_source import CaptureInfo, read_capture_comment, read_capture_info
from pcap_parser.capture import (
    CaptureRingBuffer,
    TcpreplayError,
    TcpreplayNotFoundError,
    adjust_timestamps,
    convert_capture,
    export_csv,
    export_filtered,
    export_json,
    iter_live,
    iter_live_multi,
    merge_captures,
    parse_capture,
    parse_captures_parallel,
    replay_capture,
    split_capture,
)
from pcap_parser.ek_source import TsharkError, TsharkNotFoundError
from pcap_parser.packet import RawPacket
from pcap_parser.protocols import (
    compute_mos,
    extract_dhcp,
    extract_dns,
    extract_rtp,
    extract_sip,
    extract_tls_certificate,
)
from pcap_parser.tunnels import detect_encapsulation, is_tunnel, select_innermost_layers

# pcap_parser reste independant de netcross_core (contrat import-linter) :
# loguru directement, lie au nom du module.
logger = _loguru_logger.bind(name=__name__)

# Issue #446 : pcap_parser est une bibliotheque reutilisable. Sans
# configure_logging(), loguru garde son handler par defaut (stderr, DEBUG).
# On desactive pcap_parser pour qu'il soit silencieux par defaut ;
# configure_logging() le reactive via logger.enable("pcap_parser").
# Voir https://loguru.readthedocs.io/en/stable/overview.html#suitable-for-scripts-and-libraries
_loguru_logger.disable("pcap_parser")

__all__ = [
    "CaptureInfo",
    "CaptureRingBuffer",
    "RawPacket",
    "TcpreplayError",
    "TcpreplayNotFoundError",
    "TsharkError",
    "TsharkNotFoundError",
    "adjust_timestamps",
    "compute_mos",
    "convert_capture",
    "detect_encapsulation",
    "export_csv",
    "export_filtered",
    "export_json",
    "extract_dhcp",
    "extract_dns",
    "extract_rtp",
    "extract_sip",
    "extract_tls_certificate",
    "first_timestamp",
    "is_tunnel",
    "iter_live",
    "iter_live_multi",
    "merge_captures",
    "parse_capture",
    "parse_captures_parallel",
    "read_capture_comment",
    "read_capture_info",
    "replay_capture",
    "select_innermost_layers",
    "split_capture",
]
