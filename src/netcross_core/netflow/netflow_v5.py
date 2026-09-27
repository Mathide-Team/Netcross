"""
netcross_core.netflow.netflow_v5 -- parseur NetFlow v5 (RFC 1568 /
format Cisco historique, le plus repandu et le plus simple des
protocoles vises par cet ADR -- voir docs/adr/netflow-sflow-architecture.md,
Phase 1 du plan d'implementation).

Format binaire, gros-boutiste (network byte order), un datagramme UDP
= un en-tete fixe (24 octets) + N enregistrements de flux (48 octets
chacun, N donne par le champ `count` de l'en-tete) :

En-tete (24 octets) :
    version(u16) count(u16) sys_uptime(u32) unix_secs(u32)
    unix_nsecs(u32) flow_sequence(u32) engine_type(u8) engine_id(u8)
    sampling_interval(u16)

Enregistrement (48 octets) :
    srcaddr(u32) dstaddr(u32) nexthop(u32) input(u16) output(u16)
    dPkts(u32) dOctets(u32) first(u32) last(u32) srcport(u16)
    dstport(u16) pad1(u8) tcp_flags(u8) prot(u8) tos(u8) src_as(u16)
    dst_as(u16) src_mask(u8) dst_mask(u8) pad2(u16)

`first`/`last` sont des compteurs de millisecondes depuis le demarrage
de l'exportateur (SysUptime), pas des timestamps epoch directement
utilisables -- on les convertit via unix_secs/unix_nsecs/sys_uptime de
l'en-tete (meme methode que les outils NetFlow usuels, ex. nfdump).
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Iterator

from netcross_core.logging_config import get_logger
from netcross_core.netflow.models import FlowRecord

logger = get_logger(__name__)

_HEADER = struct.Struct("!HHIIIIBBH")
_RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")

NETFLOW_V5_VERSION = 5


class NetflowV5Error(ValueError):
    """Datagramme NetFlow v5 malforme (trop court, mauvaise version...)."""


def _uptime_ms_to_epoch(uptime_ms: int, unix_secs: int, unix_nsecs: int, sys_uptime: int) -> float:
    """Convertit un compteur `first`/`last` (ms depuis le boot de
    l'exportateur) en timestamp epoch, en utilisant l'ancrage
    unix_secs/unix_nsecs = heure epoch au moment `sys_uptime`."""
    now_epoch = unix_secs + unix_nsecs / 1e9
    delta_ms = sys_uptime - uptime_ms  # anciennete du flux par rapport a "maintenant"
    return now_epoch - delta_ms / 1000.0


def parse_netflow_v5_packet(data: bytes, exporter: str) -> list[FlowRecord]:
    """Decode un datagramme UDP NetFlow v5 complet en liste de
    FlowRecord. `exporter` etiquette la source (ex: adresse IP du
    routeur emetteur) -- voir FlowRecord.exporter dans models.py.

    Leve NetflowV5Error si `data` est trop court ou n'annonce pas la
    version 5 (mauvais port/mauvais protocole branche par erreur sur
    le collecteur -- mieux vaut echouer fort que produire des
    FlowRecord silencieusement corrompus).
    """
    if len(data) < _HEADER.size:
        logger.trace("parse_netflow_v5_packet: refus, NetflowV5Error")
        raise NetflowV5Error(f"datagramme trop court pour un en-tete NetFlow v5 : {len(data)} octets")

    version, count, sys_uptime, unix_secs, unix_nsecs, flow_sequence, engine_type, engine_id, sampling = (
        _HEADER.unpack_from(data, 0)
    )
    if version != NETFLOW_V5_VERSION:
        logger.trace("parse_netflow_v5_packet: refus, NetflowV5Error")
        raise NetflowV5Error(f"version NetFlow inattendue : {version} (attendu {NETFLOW_V5_VERSION})")

    expected_size = _HEADER.size + count * _RECORD.size
    if len(data) < expected_size:
        logger.trace("parse_netflow_v5_packet: refus, NetflowV5Error")
        raise NetflowV5Error(
            f"datagramme tronque : {len(data)} octets recus, {expected_size} attendus pour {count} enregistrements"
        )

    records: list[FlowRecord] = []
    offset = _HEADER.size
    for _ in range(count):
        (
            srcaddr,
            dstaddr,
            nexthop,
            _input_idx,
            _output_idx,
            d_pkts,
            d_octets,
            first,
            last,
            srcport,
            dstport,
            _pad1,
            tcp_flags,
            prot,
            tos,
            src_as,
            dst_as,
            src_mask,
            dst_mask,
            _pad2,
        ) = _RECORD.unpack_from(data, offset)

        records.append(
            FlowRecord(
                exporter=exporter,
                version=NETFLOW_V5_VERSION,
                src_addr=str(ipaddress.IPv4Address(srcaddr)),
                dst_addr=str(ipaddress.IPv4Address(dstaddr)),
                src_port=srcport,
                dst_port=dstport,
                protocol=prot,
                packets=d_pkts,
                octets=d_octets,
                start_ts=_uptime_ms_to_epoch(first, unix_secs, unix_nsecs, sys_uptime),
                end_ts=_uptime_ms_to_epoch(last, unix_secs, unix_nsecs, sys_uptime),
                tcp_flags=tcp_flags,
                tos=tos,
                src_as=src_as,
                dst_as=dst_as,
                src_mask=src_mask,
                dst_mask=dst_mask,
                input_snmp=_input_idx,
                output_snmp=_output_idx,
                next_hop=str(ipaddress.IPv4Address(nexthop)),
                sampling_interval=sampling,
                engine_type=engine_type,
                engine_id=engine_id,
                flow_sequence=flow_sequence,
            )
        )
        offset += _RECORD.size

    return records


def iter_netflow_v5_file(path: str, exporter: str | None = None) -> Iterator[FlowRecord]:
    """Lit un fichier contenant des datagrammes NetFlow v5 concatenes
    tels que captures bruts (ex: `tcpdump -w` filtre sur le port
    collecteur, rejoue via `tcpdump -r ... -w -` sans en-tetes pcap --
    voir tests pour le format exact attendu). Mode fichier de l'ADR
    (alternative au mode collecteur UDP live) : utile pour le rejeu et
    les tests, sans dependance a un vrai exportateur.

    Chaque datagramme doit faire exactement la taille annoncee par son
    propre en-tete (count) ; un fichier est simplement la concatenation
    de N datagrammes de ce type, sans separateur.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    label = exporter or path
    offset = 0
    while offset < len(data):
        remaining = data[offset:]
        if len(remaining) < _HEADER.size:
            break
        count = struct.unpack_from("!H", remaining, 2)[0]
        packet_size = _HEADER.size + count * _RECORD.size
        if len(remaining) < packet_size:
            logger.trace("iter_netflow_v5_file: refus, NetflowV5Error")
            raise NetflowV5Error(
                f"{path}: datagramme tronque en fin de fichier (offset {offset}, "
                f"{len(remaining)} octets restants, {packet_size} attendus)"
            )
        yield from parse_netflow_v5_packet(remaining[:packet_size], exporter=label)
        offset += packet_size
