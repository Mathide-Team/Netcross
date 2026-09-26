"""
netcross_core.parsing -- adaptateur entre pcap_parser (decodage via
tshark -T ek) et le modele Pkt de netcross_core.

Tout le decodage protocolaire (tunnels, RTP/DHCP/SIP, gestion des
couches empilees...) vit desormais dans le package pcap_parser,
independant de netcross_core -- voir sa documentation. Ce module ne
fait que deux choses :
  1. attacher le label du point de capture a chaque RawPacket (concept
     d'analyse multi-points propre a netcross_core, absent de
     pcap_parser) et le convertir en Pkt ;
  2. conserver EXACTEMENT la meme API publique que l'ancienne version
     de ce module (memes noms de fonctions, meme ordre de
     parametres, meme comportement d'erreur) pour que __init__.py,
     analysis.py, report_text.py etc. n'aient rien a changer.

API publique inchangee : parse_capture(label, path, raise_on_error),
parse_captures_parallel(captures, max_workers), parse_live, parse_rtp,
parse_sip, compute_mos, detect_encapsulation ; seuls ajouts : parse_live_multi
(capture simultanee sur plusieurs interfaces) puis read_capture_comments
(Job 39, issue #159) -- seule fonction de ce module qui ne convertit PAS de
RawPacket : elle lit le commentaire de section pcapng (metadonnee du
FICHIER, pas d'un paquet) de chaque capture et y attache le label, meme
raison d'etre que le point 1 ci-dessus mais appliquee a pcap_parser.
capinfos_source plutot qu'a RawPacket/Pkt. (Le DHCP est lu
directement depuis les paquets bruts par analysis.py, il n'y a pas de
parse_dhcp() ici ; le choix de la couche la plus interne vit dans
pcap_parser.tunnels.select_innermost_layers.)
"""

import sys

import pcap_parser
from netcross_core.application.banners import extract_banners
from netcross_core.fingerprint.report import compute_pkt_fingerprints
from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt
from pcap_parser.capinfos_source import read_capture_comment
from pcap_parser.ek_source import TsharkError, TsharkNotFoundError
from pcap_parser.packet import RawPacket
from pcap_parser.protocols import compute_mos

logger = get_logger(__name__)
__all__ = [
    "compute_mos",
    "detect_encapsulation",
    "parse_capture",
    "parse_captures_parallel",
    "parse_live",
    "parse_live_multi",
    "parse_rtp",
    "parse_sip",
    "read_capture_comments",
]


def _to_pkt(label: str, raw: RawPacket) -> Pkt:
    fingerprints = compute_pkt_fingerprints(raw.proto, raw.sport, raw.dport, raw.payload)
    return Pkt(
        point=label,
        ts=raw.ts,
        frame_number=raw.frame_number,
        proto=raw.proto,
        src=raw.src,
        dst=raw.dst,
        sport=raw.sport,
        dport=raw.dport,
        length=raw.length,
        ttl=raw.ttl,
        dscp=raw.dscp,
        ecn=raw.ecn,
        seq=raw.seq,
        ack=raw.ack,
        window=raw.window,
        flags=raw.flags,
        key_id=raw.key_id,
        payload_hash=raw.payload_hash,
        ip_id=raw.ip_id,
        is_fragment=raw.is_fragment,
        df=raw.df,
        is_retransmission=raw.is_retransmission,
        is_fast_retransmission=raw.is_fast_retransmission,
        is_spurious_retransmission=raw.is_spurious_retransmission,
        mss_val=raw.mss_val,
        wscale_shift=raw.wscale_shift,
        sack_permitted=raw.sack_permitted,
        icmp_type=raw.icmp_type,
        icmp_code=raw.icmp_code,
        icmpv6_type=raw.icmpv6_type,
        icmpv6_code=raw.icmpv6_code,
        arp_opcode=raw.arp_opcode,
        arp_sender_mac=raw.arp_sender_mac,
        arp_is_gratuitous=raw.arp_is_gratuitous,
        stp_bpdu_type=raw.stp_bpdu_type,
        stp_flags_tc=raw.stp_flags_tc,
        stp_root_id=raw.stp_root_id,
        tls_cert_not_before=raw.tls_cert_not_before,
        tls_cert_not_after=raw.tls_cert_not_after,
        tls_cert_san=raw.tls_cert_san,
        tls_cert_serial=raw.tls_cert_serial,
        tls_client_hello=raw.tls_client_hello,
        tls_server_hello=raw.tls_server_hello,
        tls_application_data=raw.tls_application_data,
        vlan_id=raw.vlan_id,
        vlan_prio=raw.vlan_prio,
        is_rtp=raw.is_rtp,
        rtp_seq=raw.rtp_seq,
        rtp_ts=raw.rtp_ts,
        rtp_ssrc=raw.rtp_ssrc,
        encap_tags=raw.encap_tags,
        dhcp_xid=raw.dhcp_xid,
        dhcp_msg_type=raw.dhcp_msg_type,
        dhcp_server_id=raw.dhcp_server_id,
        dhcp_vendor_class=raw.dhcp_vendor_class,
        sip_call_id=raw.sip_call_id,
        sip_msg_type=raw.sip_msg_type,
        sip_cseq=raw.sip_cseq,
        sip_user_agent=raw.sip_user_agent,
        sip_server=raw.sip_server,
        dns_txn_id=raw.dns_txn_id,
        dns_is_response=raw.dns_is_response,
        dns_qry_name=raw.dns_qry_name,
        dns_rcode=raw.dns_rcode,
        payload_entropy=raw.payload_entropy,
        payload_len=len(raw.payload),
        http_is_request=raw.http_is_request,
        http_is_response=raw.http_is_response,
        http_method=raw.http_method,
        http_uri=raw.http_uri,
        http_status_code=raw.http_status_code,
        http_response_time_ms=raw.http_response_time_ms,
        http_content_type=raw.http_content_type,
        http_content_length=raw.http_content_length,
        tcp_len=raw.tcp_len,
        dns_answers=raw.dns_answers,
        comment=raw.comment,
        ip_checksum=raw.ip_checksum,
        ip_checksum_bad=raw.ip_checksum_bad,
        tcp_checksum=raw.tcp_checksum,
        tcp_checksum_bad=raw.tcp_checksum_bad,
        udp_checksum=raw.udp_checksum,
        udp_checksum_bad=raw.udp_checksum_bad,
        tls_cert_issuer=raw.tls_cert_issuer,
        tls_cert_subject=raw.tls_cert_subject,
        tls_cert_sig_hash=raw.tls_cert_sig_hash,
        tls_cert_key_type=raw.tls_cert_key_type,
        tls_cert_key_bits=raw.tls_cert_key_bits,
        tls_cert_san_ip=raw.tls_cert_san_ip,
        tls_cert_chain_len=raw.tls_cert_chain_len,
        expert_flags=raw.expert_flags,
        expert_details=raw.expert_details,
        service_banners=extract_banners(raw.proto, raw.sport, raw.dport, raw.payload),
        **fingerprints,
    )


def parse_capture(label, path, raise_on_error=False) -> list[Pkt]:
    """Meme signature/comportement que l'ancienne version de ce module : lit
    `path` via pcap_parser (tshark -T ek), etiquette chaque paquet avec
    `label`. raise_on_error=True laisse remonter l'exception au lieu de
    l'avaler (utilise par parse_captures_parallel)."""
    logger.debug("parse_capture: point {} <- {}", label, path)
    try:
        raw_packets = pcap_parser.parse_capture(path, raise_on_error=True)
    except (TsharkNotFoundError, TsharkError) as e:
        logger.exception("parse_capture: lecture de {} ({}) impossible: {}", path, label, e)
        if raise_on_error:
            raise
        print(f"[{label}] impossible de lire {path} : {e}", file=sys.stderr)
        return []
    # Convertit en liberant chaque RawPacket au fur et a mesure (au lieu
    # d'une comprehension de liste, qui garderait raw_packets ET pkts
    # entierement materialisees en RAM simultanement jusqu'a la fin de la
    # fonction) -- reduit le pic memoire transitoire pendant le chargement
    # d'une grosse capture, mesure empiriquement comme significatif sur ce
    # projet (voir FEATURES.md/claude.md, piste "gestion memoire des
    # grosses captures"). raw_packets[i] = None plutot que raw_packets.pop(0)
    # (O(n) par appel sur une liste Python) : le cout residuel est une
    # liste de pointeurs None de la meme longueur, negligeable face aux
    # ~600 octets par RawPacket ainsi liberes immediatement.
    n = len(raw_packets)
    pkts: list[Pkt] = []
    for i in range(n):
        pkts.append(_to_pkt(label, raw_packets[i]))
        raw_packets[i] = None  # type: ignore[call-overload]  # liberation memoire volontaire
    logger.debug("parse_capture: {} paquet(s) convertis pour {}", len(pkts), label)
    return pkts


def _parse_capture_timed(label, path):
    """Wrapper picklable pour ProcessPoolExecutor, cf. l'ancienne version."""
    import time

    t0 = time.time()
    pkts = parse_capture(label, path, raise_on_error=True)
    return pkts, time.time() - t0


def parse_captures_parallel(captures, max_workers=None) -> tuple[list[Pkt], list[dict]]:
    """Identique a l'ancienne version : un processus tshark par fichier
    en parallele. Renvoie (all_packets, per_file_stats), meme format
    (voir docstring de l'ancienne implementation pour le detail des cles)."""
    from concurrent.futures import ProcessPoolExecutor, as_completed

    all_packets: list[Pkt] = []
    per_file_stats: list[dict] = []

    logger.debug("parse_captures_parallel: {} capture(s), max_workers={}", len(captures), max_workers)
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_capture = {
            executor.submit(_parse_capture_timed, label, path): (label, path) for label, path in captures
        }
        for future in as_completed(future_to_capture):
            label, path = future_to_capture[future]
            try:
                pkts, seconds = future.result()
                all_packets.extend(pkts)
                per_file_stats.append(
                    {
                        "label": label,
                        "path": path,
                        "count": len(pkts),
                        "seconds": seconds,
                        "error": None,
                    }
                )
            except Exception as e:  # noqa: BLE001 -- catch-all volontaire : un
                # fichier en echec (tshark absent, pcap corrompu, permission...)
                # ne doit jamais interrompre le traitement parallele des autres.
                logger.exception("parse_captures_parallel: échec de {} ({}): {}", path, label, e)
                per_file_stats.append(
                    {
                        "label": label,
                        "path": path,
                        "count": 0,
                        "seconds": None,
                        "error": f"{type(e).__name__}: {e}",
                    }
                )

    order = {(label, path): i for i, (label, path) in enumerate(captures)}
    per_file_stats.sort(key=lambda s: order[(s["label"], s["path"])])

    logger.debug(
        "parse_captures_parallel: {} paquet(s), {} capture(s) en échec",
        len(all_packets),
        sum(1 for st in per_file_stats if st["error"]),
    )
    return all_packets, per_file_stats


def read_capture_comments(captures) -> list[str]:
    """Lit le commentaire de section pcapng (Section Header Block) de
    chaque fichier de `captures` (memes paires (label, path) que
    parse_captures_parallel ci-dessus) et y attache le label -- meme
    raison d'etre que _to_pkt() pour les paquets (pcap_parser.
    capinfos_source.read_capture_comment ne connait, volontairement,
    aucune notion de label/point de capture, voir sa docstring).

    Contrairement a parse_capture, une capture SANS commentaire de
    section (cas le plus frequent : pcap classique, ou pcapng qui n'en
    porte simplement pas) ne produit aucune entree plutot qu'une entree
    vide -- capinfos absent/en echec sur un fichier donne : meme
    traitement silencieux (voir read_capture_comment), un commentaire
    reste une annotation facultative, jamais une raison d'interrompre
    l'analyse ni d'exiger --raise-on-error comme parse_capture."""
    comments = []
    for label, path in captures:
        comment = read_capture_comment(path)
        if comment:
            comments.append(f"{label} : {comment}")
    logger.debug("read_capture_comments: {} commentaire(s)", len(comments))
    return comments


def read_capture_infos(captures) -> list[dict]:
    """Lit les metadonnees de capture (format, snaplen, paquets perdus...)
    de chaque fichier de ``captures`` (memes paires (label, path) que
    parse_captures_parallel ci-dessus) et les renvoie sous forme de dicts
    plats (un par fichier ayant reussi la lecture) -- meme raison d'etre
    que read_capture_comments : pcap_parser.capinfos_source.read_capture_info
    ne connait, volontairement, aucune notion de label/point de capture.

    Contrairement a read_capture_comments, une capture SANS metadonnees
    (capinfos absent, fichier illisible) ne produit aucune entree plutot
    qu'une entree vide -- les metadonnees restent facultatives, jamais
    une raison d'interrompre l'analyse.

    Chaque dict porte les cles : label, path, file_type, version,
    encapsulation, snaplen, packet_count, byte_count, duration_seconds,
    start_time, end_time, hardware, operating_system, application,
    dropped_by_interface, dropped_by_os, interfaces (liste de dicts
    plats avec index, linktype, snaplen, name, received,
    dropped_by_interface, dropped_by_os). Les cles absentes valent None."""
    from pcap_parser.capinfos_source import read_capture_info

    infos = []
    for label, path in captures:
        info = read_capture_info(path)
        if info is None:
            continue
        infos.append(
            {
                "label": label,
                "path": path,
                "file_type": info.file_type,
                "version": info.version,
                "encapsulation": info.encapsulation,
                "timestamp_precision": info.timestamp_precision,
                "snaplen": info.snaplen,
                "packet_count": info.packet_count,
                "byte_count": info.byte_count,
                "file_size": info.file_size,
                "duration_seconds": info.duration_seconds,
                "start_time": info.start_time,
                "end_time": info.end_time,
                "strict_time_order": info.strict_time_order,
                "hardware": info.hardware,
                "operating_system": info.operating_system,
                "application": info.application,
                "dropped_by_interface": info.dropped_by_interface,
                "dropped_by_os": info.dropped_by_os,
                "interfaces": [
                    {
                        "index": iface.index,
                        "linktype": iface.linktype,
                        "snaplen": iface.snaplen,
                        "name": iface.name,
                        "received": iface.received,
                        "dropped_by_interface": iface.dropped_by_interface,
                        "dropped_by_os": iface.dropped_by_os,
                    }
                    for iface in info.interfaces
                ],
            }
        )
    logger.debug("read_capture_infos: {} fiche(s) capinfos", len(infos))
    return infos


def parse_live(label, interface, bpf_filter=None, stop_event=None):
    """Nouveaute (absente de l'ancienne version, qui ne savait lire
    que des fichiers deja ecrits) : capture en direct sur `interface`,
    yield un Pkt etiquete `label` au fil de l'eau -- meme pipeline de
    decodage que parse_capture, juste une source live plutot qu'un
    fichier.

    stop_event (threading.Event, optionnel) : positionne depuis un autre
    thread pour demander l'arret -- voir pcap_parser.iter_live /
    ek_source.iter_ek_records pour le detail (arret reactif y compris
    sans trafic sur l'interface)."""
    logger.debug("parse_live: point {} sur {} (filtre={})", label, interface, bpf_filter)
    for raw in pcap_parser.iter_live(interface, bpf_filter=bpf_filter, stop_event=stop_event):
        yield _to_pkt(label, raw)


def parse_live_multi(interfaces, stop_event=None, *, bpf_filter=None):
    """Capture en direct SIMULTANEE sur plusieurs interfaces : yield un Pkt
    au fil de l'eau, etiquete du label de son interface d'origine (le
    label devient le point de capture du Pkt, comme parse_live).

    `interfaces` : sequence de (label, interface), ex.
    [("LAN", "eth0"), ("WAN", "eth1")] -- un label distinct par interface.
    Fusion en temps reel dans l'ordre d'arrivee, arret simultane via
    `stop_event`, echec de toute la capture si une interface echoue : voir
    pcap_parser.iter_live_multi pour le detail de ces garanties.

    Renvoie un iterateur (et non un generateur) : la validation des
    arguments (liste vide, label en double...) leve ValueError des
    l'appel, pas au premier paquet -- utile a un appelant qui lance la
    capture dans un thread (LiveDiffEngine.start_multi)."""
    logger.debug("parse_live_multi: capture multi-interfaces (filtre={})", bpf_filter)
    packets = pcap_parser.iter_live_multi(interfaces, stop_event=stop_event, bpf_filter=bpf_filter)
    return (_to_pkt(label, raw) for label, raw in packets)


# -- re-exports pour compat avec l'ancienne API (baseline_diff.py et
# consorts n'importent pas ces noms, mais __init__.py les exposait) --


def parse_rtp(payload: bytes):
    from pcap_parser.protocols import _parse_rtp_heuristic

    return _parse_rtp_heuristic(payload)


def parse_sip(payload: bytes):
    from pcap_parser.protocols import _parse_sip_heuristic

    return _parse_sip_heuristic(payload)


def detect_encapsulation(layers: dict):
    """ATTENTION signature changee par rapport a l'ancienne version de ce
    module : prend desormais le dict "layers" EK d'un paquet (pcap_parser),
    pas un objet de l'ancien decodeur. Fourni pour compat de nom -- voir
    pcap_parser.tunnels.detect_encapsulation pour l'implementation."""
    from pcap_parser.tunnels import detect_encapsulation as _detect

    return _detect(layers)
