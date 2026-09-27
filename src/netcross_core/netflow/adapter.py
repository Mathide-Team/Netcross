"""
netcross_core.netflow.adapter -- conversion FlowRecord -> Pkt.

Permet de reutiliser le pipeline d'analyse existant (correlate() /
analyse(), qui consomment tous deux list[Pkt]) sans le reecrire pour
NetFlow/sFlow -- voir docs/adr/netflow-sflow-architecture.md, section
"Adaptateur : FlowRecord -> Pkt", qui documente aussi les limitations
assumees ci-dessous.

Le Pkt produit est SYNTHETIQUE : un flux agrege n'est pas un paquet,
la conversion perd donc necessairement de l'information (pas de
retransmission, pas de TTL, pas de TLS/HTTP/DNS applicatif...). Tous
les champs non derivables du FlowRecord sont mis a leur valeur neutre
(None/False/tuple vide), jamais devines.
"""

from __future__ import annotations

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt
from netcross_core.netflow.models import FlowRecord

logger = get_logger(__name__)

# Numeros de protocole IP (IANA) vers le nom utilise par Pkt.proto
# ailleurs dans netcross_core (pcap_parser.packet produit les memes
# chaines pour TCP/UDP/ICMP -- voir netcross_core.models.Pkt.proto).
_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def flow_record_to_pkt(flow: FlowRecord, point: str | None = None) -> Pkt:
    """Convertit un FlowRecord en Pkt synthetique.

    `point` etiquette le point de capture au sens Pkt (defaut :
    `flow.exporter`) -- voir ADR, "un flux NetFlow vient d'un seul
    routeur, il n'y a pas de point A -> point B au sens Netcross" : ce
    Pkt synthetique ne doit donc pas etre melange avec de vrais
    paquets multi-points sans en avoir conscience.
    """
    proto = _PROTO_NAMES.get(flow.protocol, str(flow.protocol))
    avg_length = flow.octets // flow.packets if flow.packets else flow.octets

    logger.debug("flow_record_to_pkt: retour Pkt(…)")
    return Pkt(
        point=point or flow.exporter,
        ts=flow.start_ts,
        frame_number=None,  # pas de notion de trame individuelle pour un agregat
        proto=proto,
        src=flow.src_addr,
        dst=flow.dst_addr,
        sport=flow.src_port,
        dport=flow.dst_port,
        length=avg_length,
        ttl=None,
        dscp=(flow.tos >> 2) if flow.tos is not None else None,
        ecn=(flow.tos & 0x03) if flow.tos is not None else None,
        seq=None,
        ack=None,
        window=None,
        flags=f"{flow.tcp_flags:#04x}" if flow.tcp_flags else None,
        key_id=None,
        payload_hash=None,
        ip_id=None,
        is_fragment=False,
        df=False,
        is_retransmission=False,
        is_fast_retransmission=False,
        is_spurious_retransmission=False,
        mss_val=None,
        wscale_shift=None,
        sack_permitted=False,
        icmp_type=None,
        icmp_code=None,
        icmpv6_type=None,
        icmpv6_code=None,
        arp_opcode=None,
        arp_sender_mac=None,
        arp_is_gratuitous=False,
        stp_bpdu_type=None,
        stp_flags_tc=False,
        stp_root_id=None,
        tls_cert_not_before=None,
        tls_cert_not_after=None,
        tls_cert_san=None,
        tls_cert_serial=None,
        tls_cert_issuer=None,
        tls_cert_subject=None,
        tls_cert_sig_hash=None,
        tls_cert_key_type=None,
        tls_cert_key_bits=None,
        tls_cert_san_ip=None,
        tls_cert_chain_len=None,
        tls_client_hello=False,
        tls_server_hello=False,
        tls_application_data=False,
        vlan_id=None,
        vlan_prio=None,
        is_rtp=False,
        rtp_seq=None,
        rtp_ts=None,
        rtp_ssrc=None,
        encap_tags=(),
        dhcp_xid=None,
        dhcp_msg_type=None,
        dhcp_server_id=None,
        dhcp_vendor_class=None,
        sip_call_id=None,
        sip_msg_type=None,
        sip_cseq=None,
        sip_user_agent=None,
        sip_server=None,
        dns_txn_id=None,
        dns_is_response=False,
        dns_qry_name=None,
        dns_rcode=None,
        http_is_request=False,
        http_is_response=False,
        http_method=None,
        http_uri=None,
        http_status_code=None,
        http_response_time_ms=None,
        expert_flags=(),
        expert_details=(),
    )


def flow_records_to_pkts(flows: list[FlowRecord], point: str | None = None) -> list[Pkt]:
    """Convertit une liste de FlowRecord en liste de Pkt synthetiques,
    meme convention que parsing.parse_capture (voir cette fonction)."""
    logger.debug("flow_records_to_pkts: retour liste")
    return [flow_record_to_pkt(flow, point=point) for flow in flows]
