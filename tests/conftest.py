"""
Fixtures et fabriques partagees par toute la suite de tests.

Aucun test de ce depot ne depend de tshark, scapy ou GTK4 : tous les
objets Pkt/RawPacket sont construits synthetiquement (memes methodes
que celles decrites dans claude.md pour la validation manuelle faite
au fil des sessions), ou passes a des couches EK synthetiques quand le
test porte sur pcap_parser lui-meme.
"""

from __future__ import annotations

import os

# Issue #299 : les tests comparent les chaines source (francais). Un poste de
# developpement avec des catalogues compiles et LANG=en_US ne doit pas les
# traduire ; "C" desactive gettext. tests/test_i18n.py choisit sa langue.
os.environ["NETCROSS_LANG"] = "C"

from netcross_core.models import Pkt  # noqa: E402


def make_pkt(**overrides) -> Pkt:
    """Pkt avec des valeurs par defaut neutres sur tous les champs ;
    ne passer que ce que le test doit reellement faire varier."""
    defaults = {
        "point": "A",
        "ts": 0.0,
        "frame_number": None,
        "proto": "TCP",
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "sport": 1234,
        "dport": 443,
        "length": 100,
        "ttl": 64,
        "dscp": 0,
        "ecn": 0,
        "seq": 1000,
        "ack": 0,
        "window": 65535,
        "flags": ".......",
        "key_id": 1000,
        "payload_hash": None,
        "ip_id": 1,
        "is_fragment": False,
        "df": False,
        "is_retransmission": False,
        "is_fast_retransmission": False,
        "is_spurious_retransmission": False,
        # Signaux d'expertise bruts tshark (Session 1) -- tuple vide par
        # defaut, comme un paquet sans aucune condition d'expertise
        # active (cas le plus frequent) ; voir pcap_parser.packet.
        # RawPacket.expert_flags et netcross_core.wireshark_expert.
        "expert_flags": (),
        # Vue enrichie de expert_flags ci-dessus (severite/groupe/message
        # NATIFS tshark, second lot de la Session 1) -- tuple vide par
        # defaut, meme convention ; voir pcap_parser.packet.RawPacket.
        # expert_details et netcross_core.wireshark_expert.
        "expert_details": (),
        "mss_val": None,
        "wscale_shift": None,
        "sack_permitted": False,
        "icmp_type": None,
        "icmp_code": None,
        "icmpv6_type": None,
        "icmpv6_code": None,
        "arp_opcode": None,
        "arp_sender_mac": None,
        "arp_is_gratuitous": False,
        "stp_bpdu_type": None,
        "stp_flags_tc": False,
        "stp_root_id": None,
        "tls_cert_not_before": None,
        "tls_cert_not_after": None,
        "tls_cert_san": None,
        "tls_cert_serial": None,
        "tls_cert_issuer": None,
        "tls_cert_subject": None,
        "tls_cert_sig_hash": None,
        "tls_cert_key_type": None,
        "tls_cert_key_bits": None,
        "tls_cert_san_ip": None,
        "tls_cert_chain_len": None,
        "tls_client_hello": False,
        "tls_server_hello": False,
        "tls_application_data": False,
        "vlan_id": None,
        "vlan_prio": None,
        "is_rtp": False,
        "rtp_seq": None,
        "rtp_ts": None,
        "rtp_ssrc": None,
        "encap_tags": (),
        "dhcp_xid": None,
        "dhcp_msg_type": None,
        "dhcp_server_id": None,
        "dhcp_vendor_class": None,
        "sip_call_id": None,
        "sip_msg_type": None,
        "sip_cseq": None,
        "sip_user_agent": None,
        "sip_server": None,
        "dns_txn_id": None,
        "dns_is_response": False,
        "dns_qry_name": None,
        "dns_rcode": None,
        "http_is_request": False,
        "http_is_response": False,
        "http_method": None,
        "http_uri": None,
        "http_status_code": None,
        "http_response_time_ms": None,
        # Job 43/issue #163 : checksums IP/TCP/UDP -- None par defaut
        # (paquet sans verdict, comme IPv6 sans checksum d'en-tete, ou
        # preferences tshark non activees) : jamais suppose invalide.
        "ip_checksum": None,
        "ip_checksum_bad": None,
        "tcp_checksum": None,
        "tcp_checksum_bad": None,
        "udp_checksum": None,
        "udp_checksum_bad": None,
    }
    defaults.update(overrides)
    return Pkt(**defaults)
