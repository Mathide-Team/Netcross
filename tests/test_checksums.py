"""
Checksums IP/TCP/UDP (Job 43, issue #163).

Trois niveaux :
  1. ek_fields.checksum_is_bad : fonction pure, directement sur les codes
     de statut rendus par tshark en EK ("0"=Bad, "1"=Good, "2"=Unverified,
     verifie empiriquement sur tshark 4.2.2 avec les preferences
     ip/tcp/udp.check_checksum activees) ;
  2. build_packet : extraction des valeurs brutes et des verdicts depuis
     des couches EK synthetiques, y compris les cas degeneres -- IPv6 (pas
     de checksum d'en-tete), statut absent (preferences non activees ->
     None, jamais suppose invalide), ARP/STP (ni IP ni TCP/UDP) ;
  3. netcross_core.forensic.validate_checksums : CONSOMMATEUR pur des deux
     champs *_checksum/*_checksum_bad deja portes par Pkt -- distingue
     l'offload materiel (checksum a 0x0000, jamais une erreur meme si
     tshark le rend "Bad") d'un checksum reellement invalide.
"""

from conftest import make_pkt

from netcross_core.forensic import validate_checksums
from netcross_core.models import ChecksumError
from pcap_parser.ek_fields import checksum_is_bad
from pcap_parser.ek_source import DEFAULT_PREFS
from pcap_parser.packet import build_packet

# -- checksum_is_bad : interpretation tri-etat du code de statut ---------


def test_checksum_is_bad_code_0_invalide():
    assert checksum_is_bad("0") is True


def test_checksum_is_bad_code_1_valide():
    assert checksum_is_bad("1") is False


def test_checksum_is_bad_code_2_non_verifie():
    # valeur systematique SANS les preferences ip/tcp/udp.check_checksum
    # (desactivees par defaut cote tshark) : ni valide ni invalide.
    assert checksum_is_bad("2") is None


def test_checksum_is_bad_champ_absent():
    assert checksum_is_bad(None) is None


def test_checksum_is_bad_valeur_hexa_decimale():
    # meme tolerance d'entree que hex_or_dec_to_int : les statuts reels
    # arrivent en chaine decimale, mais un "0x0"/"0x1" doit marcher aussi.
    assert checksum_is_bad("0x0") is True
    assert checksum_is_bad("0x1") is False


# -- DEFAULT_PREFS : preferences checksum actives -------------------------


def test_default_prefs_active_la_validation_checksums():
    # sans ces preferences, le champ EK *.checksum.status reste TOUJOURS a
    # "2" (Unverified) quelle que soit la validite reelle (verifie
    # empiriquement, voir ek_source.DEFAULT_PREFS).
    for pref in ("ip.check_checksum:TRUE", "tcp.check_checksum:TRUE", "udp.check_checksum:TRUE"):
        assert pref in DEFAULT_PREFS


# -- build_packet : extraction ---------------------------------------------


def _ip4_layers(ip_status=None, tcp_status=None, udp_status=None, transport="tcp"):
    ip = {
        "ip_ip_src": "10.0.0.1",
        "ip_ip_dst": "10.0.0.2",
        "ip_ip_ttl": "64",
        "ip_ip_dsfield_dscp": "0",
        "ip_ip_dsfield_ecn": "0",
        "ip_ip_id": "0x1234",
        "ip_ip_checksum": "0x66cd",
    }
    if ip_status is not None:
        ip["ip_ip_checksum_status"] = ip_status
    if transport == "tcp":
        layer = {
            "tcp_tcp_srcport": "51234",
            "tcp_tcp_dstport": "443",
            "tcp_tcp_seq_raw": "1000",
            "tcp_tcp_ack_raw": "0",
            "tcp_tcp_window_size_value": "65535",
            "tcp_tcp_flags_str": "········S·",
            "tcp_tcp_checksum": "0x8cfa",
        }
        if tcp_status is not None:
            layer["tcp_tcp_checksum_status"] = tcp_status
    else:
        layer = {
            "udp_udp_srcport": "5353",
            "udp_udp_dstport": "53",
            "udp_udp_checksum": "0x1234",
        }
        if udp_status is not None:
            layer["udp_udp_checksum_status"] = udp_status
    return {"frame": {"frame_frame_len": "60", "frame_frame_number": "1"}, "ip": ip, transport: layer}


def test_build_packet_extrait_checksum_ip_invalide():
    pkt = build_packet(1.0, _ip4_layers(ip_status="0", tcp_status="1"))
    assert pkt is not None
    assert pkt.ip_checksum == "0x66cd"
    assert pkt.ip_checksum_bad is True
    assert pkt.tcp_checksum == "0x8cfa"
    assert pkt.tcp_checksum_bad is False


def test_build_packet_extrait_checksum_udp_non_verifie():
    pkt = build_packet(1.0, _ip4_layers(transport="udp", udp_status="2"))
    assert pkt is not None
    assert pkt.udp_checksum == "0x1234"
    assert pkt.udp_checksum_bad is None


def test_build_packet_statut_absent_donne_verdict_none():
    # preferences non activees cote tshark -> champ *.checksum_status
    # absent : valeur brute conservee, verdict None (jamais suppose
    # invalide), meme comportement que checksum_is_bad(None).
    pkt = build_packet(1.0, _ip4_layers())
    assert pkt is not None
    assert pkt.ip_checksum == "0x66cd"
    assert pkt.ip_checksum_bad is None
    assert pkt.tcp_checksum == "0x8cfa"
    assert pkt.tcp_checksum_bad is None


def _ip6_layers():
    return {
        "frame": {"frame_frame_len": "60", "frame_frame_number": "1"},
        "ipv6": {
            "ipv6_ipv6_src": "fe80::1",
            "ipv6_ipv6_dst": "fe80::2",
            "ipv6_ipv6_hlim": "64",
            "ipv6_ipv6_tclass_dscp": "0",
            "ipv6_ipv6_tclass_ecn": "0",
        },
        "tcp": {
            "tcp_tcp_srcport": "51234",
            "tcp_tcp_dstport": "443",
            "tcp_tcp_seq_raw": "1000",
            "tcp_tcp_ack_raw": "0",
            "tcp_tcp_window_size_value": "65535",
            "tcp_tcp_flags_str": "········S·",
            "tcp_tcp_checksum": "0x9a13",
            "tcp_tcp_checksum_status": "1",
        },
    }


def test_build_packet_ipv6_sans_checksum_ip_mais_tcp_extrait():
    # IPv6 : pas de checksum d'en-tete (RFC 8200) -> ip_checksum/ip_checksum_bad
    # restent None ; le checksum TCP (pseudo-en-tete, independant de la
    # version IP) est extrait et evalue normalement.
    pkt = build_packet(1.0, _ip6_layers())
    assert pkt is not None
    assert pkt.ip_checksum is None
    assert pkt.ip_checksum_bad is None
    assert pkt.tcp_checksum == "0x9a13"
    assert pkt.tcp_checksum_bad is False


# -- netcross_core.forensic.validate_checksums : distinction offload/invalide --


def test_validate_checksums_paquet_valide_pas_d_erreur():
    pkts = [make_pkt(ip_checksum="0x66cd", ip_checksum_bad=False, tcp_checksum="0x76be", tcp_checksum_bad=False)]
    assert validate_checksums(pkts) == []


def test_validate_checksums_paquet_invalide_erreur_signalee():
    pkts = [make_pkt(point="A", frame_number=2, tcp_checksum="0x1111", tcp_checksum_bad=True)]
    errors = validate_checksums(pkts)
    assert errors == [ChecksumError(point="A", frame_number=2, protocol="TCP", checksum="0x1111")]


def test_validate_checksums_offload_0x0000_ignore():
    # tshark rend ce paquet "Bad" (0x0000 ne correspond quasiment jamais a
    # la valeur recalculee), mais c'est la signature de l'offload
    # materiel -- jamais une erreur, voir docstring de validate_checksums.
    pkts = [make_pkt(tcp_checksum="0x0000", tcp_checksum_bad=True)]
    assert validate_checksums(pkts) == []


def test_validate_checksums_ip_invalide_aussi_detectee():
    pkts = [make_pkt(point="B", frame_number=5, ip_checksum="0x2222", ip_checksum_bad=True)]
    errors = validate_checksums(pkts)
    assert errors == [ChecksumError(point="B", frame_number=5, protocol="IP", checksum="0x2222")]


def test_validate_checksums_udp_invalide_aussi_detectee():
    pkts = [make_pkt(point="A", frame_number=9, udp_checksum="0xdead", udp_checksum_bad=True)]
    errors = validate_checksums(pkts)
    assert errors == [ChecksumError(point="A", frame_number=9, protocol="UDP", checksum="0xdead")]


def test_validate_checksums_statut_inconnu_ignore():
    # ip_checksum_bad=None -- checksum absent ou validation desactivee
    # (statut "Unverified") : jamais suppose invalide.
    pkts = [make_pkt(ip_checksum="0x66cd", ip_checksum_bad=None)]
    assert validate_checksums(pkts) == []


def test_validate_checksums_plusieurs_paquets_plusieurs_protocoles():
    pkts = [
        make_pkt(point="A", frame_number=1, tcp_checksum="0x76be", tcp_checksum_bad=False),  # valide
        make_pkt(point="A", frame_number=2, tcp_checksum="0x1111", tcp_checksum_bad=True),  # invalide
        make_pkt(point="A", frame_number=3, tcp_checksum="0x0000", tcp_checksum_bad=True),  # offload
        make_pkt(point="B", frame_number=4, ip_checksum="0x2222", ip_checksum_bad=True),  # invalide
    ]
    errors = validate_checksums(pkts)
    assert len(errors) == 2
    assert {(e.point, e.frame_number, e.protocol) for e in errors} == {("A", 2, "TCP"), ("B", 4, "IP")}
