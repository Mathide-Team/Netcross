"""
tests/test_netflow_v5.py -- tests du parseur NetFlow v5 et de
l'adaptateur FlowRecord -> Pkt (Job 32/issue #32, Phases 1-2 de
docs/adr/netflow-sflow-architecture.md).

Aucune dependance a un vrai exportateur NetFlow : les datagrammes sont
construits octet par octet avec `struct`, meme esprit que les couches
EK synthetiques utilisees pour pcap_parser ailleurs dans la suite (voir
tests/conftest.py).
"""

from __future__ import annotations

import ipaddress
import struct

import pytest

from netcross_core.netflow import (
    NetflowV5Error,
    flow_record_to_pkt,
    flow_records_to_pkts,
    iter_netflow_v5_file,
    parse_netflow_v5_packet,
)

_HEADER = struct.Struct("!HHIIIIBBH")
_RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")


def _ipv4_int(addr: str) -> int:
    return int(ipaddress.IPv4Address(addr))


def _build_packet(
    records: list[dict],
    *,
    version: int = 5,
    sys_uptime: int = 60_000,
    unix_secs: int = 1_700_000_000,
    unix_nsecs: int = 0,
    flow_sequence: int = 1,
    engine_type: int = 0,
    engine_id: int = 0,
    sampling: int = 0,
) -> bytes:
    header = _HEADER.pack(
        version,
        len(records),
        sys_uptime,
        unix_secs,
        unix_nsecs,
        flow_sequence,
        engine_type,
        engine_id,
        sampling,
    )
    body = b"".join(
        _RECORD.pack(
            _ipv4_int(r.get("src_addr", "192.0.2.1")),
            _ipv4_int(r.get("dst_addr", "192.0.2.2")),
            _ipv4_int(r.get("next_hop", "0.0.0.0")),
            r.get("input", 0),
            r.get("output", 0),
            r.get("packets", 10),
            r.get("octets", 1500),
            r.get("first", 0),
            r.get("last", sys_uptime),
            r.get("src_port", 12345),
            r.get("dst_port", 443),
            0,  # pad1
            r.get("tcp_flags", 0x1B),  # SYN+PSH+ACK+FIN, valeur arbitraire non nulle
            r.get("protocol", 6),
            r.get("tos", 0),
            r.get("src_as", 0),
            r.get("dst_as", 0),
            r.get("src_mask", 24),
            r.get("dst_mask", 24),
            0,  # pad2
        )
        for r in records
    )
    return header + body


def test_parse_single_record_roundtrip():
    packet = _build_packet(
        [
            {
                "src_addr": "10.1.1.1",
                "dst_addr": "10.2.2.2",
                "src_port": 51000,
                "dst_port": 443,
                "protocol": 6,
                "packets": 7,
                "octets": 4200,
                "tos": 0x08,  # DSCP=2, ECN=0
            }
        ]
    )

    flows = parse_netflow_v5_packet(packet, exporter="10.0.0.254")

    assert len(flows) == 1
    flow = flows[0]
    assert flow.exporter == "10.0.0.254"
    assert flow.version == 5
    assert flow.src_addr == "10.1.1.1"
    assert flow.dst_addr == "10.2.2.2"
    assert flow.src_port == 51000
    assert flow.dst_port == 443
    assert flow.protocol == 6
    assert flow.packets == 7
    assert flow.octets == 4200
    assert flow.tos == 0x08


def test_parse_multiple_records_preserves_order():
    packet = _build_packet(
        [
            {"src_port": 1111, "dst_port": 80},
            {"src_port": 2222, "dst_port": 443},
            {"src_port": 3333, "dst_port": 22},
        ]
    )

    flows = parse_netflow_v5_packet(packet, exporter="R1")

    assert [f.src_port for f in flows] == [1111, 2222, 3333]


def test_parse_zero_records_is_valid_keepalive():
    # Un datagramme NetFlow v5 avec count=0 est un en-tete valide sans
    # enregistrement (rare mais legal) -- ne doit pas lever.
    packet = _build_packet([])
    assert parse_netflow_v5_packet(packet, exporter="R1") == []


def test_wrong_version_raises():
    packet = _build_packet([{}], version=9)
    with pytest.raises(NetflowV5Error, match="version"):
        parse_netflow_v5_packet(packet, exporter="R1")


def test_truncated_header_raises():
    with pytest.raises(NetflowV5Error, match="trop court"):
        parse_netflow_v5_packet(b"\x00\x05", exporter="R1")


def test_truncated_body_raises():
    packet = _build_packet([{}, {}])[:-1]  # un octet manquant sur le 2e enregistrement
    with pytest.raises(NetflowV5Error, match="tronque"):
        parse_netflow_v5_packet(packet, exporter="R1")


def test_uptime_to_epoch_conversion_is_consistent():
    # first=0 -> flux demarre au boot de l'exportateur, "il y a
    # sys_uptime ms" par rapport a l'instant d'export (unix_secs).
    sys_uptime = 120_000  # 120s d'uptime au moment de l'export
    packet = _build_packet(
        [{"first": 0, "last": sys_uptime}],
        sys_uptime=sys_uptime,
        unix_secs=1_700_000_000,
        unix_nsecs=0,
    )

    flow = parse_netflow_v5_packet(packet, exporter="R1")[0]

    assert flow.start_ts == pytest.approx(1_700_000_000 - 120.0)
    assert flow.end_ts == pytest.approx(1_700_000_000)
    assert flow.end_ts > flow.start_ts


def test_iter_netflow_v5_file_reads_concatenated_datagrams(tmp_path):
    packet_a = _build_packet([{"src_port": 1}, {"src_port": 2}], flow_sequence=1)
    packet_b = _build_packet([{"src_port": 3}], flow_sequence=2)
    path = tmp_path / "export.netflow5"
    path.write_bytes(packet_a + packet_b)

    flows = list(iter_netflow_v5_file(str(path), exporter="R2"))

    assert [f.src_port for f in flows] == [1, 2, 3]
    assert all(f.exporter == "R2" for f in flows)


def test_iter_netflow_v5_file_truncated_trailing_datagram(tmp_path):
    packet = _build_packet([{}, {}])
    path = tmp_path / "bad.netflow5"
    path.write_bytes(packet[:-1])  # dernier datagramme coupe

    with pytest.raises(NetflowV5Error, match="tronque"):
        list(iter_netflow_v5_file(str(path)))


def test_flow_record_to_pkt_maps_core_fields():
    packet = _build_packet(
        [
            {
                "src_addr": "10.1.1.1",
                "dst_addr": "10.2.2.2",
                "src_port": 51000,
                "dst_port": 443,
                "protocol": 6,
                "packets": 10,
                "octets": 5000,
                "tos": 0b10110001,  # dscp=0b101100=44, ecn=0b01=1
            }
        ]
    )
    flow = parse_netflow_v5_packet(packet, exporter="10.0.0.254")[0]

    pkt = flow_record_to_pkt(flow)

    assert pkt.point == "10.0.0.254"
    assert pkt.proto == "TCP"
    assert pkt.src == "10.1.1.1"
    assert pkt.dst == "10.2.2.2"
    assert pkt.sport == 51000
    assert pkt.dport == 443
    assert pkt.length == 500  # octets // packets
    assert pkt.dscp == 0b101100
    assert pkt.ecn == 0b01
    assert pkt.ts == flow.start_ts
    # Champs non derivables d'un agregat : valeurs neutres, jamais devinees.
    assert pkt.ttl is None
    assert pkt.is_retransmission is False
    assert pkt.tls_client_hello is False
    assert pkt.expert_flags == ()


def test_flow_record_to_pkt_custom_point_overrides_exporter():
    packet = _build_packet([{}])
    flow = parse_netflow_v5_packet(packet, exporter="10.0.0.254")[0]

    pkt = flow_record_to_pkt(flow, point="NETFLOW-ROUTER-A")

    assert pkt.point == "NETFLOW-ROUTER-A"


def test_flow_record_to_pkt_unknown_protocol_falls_back_to_number():
    packet = _build_packet([{"protocol": 47}])  # GRE, hors table _PROTO_NAMES
    flow = parse_netflow_v5_packet(packet, exporter="R1")[0]

    pkt = flow_record_to_pkt(flow)

    assert pkt.proto == "47"


def test_flow_records_to_pkts_converts_each_flow_in_order():
    packet = _build_packet([{"src_port": 1, "protocol": 6}, {"src_port": 2, "protocol": 17}])
    flows = parse_netflow_v5_packet(packet, exporter="10.0.0.254")

    pkts = flow_records_to_pkts(flows)

    assert [p.sport for p in pkts] == [1, 2]
    assert [p.proto for p in pkts] == ["TCP", "UDP"]
    assert all(p.point == "10.0.0.254" for p in pkts)


def test_flow_records_to_pkts_custom_point_applies_to_all_flows():
    packet = _build_packet([{}, {}])
    flows = parse_netflow_v5_packet(packet, exporter="10.0.0.254")

    pkts = flow_records_to_pkts(flows, point="NETFLOW-ROUTER-A")

    assert [p.point for p in pkts] == ["NETFLOW-ROUTER-A", "NETFLOW-ROUTER-A"]


def test_flow_records_to_pkts_empty_list_returns_empty_list():
    assert flow_records_to_pkts([]) == []
