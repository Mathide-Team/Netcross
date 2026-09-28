"""
tests/test_flow_view.py -- tests du FlowView (netcross_core.flow_view,
Job 9/issue #6).

Verifie : duree, debit, latence inter-points, synthese TCP, transactions,
timeline.
"""

from conftest import make_pkt

from netcross_core.correlate import correlate
from netcross_core.expert_model import ExpertEvent, Flow
from netcross_core.flow_view import build_flow_view
from netcross_core.models import Pkt


def _pkt(**overrides) -> Pkt:
    return make_pkt(**overrides)


def _build_view(packets=None):
    """Construit un FlowView depuis une liste de paquets synthetiques."""
    if packets is None:
        packets = [
            _pkt(point="A", frame_number=1, ts=1.0),
            _pkt(point="A", frame_number=2, ts=2.0),
            _pkt(point="B", frame_number=1, ts=1.5),
            _pkt(point="B", frame_number=2, ts=2.5),
        ]
    flows = correlate(packets)
    first_key = next(iter(flows))
    first_point = flows[first_key]
    flow = Flow(key=first_key)
    for point, pkts in first_point.items():
        flow.points.append(point)
        flow.packet_count[point] = len(pkts)
        flow.byte_count[point] = sum(pk.length for pk in pkts)
        flow.first_ts[point] = min(pk.ts for pk in pkts)
        flow.last_ts[point] = max(pk.ts for pk in pkts)
        if flow.endpoints is None:
            flow.endpoints = tuple(sorted((pkts[0].src, pkts[0].dst)))
    return build_flow_view(flow, first_point), first_point, first_key


# -- Duree et debit -------------------------------------------------------


def test_duree_calculee():
    view, _, _ = _build_view()
    assert view.duration_s > 0
    # ts_min=1.0, ts_max=2.5 -> duree = 1.5s
    assert abs(view.duration_s - 1.5) < 0.01


def test_debit_calcule():
    view, _, _ = _build_view()
    assert view.throughput_bps > 0
    # 4 paquets * 100 bytes * 8 bits / 1.5s = 2133.33 bps
    assert abs(view.throughput_bps - (400 * 8 / 1.5)) < 1.0


def test_debit_zero_si_duree_zero():
    pk = _pkt(point="A", frame_number=1, ts=5.0)
    flows = correlate([pk])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    view = build_flow_view(flow, flows[key])
    assert view.throughput_bps == 0.0


# -- Compteurs ------------------------------------------------------------


def test_packet_count_total():
    view, _, _ = _build_view()
    assert view.packet_count == 4  # 2 sur A + 2 sur B


def test_byte_count_total():
    view, _, _ = _build_view()
    assert view.byte_count == 400  # 4 * 100


# -- Latence inter-points --------------------------------------------------


def test_latence_inter_points_calculee():
    view, _, _ = _build_view()
    assert "A -> B" in view.inter_point_latency_ms
    # first_ts A = 1.0, first_ts B = 1.5 -> 500ms
    assert abs(view.inter_point_latency_ms["A -> B"] - 500.0) < 1.0


def test_latence_inter_points_un_seul_point():
    pk = _pkt(point="A", frame_number=1, ts=1.0)
    flows = correlate([pk])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    view = build_flow_view(flow, flows[key])
    assert view.inter_point_latency_ms == {}


# -- Synthese TCP ----------------------------------------------------------


def test_tcp_retransmissions_comptees():
    pk = _pkt(
        point="A",
        frame_number=1,
        ts=1.0,
        proto="TCP",
        is_retransmission=True,
        flags="...A...",
    )
    flows = correlate([pk])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    view = build_flow_view(flow, flows[key])
    assert view.tcp.retransmissions == 1


def test_tcp_syn_fin_rst_detectes():
    pk = _pkt(
        point="A",
        frame_number=1,
        ts=1.0,
        proto="TCP",
        flags="S",  # SYN
    )
    flows = correlate([pk])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    view = build_flow_view(flow, flows[key])
    assert view.tcp.syn_seen is True
    assert view.tcp.fin_seen is False
    assert view.tcp.rst_seen is False


def test_tcp_mss_wscale_sack_extraits():
    pk = _pkt(
        point="A",
        frame_number=1,
        ts=1.0,
        proto="TCP",
        flags="S",
        mss_val=1460,
        wscale_shift=7,
        sack_permitted=True,
    )
    flows = correlate([pk])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    view = build_flow_view(flow, flows[key])
    assert view.tcp.mss == 1460
    assert view.tcp.wscale == 7
    assert view.tcp.sack_permitted is True


def test_tcp_synthese_zero_paquet_tcp():
    """Un flux sans paquet TCP a une synthese TCP vide."""
    pk = _pkt(point="A", frame_number=1, ts=1.0, proto="UDP")
    flows = correlate([pk])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    view = build_flow_view(flow, flows[key])
    assert view.tcp.retransmissions == 0
    assert view.tcp.syn_seen is False


# -- Transactions ----------------------------------------------------------


def test_transaction_http_detectee():
    pk_req = _pkt(
        point="A",
        frame_number=1,
        ts=1.0,
        proto="TCP",
        http_is_request=True,
        http_uri="/index.html",
    )
    pk_resp = _pkt(
        point="A",
        frame_number=2,
        ts=1.5,
        proto="TCP",
        http_is_response=True,
        http_status_code=200,
    )
    flows = correlate([pk_req, pk_resp])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    view = build_flow_view(flow, flows[key])
    http_txns = [t for t in view.transactions if t.kind == "http"]
    assert len(http_txns) == 1
    assert http_txns[0].response_time_ms is not None
    assert abs(http_txns[0].response_time_ms - 500.0) < 1.0


def test_transaction_dns_detectee():
    pk_req = _pkt(
        point="A",
        frame_number=1,
        ts=1.0,
        proto="UDP",
        dns_txn_id=0x1234,
        dns_qry_name="example.com",
        dns_is_response=False,
    )
    pk_resp = _pkt(
        point="A",
        frame_number=2,
        ts=1.2,
        proto="UDP",
        dns_txn_id=0x1234,
        dns_qry_name="example.com",
        dns_is_response=True,
    )
    flows = correlate([pk_req, pk_resp])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    view = build_flow_view(flow, flows[key])
    dns_txns = [t for t in view.transactions if t.kind == "dns"]
    assert len(dns_txns) == 1
    assert abs(dns_txns[0].response_time_ms - 200.0) < 1.0


def test_transaction_tcp_handshake_detectee():
    pk_syn = _pkt(
        point="A",
        frame_number=1,
        ts=1.0,
        proto="TCP",
        flags="S",
    )
    pk_synack = _pkt(
        point="A",
        frame_number=2,
        ts=1.1,
        proto="TCP",
        flags="S A",  # SYN-ACK
    )
    flows = correlate([pk_syn, pk_synack])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    view = build_flow_view(flow, flows[key])
    handshake = [t for t in view.transactions if t.kind == "tcp_handshake"]
    assert len(handshake) == 1
    assert abs(handshake[0].response_time_ms - 100.0) < 1.0


def test_aucune_transaction_paquet_sans_applicatif():
    pk = _pkt(point="A", frame_number=1, ts=1.0, proto="TCP", flags="...A...")
    flows = correlate([pk])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    view = build_flow_view(flow, flows[key])
    assert view.transactions == []


# -- Timeline --------------------------------------------------------------


def test_timeline_triee_par_ts():
    pk1 = _pkt(point="A", frame_number=1, ts=2.0)
    pk2 = _pkt(point="A", frame_number=2, ts=1.0)
    flows = correlate([pk1, pk2])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    view = build_flow_view(flow, flows[key])
    assert len(view.timeline) == 2
    # Trie par ts croissant
    assert view.timeline[0][0] <= view.timeline[1][0]


def test_timeline_format_correct():
    pk = _pkt(point="A", frame_number=1, ts=1.0)
    flows = correlate([pk])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    view = build_flow_view(flow, flows[key])
    assert len(view.timeline) == 1
    ts, point, direction = view.timeline[0]
    assert ts == 1.0
    assert point == "A"
    assert "10.0.0.1" in direction


# -- Evenements -----------------------------------------------------------


def test_events_associes_au_flow():
    pk = _pkt(point="A", frame_number=1, ts=1.0)
    flows = correlate([pk])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    ev = ExpertEvent(
        category="TCP",
        severity="info",
        segment="A",
        message="test event",
    )
    view = build_flow_view(flow, flows[key], events=[ev])
    assert len(view.events) == 1
    assert view.events[0].message == "test event"


def test_events_vide_par_defaut():
    pk = _pkt(point="A", frame_number=1, ts=1.0)
    flows = correlate([pk])
    key = next(iter(flows))
    flow = Flow(key=key, points=["A"])
    view = build_flow_view(flow, flows[key])
    assert view.events == []


# -- Cas limites ----------------------------------------------------------


def test_flow_sans_paquet_retourne_vue_vide():
    flow = Flow(key=("TCP", "x", 1, "y", 2, 3))
    view = build_flow_view(flow, {})
    assert view.packet_count == 0
    assert view.duration_s == 0.0
    assert view.throughput_bps == 0.0
    assert view.transactions == []
    assert view.timeline == []


# -- Issue #716 : branches non couvertes de build_flow_view -------------------


def test_point_sans_paquet_ignore_et_drapeaux_tcp_fin_rst_fast_retrans():
    """Lignes 110, 144, 152, 154 : un point du flux sans paquet est ignore ;
    fast-retransmission, FIN et RST sont comptes dans la synthese TCP."""
    pkts = [
        _pkt(point="A", frame_number=1, ts=1.0, flags="FA", is_fast_retransmission=True),
        _pkt(point="A", frame_number=2, ts=2.0, flags="R"),
    ]
    flow = Flow(key=("k",))
    flow.points.extend(["VIDE", "A"])
    view = build_flow_view(flow, {"VIDE": [], "A": pkts})
    assert view.flow.points == ["VIDE", "A"]
    assert view.tcp.fast_retransmissions == 1
    assert view.tcp.fin_seen is True
    assert view.tcp.rst_seen is True
