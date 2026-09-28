"""
tests/test_flow_timeline.py -- tests de la vue temporelle detaillee
(netcross_core.flow_timeline, Job 13/issue #10).

Verifie : inter-arrival, fenetres de debit, phases, RTT estimate.
"""

from conftest import make_pkt

from netcross_core.flow_timeline import (
    _detect_phases,
    _median,
    build_flow_timeline,
)
from netcross_core.models import Pkt


def _pkt(**overrides) -> Pkt:
    return make_pkt(**overrides)


# -- Packet timings (inter-arrival) ---------------------------------------


def test_packet_timings_calcules():
    pkts = [
        _pkt(ts=1.0, length=100),
        _pkt(ts=1.5, length=200),
        _pkt(ts=2.0, length=150),
    ]
    timeline = build_flow_timeline(pkts)
    assert len(timeline.packet_timings) == 3
    assert timeline.packet_timings[0].delta_ms == 0.0  # premier paquet
    assert abs(timeline.packet_timings[1].delta_ms - 500.0) < 1.0
    assert abs(timeline.packet_timings[2].delta_ms - 500.0) < 1.0


def test_cumulative_bytes():
    pkts = [
        _pkt(ts=1.0, length=100),
        _pkt(ts=2.0, length=200),
        _pkt(ts=3.0, length=150),
    ]
    timeline = build_flow_timeline(pkts)
    assert timeline.packet_timings[0].cumulative_bytes == 100
    assert timeline.packet_timings[1].cumulative_bytes == 300
    assert timeline.packet_timings[2].cumulative_bytes == 450


def test_packet_timings_tries_par_ts():
    pkts = [
        _pkt(ts=3.0, length=100),
        _pkt(ts=1.0, length=100),
        _pkt(ts=2.0, length=100),
    ]
    timeline = build_flow_timeline(pkts)
    assert timeline.packet_timings[0].ts == 1.0
    assert timeline.packet_timings[1].ts == 2.0
    assert timeline.packet_timings[2].ts == 3.0


# -- Inter-arrival stats --------------------------------------------------


def test_inter_arrival_stats_calculees():
    pkts = [
        _pkt(ts=1.0, length=100),
        _pkt(ts=1.5, length=100),
        _pkt(ts=3.0, length=100),
    ]
    timeline = build_flow_timeline(pkts)
    stats = timeline.inter_arrival_stats
    assert "min_ms" in stats
    assert "max_ms" in stats
    assert "mean_ms" in stats
    assert "median_ms" in stats
    assert abs(stats["min_ms"] - 500.0) < 1.0
    assert abs(stats["max_ms"] - 1500.0) < 1.0


def test_inter_arrival_stats_vide_si_un_seul_paquet():
    pkts = [_pkt(ts=1.0, length=100)]
    timeline = build_flow_timeline(pkts)
    assert timeline.inter_arrival_stats == {}


# -- Throughput windows ----------------------------------------------------


def test_throughput_windows_calculees():
    pkts = [
        _pkt(ts=1.0, length=1000),
        _pkt(ts=1.5, length=1000),
        _pkt(ts=2.5, length=1000),
        _pkt(ts=3.0, length=1000),
    ]
    timeline = build_flow_timeline(pkts, window_s=1.0)
    assert len(timeline.throughput_windows) >= 2
    # Chaque fenetre de 1s devrait contenir des octets
    for w in timeline.throughput_windows:
        assert w.bytes > 0
        assert w.bps > 0


def test_throughput_window_bps_calcule():
    pkts = [
        _pkt(ts=1.0, length=1000),
        _pkt(ts=1.5, length=1000),
    ]
    timeline = build_flow_timeline(pkts, window_s=1.0)
    assert len(timeline.throughput_windows) >= 1
    w = timeline.throughput_windows[0]
    assert w.bytes == 2000
    # Fenetre: 1.0 -> 1.5 (duree reelle 0.5s), 2000*8/0.5 = 32000 bps
    assert abs(w.bps - 32000.0) < 100.0


def test_throughput_windows_vides_si_duree_zero():
    pkts = [_pkt(ts=5.0, length=100)]
    timeline = build_flow_timeline(pkts)
    assert timeline.throughput_windows == []


# -- Phases ----------------------------------------------------------------


def test_phase_tcp_handshake_detectee():
    pkts = [
        _pkt(ts=1.0, proto="TCP", flags="S"),
        _pkt(ts=1.1, proto="TCP", flags="S A"),
        _pkt(ts=1.2, proto="TCP", flags="...A..."),
    ]
    timeline = build_flow_timeline(pkts)
    assert "tcp-handshake" in timeline.phases


def test_phase_burst_detectee():
    pkts = [
        _pkt(ts=1.0, length=100),
        _pkt(ts=1.005, length=100),  # delta 5ms < 10ms -> burst
        _pkt(ts=1.010, length=100),
    ]
    timeline = build_flow_timeline(pkts)
    assert "burst" in timeline.phases


def test_phase_idle_detectee():
    pkts = [
        _pkt(ts=1.0, length=100),
        _pkt(ts=3.0, length=100),  # delta 2000ms > 1000ms -> idle
    ]
    timeline = build_flow_timeline(pkts)
    assert "idle" in timeline.phases


def test_phase_steady_detectee():
    pkts = [
        _pkt(ts=1.0, length=100),
        _pkt(ts=1.05, length=100),  # delta 50ms -> steady
        _pkt(ts=1.10, length=100),
    ]
    timeline = build_flow_timeline(pkts)
    assert "steady" in timeline.phases


def test_phase_teardown_detectee():
    pkts = [
        _pkt(ts=1.0, proto="TCP", flags="...A..."),
        _pkt(ts=2.0, proto="TCP", flags="F"),  # FIN -> teardown
    ]
    timeline = build_flow_timeline(pkts)
    assert "teardown" in timeline.phases


# -- RTT estimate ----------------------------------------------------------


def test_rtt_estimate_tcp_handshake():
    pkts = [
        _pkt(ts=1.0, proto="TCP", flags="S"),
        _pkt(ts=1.1, proto="TCP", flags="S A"),  # SYN-ACK -> RTT 100ms
    ]
    timeline = build_flow_timeline(pkts)
    assert timeline.rtt_estimate_ms is not None
    assert abs(timeline.rtt_estimate_ms - 100.0) < 1.0


def test_rtt_estimate_http():
    pkts = [
        _pkt(ts=1.0, proto="TCP", http_is_request=True, http_uri="/"),
        _pkt(ts=1.5, proto="TCP", http_is_response=True, http_status_code=200),
    ]
    timeline = build_flow_timeline(pkts)
    assert timeline.rtt_estimate_ms is not None
    assert abs(timeline.rtt_estimate_ms - 500.0) < 1.0


def test_rtt_estimate_dns():
    pkts = [
        _pkt(ts=1.0, proto="UDP", dns_txn_id=0x1234, dns_qry_name="example.com", dns_is_response=False),
        _pkt(ts=1.2, proto="UDP", dns_txn_id=0x1234, dns_qry_name="example.com", dns_is_response=True),
    ]
    timeline = build_flow_timeline(pkts)
    assert timeline.rtt_estimate_ms is not None
    assert abs(timeline.rtt_estimate_ms - 200.0) < 1.0


def test_rtt_estimate_none_sans_paire():
    pkts = [_pkt(ts=1.0, proto="TCP", flags="...A...")]
    timeline = build_flow_timeline(pkts)
    assert timeline.rtt_estimate_ms is None


# -- Cas limites -----------------------------------------------------------


def test_timeline_vide_sans_paquet():
    timeline = build_flow_timeline([])
    assert timeline.packet_timings == []
    assert timeline.throughput_windows == []
    assert timeline.phases == []
    assert timeline.rtt_estimate_ms is None


def test_timeline_un_seul_paquet():
    pkts = [_pkt(ts=5.0, length=100)]
    timeline = build_flow_timeline(pkts)
    assert len(timeline.packet_timings) == 1
    assert timeline.packet_timings[0].delta_ms == 0.0
    assert timeline.packet_timings[0].cumulative_bytes == 100


# -- Gardes defensives et branches rares (issue #740) ----------------------
# `_median` n'est appelee par build_flow_timeline qu'avec des deltas non vides
# et `_detect_phases` qu'apres le retour anticipe sur liste de paquets vide :
# ces deux gardes ne sont atteignables que par appel direct du helper.


def test_median_liste_vide_retourne_zero():
    assert _median([]) == 0.0


def test_detect_phases_sans_timings_retourne_liste_vide():
    assert _detect_phases([], []) == []


def test_phases_idle_consecutives_fusionnees():
    pkts = [
        _pkt(ts=1.0),
        _pkt(ts=3.0),  # delta 2000 ms -> idle
        _pkt(ts=5.0),  # delta 2000 ms -> deja en idle, pas de doublon
    ]
    timeline = build_flow_timeline(pkts)
    assert timeline.phases == ["idle"]


def test_rtt_dns_reponse_orpheline_ignoree():
    pkts = [
        _pkt(ts=1.0, proto="UDP", dns_txn_id=0x1234, dns_qry_name="example.com", dns_is_response=True),
    ]
    timeline = build_flow_timeline(pkts)
    assert timeline.rtt_estimate_ms is None


def test_rtt_dns_reponse_orpheline_puis_paire_complete():
    pkts = [
        _pkt(ts=0.5, proto="UDP", dns_txn_id=0x1, dns_qry_name="orphan.example", dns_is_response=True),
        _pkt(ts=1.0, proto="UDP", dns_txn_id=0x1234, dns_qry_name="example.com", dns_is_response=False),
        _pkt(ts=1.2, proto="UDP", dns_txn_id=0x1234, dns_qry_name="example.com", dns_is_response=True),
    ]
    timeline = build_flow_timeline(pkts)
    assert timeline.rtt_estimate_ms is not None
    assert abs(timeline.rtt_estimate_ms - 200.0) < 1.0
