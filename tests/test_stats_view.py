"""tests/test_stats_view.py -- tests du module netcross_gtk4.stats_view.

Logique de presentation pour la vue d'exploration statistique (Job 27).
Testable sans display GTK : aucun import Gtk dans stats_view.py.
"""

from __future__ import annotations

from netcross_core.expert_model import Flow
from netcross_core.models import Report
from netcross_core.stats import StatRow
from netcross_gtk4.stats_view import (
    build_events_by_segment,
    build_query,
    flows_for_row,
    format_bps,
    format_bytes,
    format_flow_summary,
    format_row,
    format_rows,
    group_options,
    run_stats,
    sort_options,
)

# -- Helpers ----------------------------------------------------------------


def _make_flow(
    key: tuple = ("TCP", "10.0.0.1", 50000, "10.0.0.2", 80),
    points: tuple = ("LAN", "WAN"),
    packet_count: dict | None = None,
    byte_count: dict | None = None,
    endpoints: tuple = ("10.0.0.1", "10.0.0.2"),
    first_ts: dict | None = None,
    last_ts: dict | None = None,
) -> Flow:
    return Flow(
        key=key,
        points=points,
        packet_count=packet_count or {"LAN": 10, "WAN": 8},
        byte_count=byte_count or {"LAN": 1000, "WAN": 800},
        endpoints=endpoints,
        first_ts=first_ts or {"LAN": 1.0, "WAN": 1.1},
        last_ts=last_ts or {"LAN": 5.0, "WAN": 4.9},
    )


def _make_report() -> Report:
    return Report(points=["LAN", "WAN"])


# -- Tests format_bytes ------------------------------------------------------


def test_format_bytes_units():
    assert format_bytes(0) == "0 o"
    assert format_bytes(512) == "512 o"
    assert format_bytes(1024) == "1.0 Ko"
    assert format_bytes(1024 * 1024) == "1.0 Mo"
    assert format_bytes(1024 * 1024 * 1024) == "1.0 Go"


def test_format_bps_units():
    assert format_bps(0) == "0 bps"
    assert format_bps(999) == "999 bps"
    assert format_bps(1000) == "1.0 kbps"
    assert format_bps(1_000_000) == "1.0 Mbps"


# -- Tests format_row --------------------------------------------------------


def test_format_row_includes_label_and_packets():
    row = StatRow(label="TCP 10.0.0.1:50000 -> 10.0.0.2:80", group_by="flow", packets=18, bytes=1800)
    text = format_row(row)
    assert "TCP 10.0.0.1" in text
    assert "paquets=18" in text
    assert "octets=" in text


def test_format_row_omits_zero_fields():
    row = StatRow(label="UDP", group_by="protocol", packets=0, bytes=0)
    text = format_row(row)
    assert "duree=" not in text
    assert "debit=" not in text
    assert "latence=" not in text
    assert "evenements=" not in text


def test_format_row_includes_latency_when_present():
    row = StatRow(label="LAN -> WAN", group_by="segment", packets=5, bytes=500, latency_ms=12.5)
    text = format_row(row)
    assert "latence=12.5ms" in text


def test_format_row_includes_duration_and_throughput_when_present():
    row = StatRow(
        label="LAN -> WAN",
        group_by="segment",
        packets=5,
        bytes=500,
        duration_ms=250.0,
        throughput_bps=32000.0,
    )
    text = format_row(row)
    assert "duree=250ms" in text
    assert "debit=" in text


def test_format_row_includes_events_when_present():
    row = StatRow(label="LAN -> WAN", group_by="segment", packets=5, bytes=500, events=3)
    text = format_row(row)
    assert "evenements=3" in text


def test_format_rows_returns_list():
    rows = [
        StatRow(label="A", group_by="endpoint", packets=1, bytes=100),
        StatRow(label="B", group_by="endpoint", packets=2, bytes=200),
    ]
    result = format_rows(rows)
    assert len(result) == 2
    assert "A" in result[0]
    assert "B" in result[1]


# -- Tests options -----------------------------------------------------------


def test_sort_options_returns_pairs():
    opts = sort_options()
    assert len(opts) == 6
    assert all(isinstance(v, str) and isinstance(lbl, str) for v, lbl in opts)
    values = [v for v, _ in opts]
    assert "packets" in values
    assert "bytes" in values
    assert "events" in values


def test_group_options_returns_pairs():
    opts = group_options()
    assert len(opts) == 4
    values = [v for v, _ in opts]
    assert "endpoint" in values
    assert "protocol" in values
    assert "segment" in values
    assert "flow" in values


# -- Tests build_query --------------------------------------------------------


def test_build_query_defaults():
    q = build_query(group_by="endpoint", sort_by="bytes", top_n=10)
    assert q.group_by == "endpoint"
    assert q.sort_by == "bytes"
    assert q.top_n == 10


def test_build_query_top_n_zero_becomes_none():
    q = build_query(group_by="protocol", sort_by="packets", top_n=0)
    assert q.top_n is None


def test_build_query_invalid_group_by_raises():
    import pytest

    with pytest.raises(ValueError):
        build_query(group_by="invalid", sort_by="bytes", top_n=10)


def test_build_query_with_time_filter():
    q = build_query(
        group_by="flow",
        sort_by="duration_ms",
        top_n=5,
        time_start=1.0,
        time_end=10.0,
        segment="LAN",
    )
    assert q.time_start == 1.0
    assert q.time_end == 10.0
    assert q.segment == "LAN"


# -- Tests run_stats ---------------------------------------------------------


def test_run_stats_with_none_flows_returns_empty():
    q = build_query(group_by="endpoint", sort_by="bytes", top_n=10)
    result = run_stats(None, _make_report(), q)
    assert result == []


def test_run_stats_with_none_report_returns_empty():
    flows = [_make_flow()]
    q = build_query(group_by="endpoint", sort_by="bytes", top_n=10)
    result = run_stats(flows, None, q)
    assert result == []


def test_run_stats_returns_rows():
    flows = [_make_flow(), _make_flow(key=("UDP", "10.0.0.3", 53, "10.0.0.4", 53))]
    report = _make_report()
    q = build_query(group_by="protocol", sort_by="packets", top_n=10)
    rows = run_stats(flows, report, q)
    assert len(rows) >= 1
    assert all(r.group_by == "protocol" for r in rows)


# -- Tests flows_for_row ------------------------------------------------------


def test_flows_for_row_matches_by_key():
    flow = _make_flow()
    row = StatRow(
        label="test",
        group_by="flow",
        packets=10,
        bytes=100,
        flow_keys=[flow.key],
    )
    result = flows_for_row(row, [flow])
    assert len(result) == 1
    assert result[0].key == flow.key


def test_flows_for_row_no_match_returns_empty():
    row = StatRow(
        label="test",
        group_by="flow",
        packets=10,
        bytes=100,
        flow_keys=[("TCP", "1.2.3.4", 80, "5.6.7.8", 90)],
    )
    result = flows_for_row(row, [_make_flow()])
    assert result == []


# -- Tests format_flow_summary -----------------------------------------------


def test_format_flow_summary_includes_points_and_bytes():
    flow = _make_flow()
    text = format_flow_summary(flow)
    assert "LAN" in text
    assert "WAN" in text
    assert "pkts" in text


def test_format_flow_summary_without_points_or_endpoints():
    flow = _make_flow(points=(), endpoints=())
    text = format_flow_summary(flow)
    assert "?" in text


# -- Tests build_events_by_segment -------------------------------------------


def test_build_events_by_segment_empty():
    result = build_events_by_segment(None, None)
    assert result == {}


def test_build_events_by_segment_with_findings():
    class FakeFinding:
        def __init__(self, segment="LAN -> WAN"):
            self.segment = segment

    findings = [FakeFinding(), FakeFinding("WAN -> LAN")]
    result = build_events_by_segment(findings, None)
    assert "LAN -> WAN" in result
    assert len(result["LAN -> WAN"]) == 1
    assert "WAN -> LAN" in result


def test_build_events_by_segment_without_segment_or_pair():
    class FakeFindingNoSegment:
        pass

    findings = [FakeFindingNoSegment()]
    result = build_events_by_segment(findings, None)
    assert "?" in result
    assert len(result["?"]) == 1
