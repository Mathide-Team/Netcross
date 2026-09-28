"""Issue #698 (suite de #665) : branches restantes de ``netcross_gtk4.dashboard_context``.

Complete ``tests/test_dashboard_context.py`` (scenario reel via ``correlate``)
avec des ``Flow``/``Report`` construits a la main pour les formes de cle
atypiques (cle vide, cle NAT, cle trop courte), les flux sans endpoints, les
filtres par point / cle de flux, les evenements heterogenes et le resume
complet de la selection. Logique pure : aucun import Gtk.
"""

from __future__ import annotations

from types import SimpleNamespace

from netcross_core.expert_model import Flow
from netcross_core.models import Report
from netcross_gtk4.dashboard_context import (
    DashboardSelection,
    build_dashboard_snapshot,
    select_bucket,
    select_event,
    select_flow,
    select_point,
)

TCP = ("TCP", "10.0.0.1", 1234, "10.0.0.2", 80, 0)
NAT = ("NAT", "UDP", "h1", 3)
COURTE = ("ICMP", "10.0.0.5", 8)  # plus courte que la forme stricte : port 2 lisible, port 4 non


def _flow(key, points, endpoints):
    return Flow(
        key=key,
        points=list(points),
        packet_count=dict.fromkeys(points, 2),
        byte_count=dict.fromkeys(points, 100),
        first_ts=dict.fromkeys(points, 0.0),
        last_ts=dict.fromkeys(points, 1.0),
        endpoints=endpoints,
    )


def _flows():
    return [
        _flow(TCP, ["A", "B"], ("10.0.0.1", "10.0.0.2")),
        _flow(NAT, ["B", "C"], ("10.0.0.3", "10.0.0.4")),
        _flow(COURTE, ["A"], None),  # sans endpoints : ni conversation, ni endpoint de protocole
        _flow((), ["C"], None),  # sans cle : protocole et ports inconnus
    ]


def _report():
    r = Report()
    r.pairs = [("A", "B"), ("B", "C")]
    r.loss_count.update({"A": 1, "B": 2})
    r.retrans.update({"A": 4})
    r.latency[("A", "B")] = [10.0, 20.0]
    r.loss_event_buckets[("A", "B")] = [0, 2]
    r.loss_event_buckets[("B", "C")] = [2]
    return r


# -- select_flow / select_event ------------------------------------------------------


def test_select_bucket_et_point_ne_touchent_que_leur_dimension():
    sel = select_point(select_bucket(DashboardSelection(protocol="TCP"), 3), "A")
    assert sel == DashboardSelection(protocol="TCP", bucket=3, point="A")


def test_select_flow_cle_vide_ou_nat():
    base = DashboardSelection(protocol="DNS", endpoint="9.9.9.9")
    vide = select_flow(base, _flow((), ["A", "B", "C"], None))
    assert vide.protocol == "DNS" and vide.endpoint == "9.9.9.9" and vide.pair is None  # rien d'ecrase
    nat = select_flow(base, _flow(NAT, ["B", "C"], ("10.0.0.3", "10.0.0.4")))
    assert nat.protocol == "UDP" and nat.endpoint == "10.0.0.3" and nat.pair == ("B", "C")


def test_select_event_sans_point_a_propager():
    sel = DashboardSelection(point="A", protocol="TCP")
    events = [
        SimpleNamespace(segment="A -> B"),  # une paire, pas un point
        SimpleNamespace(),  # aucun attribut
        SimpleNamespace(segment="B", protocol="UDP"),
    ]
    assert select_event(sel, 0, events) == DashboardSelection(point="A", protocol="TCP", event_id=0)
    assert select_event(sel, 1, events) == DashboardSelection(point="A", protocol="TCP", event_id=1)
    assert select_event(sel, 2, events) == DashboardSelection(point="B", protocol="UDP", event_id=2)


# -- build_dashboard_snapshot : flux, ports, protocoles -----------------------------------


def test_snapshot_libelles_de_flux_et_protocoles_atypiques():
    snap = build_dashboard_snapshot(_report(), _flows())
    assert [row["label"] for row in snap.flow_rows] == [
        "TCP 10.0.0.1:1234 -> 10.0.0.2:80",
        "UDP 10.0.0.3:? -> 10.0.0.4:?",  # cle NAT : pas de port lisible
        "ICMP None:8 -> None:?",  # cle trop courte : seul le port source est lisible
        "? None:? -> None:?",  # cle vide
    ]
    protocols = {row["protocol"]: row for row in snap.protocol_rows}
    assert set(protocols) == {"?", "ICMP", "TCP", "UDP"}
    assert protocols["ICMP"]["flows"] == 1 and protocols["ICMP"]["endpoints"] == []  # flux sans endpoints
    assert [row["endpoint"] for row in snap.endpoint_rows] == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]


def test_snapshot_filtre_par_cle_de_flux():
    snap = build_dashboard_snapshot(_report(), _flows(), selection=DashboardSelection(flow_key=NAT))
    assert [row["flow_key"] for row in snap.flow_rows] == [NAT]


# -- build_dashboard_snapshot : segments et timeline filtres par point --------------------


def test_snapshot_sans_selection_segments_et_timeline_complets():
    snap = build_dashboard_snapshot(_report(), _flows())
    assert [row["pair"] for row in snap.segment_rows] == ["A -> B", "B -> C"]
    assert snap.segment_rows[0]["loss"] == 3 and snap.segment_rows[0]["retrans"] == 4
    assert snap.segment_rows[0]["latency_ms"] == 15.0 and snap.segment_rows[1]["latency_ms"] is None
    assert [(r["bucket"], r["loss_events"], r["segments"]) for r in snap.timeline_rows] == [
        (0, 1, ["A -> B"]),
        (2, 2, ["A -> B", "B -> C"]),
    ]


def test_snapshot_filtre_par_point_ecarte_les_segments_etrangers():
    snap = build_dashboard_snapshot(_report(), _flows(), selection=DashboardSelection(point="A"))
    assert [row["pair"] for row in snap.segment_rows] == ["A -> B"]  # B -> C ne contient pas A
    assert [(r["bucket"], r["segments"]) for r in snap.timeline_rows] == [(0, ["A -> B"]), (2, ["A -> B"])]
    assert [row["flow_key"] for row in snap.flow_rows] == [TCP, COURTE]


# -- build_dashboard_snapshot : evenements ------------------------------------------------


def test_snapshot_evenements_filtres_par_point():
    events = [
        SimpleNamespace(segment="A", message="meme point"),
        SimpleNamespace(segment="B", message="autre point"),
        SimpleNamespace(segment="A -> B", message="paire contenant le point"),
        SimpleNamespace(segment="C -> D", message="paire sans le point"),
        SimpleNamespace(message="sans segment"),
    ]
    snap = build_dashboard_snapshot(None, None, findings=events, selection=DashboardSelection(point="A"))
    assert [row["message"] for row in snap.event_rows] == ["meme point", "paire contenant le point", "sans segment"]
    assert [row["id"] for row in snap.event_rows] == [0, 2, 4]  # indices dans la liste fusionnee


# -- resume de la selection ---------------------------------------------------------------


def test_resume_de_toutes_les_dimensions():
    sel = DashboardSelection(
        point="A",
        endpoint="10.0.0.1",
        protocol="TCP",
        flow_key=TCP,
        pair=("A", "B"),
        bucket=3,
        event_id=7,
    )
    summary = build_dashboard_snapshot(None, None, selection=sel).selection_summary
    assert summary == (
        "point=A | endpoint=10.0.0.1 | proto=TCP | flow=selectionne | segment=A -> B | bucket=3 | evenement=#7"
    )
    assert build_dashboard_snapshot(None, None).selection_summary == "aucune selection active"
