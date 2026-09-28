"""Tests de couverture de netcross_core/analysis.py (issue #697, suite #665).

Chemins rares, testes directement sur les fonctions internes :

- topologie deduite du TTL sans --order (arcs, reduction transitive,
  Jaccard insuffisant, points de branchement) puis detection de perte et
  de trafic hors chemin sur ces arcs ;
- coherence de --order avec la topologie, saturation, bufferbloat ;
- temps de traitement serveur, DHCP, SIP, RTP, resume des champs loggues.
"""

from __future__ import annotations

from types import SimpleNamespace

from conftest import make_pkt

from netcross_core import analysis
from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.models import Report


def _p(ts, ttl):
    return SimpleNamespace(ts=ts, ttl=ttl)


# -- topologie deduite -----------------------------------------------------------


def test_topologie_chaine_reduite_et_jaccard_insuffisant():
    """Lignes 2086-2128 et 1978-1986 : A -> B -> C deduit du TTL, l'arc A -> C
    est explique par B et retire ; ligne 2050 : D partage trop peu de flux."""
    flows = {}
    for i in range(5):
        flows[f"f{i}"] = {"A": [_p(1.0, 64)], "B": [_p(1.1, 63)], "C": [_p(1.2, 62)]}
    for i in range(3):
        flows[f"f{i}"]["D"] = [_p(1.3, 60)]
    for i in range(200):
        flows[f"seul{i}"] = {"D": [_p(2.0, 60)]}
    edges, _ambigus, isoles, branches, fusions = analysis._infer_topology(flows, ["A", "B", "C", "D"])
    assert [(u, d) for u, d, _ in edges] == [("A", "B"), ("B", "C")]
    assert edges[0][2]["votes"] == "5/5"
    assert isoles == ["D"]
    assert (branches, fusions) == ([], [])


def test_topologie_point_de_branchement():
    """Lignes 2127-2129 : A alimente B et C, qui ne se recoupent pas."""
    flows = {}
    for i in range(4):
        flows[f"b{i}"] = {"A": [_p(1.0, 64)], "B": [_p(1.1, 63)]}
        flows[f"c{i}"] = {"A": [_p(1.0, 64)], "C": [_p(1.1, 63)]}
    edges, _ambigus, _isoles, branches, _fusions = analysis._infer_topology(flows, ["A", "B", "C"])
    assert sorted((u, d) for u, d, _ in edges) == [("A", "B"), ("A", "C")]
    assert branches == ["A"]


def test_analyse_sans_order_perte_et_hors_chemin_sur_la_topologie():
    """Lignes 112-113 : paires issues de la topologie ; lignes 300-313 : perte
    en aval d'un arc bien couvert, et couple d'hotes jamais vu en aval
    classe hors chemin."""
    pkts = []
    for sport in range(1, 11):
        pkts.append(make_pkt(point="A", sport=sport, ts=1.0 + sport, ttl=64))
        pkts.append(make_pkt(point="B", sport=sport, ts=1.001 + sport, ttl=63))
    pkts.append(make_pkt(point="A", sport=99, ts=20.0, ttl=64))
    pkts.append(make_pkt(point="A", src="10.9.9.9", dst="10.8.8.8", sport=5, ts=21.0, ttl=64))
    r = analyse(correlate(pkts), None, pkts)
    assert r.pairs == [("A", "B")]
    assert r.loss_count["B"] == 1
    assert r.off_path_count["B"] == 1
    assert r.loss_event_buckets[("A", "B")] == [20]


def test_topologie_ttl_indisponible():
    """Lignes 2054-2055 : flux communs mais sans TTL -> paire ambigue."""
    flows = {f"f{i}": {"A": [_p(1.0, None)], "B": [_p(1.1, None)]} for i in range(4)}
    edges, ambigus, _isoles, _b, _f = analysis._infer_topology(flows, ["A", "B"])
    assert edges == []
    assert ambigus == [("A", "B", "TTL indisponible pour comparer ces deux points")]


def test_vlan_ajoute_en_aval():
    """Ligne 284 : paquet non etiquete en A, etiquete en B."""
    pkts = [make_pkt(point="A", ts=1.0), make_pkt(point="B", ts=1.001, vlan_id=20)]
    r = analyse(correlate(pkts), ["A", "B"], pkts)
    assert r.vlan_tag_flip[("A", "B")]["untagged_to_tagged"] == 1


def test_order_contredit_par_la_topologie():
    """Lignes 2146-2147 : --order place B avant A alors que le TTL dit A -> B."""
    info = {"confidence": 0.9, "common_flows": 12}
    conflits = analysis._check_order_consistency(["B", "A"], [("A", "B", info), ("A", "Z", info)])
    assert conflits == ["--order place B avant A, mais le TTL indique plutot A -> B (confiance 90%, 12 flux communs)"]


# -- saturation et bufferbloat ----------------------------------------------------


def test_saturation_debit_absent_puis_pertes_aux_pics():
    """Ligne 1285 : pas de debit au point amont -> ignore ; ligne 1306 :
    pertes concentrees sur les pics de debit, sans plafond net."""
    r = Report(points=["A", "B", "X"], pairs=[("A", "B"), ("X", "B")])
    r.throughput["A"] = {0: 10, 1: 12, 2: 11, 3: 100, 4: 90, 5: 95, 6: 200}
    r.loss_event_buckets[("A", "B")] = [3, 6, 3, 6, 0]
    r.loss_event_buckets[("X", "B")] = [1]
    analysis._analyse_saturation(r)
    assert ("X", "B") not in r.saturation_verdict
    assert "saturation de lien ou de buffer" in r.saturation_verdict[("A", "B")]


def test_bufferbloat_latence_qui_monte_avec_le_debit():
    """Lignes 1327-1338 : latence moyenne x20 dans le quart le plus charge."""
    r = Report(points=["A", "B"], pairs=[("A", "B")])
    r.throughput["A"] = {0: 1, 1: 1, 2: 100, 3: 100}
    r.latency_by_bucket[("A", "B")] = {0: [1.0], 1: [1.0], 2: [20.0], 3: [20.0]}
    analysis._analyse_bufferbloat(r)
    assert r.bufferbloat_hint[("A", "B")] == (1.0, 20.0)


# -- analyse() de bout en bout : QoS, VLAN, fragmentation, temps serveur ----------


def test_remarquage_l3_changement_pcp_et_fragmentation_avec_encapsulation():
    """Ligne 270 : DSCP modifie avec un saut routeur ; ligne 280 : priorite
    802.1p modifiee ; ligne 370 : datagramme fragmente en aval ET dont la
    pile d'encapsulation change."""
    a = make_pkt(point="A", ts=1.0, dscp=46, ttl=64, vlan_id=10, vlan_prio=5, ip_id=7)
    b = make_pkt(
        point="B", ts=1.001, dscp=0, ttl=63, vlan_id=10, vlan_prio=0, ip_id=7, is_fragment=True, encap_tags=("MPLS",)
    )
    pkts = [a, b]
    r = analyse(correlate(pkts), ["A", "B"], pkts)
    assert r.qos_l3_remark[("A", "B")] == 1
    assert r.pcp_change[("A", "B")] == 1
    assert r.encap_frag_correlated[("A", "B")] == 1


def test_temps_de_traitement_serveur():
    """Lignes 1602-1616 : ecart requete client -> reponse serveur au point
    cote serveur, client identifie par son SYN."""
    c, s = ("10.0.0.1", 40000), ("10.0.0.2", 80)
    kw_c = {"src": c[0], "sport": c[1], "dst": s[0], "dport": s[1]}
    kw_s = {"src": s[0], "sport": s[1], "dst": c[0], "dport": c[1]}
    pkts = [
        make_pkt(point="B", ts=1.0, flags="S", seq=100, **kw_c),
        make_pkt(point="B", ts=2.0, payload_hash="req", seq=101, **kw_c),
        make_pkt(point="B", ts=2.05, payload_hash="rep", seq=500, **kw_s),
        make_pkt(point="B", ts=3.0, payload_hash="rep2", seq=600, **kw_s),
    ]
    r = analyse(correlate(pkts), ["A", "B"], pkts)
    (duree,) = r.server_think_time["10.0.0.1:40000 -> 10.0.0.2:80"]
    assert abs(duree - 50.0) < 1e-6


# -- fonctions internes -------------------------------------------------------------


def test_handshake_syn_sans_sequence_ou_hors_des_points():
    """Ligne 1373 : SYN sans numero de sequence ; ligne 1379 : SYN vu
    seulement a un point absent de l'ordre."""
    r = Report(points=["A", "B"], pairs=[("A", "B")])
    flows = {
        ("TCP", "10.0.0.1", 1, "10.0.0.2", 80, 1): {"A": [make_pkt(flags="S", seq=None)]},
        ("TCP", "10.0.0.1", 2, "10.0.0.2", 80, 2): {"Z": [make_pkt(point="Z", flags="S", seq=5)]},
    }
    analysis._analyse_handshake(r, flows, ["A", "B"], ["A", "B"], False)
    assert not r.syn_no_synack
    assert not r.syn_reply_missing


def test_rtp_sequence_absente_rebouclage_arriere_et_decalage_horloge():
    """Ligne 1499 : paquet sans n de sequence ; ligne 1503 : rebouclage
    65535 -> 0 ; ligne 1505 : paquet en
    retard d'avant le rebouclage ; ligne 1531 : delai corrige du decalage
    d'horloge estime."""
    base = {"proto": "UDP", "is_rtp": True, "rtp_ssrc": 1, "sport": 5004, "dport": 5004}
    pkts = [
        make_pkt(point="A", ts=1.0, rtp_seq=65535, rtp_ts=0, **base),
        make_pkt(point="A", ts=1.02, rtp_seq=None, rtp_ts=160, **base),
        make_pkt(point="A", ts=1.04, rtp_seq=0, rtp_ts=160, **base),
        make_pkt(point="B", ts=1.010, rtp_seq=0, rtp_ts=160, **base),
        make_pkt(point="B", ts=1.030, rtp_seq=65535, rtp_ts=0, **base),
    ]
    r = Report(points=["A", "B"], pairs=[("A", "B")])
    r.clock_offset_estimate[("A", "B")] = (4.0, 0.0)
    analysis._analyse_rtp(r, pkts, ["A", "B"], ["A", "B"], 8000)
    (flux,) = r.rtp_streams
    assert flux["loss_pct"]["B"] == 0.0
    assert abs(flux["delay_ms"] - 6.0) < 1e-6


def test_dhcp_nak_serveur_et_vendor_class():
    """Lignes 1633-1641 : comptage des messages, NAK, identification serveur."""
    pkts = [
        make_pkt(point="A", ts=1.0, dhcp_xid=1, dhcp_msg_type="discover", dhcp_vendor_class="MSFT 5.0"),
        make_pkt(point="A", ts=1.1, dhcp_xid=1, dhcp_msg_type="nak", dhcp_server_id="10.0.0.254"),
    ]
    r = Report(points=["A"], pairs=[])
    analysis._analyse_dhcp(r, pkts, ["A"], ["A"])
    assert r.dhcp_msg_count["A"] == {"discover": 1, "nak": 1}
    assert r.dhcp_nak_count["A"] == 1
    assert r.dhcp_server_seen["A"] == {"? (vendor-class: MSFT 5.0)", "10.0.0.254"}


def test_dhcp_message_perdu_entre_deux_points_et_duree():
    """Lignes 1646-1649 : ACK vu en A, absent en B ; ligne 1660 : duree
    DISCOVER -> ACK."""
    pkts = [
        make_pkt(point="A", ts=1.0, dhcp_xid=0x2A, dhcp_msg_type="discover"),
        make_pkt(point="B", ts=1.001, dhcp_xid=0x2A, dhcp_msg_type="discover"),
        make_pkt(point="A", ts=1.25, dhcp_xid=0x2A, dhcp_msg_type="ack"),
    ]
    r = Report(points=["A", "B"], pairs=[("A", "B")])
    analysis._analyse_dhcp(r, pkts, ["A", "B"], ["A", "B"])
    assert r.dhcp_missing[("A", "B")] == ["xid=0x0000002a : ack vu en A, absent en B"]
    assert abs(r.dhcp_duration_ms[0] - 250.0) < 1e-6


def test_sip_user_agent_releve():
    """Lignes 1692 et 1694 : en-tetes User-Agent et Server repris tels quels."""
    pkts = [
        make_pkt(point="A", sip_call_id="c1", sip_msg_type="INVITE", sip_user_agent="Linphone/5"),
        make_pkt(point="A", ts=0.1, sip_call_id="c1", sip_msg_type="200", sip_server="Asterisk PBX 20"),
    ]
    r = Report(points=["A"], pairs=[])
    analysis._analyse_sip(r, pkts, ["A"], ["A"])
    assert r.sip_agents_seen["A"] == {"User-Agent: Linphone/5", "Server: Asterisk PBX 20"}


def test_taille_et_cle_de_conversation():
    """Lignes 49-50 : valeur scalaire rendue telle quelle ; lignes 464-466 :
    cle NAT ou mal formee -> pas de couple d'hotes."""
    assert analysis._taille(3.5) == 3.5
    assert analysis._conversation_key(("NAT", "TCP", "h", 0)) is None
    assert analysis._conversation_key(("NAT", "TCP", "a", 1, "b", 2)) is None
