"""
netcross_core.security.expert_correlation -- issue #137 (CVE-3) :
detection de tentatives d'exploitation (fuzzing, overflow, dos) a partir
des alertes Expert Info. Les paquets sont synthetiques ; la collecte
applicative de pcap_parser.packet.build_packet est verifiee sur des couches
EK synthetiques dont la structure a ete relevee avec un vrai tshark 4.2.2
(`_ws_malformed` de premier niveau, `_ws_expert` sous dns/http).
"""

import pytest
from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.security.expert_correlation import (
    CorrelationThresholds,
    _protocol_hint,
    app_anomaly,
    apply_expert_correlation,
    correlate_expert_alerts,
    flow_id,
)
from pcap_parser.packet import build_packet

MALFORMED = "_ws_malformed__ws_malformed_expert"
LOST = "tcp_tcp_analysis_lost_segment"


def _malformed(ts, *, sport=40000, dport=53, proto="UDP", frame=None, point="A", src="10.0.0.1", dst="10.0.0.2"):
    return make_pkt(
        point=point,
        ts=ts,
        proto=proto,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        frame_number=frame,
        expert_flags=(MALFORMED,),
        expert_details=((MALFORMED, "Error", "Malformed", "Malformed Packet (Exception occurred)"),),
    )


def _tcp_gap(ts, *, sport=40000, dport=443, point="A"):
    return make_pkt(point=point, ts=ts, sport=sport, dport=dport, expert_flags=(LOST,))


def _kinds(result):
    return sorted((s["kind"], s["flow"]) for s in result.suspicions)


# --- classification d'un paquet ---


def test_app_anomaly_malforme_protocole_deduit_du_port():
    a = app_anomaly(_malformed(0.0, dport=53))
    assert a is not None and a.malformed and a.protocol == "DNS"
    assert app_anomaly(_malformed(0.0, dport=443, proto="TCP")).protocol == "TLS"
    assert app_anomaly(_malformed(0.0, dport=80, proto="TCP")).protocol == "HTTP"
    assert app_anomaly(_malformed(0.0, dport=445, proto="TCP")).protocol == "SMB"
    assert app_anomaly(_malformed(0.0, dport=9999, proto="TCP")).protocol == "OTHER"


def test_app_anomaly_protocole_prefere_les_champs_decodes_au_port():
    pk = _malformed(0.0, dport=9999, proto="TCP")
    pk.http_is_request = True
    assert app_anomaly(pk).protocol == "HTTP"


def test_app_anomaly_condition_nommee_par_couche_et_severite_error():
    name = "http_http_chunked_encoding_error"
    pk = make_pkt(expert_flags=(name,), expert_details=((name, "Error", "Protocol", "bad chunk"),))
    a = app_anomaly(pk)
    assert a is not None and a.protocol == "HTTP" and not a.malformed


def test_app_anomaly_groupe_malformed_sans_le_prefixe_ws_malformed():
    name = "smb2_smb2_bad_length"
    pk = make_pkt(expert_flags=(name,), expert_details=((name, "Warning", "Malformed", "x"),))
    a = app_anomaly(pk)
    assert a is not None and a.protocol == "SMB" and a.malformed


def test_app_anomaly_ignore_note_l3_l4_et_paquet_sans_details():
    note = "dns_dns_extraneous"
    assert app_anomaly(make_pkt(expert_flags=(note,), expert_details=((note, "Note", "Undecoded", "x"),))) is None
    assert app_anomaly(make_pkt(expert_flags=("tcp_tcp_analysis_retransmission",))) is None
    # condition applicative sans metadonnees de severite : non classable, ignoree
    assert app_anomaly(make_pkt(expert_flags=("dns_dns_something",))) is None
    assert app_anomaly(make_pkt()) is None


def test_flow_id_est_bidirectionnel():
    fwd = make_pkt(src="10.0.0.1", sport=1111, dst="10.0.0.2", dport=53)
    rev = make_pkt(src="10.0.0.2", sport=53, dst="10.0.0.1", dport=1111)
    assert flow_id(fwd) == flow_id(rev)
    assert flow_id(make_pkt(sport=None, dport=None)).startswith("TCP ")


# --- fuzzing ---


def test_fuzzing_malformations_repetees_sur_un_meme_flux():
    pkts = [_malformed(t, sport=40000, frame=t + 1) for t in range(3)]
    r = correlate_expert_alerts(pkts)
    assert _kinds(r) == [("fuzzing", flow_id(pkts[0]))]
    s = r.suspicions[0]
    assert s["count"] == 3 and s["protocols"] == {"DNS": 3} and s["frames"] == [1, 2, 3]


def test_fuzzing_pas_declenche_sous_le_seuil():
    r = correlate_expert_alerts([_malformed(0.0), _malformed(1.0)])
    assert r.suspicions == []
    assert r.malformed_by_point == {"A": {"DNS": 2}}


def test_fuzzing_exige_le_meme_flux():
    pkts = [_malformed(float(i), sport=40000 + i) for i in range(3)]
    assert [s["kind"] for s in correlate_expert_alerts(pkts).suspicions] == []


def test_fuzzing_seuil_parametrable():
    pkts = [_malformed(0.0), _malformed(1.0)]
    r = correlate_expert_alerts(pkts, CorrelationThresholds(fuzzing_min_malformed=2))
    assert [s["kind"] for s in r.suspicions] == ["fuzzing"]


# --- overflow ---


def test_overflow_malforme_apres_anomalie_de_sequence_tcp():
    pkts = [_tcp_gap(10.0), _malformed(10.5, proto="TCP", dport=443, frame=7)]
    r = correlate_expert_alerts(pkts)
    assert [s["kind"] for s in r.suspicions] == ["overflow"]
    assert r.suspicions[0]["frames"] == [7] and r.suspicions[0]["protocols"] == {"TLS": 1}


def test_overflow_meme_paquet_malforme_et_anomalie_tcp():
    pk = _malformed(5.0, proto="TCP", dport=443)
    pk.expert_flags = (LOST, MALFORMED)
    assert [s["kind"] for s in correlate_expert_alerts([pk]).suspicions] == ["overflow"]


def test_overflow_pas_declenche_hors_fenetre_ou_dans_le_mauvais_ordre():
    late = [_tcp_gap(10.0), _malformed(20.0, proto="TCP", dport=443)]
    assert correlate_expert_alerts(late).suspicions == []
    before = [_malformed(10.0, proto="TCP", dport=443), _tcp_gap(10.5)]
    assert correlate_expert_alerts(before).suspicions == []


def test_overflow_pas_declenche_sans_anomalie_tcp_ou_sur_un_autre_flux():
    assert correlate_expert_alerts([_malformed(1.0, proto="TCP", dport=443)]).suspicions == []
    other_flow = [_tcp_gap(10.0, sport=41000), _malformed(10.5, proto="TCP", dport=443, sport=40000)]
    assert correlate_expert_alerts(other_flow).suspicions == []


def test_overflow_retransmission_seule_n_est_pas_une_anomalie_de_sequence():
    retrans = make_pkt(ts=10.0, expert_flags=("tcp_tcp_analysis_retransmission",))
    pkts = [retrans, _malformed(10.1, proto="TCP", dport=443)]
    assert correlate_expert_alerts(pkts).suspicions == []


# --- dos ---


def _burst(n, *, start=0.0, step=0.1, **kw):
    return [_malformed(start + i * step, sport=40000 + i, frame=i + 1, **kw) for i in range(n)]


def test_dos_volume_anormal_d_erreurs_tous_flux_confondus():
    r = correlate_expert_alerts(_burst(20))
    dos = [s for s in r.suspicions if s["kind"] == "dos"]
    assert len(dos) == 1
    assert dos[0]["flow"] == "10.0.0.1 -> 10.0.0.2" and dos[0]["count"] == 20 and dos[0]["bursts"] == 1
    assert len(dos[0]["frames"]) == 10  # preuve plafonnee


def test_dos_pas_declenche_si_les_erreurs_sont_etalees_dans_le_temps():
    assert correlate_expert_alerts(_burst(20, step=1.0)).suspicions == []


def test_dos_compte_les_erreurs_applicatives_non_malformees():
    name = "http_http_chunked_encoding_error"
    pkts = [
        make_pkt(
            ts=i * 0.1,
            sport=40000 + i,
            dport=80,
            expert_flags=(name,),
            expert_details=((name, "Error", "Protocol", "x"),),
        )
        for i in range(20)
    ]
    r = correlate_expert_alerts(pkts)
    assert [s["kind"] for s in r.suspicions] == ["dos"]
    assert r.malformed_by_point == {}  # erreurs applicatives : pas des paquets malformes


def test_dos_deux_rafales_distinctes_comptees_separement():
    pkts = _burst(20, start=0.0) + _burst(20, start=100.0)
    dos = next(s for s in correlate_expert_alerts(pkts).suspicions if s["kind"] == "dos")
    assert dos["bursts"] == 2 and dos["count"] == 40


# --- compteurs par point et par flux ---


def test_compteurs_par_point_par_protocole_et_par_flux():
    pkts = [
        _malformed(0.0, dport=53, point="A", frame=1),
        _malformed(1.0, dport=53, point="A", frame=2),
        _malformed(2.0, dport=443, proto="TCP", point="A", sport=41000, frame=3),
        _malformed(0.0, dport=53, point="B"),
    ]
    r = correlate_expert_alerts(pkts)
    assert r.malformed_by_point == {"A": {"DNS": 2, "TLS": 1}, "B": {"DNS": 1}}
    top = r.malformed_flows[0]
    assert (top["point"], top["count"], top["protocols"], top["frames"]) == ("A", 2, {"DNS": 2}, [1, 2])
    assert len(r.malformed_flows) == 3


def test_aucun_paquet_anormal_ne_produit_rien():
    r = correlate_expert_alerts([make_pkt(), make_pkt(ts=1.0)])
    assert r.malformed_by_point == {} and r.malformed_flows == [] and r.suspicions == []


# --- integration Report / analyse() ---


def test_analyse_renseigne_le_report():
    pkts = [_malformed(float(i), frame=i + 1) for i in range(3)]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A"], all_packets=pkts)
    assert r.exploit_suspicion["A"]["fuzzing"] == 1
    assert r.expert_malformed["A"]["DNS"] == 3
    assert r.expert_malformed_flows[0]["count"] == 3
    assert r.exploit_suspicion_flows[0]["kind"] == "fuzzing"


def test_report_sans_anomalie_reste_vide():
    pkts = [make_pkt(sport=1)]
    r = analyse(correlate(pkts), points_order=["A"], all_packets=pkts)
    assert not r.exploit_suspicion and not r.expert_malformed
    assert r.exploit_suspicion_flows == [] and r.expert_malformed_flows == []


def test_apply_expert_correlation_ecrase_le_resultat_precedent():
    from netcross_core.models import Report

    r = Report()
    apply_expert_correlation(r, [_malformed(float(i)) for i in range(3)])
    apply_expert_correlation(r, [])
    assert r.exploit_suspicion_flows == [] and r.expert_malformed_flows == []


# --- collecte applicative (pcap_parser.packet.build_packet) ---


def _layers(**extra):
    return {
        "frame": {"frame_frame_len": "80"},
        "ip": {"ip_ip_src": "10.0.0.1", "ip_ip_dst": "10.0.0.2", "ip_ip_ttl": "64"},
        "udp": {"udp_udp_srcport": "5353", "udp_udp_dstport": "53"},
        **extra,
    }


def _expert(name, severity, group, message):
    return {
        name: None,
        "_ws_expert__ws_expert_severity": severity,
        "_ws_expert__ws_expert_group": group,
        "_ws_expert__ws_expert_message": message,
    }


def test_build_packet_collecte_la_couche_ws_malformed_de_premier_niveau():
    # structure relevee avec tshark 4.2.2 : DNS tronque -> couche `_ws_malformed`
    layers = _layers(
        dns={"dns_dns_id": "0x1234"},
        _ws_malformed={
            "_ws_expert": _expert(MALFORMED, "8388608", "117440512", "Malformed Packet (Exception occurred)"),
            "_ws_malformed": {},
        },
    )
    pkt = build_packet(1.0, layers)
    assert pkt.expert_flags == (MALFORMED,)
    assert pkt.expert_details == ((MALFORMED, "Error", "Malformed", "Malformed Packet (Exception occurred)"),)


def test_build_packet_collecte_l_expertise_de_la_couche_dns():
    name = "dns_dns_extraneous"
    layers = _layers(dns={"_ws_expert": _expert(name, "4194304", "83886080", "Extraneous data")})
    pkt = build_packet(1.0, layers)
    assert pkt.expert_flags == (name,)
    assert pkt.expert_details[0][:3] == (name, "Note", "Undecoded")


def test_build_packet_ecarte_le_bruit_chat_http():
    # tshark emet http_http_chat (severite Chat) sur CHAQUE message HTTP
    layers = _layers(http={"_ws_expert": _expert("http_http_chat", "2097152", "33554432", "GET / HTTP/1.1")})
    pkt = build_packet(1.0, layers)
    assert pkt.expert_flags == () and pkt.expert_details == ()


def test_build_packet_couches_applicatives_empilees_en_liste():
    a = _expert("http_http_chunked_encoding_error", "8388608", "50331648", "bad chunk")
    b = _expert("http_http_chat", "2097152", "33554432", "chat")
    layers = _layers(http=[{"_ws_expert": a}, {"_ws_expert": b}])
    assert build_packet(1.0, layers).expert_flags == ("http_http_chunked_encoding_error",)


def test_build_packet_union_l4_et_applicatif():
    layers = _layers(
        tcp={"tcp_tcp_srcport": "40000", "tcp_tcp_dstport": "443", "_ws_expert": {LOST: None}},
        tls={"_ws_expert": _expert("tls_tls_record_length_invalid", "8388608", "117440512", "x")},
    )
    layers.pop("udp")
    assert build_packet(1.0, layers).expert_flags == (LOST, "tls_tls_record_length_invalid")


# --- _protocol_hint : indices portes par le paquet, port hors table (#753) ---


@pytest.mark.parametrize(
    ("flags", "attendu"),
    [
        ({"dns_txn_id": 0x1234}, "DNS"),
        ({"dns_qry_name": "example.org"}, "DNS"),
        ({"http_is_request": True}, "HTTP"),
        ({"http_is_response": True}, "HTTP"),
        ({"tls_client_hello": True}, "TLS"),
        ({"tls_server_hello": True}, "TLS"),
        ({"tls_application_data": True}, "TLS"),
    ],
)
def test_protocol_hint_utilise_les_indices_de_couche_avant_le_port(flags, attendu):
    """Ports 40000 -> 40001, absents de la table des ports : seul l'indice de
    couche applicative peut produire DNS, HTTP ou TLS."""
    pk = make_pkt(sport=40000, dport=40001, **flags)
    assert _protocol_hint(pk) == attendu
