"""
netcross_core.report_text -- mise en forme texte/CSV d'un Report. On ne
teste pas la mise en page caractere pres (fragile, sans valeur), mais
que (1) print_report() ne leve jamais sur un Report réaliste ni sur un
Report vide, et (2) write_detail_csv() produit un CSV structurellement
correct et complet.
"""

import csv

from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.models import PacketAnnotation
from netcross_core.report_text import print_annotations, print_report, write_detail_csv


def test_print_report_report_vide_ne_leve_pas(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "ANALYSE CROISEE DE CAPTURES" in out


def test_print_report_scenario_realiste_ne_leve_pas(capsys):
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, flags="S", seq=1),
        make_pkt(point="B", sport=1, ts=0.01, flags="S", seq=1),
        make_pkt(point="A", sport=2, ts=1.0),  # perdu en B
        make_pkt(point="A", sport=3, ts=2.0, window=0),
        make_pkt(
            point="A",
            proto="UDP",
            sport=4,
            is_rtp=True,
            rtp_seq=1,
            rtp_ts=100,
            rtp_ssrc=1,
        ),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Paquets/flux identifies par point" in out
    assert "A" in out and "B" in out


def test_print_report_tcp_expert_signaux_affiche_section(capsys):
    # issue #21 : la section signaux d'expertise TCP natifs apparait et
    # distingue hors-ordre (reordonnancement) / segment perdu (perte reelle)
    # / maj de fenetre.
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            sport=10,
            expert_flags=("tcp_tcp_analysis_out_of_order",),
        ),
        make_pkt(
            point="A",
            proto="TCP",
            sport=11,
            expert_flags=("tcp_tcp_analysis_lost_segment",),
        ),
        make_pkt(
            point="A",
            proto="TCP",
            sport=12,
            expert_flags=("tcp_tcp_analysis_window_update",),
        ),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Signaux d'expertise TCP natifs" in out
    assert "hors-ordre" in out
    assert "segment(s) perdu(s)" in out
    assert "maj(s) de fenetre" in out


def test_print_report_tcp_expert_signaux_aucun_message_defaut(capsys):
    pkts = [make_pkt(point="A", proto="TCP", sport=1, ts=0.0)]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "aucun signal d'expertise TCP supplementaire detecte" in out


def test_print_report_pmtud_blackhole_affiche(capsys):
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1", df=True, length=1400),
        make_pkt(point="A", sport=1, ts=1.0, payload_hash="h2", df=True, length=1400),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "PMTUD" in out
    assert "A -> B" in out
    assert "noir PMTUD probable" in out


def test_print_report_idle_timeout_affiche(capsys):
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1"),
        make_pkt(point="B", sport=1, ts=0.1, payload_hash="h1"),
        make_pkt(point="A", sport=1, ts=90.0, payload_hash="h2"),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "coupure NAT-FW silencieuse" in out
    assert "A -> B" in out
    assert "coupure NAT/pare-feu silencieuse probable" in out


def test_print_report_sans_idle_timeout_message_par_defaut(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucune coupure detectee" in out


def test_print_report_arp_conflict_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:09"),
        make_pkt(point="A", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:99"),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Conflits d'adresse IP (ARP)" in out
    assert "conflit d'adresse IP probable" in out
    assert "10.0.0.9" in out


def test_print_report_sans_arp_conflict_message_par_defaut(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucun conflit d'adresse IP detecte" in out


def test_print_report_stp_instability_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="STP", ts=0.0, stp_bpdu_type=0x80, stp_flags_tc=False, stp_root_id=None),
        make_pkt(
            point="A", proto="STP", ts=1.0, stp_bpdu_type=0, stp_flags_tc=False, stp_root_id="32768/aa:aa:aa:aa:aa:01"
        ),
        make_pkt(
            point="A", proto="STP", ts=3.0, stp_bpdu_type=0, stp_flags_tc=False, stp_root_id="4096/aa:aa:aa:aa:aa:02"
        ),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Instabilite STP" in out
    assert "1 changement(s) de topologie, 1 reelection(s) de racine" in out


def test_print_report_sans_stp_instability_message_par_defaut(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucune instabilite STP detectee" in out


def test_print_report_tls_cert_invalid_dates_affiche(capsys):
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            ts=1924992000.0,  # 2031-01-01, apres notAfter
            tls_cert_not_before="2020-01-01 00:00:00 (UTC)",
            tls_cert_not_after="2030-01-01 00:00:00 (UTC)",
            tls_cert_serial="aa:aa",
        )
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Certificats TLS" in out
    assert "1 certificat(s) hors de leur fenetre de validite" in out


def test_print_report_tls_cert_mismatch_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.9", sport=443, tls_cert_serial="aa:aa"),
        make_pkt(point="B", proto="TCP", src="10.0.0.9", sport=443, tls_cert_serial="bb:bb"),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "interception/substitution TLS possible" in out


def test_print_report_sans_tls_cert_anomalie_message_par_defaut(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucune anomalie de certificat detectee" in out


def test_print_report_tls_handshake_no_reply_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.1", sport=1234, dst="10.0.0.2", dport=443, tls_client_hello=True)
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Negociations TLS incompletes" in out
    assert "1 negociation(s) sans reponse" in out


def test_print_report_tls_handshake_incomplete_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.1", sport=1234, dst="10.0.0.2", dport=443, tls_client_hello=True),
        make_pkt(point="A", proto="TCP", src="10.0.0.2", sport=443, dst="10.0.0.1", dport=1234, tls_server_hello=True),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "1 negociation(s) interrompue(s)" in out


def test_print_report_sans_negociation_tls_incomplete_message_par_defaut(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucune negociation TLS incomplete detectee" in out


def test_print_report_icmpv6_too_big_affiche(capsys):
    # Session 22 -- pendant IPv6 du test ICMP Fragmentation Needed
    # (deja couvert implicitement par le scenario "realiste" ci-dessus,
    # qui ne contient pas d'ICMP -- ce test-ci verifie explicitement le
    # texte ICMPv6).
    pkts = [make_pkt(point="A", proto="ICMPv6", icmpv6_type=2, icmpv6_code=0, ip_id=None)]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "ICMPv6" in out and "Packet Too Big" in out


def test_print_report_retransmissions_par_cause_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="TCP", sport=1, is_fast_retransmission=True),
        make_pkt(point="A", proto="TCP", sport=2, is_retransmission=True),
        make_pkt(point="A", proto="TCP", sport=3, is_spurious_retransmission=True),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Retransmissions TCP par cause" in out
    assert "1 rapide(s)" in out
    assert "1 par timeout/RTO" in out
    assert "1 inutile(s)" in out


def test_print_report_options_tcp_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="TCP", flags="......S.", sport=1, mss_val=1460, wscale_shift=7),
        make_pkt(point="B", proto="TCP", flags="......S.", sport=1, mss_val=1400, wscale_shift=None),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Options TCP negociees au handshake" in out
    assert "MSS reduit sur 1 handshake" in out
    assert "Window Scale retire sur 1 handshake" in out


def test_print_report_dns_affiche_compteurs_et_nxdomain(capsys):
    pkts = [
        make_pkt(
            point="A",
            proto="UDP",
            sport=1,
            ts=0.0,
            dns_txn_id=1,
            dns_is_response=False,
            dns_qry_name="example.com",
        ),
        make_pkt(
            point="A",
            proto="UDP",
            sport=1,
            ts=0.01,
            dns_txn_id=1,
            dns_is_response=True,
            dns_qry_name="example.com",
            dns_rcode=0,
        ),
        make_pkt(
            point="A",
            proto="UDP",
            sport=2,
            ts=1.0,
            dns_txn_id=2,
            dns_is_response=True,
            dns_qry_name="inexistant.example",
            dns_rcode=3,
        ),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "DNS (resolution de noms)" in out
    assert "requete(s)" in out and "reponse(s)" in out
    assert "NXDOMAIN" in out
    assert "duree moyenne de resolution" in out


def test_print_report_dns_absent_affiche_message_dedie(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucun trafic DNS detecte dans les captures" in out


def test_print_report_http_affiche_compteurs_et_erreurs(capsys):
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            sport=1,
            ts=0.0,
            http_is_request=True,
            http_method="GET",
            http_uri="/",
        ),
        make_pkt(
            point="A",
            proto="TCP",
            sport=1,
            ts=0.01,
            http_is_response=True,
            http_uri="/",
            http_status_code=200,
            http_response_time_ms=10.0,
        ),
        make_pkt(
            point="A",
            proto="TCP",
            sport=2,
            ts=1.0,
            http_is_request=True,
            http_method="GET",
            http_uri="/panne",
        ),
        make_pkt(
            point="A",
            proto="TCP",
            sport=2,
            ts=1.02,
            http_is_response=True,
            http_uri="/panne",
            http_status_code=500,
            http_response_time_ms=20.0,
        ),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "HTTP (codes de statut" in out
    assert "requete(s)" in out and "reponse(s)" in out
    assert "GET /panne -> 500" in out
    assert "duree moyenne de reponse" in out


def test_print_report_http_absent_affiche_message_dedie(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucun trafic HTTP detecte dans les captures" in out


def test_write_detail_csv_structure_et_contenu(tmp_path):
    pkts = [
        make_pkt(point="A", sport=1, dscp=10, ttl=64, ts=0.0),
        make_pkt(point="B", sport=1, dscp=20, ttl=62, ts=0.05),
    ]
    flows = correlate(pkts)
    out_path = tmp_path / "detail.csv"
    write_detail_csv(str(out_path), flows, ["A", "B"])

    with open(out_path, newline="") as f:
        rows = list(csv.reader(f))

    header = rows[0]
    assert header[:6] == ["proto", "src", "sport", "dst", "dport", "key_id"]
    assert "A_ts" in header and "B_dscp" in header and "B_ttl" in header
    assert len(rows) == 2  # en-tete + 1 flux

    row = dict(zip(header, rows[1]))
    assert row["A_dscp"] == "10"
    assert row["B_dscp"] == "20"
    assert row["A_ttl"] == "64"


def test_write_detail_csv_flux_absent_a_un_point_laisse_les_cellules_vides(tmp_path):
    pkts = [make_pkt(point="A", sport=1)]
    flows = correlate(pkts)
    out_path = tmp_path / "detail.csv"
    write_detail_csv(str(out_path), flows, ["A", "B"])
    with open(out_path, newline="") as f:
        rows = list(csv.reader(f))
    _header, row = rows[0], dict(zip(rows[0], rows[1]))
    assert row["B_dscp"] == ""
    assert row["B_ttl"] == ""


# -- Etiquetage et signets sur paquets (Job 40/issue #160) -------------------


def test_print_annotations_liste_vide_ne_leve_pas(capsys):
    print_annotations([])
    out = capsys.readouterr().out
    assert "aucune annotation" in out


def test_print_annotations_affiche_tag_et_trame(capsys):
    annotations = [
        PacketAnnotation(frame_number=7, tag="suspect", comment="a revoir"),
        PacketAnnotation(frame_number=3, tag="suspect"),
    ]
    print_annotations(annotations)
    out = capsys.readouterr().out
    assert "[suspect] 2 paquet(s)" in out
    assert "trame #7" in out
    assert "trame #3" in out
    assert "a revoir" in out


def test_print_annotations_trie_par_numero_de_trame_dans_un_tag(capsys):
    annotations = [
        PacketAnnotation(frame_number=99, tag="x"),
        PacketAnnotation(frame_number=1, tag="x"),
    ]
    print_annotations(annotations)
    out = capsys.readouterr().out
    assert out.index("trame #1") < out.index("trame #99")


def test_print_report_fichiers_extraits_affiches(capsys):
    """Issue #349 : r.extracted_files est rempli depuis #150, mais aucun
    rendu ne l'exposait -- un executable PE telecharge en HTTP etait
    invisible du rapport. Le texte doit montrer la section et au moins un
    fichier avec son empreinte (SHA-256 si presente, MD5 sinon)."""
    from netcross_core.models import Report

    r = Report(points=["A"])
    r.extracted_files = [
        {
            "point": "A",
            "proto_source": "HTTP",
            "src": "10.0.0.2",
            "dst": "10.0.0.5",
            "ts": 1.0,
            "uri": "/malware.exe",
            "content_type": "application/octet-stream",
            "size": 13312,
            "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
            "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "type_detected": "PE",
            "frame_number": 42,
        }
    ]
    print_report(r)
    out = capsys.readouterr().out
    assert "Fichiers extraits" in out
    assert "/malware.exe" in out
    assert "PE" in out
    assert "e3b0c44298fc1c14" in out  # debut du SHA-256


# -- couverture des branches manquantes (issue #246) -------------------------
# On construit des objets Report directement pour cibler les branches
# rarement atteintes par les scenarios realistes ci-dessus.

from netcross_core.models import Report, SequenceGap  # noqa: E402
from netcross_core.report_text import (  # noqa: E402
    SEQ_GAP_CAPTURE_DROP,
    SEQ_GAP_INDETERMINATE,
    SEQ_GAP_NETWORK_LOSS,
)


def _r(**overrides):
    """Report minimal avec defaults, override via kwargs."""
    r = Report(points=["A", "B"])
    r.pairs = [("A", "B")]
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


def test_print_report_linktype_none(capsys):
    """Line 61 : _linktype_lisible(None) -> '?'."""
    # Indirectement via capture_infos avec interfaces sans linktype
    r = _r(capture_infos=[{"label": "A", "interfaces": [{"name": "iface0", "linktype": None}]}])
    print_report(r)
    out = capsys.readouterr().out
    assert "linktype ?" in out


def test_print_report_capture_infos_complet(capsys):
    """Lines 102-173 : capture_infos avec tous les champs."""
    r = _r(
        capture_infos=[
            {
                "label": "WAN",
                "file_type": "pcapng",
                "version": "1.0",
                "packet_count": 100,
                "encapsulation": "ether",
                "snaplen": 65535,
                "duration_seconds": 10.5,
                "hardware": "Intel",
                "operating_system": "Linux",
                "application": "dumpcap",
                "dropped_by_interface": 5,
                "dropped_by_os": 2,
                "interfaces": [
                    {
                        "name": "eth0",
                        "linktype": 1,
                        "snaplen": 65535,
                        "received": 1000,
                        "dropped_by_interface": 3,
                        "dropped_by_os": 1,
                    },
                    {"name": None, "index": 1, "linktype": 12, "received": 500},
                ],
            }
        ]
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "WAN : pcapng v1.0" in out
    assert "encapsulation ether" in out
    assert "100 paquets" in out
    assert "snaplen : 65535" in out
    assert "duree : 10.500s" in out
    assert "materiel : Intel" in out
    assert "OS : Linux" in out
    assert "application : dumpcap" in out
    assert "interface : 5" in out and "OS : 2" in out
    assert "linktype 1 (Ethernet)" in out
    assert "iface1" in out


def test_print_report_capture_infos_sans_encap_ni_interfaces(capsys):
    """Line 152-158 : link type non renseigne."""
    r = _r(capture_infos=[{"label": "A"}])
    print_report(r)
    out = capsys.readouterr().out
    assert "link type : non renseigne" in out


def test_print_report_topology_edges_avec_coverage_faible(capsys):
    """Lines 177-197 : topology_edges, coverage < 0.8, branch/merge points."""
    r = _r(
        topology_edges=[("A", "B", {"confidence": 0.5, "common_flows": 3, "votes": 5, "coverage": 0.5})],
        topology_used_for_order=True,
        topology_branch_points=["A"],
        topology_merge_points=["B"],
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "A -> B" in out
    assert "confiance 50%" in out
    assert "branchement" in out
    assert "order non fourni" in out
    assert "points de branchement" in out
    assert "points de convergence" in out


def test_print_report_topology_ambiguous_isolated_conflicts(capsys):
    """Lines 205-219 : topology_ambiguous, topology_isolated, topology_order_conflicts."""
    r = _r(
        topology_ambiguous=[("A", "B", "chemins multiples")],
        topology_isolated=["C"],
        topology_order_conflicts=["A devrait etre avant B"],
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "Relations ambigues" in out
    assert "chemins multiples" in out
    assert "Points sans relation" in out
    assert "ATTENTION" in out
    assert "A devrait etre avant B" in out


def test_print_report_latency_avec_clock_offset(capsys):
    """Lines 242-244 : latency avec clock_offset_estimate."""
    r = _r(
        latency={("A", "B"): [1.0, 2.0, 3.0]},
        clock_offset_estimate={("A", "B"): (0.5, 0.1, 3)},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "decalage d'horloge estime" in out
    assert "latence corrigee" in out


def test_print_report_clock_offset_section(capsys):
    """Lines 251-257 : section decalage d'horloge."""
    r = _r(clock_offset_estimate={("A", "B"): (1.5, 0.2, 5)})
    print_report(r)
    out = capsys.readouterr().out
    assert "Decalage d'horloge estime" in out
    assert "A <-> B : +1.50ms" in out


def test_print_report_hop_delta_avec_outliers(capsys):
    """Lines 271, 277-284 : hop_delta avec outliers et chaine de sauts."""
    r = _r(
        points=["A", "B", "C"],
        pairs=[("A", "B"), ("B", "C")],
        hop_delta={("A", "B"): [1, 1, 1], ("B", "C"): [2, 2, 2]},
        hop_delta_outliers={("A", "B"): 1, ("B", "C"): 0},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "saut(s) routeur le plus frequent" in out
    assert "flux avec un nombre de sauts different" in out
    assert "Chaine de sauts" in out


def test_print_report_ttl_unstable(capsys):
    """Lines 287-290 : TTL instable."""
    r = _r(ttl_unstable={"A": 3, "B": 0})
    print_report(r)
    out = capsys.readouterr().out
    assert "Instabilite de route intra-flux" in out
    assert "3 flux avec TTL variable" in out


def test_print_report_qos_change_avec_l2_l3(capsys):
    """Lines 300-307 : QoS change avec l2/l3 remark."""
    r = _r(
        qos_change={("A", "B"): 5},
        qos_l2_remark={("A", "B"): 2},
        qos_l3_remark={("A", "B"): 3},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "5 paquets avec DSCP modifie" in out
    assert "2 sans saut de routeur" in out
    assert "3 avec saut de routeur" in out


def test_print_report_vlan_complet(capsys):
    """Lines 314-338 : VLAN avec change, tag_flip, pcp_change."""
    r = _r(
        vlan_seen={"A": {100, 200}, "B": {100}},
        vlan_change={("A", "B"): 2},
        vlan_tag_flip={("A", "B"): {"tagged_to_untagged": 1, "untagged_to_tagged": 1}},
        pcp_change={("A", "B"): 1},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "VLAN(s) observe(s)" in out
    assert "2 flux changent d'ID VLAN" in out
    assert "tagges en A et untagged en B" in out
    assert "untagged en A et tagges en B" in out
    assert "priorite 802.1p (PCP) modifiee" in out


def test_print_report_encap_complet(capsys):
    """Lines 349-364 : encapsulation avec change, examples, frag_correlated."""
    r = _r(
        encap_seen={"A": {"MPLS"}, "B": {"GRE"}},
        encap_change={("A", "B"): 2},
        encap_change_examples={("A", "B"): ["flux 1", "flux 2"]},
        encap_frag_correlated={("A", "B"): 1},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "pile(s) observee(s)" in out
    assert "2 flux changent de pile" in out
    assert "ex: flux 1" in out
    assert "fragmentation sur ce meme segment" in out


def test_print_report_frag_complet(capsys):
    """Lines 376-377, 381-382, 388-389 : fragmentation."""
    r = _r(
        frag_count={"A": 5, "B": 0},
        frag_new={("A", "B"): 3},
        icmp_frag_needed={"A": 2, "B": 0},
        icmpv6_too_big={"A": 1, "B": 0},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "5 paquets fragmentes" in out
    assert "3 datagrammes NON fragmentes" in out
    assert "2 messages ICMP" in out
    assert "1 messages ICMPv6" in out


def test_print_report_pmtud_avec_examples(capsys):
    """Lines 411, 431 : PMTUD avec examples, idle timeout avec examples."""
    r = _r(
        pmtud_blackhole={("A", "B"): 2},
        pmtud_blackhole_examples={("A", "B"): ["seg 1", "seg 2"]},
        idle_timeout_dropped={("A", "B"): 1},
        idle_timeout_examples={("A", "B"): ["flux X"]},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "2 segment(s) TCP retransmis" in out
    assert "ex: seg 1" in out
    assert "1 flux TCP deja etabli(s)" in out
    assert "ex: flux X" in out


def test_print_report_arp_avec_examples(capsys):
    """Lines 446-456 : ARP avec examples."""
    r = _r(
        arp_ip_conflict={"A": 1, "B": 0},
        arp_ip_conflict_examples={"A": ["10.0.0.9"]},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "1 adresse(s) IP" in out
    assert "ex: 10.0.0.9" in out


def test_print_report_stp_avec_examples(capsys):
    """Lines 461-469 : STP avec examples."""
    r = _r(
        stp_topology_change={"A": 1, "B": 0},
        stp_root_change={"A": 1, "B": 0},
        stp_root_change_examples={"A": ["old -> new"]},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "1 changement(s) de topologie" in out
    assert "ex: old -> new" in out


def test_print_report_tls_cert_avec_examples(capsys):
    """Lines 474-491 : TLS cert invalid dates + mismatch avec examples."""
    r = _r(
        tls_cert_invalid_dates={"A": 1, "B": 0},
        tls_cert_invalid_dates_examples={"A": ["cert expired"]},
        tls_cert_mismatch={("A", "B"): 1},
        tls_cert_mismatch_examples={("A", "B"): ["serial diff"]},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "1 certificat(s) hors" in out
    assert "ex: cert expired" in out
    assert "1 connexion(s)" in out
    assert "ex: serial diff" in out


def test_print_report_tls_handshake_avec_examples(capsys):
    """Lines 496-506 : TLS handshake no_reply + incomplete avec examples."""
    r = _r(
        tls_handshake_no_reply={"A": 1, "B": 0},
        tls_handshake_no_reply_examples={"A": ["10.0.0.1:1234 -> 10.0.0.2:443"]},
        tls_handshake_incomplete={"A": 0, "B": 1},
        tls_handshake_incomplete_examples={"B": ["10.0.0.3:1234 -> 10.0.0.4:443"]},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "1 negociation(s) sans reponse" in out
    assert "1 negociation(s) interrompue(s)" in out
    assert "ex: 10.0.0.1:1234" in out
    assert "ex: 10.0.0.3:1234" in out


def test_print_report_throughput(capsys):
    """Lines 511-517 : debit observe."""
    r = _r(throughput={"A": {0.0: 1000, 1.0: 2000}, "B": {}})
    print_report(r)
    out = capsys.readouterr().out
    assert "Debit observe par point" in out
    assert "moy=" in out


def test_print_report_saturation_verdict(capsys):
    """Lines 520-522 : saturation verdict."""
    r = _r(saturation_verdict={("A", "B"): "saturation probable"})
    print_report(r)
    out = capsys.readouterr().out
    assert "saturation probable" in out


def test_print_report_bufferbloat_hint(capsys):
    """Lines 528-529 : bufferbloat hint."""
    r = _r(bufferbloat_hint={("A", "B"): (5.0, 50.0)})
    print_report(r)
    out = capsys.readouterr().out
    assert "bufferbloat" in out
    assert "5.0ms" in out


def test_print_report_sack_stripped(capsys):
    """Lines 592, 603 : SACK retire."""
    r = _r(
        sack_stripped={("A", "B"): 2},
        mss_clamped={("A", "B"): 0},
        wscale_stripped={("A", "B"): 0},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "SACK Permitted retire" in out


def test_print_report_rst_avec_localized(capsys):
    """Lines 612-621 : RST avec localized."""
    r = _r(rst_count={"A": 5, "B": 0}, rst_localized={"A": 3, "B": 0})
    print_report(r)
    out = capsys.readouterr().out
    assert "5 RST" in out
    assert "3 vus a ce seul point" in out


def test_print_report_syn_reply_missing(capsys):
    """Line 635 : SYN reply missing."""
    r = _r(
        syn_no_synack={"A": 0, "B": 0},
        syn_reply_missing={"A": 2, "B": 0},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "2 SYN vus a ce point" in out


def test_print_report_rtp_streams_complet(capsys):
    """Lines 668-670, 672, 674, 676 : RTP streams avec delta, delay, mos, truncation."""
    streams = [
        {
            "label": f"stream_{i}",
            "loss_pct": {"A": 1.0, "B": 2.5},
            "jitter_ms": {"A": 5.0, "B": 10.0},
            "delay_ms": 50.0,
            "mos": 4.2,
            "r_factor": 90.0,
        }
        for i in range(55)
    ]
    r = _r(rtp_streams=streams)
    print_report(r)
    out = capsys.readouterr().out
    assert "perte RTP supplementaire" in out
    assert "delai A->B" in out
    assert "R-factor" in out
    assert "5 flux RTP supplementaires non affiches" in out


def test_print_report_server_think_time_complet(capsys):
    """Lines 688-705 : server_think_time avec > 50 entries et net_lat."""
    think = {f"conn_{i}": [10.0, 20.0] for i in range(55)}
    r = _r(
        server_think_time=think,
        latency={("A", "B"): [5.0, 6.0, 7.0]},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "temps de traitement serveur" in out
    assert "5 connexions supplementaires" in out
    assert "ensemble" in out
    assert "a comparer au temps reseau" in out


def test_print_report_dhcp_complet(capsys):
    """Lines 718-746 : DHCP avec NAK, servers, missing, duration."""
    r = _r(
        dhcp_msg_count={"A": {"DISCOVER": 1, "OFFER": 1, "REQUEST": 1, "ACK": 1}, "B": {}},
        dhcp_nak_count={"A": 1, "B": 0},
        dhcp_server_seen={"A": ["192.168.1.1/isc-dhcp"], "B": []},
        dhcp_missing={("A", "B"): ["ACK missing"]},
        dhcp_duration_ms=[100.0, 200.0],
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "DISCOVER=1" in out
    assert "1 DHCPNAK" in out
    assert "isc-dhcp" in out
    assert "ACK missing" in out
    assert "duree moyenne DISCOVER->ACK" in out


def test_print_report_dhcp_missing_long(capsys):
    """Line 743 : > 20 missing messages DHCP."""
    r = _r(
        dhcp_msg_count={"A": {"DISCOVER": 1}, "B": {}},
        dhcp_missing={("A", "B"): [f"msg {i}" for i in range(25)]},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "5 autres messages manquants" in out


def test_print_report_sip_complet(capsys):
    """Lines 752-776 : SIP avec agents, missing, setup, failed_calls."""
    r = _r(
        sip_msg_count={"A": {"INVITE": 1, "200": 1}, "B": {}},
        sip_agents_seen={"A": ["Softphone/1.0"], "B": []},
        sip_missing={("A", "B"): ["200 OK missing"]},
        sip_setup_duration_ms=[500.0, 600.0],
        sip_failed_calls=["call_1 failed", "call_2 failed"],
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "INVITE=1" in out
    assert "Softphone/1.0" in out
    assert "200 OK missing" in out
    assert "duree moyenne d'etablissement" in out
    assert "call_1 failed" in out


def test_print_report_sip_missing_long(capsys):
    """Line 765 : > 20 missing SIP messages."""
    r = _r(
        sip_msg_count={"A": {"INVITE": 1}, "B": {}},
        sip_missing={("A", "B"): [f"msg {i}" for i in range(25)]},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "5 autres messages manquants" in out


def test_print_report_sip_failed_calls_long(capsys):
    """Line 776 : > 20 failed calls."""
    r = _r(
        sip_msg_count={"A": {"INVITE": 1}, "B": {}},
        sip_failed_calls=[f"call_{i} failed" for i in range(25)],
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "5 autres echecs" in out


def test_print_report_voip_calls(capsys):
    """Lines 782-792 : VoIP calls."""
    r = _r(
        voip_calls=[
            {
                "call_id": "call-123",
                "participants": ["alice", "bob"],
                "rtp_streams": [{"label": "stream1"}],
                "quality": "good",
                "setup_duration_ms": 100.0,
                "duration_ms": 5000.0,
                "events": [{"type": "INVITE", "ts": 1.0}],
            }
        ],
        voip_quality_distribution={"good": 1},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "call-123" in out
    assert "participants=alice, bob" in out
    assert "RTP=1" in out
    assert "qualite=good" in out
    assert "INVITE @ 1.000s" in out
    assert "distribution qualite" in out


def test_print_report_dns_complet(capsys):
    """Lines 807-818 : DNS avec NXDOMAIN, SERVFAIL, timeout, missing, duration."""
    r = _r(
        dns_query_count={"A": 5, "B": 0},
        dns_response_count={"A": 4, "B": 0},
        dns_nxdomain_count={"A": 1, "B": 0},
        dns_servfail_count={"A": 1, "B": 0},
        dns_timeout={"A": ["query timed out"], "B": []},
        dns_missing={("A", "B"): ["response missing"]},
        dns_duration_ms=[10.0, 20.0],
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "5 requete(s)" in out
    assert "1 NXDOMAIN" in out
    assert "1 SERVFAIL" in out
    assert "query timed out" in out
    assert "response missing" in out
    assert "duree moyenne de resolution" in out


def test_print_report_dns_timeout_long(capsys):
    """Lines 811-813 : > 20 DNS timeouts."""
    r = _r(
        dns_query_count={"A": 1, "B": 0},
        dns_response_count={"A": 0, "B": 0},
        dns_timeout={"A": [f"timeout {i}" for i in range(25)], "B": []},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "5 autres requetes sans reponse" in out


def test_print_report_http_complet(capsys):
    """Lines 846, 848, 853 : HTTP avec errors, timeout, missing, duration."""
    r = _r(
        http_request_count={"A": 5, "B": 0},
        http_response_count={"A": 4, "B": 0},
        http_status_count={"A": {"200": 3, "500": 1}, "B": {}},
        http_error_examples={"A": ["GET / -> 500"], "B": []},
        http_timeout={"A": ["req timed out"], "B": []},
        http_missing={("A", "B"): ["response missing"]},
        http_response_time_ms=[10.0, 20.0],
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "200=3, 500=1" in out
    assert "GET / -> 500" in out
    assert "req timed out" in out
    assert "response missing" in out
    assert "duree moyenne de reponse" in out


def test_print_report_http_timeout_long(capsys):
    """Lines 846-848 : > 20 HTTP timeouts."""
    r = _r(
        http_request_count={"A": 1, "B": 0},
        http_response_count={"A": 0, "B": 0},
        http_timeout={"A": [f"timeout {i}" for i in range(25)], "B": []},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "5 autres requetes sans reponse" in out


def test_print_report_http_missing_long(capsys):
    """Line 853 : > 20 HTTP missing."""
    r = _r(
        http_request_count={"A": 1, "B": 0},
        http_response_count={"A": 0, "B": 0},
        http_missing={("A", "B"): [f"msg {i}" for i in range(25)]},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "5 autres messages manquants" in out


def test_print_report_http_objects_long(capsys):
    """Line 874 : > 50 HTTP objects."""
    objs = [
        {
            "status_code": 200,
            "method": "GET",
            "uri": f"/page{i}",
            "content_type": "text/html",
            "content_length": 100,
            "response_time_ms": 10.0,
        }
        for i in range(55)
    ]
    r = _r(http_objects=objs)
    print_report(r)
    out = capsys.readouterr().out
    assert "5 objets supplementaires non affiches" in out


def test_print_report_sequence_gaps(capsys):
    """Lines 890-918 : print_sequence_gaps."""
    from netcross_core.report_text import print_sequence_gaps

    r = _r(
        sequence_gaps=[
            SequenceGap(
                point="A",
                src="10.0.0.1",
                dst="10.0.0.2",
                sport=1,
                dport=2,
                start_seq=100,
                end_seq=200,
                missing_bytes=100,
                ts=1.0,
                frame_number=5,
                cause=SEQ_GAP_CAPTURE_DROP,
                evidence="ack but not captured",
            ),
            SequenceGap(
                point="A",
                src="10.0.0.1",
                dst="10.0.0.2",
                sport=3,
                dport=4,
                start_seq=300,
                end_seq=400,
                missing_bytes=100,
                ts=2.0,
                frame_number=None,
                cause=SEQ_GAP_NETWORK_LOSS,
                evidence="not acked",
            ),
            SequenceGap(
                point="B",
                src="10.0.0.3",
                dst="10.0.0.4",
                sport=5,
                dport=6,
                start_seq=500,
                end_seq=600,
                missing_bytes=100,
                ts=3.0,
                frame_number=None,
                cause=SEQ_GAP_INDETERMINATE,
                evidence="unknown",
            ),
        ]
    )
    print_sequence_gaps(r)
    out = capsys.readouterr().out
    assert "trou(s)" in out
    assert "de capture" in out
    assert "perte(s) reseau" in out
    assert "indetermine(s)" in out
    assert "trame 5" in out


def test_print_report_sequence_gaps_plus_de_5(capsys):
    """Lines 917-918 : > 5 gaps -> truncation."""
    from netcross_core.report_text import print_sequence_gaps

    r = _r(
        sequence_gaps=[
            SequenceGap(
                point="A",
                src="10.0.0.1",
                dst="10.0.0.2",
                sport=1,
                dport=2,
                start_seq=i * 100,
                end_seq=(i + 1) * 100,
                missing_bytes=100,
                ts=float(i),
                frame_number=i,
                cause=SEQ_GAP_CAPTURE_DROP,
                evidence="gap",
            )
            for i in range(7)
        ]
    )
    print_sequence_gaps(r)
    out = capsys.readouterr().out
    assert "2 autre(s) trou(s)" in out


# -- dernieres lignes manquantes : continue avec pairs multiples --------


def test_print_report_pmtud_idle_continue_avec_pairs_multiples(capsys):
    """Lines 411, 431 : continue quand n=0 pour une paire parmi plusieurs."""
    r = _r(
        points=["A", "B", "C"],
        pairs=[("A", "B"), ("B", "C")],
        pmtud_blackhole={("A", "B"): 2, ("B", "C"): 0},
        pmtud_blackhole_examples={("A", "B"): ["seg 1"]},
        idle_timeout_dropped={("A", "B"): 1, ("B", "C"): 0},
        idle_timeout_examples={("A", "B"): ["flux X"]},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "2 segment(s) TCP retransmis" in out
    assert "1 flux TCP deja etabli(s)" in out


def test_print_report_sack_continue_avec_pairs_multiples(capsys):
    """Line 592 : continue quand aucune option TCP pour une paire."""
    r = _r(
        points=["A", "B", "C"],
        pairs=[("A", "B"), ("B", "C")],
        sack_stripped={("A", "B"): 2, ("B", "C"): 0},
        mss_clamped={("A", "B"): 0, ("B", "C"): 0},
        wscale_stripped={("A", "B"): 0, ("B", "C"): 0},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "SACK Permitted retire" in out


def test_print_report_dns_missing_long(capsys):
    """Line 818 : > 20 DNS missing messages."""
    r = _r(
        dns_query_count={"A": 1, "B": 0},
        dns_response_count={"A": 0, "B": 0},
        dns_missing={("A", "B"): [f"msg {i}" for i in range(25)]},
    )
    print_report(r)
    out = capsys.readouterr().out
    assert "5 autres messages manquants" in out


def test_print_report_checksum_errors_affiche_section(capsys):
    # Job 43/issue #163
    pkts = [make_pkt(point="A", frame_number=2, tcp_checksum="0x1111", tcp_checksum_bad=True)]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Integrite de capture : checksums IP/TCP/UDP" in out
    assert "checksum TCP invalide" in out
    assert "trame 2" in out
    assert "0x1111" in out


def test_print_report_sans_checksum_errors_message_par_defaut(capsys):
    pkts = [make_pkt(point="A", frame_number=1, tcp_checksum="0x76be", tcp_checksum_bad=False)]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "aucun checksum IP/TCP/UDP invalide detecte" in out
