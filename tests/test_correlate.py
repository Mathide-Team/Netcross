from conftest import make_pkt

from netcross_core.correlate import (
    TOPN_OTHER_LABEL,
    build_conversations,
    build_flows,
    compute_throughput,
    compute_topn_series,
    correlate,
    flow_key,
)


def test_flow_key_strict_ignore_le_point():
    a = make_pkt(point="A", src="1.1.1.1", sport=1, dst="2.2.2.2", dport=2, key_id=99)
    b = make_pkt(point="B", src="1.1.1.1", sport=1, dst="2.2.2.2", dport=2, key_id=99)
    assert flow_key(a) == flow_key(b)


def test_flow_key_strict_distingue_les_flux_differents():
    a = make_pkt(sport=1)
    b = make_pkt(sport=2)
    assert flow_key(a) != flow_key(b)


def test_flow_key_nat_tolerant_utilise_le_hash_de_payload():
    a = make_pkt(src="10.0.0.1", sport=11111, payload_hash="abc", ts=1.0)
    b = make_pkt(src="203.0.113.1", sport=22222, payload_hash="abc", ts=1.05)
    # IP/port differents (comme apres un NAT) mais meme hash + meme fenetre
    assert flow_key(a, nat_tolerant=True) == flow_key(b, nat_tolerant=True)


def test_flow_key_nat_tolerant_sans_payload_hash_retombe_en_strict():
    a = make_pkt(payload_hash=None, src="1.1.1.1", sport=1, dst="2.2.2.2", dport=2, key_id=5)
    strict_key = flow_key(a, nat_tolerant=False)
    nat_key = flow_key(a, nat_tolerant=True)
    assert nat_key == strict_key


def test_flow_key_nat_tolerant_fenetre_temporelle_separe_les_evenements_distants():
    a = make_pkt(payload_hash="abc", ts=0.0)
    b = make_pkt(payload_hash="abc", ts=5.0)  # bien au-dela de nat_window_ms
    assert flow_key(a, nat_tolerant=True, nat_window_ms=200) != flow_key(b, nat_tolerant=True, nat_window_ms=200)


def test_correlate_regroupe_par_flow_key_et_par_point():
    p1 = make_pkt(point="A", sport=1)
    p2 = make_pkt(point="B", sport=1)
    p3 = make_pkt(point="A", sport=2)
    flows = correlate([p1, p2, p3])
    assert len(flows) == 2
    key_sport1 = flow_key(p1)
    assert set(flows[key_sport1]) == {"A", "B"}
    assert flows[key_sport1]["A"] == [p1]
    assert flows[key_sport1]["B"] == [p2]


def test_correlate_plusieurs_paquets_du_meme_flux_au_meme_point():
    p1 = make_pkt(point="A", ts=0.0)
    p2 = make_pkt(point="A", ts=0.1)
    flows = correlate([p1, p2])
    key = flow_key(p1)
    assert flows[key]["A"] == [p1, p2]


def test_correlate_exclut_arp():
    # ARP (Session 24) est diffuse/local par nature (RFC 826, jamais
    # relaye par un routeur) -- n'a pas la semantique requete/reponse-
    # PAR-FLUX que `flows` suppose implicitement pour pertes/latence/
    # QoS/topologie. Reste disponible via all_packets pour les
    # detecteurs qui le veulent explicitement (_analyse_arp_ip_conflict),
    # voir netcross_core.correlate.correlate().
    arp_pkt = make_pkt(point="A", proto="ARP", src="10.0.0.1", dst="10.0.0.9", sport=None, dport=None)
    tcp_pkt = make_pkt(point="A", proto="TCP", sport=1)
    flows = correlate([arp_pkt, tcp_pkt])
    assert len(flows) == 1
    assert flow_key(tcp_pkt) in flows
    assert flow_key(arp_pkt) not in flows


def test_correlate_exclut_stp():
    # STP (Session 25), meme raisonnement qu'ARP ci-dessus : diffuse/
    # local par nature (adresse de groupe 01:80:c2:00:00:00, IEEE
    # 802.1D, jamais relaye par un routeur).
    stp_pkt = make_pkt(point="A", proto="STP", src="aa:aa:aa:aa:aa:01", dst="01:80:c2:00:00:00", sport=None, dport=None)
    tcp_pkt = make_pkt(point="A", proto="TCP", sport=1)
    flows = correlate([stp_pkt, tcp_pkt])
    assert len(flows) == 1
    assert flow_key(tcp_pkt) in flows
    assert flow_key(stp_pkt) not in flows


def test_compute_throughput_cumule_par_fenetre():
    pkts = [
        make_pkt(point="A", ts=0.5, length=100),
        make_pkt(point="A", ts=0.9, length=50),
        make_pkt(point="A", ts=1.5, length=200),
        make_pkt(point="B", ts=0.5, length=10),
    ]
    tp = compute_throughput(pkts, bucket_seconds=1.0)
    assert tp["A"][0] == 150
    assert tp["A"][1] == 200
    assert tp["B"][0] == 10


def test_compute_throughput_bucket_size_personnalise():
    pkts = [make_pkt(ts=4.9, length=10), make_pkt(ts=5.1, length=10)]
    tp = compute_throughput(pkts, bucket_seconds=5.0)
    assert tp["A"][0] == 10
    assert tp["A"][1] == 10


# -- compute_topn_series (graphiques temporels top-N) --


def test_topn_series_protocol_cumule_par_bucket():
    pkts = [
        make_pkt(point="A", proto="TCP", ts=0.5, length=100),
        make_pkt(point="A", proto="TCP", ts=0.9, length=50),
        make_pkt(point="A", proto="UDP", ts=0.5, length=30),
    ]
    series = compute_topn_series(pkts, bucket_seconds=1.0, dimension="protocol", top_n=5)
    assert series["A"]["TCP"][0] == 150
    assert series["A"]["UDP"][0] == 30


def test_topn_series_port_prefixe_par_le_protocole():
    pkts = [make_pkt(proto="TCP", dport=443, length=10), make_pkt(proto="UDP", dport=443, length=10)]
    series = compute_topn_series(pkts, bucket_seconds=1.0, dimension="port", top_n=5)
    # meme numero de port, protocoles differents -> deux categories distinctes
    assert "TCP/443" in series["A"]
    assert "UDP/443" in series["A"]


def test_topn_series_port_absent_etiquete_explicitement():
    pkts = [make_pkt(proto="ICMP", dport=None, length=10)]
    series = compute_topn_series(pkts, bucket_seconds=1.0, dimension="port", top_n=5)
    assert "ICMP (sans port)" in series["A"]


def test_topn_series_ip_utilise_la_destination():
    pkts = [make_pkt(dst="10.0.0.9", length=10)]
    series = compute_topn_series(pkts, bucket_seconds=1.0, dimension="ip", top_n=5)
    assert "10.0.0.9" in series["A"]


def test_topn_series_dscp_distingue_zero_de_non_marque():
    """DSCP 0 (best effort) est une valeur a part entiere, distincte de
    l'absence du champ (piege 'if pk.dscp' au lieu de 'is not None')."""
    pkts = [make_pkt(dscp=0, length=10), make_pkt(dscp=None, length=20)]
    series = compute_topn_series(pkts, bucket_seconds=1.0, dimension="dscp", top_n=5)
    assert series["A"]["DSCP 0"][0] == 10
    assert series["A"]["non marque"][0] == 20


def test_topn_series_limite_au_top_n_et_regroupe_le_reste_sous_autres():
    pkts = [
        make_pkt(proto="TCP", length=1000),  # dominant
        make_pkt(proto="UDP", length=100),
        make_pkt(proto="ICMP", length=50),
        make_pkt(proto="GRE", length=10),  # doit finir dans "autres"
    ]
    series = compute_topn_series(pkts, bucket_seconds=1.0, dimension="protocol", top_n=3)
    assert set(series["A"]) == {"TCP", "UDP", "ICMP", TOPN_OTHER_LABEL}
    assert series["A"][TOPN_OTHER_LABEL][0] == 10


def test_topn_series_top_n_independant_par_point():
    """Le point A est domine par TCP, le point B par UDP -- chaque point
    doit garder sa propre categorie dominante dans son top-N, pas un
    classement global qui favoriserait un seul point."""
    pkts = [
        make_pkt(point="A", proto="TCP", length=1000),
        make_pkt(point="A", proto="UDP", length=1),
        make_pkt(point="B", proto="UDP", length=1000),
        make_pkt(point="B", proto="TCP", length=1),
    ]
    series = compute_topn_series(pkts, bucket_seconds=1.0, dimension="protocol", top_n=1)
    assert set(series["A"]) == {"TCP", TOPN_OTHER_LABEL}
    assert set(series["B"]) == {"UDP", TOPN_OTHER_LABEL}


def test_topn_series_somme_des_categories_egale_le_debit_total_du_point():
    """Propriete cle du choix 'destination uniquement' pour ip/port (voir
    _topn_category_label) : la somme des categories d'un point, tous
    buckets confondus, doit retomber exactement sur le debit total de ce
    point -- pas de double comptage, pas de perte."""
    pkts = [
        make_pkt(point="A", proto="TCP", dst="1.1.1.1", dport=443, dscp=10, ts=0.1, length=100),
        make_pkt(point="A", proto="UDP", dst="8.8.8.8", dport=53, dscp=None, ts=0.9, length=60),
        make_pkt(point="A", proto="TCP", dst="1.1.1.1", dport=80, dscp=0, ts=1.5, length=40),
    ]
    total = sum(pk.length for pk in pkts)
    for dimension in ("protocol", "port", "ip", "dscp"):
        series = compute_topn_series(pkts, bucket_seconds=1.0, dimension=dimension, top_n=5)
        somme = sum(nbytes for buckets in series["A"].values() for nbytes in buckets.values())
        assert somme == total, dimension


def test_topn_series_dimension_inconnue_leve_value_error():
    import pytest

    with pytest.raises(ValueError):
        compute_topn_series([make_pkt()], bucket_seconds=1.0, dimension="inconnue", top_n=5)


def test_topn_series_liste_vide():
    assert compute_topn_series([], bucket_seconds=1.0, dimension="protocol", top_n=5) == {}


# -- Flow / Conversation (Session 36, objets de contrat de la Session 0) --


def test_build_flows_agrege_points_paquets_octets():
    p1 = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", sport=1, length=100, ts=0.0)
    p2 = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", sport=1, length=50, ts=1.0)
    p3 = make_pkt(point="B", src="10.0.0.1", dst="10.0.0.2", sport=1, length=100, ts=1.5)
    flows = correlate([p1, p2, p3])
    result = build_flows(flows)
    assert len(result) == 1
    f = result[0]
    assert f.key == flow_key(p1)
    assert set(f.points) == {"A", "B"}
    assert f.packet_count == {"A": 2, "B": 1}
    assert f.byte_count == {"A": 150, "B": 100}
    assert f.first_ts == {"A": 0.0, "B": 1.5}
    assert f.last_ts == {"A": 1.0, "B": 1.5}
    assert f.endpoints == ("10.0.0.1", "10.0.0.2")


def test_build_flows_endpoints_ordonnes_min_max():
    # src > dst lexicographiquement -- endpoints reste (min, max)
    p = make_pkt(point="A", src="9.9.9.9", dst="1.1.1.1", sport=1)
    flows = correlate([p])
    f = build_flows(flows)[0]
    assert f.endpoints == ("1.1.1.1", "9.9.9.9")


def test_build_flows_flux_distincts_restent_separes():
    p1 = make_pkt(point="A", sport=1)
    p2 = make_pkt(point="A", sport=2)
    flows = correlate([p1, p2])
    assert len(build_flows(flows)) == 2


def test_build_conversations_regroupe_par_paire_d_adresses():
    # deux flux (ports differents) entre les 2 memes hotes -> 1 seule Conversation
    p1 = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", sport=1, dport=80, length=100)
    p2 = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", sport=2, dport=443, length=200)
    flows = correlate([p1, p2])
    flow_objs = build_flows(flows)
    conversations = build_conversations(flow_objs)
    assert len(conversations) == 1
    conv = conversations[0]
    assert conv.endpoints == ("10.0.0.1", "10.0.0.2")
    assert len(conv.flow_keys) == 2
    assert conv.packet_count == 2
    assert conv.byte_count == 300


def test_build_conversations_hotes_differents_restent_separes():
    p1 = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", sport=1)
    p2 = make_pkt(point="A", src="10.0.0.3", dst="10.0.0.4", sport=1)
    flows = correlate([p1, p2])
    conversations = build_conversations(build_flows(flows))
    assert len(conversations) == 2


def test_build_conversations_liste_vide():
    assert build_conversations([]) == []


# -- Issue #749 : couverture des gardes defensives de build_flows/build_conversations


def test_build_flows_point_avec_liste_vide_est_ignore():
    """build_flows: un point avec une liste de paquets vide est ignore
    (garde defensive, ligne 97)."""
    from netcross_core.correlate import build_flows, Flow

    # Construction manuelle d'un Flow avec un point vide
    f = Flow(key=("TCP", "10.0.0.1", 1234, "10.0.0.2", 443, 1000))
    f.points = ["A", "B"]
    f.packet_count = {"A": 1, "B": 0}
    f.byte_count = {"A": 100, "B": 0}
    f.first_ts = {"A": 0.0, "B": 0.0}
    f.last_ts = {"A": 0.0, "B": 0.0}
    f.endpoints = ("10.0.0.1", "10.0.0.2")

    # Simule un flows dict avec un point vide
    flows = {
        ("TCP", "10.0.0.1", 1234, "10.0.0.2", 443, 1000): {
            "A": [make_pkt(point="A", sport=1)],
            "B": [],  # liste vide -> garde defensive
        }
    }
    result = build_flows(flows)
    assert len(result) == 1
    # Le point B avec liste vide ne doit pas etre ajoute
    assert "B" not in result[0].points
    assert "A" in result[0].points


def test_build_conversations_flux_sans_endpoints_est_ignore():
    """build_conversations: un Flow sans endpoints est ignore
    (garde defensive, ligne 119)."""
    from netcross_core.correlate import build_conversations, Flow

    f = Flow(key=("TCP", "10.0.0.1", 1234, "10.0.0.2", 443, 1000))
    f.endpoints = None  # pas d'endpoints -> garde defensive
    f.packet_count = {"A": 1}
    f.byte_count = {"A": 100}

    result = build_conversations([f])
    assert len(result) == 0
