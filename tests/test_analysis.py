"""
netcross_core.analysis.analyse -- coeur analytique. On construit des
flux synthetiques a 2 ou 3 points de capture et on verifie les
compteurs du Report resultant, pas la mecanique interne.
"""

import pytest
from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate


def _analyse(pkts, points_order=("A", "B"), **kwargs):
    flows = correlate(pkts)
    return analyse(flows, points_order=list(points_order), all_packets=pkts, **kwargs)


def test_perte_simple_vu_en_a_pas_en_b():
    """Les deux hotes echangent aussi en B (autre paquet) : le chemin passe
    par B, le paquet absent y est une perte."""
    pkts = [make_pkt(point="A", sport=1), make_pkt(point="A", sport=2), make_pkt(point="B", sport=2)]
    r = _analyse(pkts)
    assert r.loss_count["B"] == 1
    assert r.loss_count["A"] == 0
    assert r.off_path_count.get("B", 0) == 0


def test_hotes_jamais_vus_en_b_hors_chemin_pas_perte():
    """issue #352 : couple d'hotes jamais vu en B (ni aller ni retour)."""
    pkts = [make_pkt(point="A", sport=1)]
    r = _analyse(pkts)
    assert r.loss_count["B"] == 0
    assert r.off_path_count["B"] == 1


def test_pas_de_perte_si_vu_aux_deux_points():
    pkts = [make_pkt(point="A", sport=1), make_pkt(point="B", sport=1)]
    r = _analyse(pkts)
    assert r.loss_count["B"] == 0


def test_latence_entre_points():
    a = make_pkt(point="A", sport=1, ts=10.0)
    b = make_pkt(point="B", sport=1, ts=10.05)
    r = _analyse([a, b])
    assert r.latency[("A", "B")] == pytest.approx([50.0])


def test_retransmission_detectee_sur_paquets_avec_payload():
    p1 = make_pkt(point="A", sport=1, payload_hash="h1")
    p2 = make_pkt(point="A", sport=1, payload_hash="h2")  # meme flux, 2e paquet data
    r = _analyse([p1, p2])
    assert r.retrans["A"] == 1


def test_ack_pur_duplique_compte_a_part_de_la_retransmission():
    p1 = make_pkt(point="A", sport=1, payload_hash=None)
    p2 = make_pkt(point="A", sport=1, payload_hash=None)
    r = _analyse([p1, p2])
    assert r.dup_ack["A"] == 1
    assert r.retrans["A"] == 0


def test_ack_pur_et_segment_data_du_meme_seq_ne_comptent_pas_comme_retrans():
    # cas documente dans analysis.py : un ACK pur partage le seq d'un
    # segment de donnees, ce n'est pas une retransmission
    pure_ack = make_pkt(point="A", sport=1, payload_hash=None)
    data = make_pkt(point="A", sport=1, payload_hash="h1")
    r = _analyse([pure_ack, data])
    assert r.retrans["A"] == 0
    assert r.dup_ack["A"] == 0


def test_zero_window_detecte():
    pkt = make_pkt(point="A", sport=1, window=0)
    r = _analyse([pkt])
    assert r.zero_window["A"] == 1


def test_rst_count_par_point():
    pkt = make_pkt(point="A", sport=1, flags="....R..")
    r = _analyse([pkt])
    assert r.rst_count["A"] == 1


def test_rst_localise_uniquement_vu_a_un_seul_point():
    pkt = make_pkt(point="A", sport=1, flags="....R..")
    r = _analyse([pkt])
    assert r.rst_localized["A"] == 1


def test_rst_non_localise_si_vu_aux_deux_points():
    a = make_pkt(point="A", sport=1, flags="....R..")
    b = make_pkt(point="B", sport=1, flags="....R..")
    r = _analyse([a, b])
    assert r.rst_localized["A"] == 0
    assert r.rst_localized["B"] == 0


def test_ttl_instable_plusieurs_ttl_au_meme_point():
    p1 = make_pkt(point="A", sport=1, ttl=64)
    p2 = make_pkt(point="A", sport=1, ttl=63)
    r = _analyse([p1, p2])
    assert r.ttl_unstable["A"] == 1


def test_hop_delta_entre_points():
    a = make_pkt(point="A", sport=1, ttl=64)
    b = make_pkt(point="B", sport=1, ttl=62)
    r = _analyse([a, b])
    assert r.hop_delta[("A", "B")] == [2]


def test_qos_change_dscp_different_entre_points():
    a = make_pkt(point="A", sport=1, dscp=0)
    b = make_pkt(point="B", sport=1, dscp=46)
    r = _analyse([a, b])
    assert r.qos_change[("A", "B")] == 1


def test_qos_l2_vs_l3_remark_selon_le_ttl():
    # DSCP change + TTL stable -> remarquage local (L2), pas un routeur (L3)
    a = make_pkt(point="A", sport=1, dscp=0, ttl=64)
    b = make_pkt(point="B", sport=1, dscp=46, ttl=64)
    r = _analyse([a, b])
    assert r.qos_l2_remark[("A", "B")] == 1
    assert r.qos_l3_remark[("A", "B")] == 0


def test_vlan_change_entre_points():
    a = make_pkt(point="A", sport=1, vlan_id=100, vlan_prio=0)
    b = make_pkt(point="B", sport=1, vlan_id=200, vlan_prio=0)
    r = _analyse([a, b])
    assert r.vlan_change[("A", "B")] == 1


def test_vlan_tag_flip_tagged_vers_untagged():
    a = make_pkt(point="A", sport=1, vlan_id=100)
    b = make_pkt(point="B", sport=1, vlan_id=None)
    r = _analyse([a, b])
    assert r.vlan_tag_flip[("A", "B")]["tagged_to_untagged"] == 1


def test_encap_change_entre_points():
    a = make_pkt(point="A", sport=1, encap_tags=("GRE",))
    b = make_pkt(point="B", sport=1, encap_tags=())
    r = _analyse([a, b])
    assert r.encap_change[("A", "B")] == 1
    assert len(r.encap_change_examples[("A", "B")]) == 1


def test_fragmentation_nouvelle_apparait_entre_points():
    a = make_pkt(point="A", src="1.1.1.1", dst="2.2.2.2", ip_id=42, is_fragment=False)
    b = make_pkt(point="B", src="1.1.1.1", dst="2.2.2.2", ip_id=42, is_fragment=True)
    r = _analyse([a, b])
    assert r.frag_new[("A", "B")] == 1


def test_icmp_frag_needed_compte():
    pkt = make_pkt(point="A", proto="ICMP", icmp_type=3, icmp_code=4, ip_id=1)
    r = _analyse([pkt])
    assert r.icmp_frag_needed["A"] == 1


def test_icmpv6_too_big_compte():
    # Equivalent IPv6 (Session 22) de icmp_frag_needed ci-dessus --
    # ip_id volontairement PAS renseigne (par defaut None dans make_pkt
    # serait faux ici, il vaut 1 par defaut -- voir conftest.py) : le
    # comptage ICMPv6 Packet Too Big doit fonctionner MEME sans ip_id
    # (voir analysis.py, le compteur est increment avant le "continue"
    # sur ip_id is None -- un message Packet Too Big n'a lui-meme
    # quasiment jamais d'en-tete Fragment).
    pkt = make_pkt(point="A", proto="ICMPv6", icmpv6_type=2, icmpv6_code=0, ip_id=None)
    r = _analyse([pkt])
    assert r.icmpv6_too_big["A"] == 1


def test_icmpv6_too_big_ignore_les_autres_types_de_messages():
    # Un Echo Request (type 128) ou une Neighbor Solicitation (type 135)
    # ne doit pas etre compte comme un signal PMTUD.
    pkts = [
        make_pkt(point="A", proto="ICMPv6", icmpv6_type=128, icmpv6_code=0, sport=1),
        make_pkt(point="A", proto="ICMPv6", icmpv6_type=135, icmpv6_code=0, sport=2),
    ]
    r = _analyse(pkts)
    assert r.icmpv6_too_big["A"] == 0


def test_frag_count_generique_ipv6():
    # r.frag_count est generique IPv4/IPv6 : un paquet IPv6 fragmente
    # (is_fragment=True, ip_id = l'identifiant 32 bits du datagramme,
    # voir pcap_parser.packet) incremente le compteur exactement comme
    # un fragment IPv4 -- aucune branche par famille d'adresse dans
    # analyse() elle-meme, la genericite vient uniquement du fait que
    # pcap_parser peuple ip_id/is_fragment de la meme facon pour les
    # deux familles.
    pkt = make_pkt(point="A", src="2001:db8::1", dst="2001:db8::2", ip_id=0x711AEC75, is_fragment=True)
    r = _analyse([pkt])
    assert r.frag_count["A"] == 1


def test_frag_new_ipv6_fonctionne_si_deja_fragmente_aux_deux_points():
    # Cas ou la correlation IPv6 fonctionne : le MEME identifiant de
    # fragment (donc le meme datagramme original) est vu fragmente aux
    # deux points -- suit le meme mecanisme (src, dst, ip_id) que IPv4.
    a = make_pkt(point="A", src="2001:db8::1", dst="2001:db8::2", ip_id=99, is_fragment=True)
    b = make_pkt(point="B", src="2001:db8::1", dst="2001:db8::2", ip_id=99, is_fragment=True)
    r = _analyse([a, b])
    assert r.frag_count["A"] == 1
    assert r.frag_count["B"] == 1
    # Deja fragmente aux DEUX points -> pas une "nouvelle" fragmentation
    # apparue sur ce segment.
    assert r.frag_new[("A", "B")] == 0


def test_frag_new_ipv6_ne_detecte_pas_une_nouvelle_fragmentation_sans_ip_id_amont():
    # Limite assumee et documentee (pcap_parser.packet/netcross_core.
    # analysis, section "Fragmentation IPv6" de FEATURES.md) : contrairement
    # a IPv4 (ip.id toujours present, meme sur un paquet non fragmente),
    # un datagramme IPv6 jamais fragmente n'a AUCUN identifiant a exposer
    # (ip_id=None). Le paquet en A ne peut donc jamais etre apparie avec
    # sa version fragmentee en B via (src, dst, ip_id) -- frag_new ne
    # peut pas detecter ce cas cote IPv6, a la difference du test
    # symetrique test_fragmentation_nouvelle_apparait_entre_points()
    # (IPv4, ip_id=42 explicitement partage) plus haut.
    a = make_pkt(point="A", src="2001:db8::1", dst="2001:db8::2", ip_id=None, is_fragment=False)
    b = make_pkt(point="B", src="2001:db8::1", dst="2001:db8::2", ip_id=77, is_fragment=True)
    r = _analyse([a, b])
    assert r.frag_count["B"] == 1
    assert r.frag_new[("A", "B")] == 0  # pas detecte -- limite assumee


# -- PMTUD (noir) : segment DF retransmis en amont, jamais vu en aval, sans
# ICMP Fragmentation Needed observe en amont -------------------------------


def _df_pkt(point, **overrides):
    overrides.setdefault("proto", "TCP")
    overrides.setdefault("df", True)
    overrides.setdefault("length", 1400)
    overrides.setdefault("payload_hash", "h")
    return make_pkt(point=point, **overrides)


def test_pmtud_blackhole_detecte():
    pkts = [
        _df_pkt("A", sport=1, ts=0.0),
        _df_pkt("A", sport=1, ts=1.0),
        _df_pkt("A", sport=1, ts=2.0),
    ]
    r = _analyse(pkts)
    assert r.pmtud_blackhole[("A", "B")] == 1
    assert len(r.pmtud_blackhole_examples[("A", "B")]) == 1


def test_pmtud_blackhole_frame_number_du_paquet_representatif():
    # Session 35 : Report.pmtud_blackhole_frames doit porter le numero de
    # trame (Pkt.frame_number) du MEME paquet representatif que
    # pmtud_blackhole_examples -- meme index, premiere donnee source de
    # PacketEvidence (netcross_core.expert_model).
    pkts = [
        _df_pkt("A", sport=1, ts=0.0, frame_number=42),
        _df_pkt("A", sport=1, ts=1.0, frame_number=43),
        _df_pkt("A", sport=1, ts=2.0, frame_number=44),
    ]
    r = _analyse(pkts)
    assert r.pmtud_blackhole_frames[("A", "B")] == [42]


def test_pmtud_blackhole_frame_number_absent_reste_none():
    # frame_number jamais fourni (defaut make_pkt) -> None, tolerance
    # documentee plutot qu'une exception.
    pkts = [
        _df_pkt("A", sport=1, ts=0.0),
        _df_pkt("A", sport=1, ts=1.0),
    ]
    r = _analyse(pkts)
    assert r.pmtud_blackhole_frames[("A", "B")] == [None]


def test_pmtud_pas_de_blackhole_si_vu_aussi_en_aval():
    pkts = [
        _df_pkt("A", sport=1, ts=0.0),
        _df_pkt("A", sport=1, ts=1.0),
        _df_pkt("B", sport=1, ts=1.5),
    ]
    r = _analyse(pkts)
    assert r.pmtud_blackhole == {}


def test_pmtud_pas_de_blackhole_si_icmp_frag_needed_vu_en_amont():
    pkts = [
        _df_pkt("A", sport=1, ts=0.0),
        _df_pkt("A", sport=1, ts=1.0),
        make_pkt(point="A", proto="ICMP", icmp_type=3, icmp_code=4, ts=0.5),
    ]
    r = _analyse(pkts)
    assert r.pmtud_blackhole == {}


def test_pmtud_pas_de_blackhole_si_df_non_actif():
    pkts = [
        _df_pkt("A", sport=1, ts=0.0, df=False),
        _df_pkt("A", sport=1, ts=1.0, df=False),
    ]
    r = _analyse(pkts)
    assert r.pmtud_blackhole == {}


def test_pmtud_pas_de_blackhole_si_segment_trop_petit():
    pkts = [
        _df_pkt("A", sport=1, ts=0.0, length=100),
        _df_pkt("A", sport=1, ts=1.0, length=100),
    ]
    r = _analyse(pkts)
    assert r.pmtud_blackhole == {}


def test_pmtud_pas_de_blackhole_si_une_seule_tentative():
    pkts = [_df_pkt("A", sport=1, ts=0.0)]
    r = _analyse(pkts)
    assert r.pmtud_blackhole == {}


def test_pmtud_ignore_les_flux_non_tcp():
    pkts = [
        _df_pkt("A", sport=1, ts=0.0, proto="UDP", dport=5000),
        _df_pkt("A", sport=1, ts=1.0, proto="UDP", dport=5000),
    ]
    r = _analyse(pkts)
    assert r.pmtud_blackhole == {}


# -- PMTUD IPv6 (Session 22) : meme scenario, sans bit DF (n'existe pas
# cote IPv6 -- pk.df toujours False, voir pcap_parser.packet) et avec
# ICMPv6 Packet Too Big (type 2) comme signal de retour, au lieu de
# ICMP Fragmentation Needed. Voir netcross_core.analysis._analyse_pmtud
# pour le detail des deux branches. -------------------------------------


def _v6_pkt(point, **overrides):
    overrides.setdefault("proto", "TCP")
    overrides.setdefault("length", 1400)
    overrides.setdefault("payload_hash", "h")
    overrides.setdefault("src", "2001:db8::1")
    overrides.setdefault("dst", "2001:db8::2")
    # df volontairement laisse a False (defaut make_pkt) -- IPv6 n'a pas
    # de bit DF, le scenario doit se detecter SANS lui.
    return make_pkt(point=point, **overrides)


def test_pmtud_blackhole_detecte_ipv6_sans_bit_df():
    pkts = [
        _v6_pkt("A", sport=1, ts=0.0),
        _v6_pkt("A", sport=1, ts=1.0),
        _v6_pkt("A", sport=1, ts=2.0),
    ]
    r = _analyse(pkts)
    assert r.pmtud_blackhole[("A", "B")] == 1
    assert "IPv6" in r.pmtud_blackhole_examples[("A", "B")][0]


def test_pmtud_pas_de_blackhole_ipv6_si_vu_aussi_en_aval():
    pkts = [
        _v6_pkt("A", sport=1, ts=0.0),
        _v6_pkt("A", sport=1, ts=1.0),
        _v6_pkt("B", sport=1, ts=1.5),
    ]
    r = _analyse(pkts)
    assert r.pmtud_blackhole == {}


def test_pmtud_pas_de_blackhole_ipv6_si_icmpv6_too_big_vu_en_amont():
    pkts = [
        _v6_pkt("A", sport=1, ts=0.0),
        _v6_pkt("A", sport=1, ts=1.0),
        make_pkt(
            point="A",
            proto="ICMPv6",
            icmpv6_type=2,
            icmpv6_code=0,
            src="2001:db8::fe",
            dst="2001:db8::1",
            ts=0.5,
        ),
    ]
    r = _analyse(pkts)
    assert r.pmtud_blackhole == {}


def test_pmtud_pas_de_blackhole_ipv6_si_segment_trop_petit():
    pkts = [
        _v6_pkt("A", sport=1, ts=0.0, length=100),
        _v6_pkt("A", sport=1, ts=1.0, length=100),
    ]
    r = _analyse(pkts)
    assert r.pmtud_blackhole == {}


def test_pmtud_pas_de_blackhole_ipv6_si_une_seule_tentative():
    pkts = [_v6_pkt("A", sport=1, ts=0.0)]
    r = _analyse(pkts)
    assert r.pmtud_blackhole == {}


def test_pmtud_ipv4_toujours_exige_df_actif_meme_apres_ajout_ipv6():
    # Non-regression explicite : l'ajout de la branche IPv6 ne doit pas
    # relacher la condition DF cote IPv4 (adresses par defaut de
    # make_pkt/_df_pkt -- IPv4, voir conftest.py).
    pkts = [
        _df_pkt("A", sport=1, ts=0.0, df=False),
        _df_pkt("A", sport=1, ts=1.0, df=False),
    ]
    r = _analyse(pkts)
    assert r.pmtud_blackhole == {}


# -- Timeout d'inactivite / coupure NAT-FW silencieuse ---------------------


def test_idle_timeout_coupure_detectee():
    # Flux etabli des les deux points, puis long silence en A (> 60s),
    # trafic repris en A mais plus jamais revu en B. Le point aval (B)
    # voit deliberement son paquet 0.1s APRES le point amont (A) --
    # delai de propagation realiste. Piege repere en ecrivant ce test
    # avant le code : comparer le dernier ts de B au ts du DERNIER
    # paquet de A avant le trou (gap_start=0.0) aurait echoue ici (0.1 >
    # 0.0) et aurait fait manquer la quasi-totalite des cas reels -- la
    # bonne comparaison est contre gap_end (debut de la reprise en A),
    # pas gap_start (voir _analyse_idle_timeout).
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1"),
        make_pkt(point="B", sport=1, ts=0.1, payload_hash="h1"),
        make_pkt(point="A", sport=1, ts=1.0, payload_hash="h2"),
        make_pkt(point="B", sport=1, ts=1.1, payload_hash="h2"),
        make_pkt(point="A", sport=1, ts=90.0, payload_hash="h3"),
    ]
    r = _analyse(pkts)
    assert r.idle_timeout_dropped[("A", "B")] == 1
    assert len(r.idle_timeout_examples[("A", "B")]) == 1
    assert "silence de 89s" in r.idle_timeout_examples[("A", "B")][0]


def test_idle_timeout_frame_number_du_paquet_qui_reprend():
    # Session 37 : idle_timeout_frames porte le numero de trame du paquet
    # qui reprend le trafic en amont apres le silence (PacketEvidence).
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1", frame_number=1),
        make_pkt(point="B", sport=1, ts=0.1, payload_hash="h1", frame_number=2),
        make_pkt(point="A", sport=1, ts=1.0, payload_hash="h2", frame_number=3),
        make_pkt(point="B", sport=1, ts=1.1, payload_hash="h2", frame_number=4),
        make_pkt(point="A", sport=1, ts=90.0, payload_hash="h3", frame_number=5),
    ]
    r = _analyse(pkts)
    assert r.idle_timeout_frames[("A", "B")] == [5]


def test_idle_timeout_pas_de_coupure_si_trafic_repris_revu_en_aval():
    # Meme silence prolonge, mais le trafic repris en A est bien revu
    # ensuite en B -> pas une coupure, juste un flux peu bavard.
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1"),
        make_pkt(point="B", sport=1, ts=0.1, payload_hash="h1"),
        make_pkt(point="A", sport=1, ts=90.0, payload_hash="h2"),
        make_pkt(point="B", sport=1, ts=90.1, payload_hash="h2"),
    ]
    r = _analyse(pkts)
    assert r.idle_timeout_dropped == {}


def test_idle_timeout_pas_de_coupure_si_silence_trop_court():
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1"),
        make_pkt(point="B", sport=1, ts=0.1, payload_hash="h1"),
        make_pkt(point="A", sport=1, ts=30.0, payload_hash="h2"),
    ]
    r = _analyse(pkts)
    assert r.idle_timeout_dropped == {}


def test_idle_timeout_seconds_personnalise_via_analyse():
    # Session 37 : idle_timeout_seconds expose desormais comme parametre
    # de analyse() (--idle-timeout-seconds en CLI) -- un silence de 30s,
    # trop court pour le seuil par defaut (60s, voir test ci-dessus), doit
    # bien declencher la detection avec un seuil personnalise plus bas.
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1"),
        make_pkt(point="B", sport=1, ts=0.1, payload_hash="h1"),
        make_pkt(point="A", sport=1, ts=30.0, payload_hash="h2"),
    ]
    r = _analyse(pkts, idle_timeout_seconds=5.0)
    assert r.idle_timeout_dropped[("A", "B")] == 1


def test_idle_timeout_seconds_none_utilise_le_defaut():
    # idle_timeout_seconds=None (valeur par defaut de analyse(), CLI sans
    # --idle-timeout-seconds) doit se comporter exactement comme avant
    # l'ajout du parametre -- seuil par defaut de 60s.
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1"),
        make_pkt(point="B", sport=1, ts=0.1, payload_hash="h1"),
        make_pkt(point="A", sport=1, ts=30.0, payload_hash="h2"),
    ]
    r = _analyse(pkts, idle_timeout_seconds=None)
    assert r.idle_timeout_dropped == {}


def test_idle_timeout_pas_de_coupure_si_jamais_vu_en_aval_avant_le_trou():
    # Le flux n'a jamais ete correctement etabli en B avant le silence :
    # c'est une perte classique (r.loss_count), pas ce scenario precis.
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1"),
        make_pkt(point="A", sport=1, ts=90.0, payload_hash="h2"),
        make_pkt(point="B", sport=1, ts=90.1, payload_hash="h2"),
    ]
    r = _analyse(pkts)
    assert r.idle_timeout_dropped == {}


def test_idle_timeout_pas_de_coupure_si_moins_de_deux_paquets_en_amont():
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1"),
        make_pkt(point="B", sport=1, ts=0.1, payload_hash="h1"),
    ]
    r = _analyse(pkts)
    assert r.idle_timeout_dropped == {}


def test_idle_timeout_ignore_les_flux_non_tcp():
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, proto="UDP", dport=5000, payload_hash="h1"),
        make_pkt(point="B", sport=1, ts=0.1, proto="UDP", dport=5000, payload_hash="h1"),
        make_pkt(point="A", sport=1, ts=90.0, proto="UDP", dport=5000, payload_hash="h2"),
    ]
    r = _analyse(pkts)
    assert r.idle_timeout_dropped == {}


def test_idle_timeout_un_seul_trou_compte_par_connexion():
    # Deux longs silences successifs sur la meme connexion -> un seul
    # decompte (le plus grand silence), pas deux.
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1"),
        make_pkt(point="B", sport=1, ts=0.1, payload_hash="h1"),
        make_pkt(point="A", sport=1, ts=90.0, payload_hash="h2"),
        make_pkt(point="A", sport=1, ts=200.0, payload_hash="h3"),
    ]
    r = _analyse(pkts)
    assert r.idle_timeout_dropped[("A", "B")] == 1


def test_idle_timeout_juste_sous_le_seuil_pas_de_coupure():
    # 59s < seuil par defaut (60s) -> pas de coupure retenue (le seuil
    # est une frontiere stricte, pas approximative).
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1"),
        make_pkt(point="B", sport=1, ts=0.1, payload_hash="h1"),
        make_pkt(point="A", sport=1, ts=59.0, payload_hash="h2"),
    ]
    r = _analyse(pkts)
    assert r.idle_timeout_dropped == {}


def test_idle_timeout_detecte_meme_avec_seq_differente_apres_la_reprise():
    # Non-regression cruciale (piege repere en ecrivant ce test) : une
    # PREMIERE version de ce detecteur iterait sur `flows`
    # (netcross_core.correlate.flow_key), indexe par 5-tuple + seq TCP
    # (key_id) -- chaque SEGMENT precis (donc chaque valeur de seq)
    # formait sa PROPRE entree. Une vraie reprise de connexion envoie
    # forcement de la donnee NOUVELLE (seq different du dernier segment
    # avant le silence) : avec `flows`, le paquet d'avant-trou et celui
    # d'apres-trou tombaient dans deux entrees SEPAREES (une par seq),
    # chacune avec un seul paquet au point amont -> `len(ts_a) < 2` etait
    # TOUJOURS vrai et la coupure n'etait JAMAIS detectee, quel que soit
    # le scenario. Ce test fixe seq=1000 avant le trou et seq=5000 apres
    # (donnee nouvelle, comme une vraie reprise de session) : seule une
    # vue par CONNEXION (5-tuple, sans le seq) peut la detecter. Voir
    # netcross_core.analysis._analyse_idle_timeout, section "Note de
    # conception", pour le detail complet.
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, seq=1000, payload_hash="h1"),
        make_pkt(point="B", sport=1, ts=0.1, seq=1000, payload_hash="h1"),
        make_pkt(point="A", sport=1, ts=90.0, seq=5000, payload_hash="h2"),
    ]
    r = _analyse(pkts)
    assert r.idle_timeout_dropped[("A", "B")] == 1


# -- Conflit d'adresse IP (ARP) --------------------------------------------


def test_arp_conflit_detecte():
    pkts = [
        make_pkt(point="A", proto="ARP", src="10.0.0.9", dst="10.0.0.1", arp_sender_mac="aa:aa:aa:aa:aa:09"),
        make_pkt(point="A", proto="ARP", src="10.0.0.9", dst="10.0.0.1", arp_sender_mac="aa:aa:aa:aa:aa:99"),
    ]
    r = _analyse(pkts)
    assert r.arp_ip_conflict["A"] == 1
    assert len(r.arp_ip_conflict_examples["A"]) == 1
    assert "10.0.0.9" in r.arp_ip_conflict_examples["A"][0]


def test_arp_conflit_frame_number_du_dernier_paquet_observe():
    # Session 37 : arp_ip_conflict_frames porte le numero de trame du
    # DERNIER paquet ARP observe pour cette IP (PacketEvidence).
    pkts = [
        make_pkt(point="A", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:09", frame_number=1),
        make_pkt(point="A", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:99", frame_number=2),
    ]
    r = _analyse(pkts)
    assert r.arp_ip_conflict_frames["A"] == [2]


def test_arp_pas_de_conflit_si_une_seule_mac():
    pkts = [
        make_pkt(point="A", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:09"),
        make_pkt(point="A", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:09"),
    ]
    r = _analyse(pkts)
    assert r.arp_ip_conflict == {}


def test_arp_conflit_detecte_quel_que_soit_le_type_de_paquet():
    # Requete (who-has) OU reponse (is-at) : les deux portent une
    # revendication "sender IP <-> sender MAC" tout aussi valide, voir
    # docstring de _analyse_arp_ip_conflict.
    pkts = [
        make_pkt(point="A", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:09", arp_opcode=1),
        make_pkt(point="A", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:99", arp_opcode=2),
    ]
    r = _analyse(pkts)
    assert r.arp_ip_conflict["A"] == 1


def test_arp_conflit_ignore_par_defaut_les_paquets_non_arp():
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.9"),
        make_pkt(point="A", proto="TCP", src="10.0.0.9"),
    ]
    r = _analyse(pkts)
    assert r.arp_ip_conflict == {}


def test_arp_conflit_independant_par_point():
    # La meme IP revendiquee par 2 MAC differentes, mais chacune a un
    # point DIFFERENT -- pas un conflit (deux segments distincts,
    # potentiellement deux ARP caches independants sans lien).
    pkts = [
        make_pkt(point="A", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:09"),
        make_pkt(point="B", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:99"),
    ]
    r = _analyse(pkts)
    assert r.arp_ip_conflict == {}


def test_arp_conflit_plusieurs_ip_comptees_separement():
    pkts = [
        make_pkt(point="A", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:09"),
        make_pkt(point="A", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:99"),
        make_pkt(point="A", proto="ARP", src="10.0.0.5", arp_sender_mac="aa:aa:aa:aa:aa:05"),
        make_pkt(point="A", proto="ARP", src="10.0.0.5", arp_sender_mac="aa:aa:aa:aa:aa:55"),
    ]
    r = _analyse(pkts)
    assert r.arp_ip_conflict["A"] == 2


def test_arp_conflit_exemples_limites_a_cinq():
    pkts = []
    for i in range(10):
        ip = f"10.0.0.{i}"
        pkts.append(make_pkt(point="A", proto="ARP", src=ip, arp_sender_mac="aa:aa:aa:aa:aa:00"))
        pkts.append(make_pkt(point="A", proto="ARP", src=ip, arp_sender_mac="aa:aa:aa:aa:aa:11"))
    r = _analyse(pkts)
    assert r.arp_ip_conflict["A"] == 10
    assert len(r.arp_ip_conflict_examples["A"]) == 5


# -- Instabilite STP (tempete de changement de topologie / racine) --------


def test_stp_topology_change_detecte_via_tcn():
    pkts = [make_pkt(point="A", proto="STP", stp_bpdu_type=0x80, stp_flags_tc=False, stp_root_id=None)]
    r = _analyse(pkts)
    assert r.stp_topology_change["A"] == 1


def test_stp_topology_change_detecte_via_flag_tc():
    pkts = [make_pkt(point="A", proto="STP", stp_bpdu_type=0, stp_flags_tc=True, stp_root_id="32768/aa:aa:aa:aa:aa:01")]
    r = _analyse(pkts)
    assert r.stp_topology_change["A"] == 1


def test_stp_topology_change_pas_de_signal_sur_configuration_normale():
    pkts = [
        make_pkt(point="A", proto="STP", stp_bpdu_type=0, stp_flags_tc=False, stp_root_id="32768/aa:aa:aa:aa:aa:01"),
    ]
    r = _analyse(pkts)
    assert r.stp_topology_change == {}


def test_stp_topology_change_tcn_et_flag_tc_comptes_separement():
    # Un TCN et une Configuration-avec-TC sont deux TRAMES distinctes
    # (meme si elles signalent le meme phenomene reseau) -- chacune
    # compte pour un evenement, voir docstring de _analyse_stp_instability.
    pkts = [
        make_pkt(point="A", proto="STP", ts=0.0, stp_bpdu_type=0x80, stp_flags_tc=False, stp_root_id=None),
        make_pkt(
            point="A", proto="STP", ts=0.1, stp_bpdu_type=0, stp_flags_tc=True, stp_root_id="32768/aa:aa:aa:aa:aa:01"
        ),
    ]
    r = _analyse(pkts)
    assert r.stp_topology_change["A"] == 2


def test_stp_root_change_detecte():
    pkts = [
        make_pkt(
            point="A", proto="STP", ts=0.0, stp_bpdu_type=0, stp_flags_tc=False, stp_root_id="32768/aa:aa:aa:aa:aa:01"
        ),
        make_pkt(
            point="A", proto="STP", ts=2.0, stp_bpdu_type=0, stp_flags_tc=False, stp_root_id="4096/aa:aa:aa:aa:aa:02"
        ),
    ]
    r = _analyse(pkts)
    assert r.stp_root_change["A"] == 1
    assert len(r.stp_root_change_examples["A"]) == 1
    assert "32768/aa:aa:aa:aa:aa:01" in r.stp_root_change_examples["A"][0]
    assert "4096/aa:aa:aa:aa:aa:02" in r.stp_root_change_examples["A"][0]


def test_stp_root_change_frame_number_de_la_bpdu_qui_change():
    # Session 37 : stp_root_change_frames porte le numero de trame de la
    # BPDU qui introduit la NOUVELLE racine (PacketEvidence).
    pkts = [
        make_pkt(
            point="A",
            proto="STP",
            ts=0.0,
            stp_bpdu_type=0,
            stp_root_id="32768/aa:aa:aa:aa:aa:01",
            frame_number=10,
        ),
        make_pkt(
            point="A",
            proto="STP",
            ts=2.0,
            stp_bpdu_type=0,
            stp_root_id="4096/aa:aa:aa:aa:aa:02",
            frame_number=11,
        ),
    ]
    r = _analyse(pkts)
    assert r.stp_root_change_frames["A"] == [11]


def test_stp_root_change_pas_de_changement_si_racine_stable():
    pkts = [
        make_pkt(point="A", proto="STP", ts=0.0, stp_bpdu_type=0, stp_root_id="32768/aa:aa:aa:aa:aa:01"),
        make_pkt(point="A", proto="STP", ts=2.0, stp_bpdu_type=0, stp_root_id="32768/aa:aa:aa:aa:aa:01"),
        make_pkt(point="A", proto="STP", ts=4.0, stp_bpdu_type=0, stp_root_id="32768/aa:aa:aa:aa:aa:01"),
    ]
    r = _analyse(pkts)
    assert r.stp_root_change == {}


def test_stp_root_change_ignore_les_tcn_sans_champ_root():
    # Une TCN n'a pas de champ root (stp_root_id=None) -- ne doit ni
    # provoquer un "changement" par elle-meme, ni casser la comparaison
    # entre les deux Configuration BPDU qui l'encadrent.
    pkts = [
        make_pkt(point="A", proto="STP", ts=0.0, stp_bpdu_type=0, stp_root_id="32768/aa:aa:aa:aa:aa:01"),
        make_pkt(point="A", proto="STP", ts=1.0, stp_bpdu_type=0x80, stp_root_id=None),
        make_pkt(point="A", proto="STP", ts=2.0, stp_bpdu_type=0, stp_root_id="32768/aa:aa:aa:aa:aa:01"),
    ]
    r = _analyse(pkts)
    assert r.stp_root_change == {}


def test_stp_root_change_independant_par_point():
    pkts = [
        make_pkt(point="A", proto="STP", ts=0.0, stp_bpdu_type=0, stp_root_id="32768/aa:aa:aa:aa:aa:01"),
        make_pkt(point="B", proto="STP", ts=0.0, stp_bpdu_type=0, stp_root_id="4096/aa:aa:aa:aa:aa:02"),
    ]
    r = _analyse(pkts)
    assert r.stp_root_change == {}


def test_stp_root_change_trie_par_timestamp_avant_comparaison():
    # Paquets fournis dans le DESORDRE chronologique -- le detecteur ne
    # doit pas supposer que all_packets est deja trie (voir note de
    # conception dans _analyse_stp_instability).
    pkts = [
        make_pkt(point="A", proto="STP", ts=2.0, stp_bpdu_type=0, stp_root_id="4096/aa:aa:aa:aa:aa:02"),
        make_pkt(point="A", proto="STP", ts=0.0, stp_bpdu_type=0, stp_root_id="32768/aa:aa:aa:aa:aa:01"),
    ]
    r = _analyse(pkts)
    assert r.stp_root_change["A"] == 1


def test_stp_ignore_les_paquets_non_stp():
    pkts = [make_pkt(point="A", proto="TCP")]
    r = _analyse(pkts)
    assert r.stp_topology_change == {}
    assert r.stp_root_change == {}


# -- Certificat TLS (dates de validite / substitution entre points) -------

# Fenetre de validite commune aux tests ci-dessous : 2020-01-01 ->
# 2030-01-01 (UTC). Epoch equivalents calcules une fois pour eviter les
# erreurs de calcul mental sur des dates lointaines : voir claude.md
# Session 26 pour le detail des valeurs.
_NOT_BEFORE = "2020-01-01 00:00:00 (UTC)"
_NOT_AFTER = "2030-01-01 00:00:00 (UTC)"
_TS_VALIDE = 1767225600.0  # 2026-01-01, a l'interieur de la fenetre
_TS_EXPIRE = 1924992000.0  # 2031-01-01, apres notAfter
_TS_PAS_ENCORE_VALIDE = 1546300800.0  # 2019-01-01, avant notBefore


def test_tls_cert_valide_pas_de_signal():
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            ts=_TS_VALIDE,
            tls_cert_not_before=_NOT_BEFORE,
            tls_cert_not_after=_NOT_AFTER,
            tls_cert_serial="aa:aa",
        )
    ]
    r = _analyse(pkts)
    assert r.tls_cert_invalid_dates == {}


def test_tls_cert_expire_detecte():
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            ts=_TS_EXPIRE,
            tls_cert_not_before=_NOT_BEFORE,
            tls_cert_not_after=_NOT_AFTER,
            tls_cert_serial="aa:aa",
        )
    ]
    r = _analyse(pkts)
    assert r.tls_cert_invalid_dates["A"] == 1
    assert "deja expire" in r.tls_cert_invalid_dates_examples["A"][0]
    assert "aa:aa" in r.tls_cert_invalid_dates_examples["A"][0]


def test_tls_cert_expire_frame_number():
    # Session 37 : tls_cert_invalid_dates_frames porte le numero de trame
    # du paquet qui presente le certificat hors fenetre (PacketEvidence).
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            ts=_TS_EXPIRE,
            tls_cert_not_before=_NOT_BEFORE,
            tls_cert_not_after=_NOT_AFTER,
            tls_cert_serial="aa:aa",
            frame_number=7,
        )
    ]
    r = _analyse(pkts)
    assert r.tls_cert_invalid_dates_frames["A"] == [7]


def test_tls_cert_pas_encore_valide_detecte():
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            ts=_TS_PAS_ENCORE_VALIDE,
            tls_cert_not_before=_NOT_BEFORE,
            tls_cert_not_after=_NOT_AFTER,
            tls_cert_serial="aa:aa",
        )
    ]
    r = _analyse(pkts)
    assert r.tls_cert_invalid_dates["A"] == 1
    assert "pas encore valide" in r.tls_cert_invalid_dates_examples["A"][0]


def test_tls_cert_ignore_les_paquets_sans_certificat():
    pkts = [make_pkt(point="A", proto="TCP", ts=_TS_EXPIRE, tls_cert_serial=None)]
    r = _analyse(pkts)
    assert r.tls_cert_invalid_dates == {}


def test_tls_cert_date_illisible_ignoree_sans_planter():
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            ts=_TS_VALIDE,
            tls_cert_not_before="pas une date",
            tls_cert_not_after=_NOT_AFTER,
            tls_cert_serial="aa:aa",
        )
    ]
    r = _analyse(pkts)
    assert r.tls_cert_invalid_dates == {}


def test_tls_cert_mismatch_detecte():
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            src="10.0.0.9",
            sport=443,
            dst="10.0.0.1",
            dport=54321,
            tls_cert_serial="aa:aa",
        ),
        make_pkt(
            point="B",
            proto="TCP",
            src="10.0.0.9",
            sport=443,
            dst="10.0.0.1",
            dport=54321,
            tls_cert_serial="bb:bb",
        ),
    ]
    r = _analyse(pkts)
    assert r.tls_cert_mismatch[("A", "B")] == 1
    ex = r.tls_cert_mismatch_examples[("A", "B")][0]
    assert "aa:aa" in ex
    assert "bb:bb" in ex


def test_tls_cert_mismatch_frame_number_du_point_amont():
    # Session 37 : tls_cert_mismatch_frames porte le numero de trame du
    # paquet cote POINT A (amont, le numero de serie de reference).
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            src="10.0.0.9",
            sport=443,
            dst="10.0.0.1",
            dport=54321,
            tls_cert_serial="aa:aa",
            frame_number=5,
        ),
        make_pkt(
            point="B",
            proto="TCP",
            src="10.0.0.9",
            sport=443,
            dst="10.0.0.1",
            dport=54321,
            tls_cert_serial="bb:bb",
            frame_number=6,
        ),
    ]
    r = _analyse(pkts)
    assert r.tls_cert_mismatch_frames[("A", "B")] == [5]


def test_tls_cert_pas_de_mismatch_si_meme_serie():
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.9", sport=443, tls_cert_serial="aa:aa"),
        make_pkt(point="B", proto="TCP", src="10.0.0.9", sport=443, tls_cert_serial="aa:aa"),
    ]
    r = _analyse(pkts)
    assert r.tls_cert_mismatch == {}


def test_tls_cert_pas_de_mismatch_si_connexion_vue_a_un_seul_point():
    pkts = [make_pkt(point="A", proto="TCP", src="10.0.0.9", sport=443, tls_cert_serial="aa:aa")]
    r = _analyse(pkts)
    assert r.tls_cert_mismatch == {}


def test_tls_cert_mismatch_independant_par_connexion():
    # Deux connexions differentes (ports differents) au meme couple de
    # points : chacune comparee independamment, une seule est en mismatch.
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.9", sport=443, dport=1, tls_cert_serial="aa:aa"),
        make_pkt(point="B", proto="TCP", src="10.0.0.9", sport=443, dport=1, tls_cert_serial="aa:aa"),
        make_pkt(point="A", proto="TCP", src="10.0.0.9", sport=443, dport=2, tls_cert_serial="cc:cc"),
        make_pkt(point="B", proto="TCP", src="10.0.0.9", sport=443, dport=2, tls_cert_serial="dd:dd"),
    ]
    r = _analyse(pkts)
    assert r.tls_cert_mismatch[("A", "B")] == 1


# -- negociations TLS incompletes (Session 54) -----------------------------


def test_tls_handshake_complet_pas_de_signal():
    # ClientHello, ServerHello, PUIS application_data observes a ce point
    # -- negociation menee a son terme, aucun des deux signaux ne se
    # declenche.
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.1", sport=1234, dst="10.0.0.2", dport=443, tls_client_hello=True),
        make_pkt(point="A", proto="TCP", src="10.0.0.2", sport=443, dst="10.0.0.1", dport=1234, tls_server_hello=True),
        make_pkt(
            point="A", proto="TCP", src="10.0.0.2", sport=443, dst="10.0.0.1", dport=1234, tls_application_data=True
        ),
    ]
    r = _analyse(pkts)
    assert r.tls_handshake_no_reply == {}
    assert r.tls_handshake_incomplete == {}


def test_tls_handshake_no_reply_detecte():
    # ClientHello seul, jamais de ServerHello pour cette connexion a ce
    # point -- silence total.
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.1", sport=1234, dst="10.0.0.2", dport=443, tls_client_hello=True)
    ]
    r = _analyse(pkts)
    assert r.tls_handshake_no_reply["A"] == 1
    assert r.tls_handshake_incomplete == {}
    assert "ClientHello envoye" in r.tls_handshake_no_reply_examples["A"][0]
    assert "10.0.0.1:1234 -> 10.0.0.2:443" in r.tls_handshake_no_reply_examples["A"][0]


def test_tls_handshake_no_reply_frame_number():
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            src="10.0.0.1",
            sport=1234,
            dst="10.0.0.2",
            dport=443,
            tls_client_hello=True,
            frame_number=12,
        )
    ]
    r = _analyse(pkts)
    assert r.tls_handshake_no_reply_frames["A"] == [12]


def test_tls_handshake_incomplete_detecte():
    # ClientHello + ServerHello, mais jamais d'application_data pour
    # cette connexion a ce point -- negociation interrompue.
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.1", sport=1234, dst="10.0.0.2", dport=443, tls_client_hello=True),
        make_pkt(point="A", proto="TCP", src="10.0.0.2", sport=443, dst="10.0.0.1", dport=1234, tls_server_hello=True),
    ]
    r = _analyse(pkts)
    assert r.tls_handshake_incomplete["A"] == 1
    assert r.tls_handshake_no_reply == {}
    assert "ServerHello recu" in r.tls_handshake_incomplete_examples["A"][0]


def test_tls_handshake_incomplete_frame_number_du_client_hello():
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            src="10.0.0.1",
            sport=1234,
            dst="10.0.0.2",
            dport=443,
            tls_client_hello=True,
            frame_number=5,
        ),
        make_pkt(
            point="A",
            proto="TCP",
            src="10.0.0.2",
            sport=443,
            dst="10.0.0.1",
            dport=1234,
            tls_server_hello=True,
            frame_number=6,
        ),
    ]
    r = _analyse(pkts)
    assert r.tls_handshake_incomplete_frames["A"] == [5]


def test_tls_handshake_server_hello_seul_sans_client_hello_ignore():
    # Un point qui ne voit QUE le ServerHello (le ClientHello a ete emis
    # avant le debut de cette capture, ou vu a un autre point) n'a rien a
    # diagnostiquer -- pas de ClientHello vu ICI, donc aucun signal.
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.2", sport=443, dst="10.0.0.1", dport=1234, tls_server_hello=True)
    ]
    r = _analyse(pkts)
    assert r.tls_handshake_no_reply == {}
    assert r.tls_handshake_incomplete == {}


def test_tls_handshake_ignore_les_paquets_sans_signal_tls():
    pkts = [make_pkt(point="A", proto="TCP")]
    r = _analyse(pkts)
    assert r.tls_handshake_no_reply == {}
    assert r.tls_handshake_incomplete == {}


def test_tls_handshake_independant_par_point():
    # Le meme ClientHello vu a deux points : incomplet en A (jamais de
    # ServerHello observe a CE point), complet en B (ServerHello ET
    # application_data observes a CE point) -- chaque point est
    # diagnostique independamment, aucune comparaison entre points.
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.1", sport=1234, dst="10.0.0.2", dport=443, tls_client_hello=True),
        make_pkt(point="B", proto="TCP", src="10.0.0.1", sport=1234, dst="10.0.0.2", dport=443, tls_client_hello=True),
        make_pkt(point="B", proto="TCP", src="10.0.0.2", sport=443, dst="10.0.0.1", dport=1234, tls_server_hello=True),
        make_pkt(
            point="B", proto="TCP", src="10.0.0.2", sport=443, dst="10.0.0.1", dport=1234, tls_application_data=True
        ),
    ]
    r = _analyse(pkts)
    assert r.tls_handshake_no_reply["A"] == 1
    assert "B" not in r.tls_handshake_no_reply
    assert r.tls_handshake_incomplete == {}


# -- Classification des retransmissions TCP (Fast/RTO/Spurious) -----------


def test_retransmission_type_fast():
    pkt = make_pkt(point="A", proto="TCP", is_fast_retransmission=True)
    r = _analyse([pkt])
    assert r.retrans_fast["A"] == 1
    assert r.retrans_rto["A"] == 0
    assert r.retrans_spurious["A"] == 0


def test_retransmission_type_rto():
    pkt = make_pkt(point="A", proto="TCP", is_retransmission=True)
    r = _analyse([pkt])
    assert r.retrans_rto["A"] == 1
    assert r.retrans_fast["A"] == 0
    assert r.retrans_spurious["A"] == 0


def test_retransmission_type_spurious():
    pkt = make_pkt(point="A", proto="TCP", is_spurious_retransmission=True)
    r = _analyse([pkt])
    assert r.retrans_spurious["A"] == 1
    assert r.retrans_rto["A"] == 0
    assert r.retrans_fast["A"] == 0


def test_retransmission_type_priorite_si_plusieurs_flags_a_la_fois():
    # ce n'est PAS un cas limite improbable : verifie empiriquement (vrai
    # tshark, claude.md Session 10) que is_retransmission reste actif EN
    # PLUS de is_fast_retransmission/is_spurious_retransmission -- c'est
    # le cas normal pour un fast/spurious retransmit reel, pas une
    # exception. Un seul compteur doit etre incremente (pas de double
    # comptage) -- priorite spurious > fast > rto, la plus specifique
    # d'abord.
    pkt = make_pkt(
        point="A",
        proto="TCP",
        is_retransmission=True,
        is_fast_retransmission=True,
        is_spurious_retransmission=True,
    )
    r = _analyse([pkt])
    assert r.retrans_spurious["A"] == 1
    assert r.retrans_fast["A"] == 0
    assert r.retrans_rto["A"] == 0


def test_retransmission_type_ignore_non_tcp():
    pkt = make_pkt(point="A", proto="UDP", is_retransmission=True)
    r = _analyse([pkt])
    assert r.retrans_rto == {}


def test_retransmission_type_aucune_par_defaut():
    pkt = make_pkt(point="A", proto="TCP")
    r = _analyse([pkt])
    assert r.retrans_fast == {}
    assert r.retrans_rto == {}
    assert r.retrans_spurious == {}


# -- Signaux d'expertise TCP natifs (tcp.analysis.*, issue #21) ----------
# Distinction perte reelle / reordonnancement / RTO au-dela des trois
# retransmissions : out_of_order, lost_segment, window_update, lus depuis
# Pkt.expert_flags (noms EK tcp_tcp_analysis_*).


def test_tcp_expert_out_of_order_compte_reordonnancement():
    # un segment hors-ordre n'est PAS une retransmission : isole le
    # reordonnancement des vraies pertes.
    pkt = make_pkt(
        point="A",
        proto="TCP",
        expert_flags=("tcp_tcp_analysis_out_of_order",),
    )
    r = _analyse([pkt])
    assert r.out_of_order["A"] == 1
    assert r.lost_segment["A"] == 0
    assert r.window_update["A"] == 0
    # hors-ordre n'est pas compte comme retransmission.
    assert r.retrans_rto["A"] == 0
    assert r.retrans_fast["A"] == 0


def test_tcp_expert_lost_segment_compte_perte_reelle():
    pkt = make_pkt(
        point="A",
        proto="TCP",
        expert_flags=("tcp_tcp_analysis_lost_segment",),
    )
    r = _analyse([pkt])
    assert r.lost_segment["A"] == 1
    assert r.out_of_order["A"] == 0


def test_tcp_expert_window_update_compte():
    pkt = make_pkt(
        point="A",
        proto="TCP",
        expert_flags=("tcp_tcp_analysis_window_update",),
    )
    r = _analyse([pkt])
    assert r.window_update["A"] == 1


def test_tcp_expert_signaux_ignores_non_tcp():
    # les conditions tcp.analysis.* ne s'appliquent qu'au TCP.
    pkt = make_pkt(
        point="A",
        proto="UDP",
        expert_flags=("tcp_tcp_analysis_out_of_order", "tcp_tcp_analysis_lost_segment"),
    )
    r = _analyse([pkt])
    assert r.out_of_order == {}
    assert r.lost_segment == {}
    assert r.window_update == {}


def test_tcp_expert_signaux_aucun_par_defaut():
    pkt = make_pkt(point="A", proto="TCP")
    r = _analyse([pkt])
    assert r.out_of_order == {}
    assert r.lost_segment == {}
    assert r.window_update == {}


def test_tcp_expert_plusieurs_signaux_sur_un_seul_paquet():
    # un meme paquet peut porter plusieurs conditions d'expertise a la fois
    # (verifie empiriquement, voir ek_fields._ws_expert liste) : chacune
    # doit incrementer son compteur propre, sans double-comptage croise.
    pkt = make_pkt(
        point="A",
        proto="TCP",
        expert_flags=(
            "tcp_tcp_analysis_out_of_order",
            "tcp_tcp_analysis_lost_segment",
            "tcp_tcp_analysis_window_update",
        ),
    )
    r = _analyse([pkt])
    assert r.out_of_order["A"] == 1
    assert r.lost_segment["A"] == 1
    assert r.window_update["A"] == 1


def test_tcp_expert_signaux_repartis_par_point():
    a = make_pkt(point="A", proto="TCP", expert_flags=("tcp_tcp_analysis_lost_segment",))
    b = make_pkt(point="B", proto="TCP", expert_flags=("tcp_tcp_analysis_out_of_order",))
    r = _analyse([a, b], points_order=("A", "B"))
    assert r.lost_segment["A"] == 1
    assert r.lost_segment["B"] == 0
    assert r.out_of_order["B"] == 1
    assert r.out_of_order["A"] == 0


# -- Negociation options TCP au handshake (MSS/Window Scale/SACK) ---------


def _syn_pkt(point, **overrides):
    overrides.setdefault("proto", "TCP")
    overrides.setdefault("flags", "......S.")
    return make_pkt(point=point, **overrides)


def test_mss_clamped_detecte():
    pkts = [
        _syn_pkt("A", sport=1, mss_val=1460),
        _syn_pkt("B", sport=1, mss_val=1400),
    ]
    r = _analyse(pkts)
    assert r.mss_clamped[("A", "B")] == 1
    assert len(r.mss_clamped_examples[("A", "B")]) == 1
    assert "1460" in r.mss_clamped_examples[("A", "B")][0]
    assert "1400" in r.mss_clamped_examples[("A", "B")][0]


def test_mss_clamped_frame_number_du_point_amont():
    # Session 37 : mss_clamped_frames porte le numero de trame du SYN cote
    # POINT A (amont).
    pkts = [
        _syn_pkt("A", sport=1, mss_val=1460, frame_number=3),
        _syn_pkt("B", sport=1, mss_val=1400, frame_number=4),
    ]
    r = _analyse(pkts)
    assert r.mss_clamped_frames[("A", "B")] == [3]


def test_mss_pas_clamped_si_valeur_identique():
    pkts = [
        _syn_pkt("A", sport=1, mss_val=1460),
        _syn_pkt("B", sport=1, mss_val=1460),
    ]
    r = _analyse(pkts)
    assert r.mss_clamped == {}


def test_wscale_stripped_detecte():
    pkts = [
        _syn_pkt("A", sport=1, wscale_shift=7),
        _syn_pkt("B", sport=1, wscale_shift=None),
    ]
    r = _analyse(pkts)
    assert r.wscale_stripped[("A", "B")] == 1


def test_wscale_pas_stripped_si_present_aux_deux_points():
    pkts = [
        _syn_pkt("A", sport=1, wscale_shift=7),
        _syn_pkt("B", sport=1, wscale_shift=8),
    ]
    r = _analyse(pkts)
    assert r.wscale_stripped == {}


def test_sack_stripped_detecte():
    pkts = [
        _syn_pkt("A", sport=1, sack_permitted=True),
        _syn_pkt("B", sport=1, sack_permitted=False),
    ]
    r = _analyse(pkts)
    assert r.sack_stripped[("A", "B")] == 1


def test_sack_pas_stripped_si_permis_aux_deux_points():
    pkts = [
        _syn_pkt("A", sport=1, sack_permitted=True),
        _syn_pkt("B", sport=1, sack_permitted=True),
    ]
    r = _analyse(pkts)
    assert r.sack_stripped == {}


def test_tcp_options_ignore_les_paquets_hors_handshake():
    pkts = [
        make_pkt(point="A", proto="TCP", flags=".....A..", sport=1, mss_val=1460),
        make_pkt(point="B", proto="TCP", flags=".....A..", sport=1, mss_val=1400),
    ]
    r = _analyse(pkts)
    assert r.mss_clamped == {}


def test_tcp_options_desactive_en_nat_tolerant():
    pkts = [
        _syn_pkt("A", sport=1, mss_val=1460),
        _syn_pkt("B", sport=1, mss_val=1400),
    ]
    r = _analyse(pkts, nat_tolerant=True)
    assert r.mss_clamped == {}


def test_seen_count_par_point():
    pkts = [make_pkt(point="A", sport=1), make_pkt(point="A", sport=2)]
    r = _analyse(pkts)
    assert r.seen_count["A"] == 2
    assert r.seen_count["B"] == 0


# -- handshake TCP / decalage d'horloge (claude.md Session 1 : le bug
# seq/ack relatif vs seq_raw a ete trouve et corrige precisement sur ce
# scenario -- vraie regression a proteger) --------------------------------


def test_handshake_syn_sans_synack_signale_au_point_le_plus_eloigne():
    syn = make_pkt(
        point="A",
        src="10.0.0.1",
        sport=5000,
        dst="10.0.0.2",
        dport=443,
        flags="S",
        seq=1000,
    )
    r = _analyse([syn])
    assert r.syn_no_synack["A"] == 1


def test_handshake_matching_syn_synack_et_decalage_horloge():
    # SYN vu a A puis B ; SYN-ACK (ack = seq+1) vu a B puis A -- symetrie
    # complete requise pour l'estimation de decalage d'horloge (formule NTP).
    syn_a = make_pkt(
        point="A",
        src="10.0.0.1",
        sport=5000,
        dst="10.0.0.2",
        dport=443,
        flags="S",
        seq=1000,
        ts=0.0,
    )
    syn_b = make_pkt(
        point="B",
        src="10.0.0.1",
        sport=5000,
        dst="10.0.0.2",
        dport=443,
        flags="S",
        seq=1000,
        ts=0.01,
    )
    synack_b = make_pkt(
        point="B",
        src="10.0.0.2",
        sport=443,
        dst="10.0.0.1",
        dport=5000,
        flags="SA",
        ack=1001,
        seq=2000,
        ts=0.02,
    )
    synack_a = make_pkt(
        point="A",
        src="10.0.0.2",
        sport=443,
        dst="10.0.0.1",
        dport=5000,
        flags="SA",
        ack=1001,
        seq=2000,
        ts=0.03,
    )
    r = _analyse([syn_a, syn_b, synack_b, synack_a])
    assert r.syn_no_synack["A"] == 0
    assert r.syn_no_synack["B"] == 0
    assert r.syn_reply_missing["A"] == 0
    assert ("A", "B") in r.clock_offset_estimate
    _mean_off, _stdev, n = r.clock_offset_estimate[("A", "B")]
    assert n == 1


def test_handshake_reponse_manquante_a_un_point():
    syn_a = make_pkt(
        point="A",
        src="10.0.0.1",
        sport=5000,
        dst="10.0.0.2",
        dport=443,
        flags="S",
        seq=1000,
        ts=0.0,
    )
    syn_b = make_pkt(
        point="B",
        src="10.0.0.1",
        sport=5000,
        dst="10.0.0.2",
        dport=443,
        flags="S",
        seq=1000,
        ts=0.01,
    )
    # le SYN-ACK n'est vu qu'a B, jamais remonte jusqu'a A
    synack_b = make_pkt(
        point="B",
        src="10.0.0.2",
        sport=443,
        dst="10.0.0.1",
        dport=5000,
        flags="SA",
        ack=1001,
        seq=2000,
        ts=0.02,
    )
    r = _analyse([syn_a, syn_b, synack_b])
    assert r.syn_reply_missing["A"] == 1


def test_handshake_desactive_en_mode_nat_tolerant():
    syn = make_pkt(point="A", flags="S", seq=1000)
    r = _analyse([syn], nat_tolerant=True)
    assert r.syn_no_synack == {}


# -- DNS ----------------------------------------------------------------


def test_dns_requete_et_reponse_meme_point_calcule_la_duree():
    q = make_pkt(point="A", ts=1.000, dns_txn_id=1, dns_is_response=False, dns_qry_name="example.com")
    resp = make_pkt(point="A", ts=1.020, dns_txn_id=1, dns_is_response=True, dns_qry_name="example.com", dns_rcode=0)
    r = _analyse([q, resp])
    assert r.dns_query_count["A"] == 1
    assert r.dns_response_count["A"] == 1
    assert r.dns_duration_ms == pytest.approx([20.0])


def test_dns_requete_vue_en_a_absente_en_b():
    q_a = make_pkt(point="A", ts=1.0, dns_txn_id=2, dns_is_response=False, dns_qry_name="example.com")
    r = _analyse([q_a])
    assert len(r.dns_missing[("A", "B")]) == 1
    assert "requete" in r.dns_missing[("A", "B")][0]
    assert "example.com" in r.dns_missing[("A", "B")][0]


def test_dns_sans_reponse_nulle_part_est_un_timeout():
    q = make_pkt(point="A", ts=1.0, dns_txn_id=3, dns_is_response=False, dns_qry_name="ne-repond-jamais.example")
    r = _analyse([q])
    assert len(r.dns_timeout["A"]) == 1
    assert "ne-repond-jamais.example" in r.dns_timeout["A"][0]


def test_dns_timeout_frame_number_de_la_requete():
    # Session 37 : dns_timeout_frames porte le numero de trame de la
    # requete jamais suivie de reponse (PacketEvidence).
    q = make_pkt(
        point="A", ts=1.0, dns_txn_id=3, dns_is_response=False, dns_qry_name="ne-repond-jamais.example", frame_number=9
    )
    r = _analyse([q])
    assert r.dns_timeout_frames["A"] == [9]


def test_dns_nxdomain_et_servfail_comptes_par_point():
    resp_nx = make_pkt(point="A", ts=1.0, dns_txn_id=4, dns_is_response=True, dns_rcode=3)
    resp_sf = make_pkt(point="A", ts=1.0, dns_txn_id=5, dns_is_response=True, dns_rcode=2)
    r = _analyse([resp_nx, resp_sf])
    assert r.dns_nxdomain_count["A"] == 1
    assert r.dns_servfail_count["A"] == 1


def test_dns_paquet_sans_txn_id_ignore():
    non_dns = make_pkt(point="A", ts=1.0)
    r = _analyse([non_dns])
    assert r.dns_query_count == {}
    assert r.dns_response_count == {}
    assert r.dns_timeout == {}


# -- HTTP -----------------------------------------------------------------


def test_http_requete_et_reponse_meme_point_compte_et_reprend_la_duree_native():
    # http_response_time_ms est deja calcule par tshark (http.time) au
    # moment ou le Pkt est construit -- _analyse_http se contente de le
    # relever, pas de le recalculer (voir docstring de _analyse_http).
    q = make_pkt(point="A", ts=1.000, http_is_request=True, http_uri="/", http_method="GET")
    resp = make_pkt(
        point="A", ts=1.020, http_is_response=True, http_uri="/", http_status_code=200, http_response_time_ms=20.0
    )
    r = _analyse([q, resp])
    assert r.http_request_count["A"] == 1
    assert r.http_response_count["A"] == 1
    assert r.http_status_count["A"] == {"200": 1}
    assert r.http_response_time_ms == pytest.approx([20.0])


def test_http_requete_vue_en_a_absente_en_b():
    q_a = make_pkt(point="A", ts=1.0, http_is_request=True, http_uri="/only-a", http_method="GET")
    r = _analyse([q_a])
    assert len(r.http_missing[("A", "B")]) == 1
    assert "requete" in r.http_missing[("A", "B")][0]
    assert "/only-a" in r.http_missing[("A", "B")][0]


def test_http_sans_reponse_nulle_part_est_un_timeout():
    q = make_pkt(point="A", ts=1.0, http_is_request=True, http_uri="/ne-repond-jamais", http_method="GET")
    r = _analyse([q])
    assert len(r.http_timeout["A"]) == 1
    assert "/ne-repond-jamais" in r.http_timeout["A"][0]


def test_http_timeout_frame_number_de_la_requete():
    # Session 37 : http_timeout_frames porte le numero de trame de la
    # requete jamais suivie de reponse (PacketEvidence).
    q = make_pkt(
        point="A", ts=1.0, http_is_request=True, http_uri="/ne-repond-jamais", http_method="GET", frame_number=8
    )
    r = _analyse([q])
    assert r.http_timeout_frames["A"] == [8]


def test_http_erreurs_4xx_et_5xx_comptees_par_point():
    resp_404 = make_pkt(point="A", ts=1.0, http_is_response=True, http_uri="/a", http_status_code=404)
    resp_500 = make_pkt(point="A", ts=2.0, http_is_response=True, http_uri="/b", http_status_code=500)
    r = _analyse([resp_404, resp_500])
    assert r.http_client_error_count["A"] == 1
    assert r.http_server_error_count["A"] == 1
    assert r.http_status_count["A"] == {"404": 1, "500": 1}


def test_http_exemple_erreur_inclut_la_methode_de_la_requete():
    q = make_pkt(point="A", ts=1.0, http_is_request=True, http_uri="/error", http_method="GET")
    resp = make_pkt(point="A", ts=1.01, http_is_response=True, http_uri="/error", http_status_code=500)
    r = _analyse([q, resp])
    assert r.http_error_examples["A"] == ["GET /error -> 500"]


def test_http_error_frame_number_de_la_reponse():
    # Session 37 : http_error_frames porte le numero de trame de la
    # REPONSE d'erreur (PacketEvidence), meme index que http_error_examples.
    q = make_pkt(point="A", ts=1.0, http_is_request=True, http_uri="/error", http_method="GET", frame_number=1)
    resp = make_pkt(point="A", ts=1.01, http_is_response=True, http_uri="/error", http_status_code=500, frame_number=2)
    r = _analyse([q, resp])
    assert r.http_error_frames["A"] == [2]


def test_http_paquet_sans_requete_ni_reponse_ignore():
    non_http = make_pkt(point="A", ts=1.0)
    r = _analyse([non_http])
    assert r.http_request_count == {}
    assert r.http_response_count == {}
    assert r.http_timeout == {}


def test_http_uri_evite_le_glissement_quand_une_requete_differente_est_perdue():
    # Verifie precisement la limite discutee dans la docstring de
    # _analyse_http : /a et /b sont deux requetes DIFFERENTES sur la
    # meme connexion. /b n'atteint jamais B (perdue), /a est presente
    # aux deux points. Une cle purement ordinale (1ere requete, 2eme
    # requete...) confondrait a tort la position 2 de A (=/b) avec la
    # position 2 de B (qui n'existe pas) -- ou pire, avec une requete
    # suivante sur une URI differente. La cle par URI ne doit PAS
    # signaler /a comme manquante, et doit signaler /b precisement.
    pkts = [
        make_pkt(point="A", ts=1.0, http_is_request=True, http_uri="/a", http_method="GET"),
        make_pkt(point="A", ts=1.01, http_is_response=True, http_uri="/a", http_status_code=200),
        make_pkt(point="A", ts=2.0, http_is_request=True, http_uri="/b", http_method="GET"),
        make_pkt(point="A", ts=2.01, http_is_response=True, http_uri="/b", http_status_code=200),
        make_pkt(point="B", ts=1.05, http_is_request=True, http_uri="/a", http_method="GET"),
        make_pkt(point="B", ts=1.06, http_is_response=True, http_uri="/a", http_status_code=200),
    ]
    r = _analyse(pkts)
    missing = r.http_missing[("A", "B")]
    assert any("/b" in m for m in missing)
    assert not any("/a" in m for m in missing)
    # Pas de timeout ici : la reponse a /b a bien ete observee (a A),
    # seul le segment A->B la perd -- ce qui est precisement ce que
    # http_missing signale deja. Un timeout (aucune reponse nulle part
    # dans la capture entiere) est un scenario different, teste separement
    # ci-dessus (test_http_sans_reponse_nulle_part_est_un_timeout).
    assert r.http_timeout == {}


def test_http_meme_uri_rejouee_deux_fois_sans_perte_ne_signale_rien():
    # Cas de polling (meme URI plusieurs fois sur la meme connexion) --
    # tant qu'aucune occurrence n'est perdue, le compteur d'occurrence ne
    # doit provoquer aucun faux "manquant".
    pkts = [
        make_pkt(point="A", ts=1.0, http_is_request=True, http_uri="/health", http_method="GET"),
        make_pkt(point="A", ts=1.01, http_is_response=True, http_uri="/health", http_status_code=200),
        make_pkt(point="A", ts=2.0, http_is_request=True, http_uri="/health", http_method="GET"),
        make_pkt(point="A", ts=2.01, http_is_response=True, http_uri="/health", http_status_code=200),
        make_pkt(point="B", ts=1.05, http_is_request=True, http_uri="/health", http_method="GET"),
        make_pkt(point="B", ts=1.06, http_is_response=True, http_uri="/health", http_status_code=200),
        make_pkt(point="B", ts=2.05, http_is_request=True, http_uri="/health", http_method="GET"),
        make_pkt(point="B", ts=2.06, http_is_response=True, http_uri="/health", http_status_code=200),
    ]
    r = _analyse(pkts)
    assert r.http_missing[("A", "B")] == []
    assert r.http_timeout == {}


# -- RTP : sample_count (score de confiance, voir synthesis.py) --


def _rtp_pkt(point, ts, seq):
    return make_pkt(
        point=point,
        proto="UDP",
        sport=5000,
        dport=5000,
        is_rtp=True,
        rtp_seq=seq,
        rtp_ts=seq * 160,
        rtp_ssrc=42,
    )


def test_rtp_sample_count_est_le_nombre_de_paquets_au_point_de_reference():
    pkts = [_rtp_pkt("A", ts, seq) for seq, ts in enumerate([0.0, 0.02, 0.04])]
    pkts += [_rtp_pkt("B", ts, seq) for seq, ts in enumerate([0.05, 0.07, 0.09, 0.11, 0.13])]
    r = _analyse(pkts, points_order=("A", "B"))
    assert len(r.rtp_streams) == 1
    # points_order=("A","B") -> ref_point = points[-1] = "B" (5 paquets recus)
    assert r.rtp_streams[0]["sample_count"] == 5


def test_rtp_sample_count_absent_si_pas_de_points_order():
    """Sans --order et sans topologie deduite (un seul point), ref_point
    utilise malgre tout le seul point disponible (repli sur loss_pct) --
    sample_count reste le compte de paquets a ce point, la ou seul `mos`
    reste None faute de delay_ms calculable (pas de finding cree, voir
    synthesis.py, mais le champ lui-meme ne plante pas)."""
    pkts = [_rtp_pkt("A", ts, seq) for seq, ts in enumerate([0.0, 0.02, 0.04])]
    r = _analyse(pkts, points_order=())
    assert r.rtp_streams[0]["sample_count"] == 3
    assert r.rtp_streams[0]["mos"] is None


# -- topn_timeseries (graphiques temporels top-N, voir netcross_core.correlate) --


def test_analyse_peuple_topn_timeseries_pour_les_4_dimensions():
    pkts = [make_pkt(point="A", proto="TCP", dst="1.1.1.1", dport=443, dscp=0, ts=0.1, length=100)]
    r = _analyse(pkts)
    assert set(r.topn_timeseries) == {"protocol", "port", "ip", "dscp"}
    assert r.topn_timeseries["protocol"]["A"]["TCP"][0] == 100


def test_analyse_topn_parametre_reglable():
    pkts = [
        make_pkt(point="A", proto="TCP", length=100),
        make_pkt(point="A", proto="UDP", length=50),
        make_pkt(point="A", proto="ICMP", length=10),
    ]
    r = _analyse(pkts, topn=1)
    from netcross_core.correlate import TOPN_OTHER_LABEL

    assert set(r.topn_timeseries["protocol"]["A"]) == {"TCP", TOPN_OTHER_LABEL}


def test_analyse_topn_defaut_a_5():
    pkts = [make_pkt(point="A", proto="TCP", length=100)]
    r = _analyse(pkts)
    assert "TCP" in r.topn_timeseries["protocol"]["A"]


# -- Issue #762 : validate_checksums() branchee dans analyse() ------------


def test_analyse_remplit_checksum_errors_si_checksum_invalide():
    """analyse() appelle validate_checksums() et remplit Report.checksum_errors."""
    pkts = [
        make_pkt(point="A", sport=1, ip_checksum="0x1234", ip_checksum_bad=True),
        make_pkt(point="A", sport=2, tcp_checksum="0x5678", tcp_checksum_bad=True),
    ]
    r = _analyse(pkts)
    assert len(r.checksum_errors) == 2
    assert r.checksum_errors[0].protocol == "IP"
    assert r.checksum_errors[0].checksum == "0x1234"
    assert r.checksum_errors[1].protocol == "TCP"
    assert r.checksum_errors[1].checksum == "0x5678"


def test_analyse_checksum_vide_si_pas_derreur():
    """Aucun checksum invalide -> Report.checksum_errors reste vide."""
    pkts = [
        make_pkt(point="A", sport=1, ip_checksum="0x1234", ip_checksum_bad=False),
        make_pkt(point="A", sport=2, tcp_checksum="0x5678", tcp_checksum_bad=False),
    ]
    r = _analyse(pkts)
    assert r.checksum_errors == []


def test_analyse_checksum_offload_non_signale():
    """Checksum a 0x0000 (offload materiel) n'est jamais signale."""
    pkts = [
        make_pkt(point="A", sport=1, ip_checksum="0x0000", ip_checksum_bad=True),
    ]
    r = _analyse(pkts)
    assert r.checksum_errors == []


def test_analyse_checksum_udp_invalide_detecte():
    """Checksum UDP invalide est detecte."""
    pkts = [
        make_pkt(point="A", proto="UDP", sport=1, udp_checksum="0xdead", udp_checksum_bad=True),
    ]
    r = _analyse(pkts)
    assert len(r.checksum_errors) == 1
    assert r.checksum_errors[0].protocol == "UDP"


def test_analyse_checksum_exclude_duplicates():
    """exclude_duplicates retire les paquets dupliques avant validation checksums."""
    pkts = [
        make_pkt(point="A", sport=1, ip_checksum="0x1234", ip_checksum_bad=True, is_duplicate=True),
    ]
    r = _analyse(pkts, exclude_duplicates=True)
    assert r.checksum_errors == []
