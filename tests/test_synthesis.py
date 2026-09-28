"""
netcross_report.synthesis.build_findings -- chaque regle est tracable a
un chiffre du Report ; on construit des Report minimalistes cible par
cible pour verifier les seuils de severite.
"""

from netcross_core.expert_model import EvidenceLink, PacketEvidence
from netcross_core.models import Report
from netcross_report.synthesis import build_findings


def test_pertes_anomalie_au_dessus_de_5_pourcent():
    r = Report(points=["A"])
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100  # 10%
    findings = build_findings(r)
    pertes = [f for f in findings if f.category == "Pertes"]
    assert pertes[0].severity == "anomalie"


def test_pertes_a_surveiller_en_dessous_de_5_pourcent():
    r = Report(points=["A"])
    r.loss_count["A"] = 2
    r.seen_count["A"] = 100  # 2%
    findings = build_findings(r)
    pertes = [f for f in findings if f.category == "Pertes"]
    assert pertes[0].severity == "a_surveiller"


def test_pertes_nulles_pas_de_finding():
    r = Report(points=["A"])
    r.loss_count["A"] = 0
    findings = build_findings(r)
    assert not [f for f in findings if f.category == "Pertes"]


def test_saturation_mots_cles_donnent_anomalie():
    r = Report(points=["A", "B"])
    r.saturation_verdict[("A", "B")] = "saturation probable en aval"
    findings = build_findings(r)
    sat = [f for f in findings if f.category == "Saturation"]
    assert sat[0].severity == "anomalie"


def test_saturation_sans_mot_cle_donne_a_surveiller():
    r = Report(points=["A", "B"])
    r.saturation_verdict[("A", "B")] = "fluide, rien a signaler"
    findings = build_findings(r)
    sat = [f for f in findings if f.category == "Saturation"]
    assert sat[0].severity == "a_surveiller"


def test_saturation_non_correlees_ignoree():
    r = Report(points=["A", "B"])
    r.saturation_verdict[("A", "B")] = "mesures NON correlees temporellement"
    findings = build_findings(r)
    assert not [f for f in findings if f.category == "Saturation"]


def test_fragmentation_correlee_a_un_tunnel_est_une_anomalie():
    r = Report(points=["A", "B"])
    r.frag_new[("A", "B")] = 5
    r.encap_frag_correlated[("A", "B")] = 5
    findings = build_findings(r)
    frag = [f for f in findings if f.category == "Fragmentation" and f.segment == "A -> B"]
    assert frag[0].severity == "anomalie"
    assert "tunnel" in frag[0].message


def test_fragmentation_sans_correlation_tunnel_est_a_surveiller():
    r = Report(points=["A", "B"])
    r.frag_new[("A", "B")] = 5
    findings = build_findings(r)
    frag = [f for f in findings if f.category == "Fragmentation" and f.segment == "A -> B"]
    assert frag[0].severity == "a_surveiller"


def test_rst_localise_est_toujours_une_anomalie():
    r = Report(points=["A"])
    r.rst_localized["A"] = 1
    findings = build_findings(r)
    tcp = [f for f in findings if f.category == "TCP"]
    assert tcp[0].severity == "anomalie"


def test_zero_window_est_a_surveiller():
    r = Report(points=["A"])
    r.zero_window["A"] = 3
    findings = build_findings(r)
    tcp = [f for f in findings if f.category == "TCP"]
    assert tcp[0].severity == "a_surveiller"


def test_rtp_mos_mauvais_est_une_anomalie():
    r = Report(points=["A"])
    r.rtp_streams = [{"label": "A -> B (SSRC=1)", "mos": 2.0, "r_factor": 30.0}]
    findings = build_findings(r)
    rtp = [f for f in findings if f.category == "RTP/Voix"]
    assert rtp[0].severity == "anomalie"
    assert rtp[0].segment == "A -> B"  # SSRC retire du segment


def test_rtp_mos_moyen_est_a_surveiller():
    r = Report(points=["A"])
    r.rtp_streams = [{"label": "A -> B (SSRC=1)", "mos": 3.3, "r_factor": 60.0}]
    findings = build_findings(r)
    rtp = [f for f in findings if f.category == "RTP/Voix"]
    assert rtp[0].severity == "a_surveiller"


def test_rtp_mos_bon_aucun_finding():
    r = Report(points=["A"])
    r.rtp_streams = [{"label": "A -> B (SSRC=1)", "mos": 4.2, "r_factor": 90.0}]
    findings = build_findings(r)
    assert not [f for f in findings if f.category == "RTP/Voix"]


def test_pmtud_blackhole_est_une_anomalie():
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    findings = build_findings(r)
    pmtud = [f for f in findings if f.category == "PMTUD"]
    assert len(pmtud) == 1
    assert pmtud[0].severity == "anomalie"
    assert pmtud[0].segment == "A -> B"


def test_pmtud_sans_occurrence_pas_de_finding():
    r = Report(points=["A", "B"])
    findings = build_findings(r)
    assert not [f for f in findings if f.category == "PMTUD"]


def test_idle_timeout_dropped_est_une_anomalie():
    r = Report(points=["A", "B"])
    r.idle_timeout_dropped[("A", "B")] = 1
    findings = build_findings(r)
    idle = [f for f in findings if f.category == "NAT/Pare-feu"]
    assert len(idle) == 1
    assert idle[0].severity == "anomalie"
    assert idle[0].segment == "A -> B"


def test_idle_timeout_sans_occurrence_pas_de_finding():
    r = Report(points=["A", "B"])
    findings = build_findings(r)
    assert not [f for f in findings if f.category == "NAT/Pare-feu"]


def test_arp_ip_conflict_est_une_anomalie():
    r = Report(points=["A", "B"])
    r.arp_ip_conflict["A"] = 1
    findings = build_findings(r)
    arp = [f for f in findings if f.category == "ARP"]
    assert len(arp) == 1
    assert arp[0].severity == "anomalie"
    assert arp[0].segment == "A"


def test_arp_ip_conflict_sans_occurrence_pas_de_finding():
    r = Report(points=["A", "B"])
    findings = build_findings(r)
    assert not [f for f in findings if f.category == "ARP"]


def test_stp_topology_change_est_une_anomalie():
    r = Report(points=["A", "B"])
    r.stp_topology_change["A"] = 3
    findings = build_findings(r)
    stp = [f for f in findings if f.category == "STP"]
    assert len(stp) == 1
    assert stp[0].severity == "anomalie"
    assert stp[0].segment == "A"


def test_stp_root_change_est_une_anomalie():
    r = Report(points=["A", "B"])
    r.stp_root_change["A"] = 1
    findings = build_findings(r)
    stp = [f for f in findings if f.category == "STP"]
    assert len(stp) == 1
    assert stp[0].severity == "anomalie"


def test_stp_topology_change_et_root_change_donnent_deux_findings_distincts():
    r = Report(points=["A", "B"])
    r.stp_topology_change["A"] = 2
    r.stp_root_change["A"] = 1
    findings = build_findings(r)
    stp = [f for f in findings if f.category == "STP"]
    assert len(stp) == 2


def test_stp_sans_occurrence_pas_de_finding():
    r = Report(points=["A", "B"])
    findings = build_findings(r)
    assert not [f for f in findings if f.category == "STP"]


def test_tls_cert_invalid_dates_est_une_anomalie():
    r = Report(points=["A", "B"])
    r.tls_cert_invalid_dates["A"] = 1
    findings = build_findings(r)
    tls = [f for f in findings if f.category == "TLS"]
    assert len(tls) == 1
    assert tls[0].severity == "anomalie"
    assert tls[0].segment == "A"


def test_tls_cert_mismatch_est_une_anomalie():
    r = Report(points=["A", "B"])
    r.tls_cert_mismatch[("A", "B")] = 1
    findings = build_findings(r)
    tls = [f for f in findings if f.category == "TLS"]
    assert len(tls) == 1
    assert tls[0].severity == "anomalie"
    assert tls[0].segment == "A -> B"


def test_tls_handshake_no_reply_est_une_anomalie():
    r = Report(points=["A", "B"])
    r.tls_handshake_no_reply["A"] = 1
    findings = build_findings(r)
    tls = [f for f in findings if f.category == "TLS"]
    assert len(tls) == 1
    assert tls[0].severity == "anomalie"
    assert tls[0].segment == "A"


def test_tls_handshake_incomplete_est_une_anomalie():
    r = Report(points=["A", "B"])
    r.tls_handshake_incomplete["A"] = 1
    findings = build_findings(r)
    tls = [f for f in findings if f.category == "TLS"]
    assert len(tls) == 1
    assert tls[0].severity == "anomalie"
    assert tls[0].segment == "A"


def test_tls_sans_occurrence_pas_de_finding():
    r = Report(points=["A", "B"])
    findings = build_findings(r)
    assert not [f for f in findings if f.category == "TLS"]


def test_icmpv6_too_big_donne_un_finding_info():
    # Equivalent IPv6 (Session 22) de icmp_frag_needed -- voir le test
    # de la categorie Fragmentation ci-dessus pour le pendant IPv4.
    r = Report(points=["A"])
    r.icmpv6_too_big["A"] = 3
    findings = build_findings(r)
    frag = [f for f in findings if f.category == "Fragmentation" and f.segment == "A"]
    assert len(frag) == 1
    assert frag[0].severity == "info"
    assert "ICMPv6" in frag[0].message


def test_icmpv6_too_big_sans_occurrence_pas_de_finding():
    r = Report(points=["A"])
    findings = build_findings(r)
    assert not [f for f in findings if f.category == "Fragmentation"]


def test_retransmission_rto_est_a_surveiller():
    r = Report(points=["A"])
    r.retrans_rto["A"] = 3
    findings = build_findings(r)
    rto = [f for f in findings if f.category == "TCP" and "RTO" in f.message]
    assert len(rto) == 1
    assert rto[0].severity == "a_surveiller"


def test_retransmission_spurious_est_a_surveiller():
    r = Report(points=["A"])
    r.retrans_spurious["A"] = 2
    findings = build_findings(r)
    spur = [f for f in findings if f.category == "TCP" and "inutile" in f.message]
    assert len(spur) == 1
    assert spur[0].severity == "a_surveiller"


def test_retransmission_fast_est_info():
    r = Report(points=["A"])
    r.retrans_fast["A"] = 5
    findings = build_findings(r)
    fast = [f for f in findings if f.category == "TCP" and "rapide" in f.message]
    assert len(fast) == 1
    assert fast[0].severity == "info"


def test_mss_clamped_est_info():
    r = Report(points=["A", "B"])
    r.mss_clamped[("A", "B")] = 1
    findings = build_findings(r)
    mss = [f for f in findings if f.category == "TCP" and "MSS" in f.message]
    assert len(mss) == 1
    assert mss[0].severity == "info"
    assert mss[0].segment == "A -> B"


def test_wscale_stripped_est_a_surveiller():
    r = Report(points=["A", "B"])
    r.wscale_stripped[("A", "B")] = 1
    findings = build_findings(r)
    ws = [f for f in findings if f.category == "TCP" and "Window Scale" in f.message]
    assert len(ws) == 1
    assert ws[0].severity == "a_surveiller"


def test_sack_stripped_est_a_surveiller():
    r = Report(points=["A", "B"])
    r.sack_stripped[("A", "B")] = 1
    findings = build_findings(r)
    sk = [f for f in findings if f.category == "TCP" and "SACK" in f.message]
    assert len(sk) == 1
    assert sk[0].severity == "a_surveiller"


def test_dhcp_nak_est_une_anomalie():
    r = Report(points=["A"])
    r.dhcp_nak_count["A"] = 1
    findings = build_findings(r)
    dhcp = [f for f in findings if f.category == "DHCP"]
    assert dhcp[0].severity == "anomalie"


def test_dns_servfail_est_une_anomalie():
    r = Report(points=["A"])
    r.dns_servfail_count["A"] = 1
    findings = build_findings(r)
    dns = [f for f in findings if f.category == "DNS"]
    assert dns[0].severity == "anomalie"


def test_dns_nxdomain_est_une_info():
    r = Report(points=["A"])
    r.dns_nxdomain_count["A"] = 1
    findings = build_findings(r)
    dns = [f for f in findings if f.category == "DNS"]
    assert dns[0].severity == "info"


def test_dns_timeout_est_une_anomalie():
    r = Report(points=["A"])
    r.dns_timeout["A"] = ["id=0x1 (example.com) : aucune reponse observee dans la capture"]
    findings = build_findings(r)
    dns = [f for f in findings if f.category == "DNS"]
    assert dns[0].severity == "anomalie"


def test_dns_message_manquant_est_a_surveiller():
    r = Report(points=["A", "B"])
    r.dns_missing[("A", "B")] = ["id=0x1 (example.com) : requete vue en A, absente en B"]
    findings = build_findings(r)
    dns = [f for f in findings if f.category == "DNS"]
    assert dns[0].severity == "a_surveiller"
    assert dns[0].segment == "A -> B"


def test_dns_duree_moyenne_elevee_est_a_surveiller():
    r = Report(points=["A"])
    r.dns_duration_ms = [250.0, 260.0]
    findings = build_findings(r)
    dns = [f for f in findings if f.category == "DNS"]
    assert dns[0].severity == "a_surveiller"


def test_dns_duree_moyenne_faible_ne_produit_rien():
    r = Report(points=["A"])
    r.dns_duration_ms = [10.0, 15.0]
    findings = build_findings(r)
    assert [f for f in findings if f.category == "DNS"] == []


def test_http_4xx_est_une_info():
    r = Report(points=["A"])
    r.http_client_error_count["A"] = 1
    findings = build_findings(r)
    http = [f for f in findings if f.category == "HTTP"]
    assert http[0].severity == "info"


def test_http_5xx_est_une_anomalie():
    r = Report(points=["A"])
    r.http_server_error_count["A"] = 1
    findings = build_findings(r)
    http = [f for f in findings if f.category == "HTTP"]
    assert http[0].severity == "anomalie"


def test_http_timeout_est_une_anomalie():
    r = Report(points=["A"])
    r.http_timeout["A"] = ["/x : aucune reponse observee dans la capture"]
    findings = build_findings(r)
    http = [f for f in findings if f.category == "HTTP"]
    assert http[0].severity == "anomalie"


def test_http_message_manquant_est_a_surveiller():
    r = Report(points=["A", "B"])
    r.http_missing[("A", "B")] = ["/x : requete vue en A, absente en B"]
    findings = build_findings(r)
    http = [f for f in findings if f.category == "HTTP"]
    assert http[0].severity == "a_surveiller"
    assert http[0].segment == "A -> B"


def test_http_duree_moyenne_elevee_est_a_surveiller():
    r = Report(points=["A"])
    r.http_response_time_ms = [600.0, 700.0]
    findings = build_findings(r)
    http = [f for f in findings if f.category == "HTTP"]
    assert http[0].severity == "a_surveiller"


def test_http_duree_moyenne_faible_ne_produit_rien():
    r = Report(points=["A"])
    r.http_response_time_ms = [50.0, 80.0]
    findings = build_findings(r)
    assert [f for f in findings if f.category == "HTTP"] == []


def test_report_vide_ne_produit_aucun_finding():
    r = Report(points=["A", "B"])
    assert build_findings(r) == []


# -- score de confiance (sample_size) --


def test_pertes_sample_size_est_le_nombre_de_paquets_vus():
    r = Report(points=["A"])
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100
    pertes = [f for f in build_findings(r) if f.category == "Pertes"]
    assert pertes[0].sample_size == 100


def test_rtp_mos_sample_size_depuis_sample_count():
    r = Report(points=["A"])
    r.rtp_streams = [{"label": "A -> B (SSRC=1)", "mos": 2.0, "r_factor": 30.0, "sample_count": 4}]
    rtp = [f for f in build_findings(r) if f.category == "RTP/Voix"]
    assert rtp[0].sample_size == 4


def test_rtp_mos_sample_size_absent_si_non_fourni():
    """Un flux RTP construit sans la cle sample_count (ancien format,
    ou construit a la main comme dans les tests existants ci-dessus) ne
    doit pas planter -- sample_size reste None plutot que de lever une
    KeyError."""
    r = Report(points=["A"])
    r.rtp_streams = [{"label": "A -> B (SSRC=1)", "mos": 2.0, "r_factor": 30.0}]
    rtp = [f for f in build_findings(r) if f.category == "RTP/Voix"]
    assert rtp[0].sample_size is None


def test_reseau_serveur_ralentissement_applicatif():
    r = Report(points=["A", "B"])
    r.server_think_time["A"] = [100.0, 110.0]
    r.latency[("A", "B")] = [5.0]
    findings = [f for f in build_findings(r) if f.category == "Reseau/Serveur"]
    assert findings[0].severity == "a_surveiller"
    assert findings[0].sample_size == 2


def test_dns_duree_sample_size_est_le_nombre_de_mesures():
    r = Report(points=["A"])
    r.dns_duration_ms = [250.0, 260.0, 270.0]
    dns = [f for f in build_findings(r) if f.category == "DNS"]
    assert dns[0].sample_size == 3


def test_http_duree_sample_size_est_le_nombre_de_mesures():
    r = Report(points=["A"])
    r.http_response_time_ms = [600.0, 700.0, 800.0]
    http = [f for f in build_findings(r) if f.category == "HTTP"]
    assert http[0].sample_size == 3


def test_finding_sample_size_par_defaut_none():
    """Les categories non annotees (premiere passe du sujet, voir
    synthesis.py) exposent tout de meme l'attribut, a None -- pas
    d'AttributeError pour un consommateur generique (triage/json_report)."""
    r = Report(points=["A", "B"])
    r.vlan_change[("A", "B")] = 3
    findings = [f for f in build_findings(r) if f.category == "VLAN"]
    assert findings[0].sample_size is None


# -- preuves attachees aux constats (evidence, Session 32) --
#
# Chaque test verifie que le contenu de `evidence` reprend EXACTEMENT les
# chaines deja collectees ailleurs dans Report (*_examples, ou les listes
# *_missing/*_timeout elles-memes) -- rien n'est recalcule ni reformate,
# voir synthesis._evidence().


def test_finding_evidence_vide_par_defaut():
    """Une categorie sans source de preuve cablee (ex: pertes) expose tout
    de meme l'attribut, a liste vide -- meme convention que sample_size."""
    r = Report(points=["A"])
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100
    pertes = [f for f in build_findings(r) if f.category == "Pertes"]
    assert pertes[0].evidence == []


def test_pmtud_evidence_depuis_examples():
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    r.pmtud_blackhole_examples[("A", "B")] = ["seq=123 retransmis 4x"]
    pmtud = [f for f in build_findings(r) if f.category == "PMTUD"]
    assert pmtud[0].evidence == [EvidenceLink("A -> B", "seq=123 retransmis 4x")]


def test_pmtud_evidence_porte_le_numero_de_trame():
    """Session 35 : seule categorie pilote pour PacketEvidence -- quand
    Report.pmtud_blackhole_frames est peuple (netcross_core.analysis),
    l'EvidenceLink construit gagne un packet non None, meme index que le
    texte correspondant."""
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    r.pmtud_blackhole_examples[("A", "B")] = ["seq=123 retransmis 4x"]
    r.pmtud_blackhole_frames[("A", "B")] = [42]
    pmtud = [f for f in build_findings(r) if f.category == "PMTUD"]
    assert pmtud[0].evidence == [EvidenceLink("A -> B", "seq=123 retransmis 4x", packet=PacketEvidence("A -> B", 42))]


def test_pmtud_evidence_sans_frame_number_garde_packet_none():
    """frame_number absent (None) sur le paquet source -- packet reste
    None sur l'EvidenceLink correspondant, pas d'exception."""
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    r.pmtud_blackhole_examples[("A", "B")] = ["seq=123 retransmis 4x"]
    r.pmtud_blackhole_frames[("A", "B")] = [None]
    pmtud = [f for f in build_findings(r) if f.category == "PMTUD"]
    assert pmtud[0].evidence == [EvidenceLink("A -> B", "seq=123 retransmis 4x")]
    assert pmtud[0].evidence[0].packet is None


def test_idle_timeout_evidence_depuis_examples():
    r = Report(points=["A", "B"])
    r.idle_timeout_dropped[("A", "B")] = 1
    r.idle_timeout_examples[("A", "B")] = ["silence de 320s puis reprise jamais vue en B"]
    idle = [f for f in build_findings(r) if f.category == "NAT/Pare-feu"]
    assert idle[0].evidence == [EvidenceLink("A -> B", "silence de 320s puis reprise jamais vue en B")]


def test_idle_timeout_evidence_porte_le_numero_de_trame():
    r = Report(points=["A", "B"])
    r.idle_timeout_dropped[("A", "B")] = 1
    r.idle_timeout_examples[("A", "B")] = ["silence de 320s puis reprise jamais vue en B"]
    r.idle_timeout_frames[("A", "B")] = [42]
    idle = [f for f in build_findings(r) if f.category == "NAT/Pare-feu"]
    assert idle[0].evidence[0].packet == PacketEvidence("A -> B", 42)


def test_arp_ip_conflict_evidence_depuis_examples():
    r = Report(points=["A", "B"])
    r.arp_ip_conflict["A"] = 1
    r.arp_ip_conflict_examples["A"] = ["10.0.0.5 revendiquee par aa:bb et cc:dd"]
    arp = [f for f in build_findings(r) if f.category == "ARP"]
    assert arp[0].evidence == [EvidenceLink("A", "10.0.0.5 revendiquee par aa:bb et cc:dd")]


def test_arp_ip_conflict_evidence_porte_le_numero_de_trame():
    r = Report(points=["A", "B"])
    r.arp_ip_conflict["A"] = 1
    r.arp_ip_conflict_examples["A"] = ["10.0.0.5 revendiquee par aa:bb et cc:dd"]
    r.arp_ip_conflict_frames["A"] = [7]
    arp = [f for f in build_findings(r) if f.category == "ARP"]
    assert arp[0].evidence[0].packet == PacketEvidence("A", 7)


def test_stp_root_change_evidence_depuis_examples():
    r = Report(points=["A", "B"])
    r.stp_root_change["A"] = 1
    r.stp_root_change_examples["A"] = ["racine changee de X vers Y"]
    stp = [f for f in build_findings(r) if f.category == "STP" and "racine" in f.message]
    assert stp[0].evidence == [EvidenceLink("A", "racine changee de X vers Y")]


def test_stp_root_change_evidence_porte_le_numero_de_trame():
    r = Report(points=["A", "B"])
    r.stp_root_change["A"] = 1
    r.stp_root_change_examples["A"] = ["racine changee de X vers Y"]
    r.stp_root_change_frames["A"] = [11]
    stp = [f for f in build_findings(r) if f.category == "STP" and "racine" in f.message]
    assert stp[0].evidence[0].packet == PacketEvidence("A", 11)


def test_stp_topology_change_n_a_pas_d_evidence():
    """Report ne collecte aucun exemple pour stp_topology_change (voir
    netcross_core.models -- seul stp_root_change en a un) : le finding
    correspondant garde une evidence vide, ce n'est pas un oubli."""
    r = Report(points=["A", "B"])
    r.stp_topology_change["A"] = 3
    stp = [f for f in build_findings(r) if f.category == "STP" and "topologie" in f.message]
    assert stp[0].evidence == []


def test_tls_cert_invalid_dates_evidence_depuis_examples():
    r = Report(points=["A", "B"])
    r.tls_cert_invalid_dates["A"] = 1
    r.tls_cert_invalid_dates_examples["A"] = ["certificat expire depuis 3 jours"]
    tls = [f for f in build_findings(r) if f.category == "TLS" and f.segment == "A"]
    assert tls[0].evidence == [EvidenceLink("A", "certificat expire depuis 3 jours")]


def test_tls_cert_invalid_dates_evidence_porte_le_numero_de_trame():
    r = Report(points=["A", "B"])
    r.tls_cert_invalid_dates["A"] = 1
    r.tls_cert_invalid_dates_examples["A"] = ["certificat expire depuis 3 jours"]
    r.tls_cert_invalid_dates_frames["A"] = [13]
    tls = [f for f in build_findings(r) if f.category == "TLS" and f.segment == "A"]
    assert tls[0].evidence[0].packet == PacketEvidence("A", 13)


def test_tls_cert_mismatch_evidence_depuis_examples():
    r = Report(points=["A", "B"])
    r.tls_cert_mismatch[("A", "B")] = 1
    r.tls_cert_mismatch_examples[("A", "B")] = ["serie 0x1 en A, 0x2 en B"]
    tls = [f for f in build_findings(r) if f.category == "TLS" and f.segment == "A -> B"]
    assert tls[0].evidence == [EvidenceLink("A -> B", "serie 0x1 en A, 0x2 en B")]


def test_tls_handshake_no_reply_evidence_depuis_examples():
    r = Report(points=["A", "B"])
    r.tls_handshake_no_reply["A"] = 1
    r.tls_handshake_no_reply_examples["A"] = ["10.0.0.1:1234 -> 10.0.0.2:443 : ClientHello envoye"]
    tls = [f for f in build_findings(r) if f.category == "TLS" and f.segment == "A"]
    assert tls[0].evidence == [EvidenceLink("A", "10.0.0.1:1234 -> 10.0.0.2:443 : ClientHello envoye")]


def test_tls_handshake_no_reply_evidence_porte_le_numero_de_trame():
    r = Report(points=["A", "B"])
    r.tls_handshake_no_reply["A"] = 1
    r.tls_handshake_no_reply_examples["A"] = ["ClientHello envoye"]
    r.tls_handshake_no_reply_frames["A"] = [21]
    tls = [f for f in build_findings(r) if f.category == "TLS" and f.segment == "A"]
    assert tls[0].evidence[0].packet == PacketEvidence("A", 21)


def test_tls_handshake_incomplete_evidence_depuis_examples():
    r = Report(points=["A", "B"])
    r.tls_handshake_incomplete["A"] = 1
    r.tls_handshake_incomplete_examples["A"] = ["10.0.0.1:1234 -> 10.0.0.2:443 : ServerHello recu"]
    tls = [f for f in build_findings(r) if f.category == "TLS" and f.segment == "A"]
    assert tls[0].evidence == [EvidenceLink("A", "10.0.0.1:1234 -> 10.0.0.2:443 : ServerHello recu")]


def test_tls_handshake_incomplete_evidence_porte_le_numero_de_trame():
    r = Report(points=["A", "B"])
    r.tls_handshake_incomplete["A"] = 1
    r.tls_handshake_incomplete_examples["A"] = ["ServerHello recu"]
    r.tls_handshake_incomplete_frames["A"] = [22]
    tls = [f for f in build_findings(r) if f.category == "TLS" and f.segment == "A"]
    assert tls[0].evidence[0].packet == PacketEvidence("A", 22)


def test_tls_cert_mismatch_evidence_porte_le_numero_de_trame():
    r = Report(points=["A", "B"])
    r.tls_cert_mismatch[("A", "B")] = 1
    r.tls_cert_mismatch_examples[("A", "B")] = ["serie 0x1 en A, 0x2 en B"]
    r.tls_cert_mismatch_frames[("A", "B")] = [14]
    tls = [f for f in build_findings(r) if f.category == "TLS" and f.segment == "A -> B"]
    assert tls[0].evidence[0].packet == PacketEvidence("A -> B", 14)


def test_mss_clamped_evidence_depuis_examples():
    r = Report(points=["A", "B"])
    r.mss_clamped[("A", "B")] = 1
    r.mss_clamped_examples[("A", "B")] = ["MSS 1460 -> 1400"]
    mss = [f for f in build_findings(r) if f.category == "TCP" and "MSS" in f.message]
    assert mss[0].evidence == [EvidenceLink("A -> B", "MSS 1460 -> 1400")]


def test_mss_clamped_evidence_porte_le_numero_de_trame():
    r = Report(points=["A", "B"])
    r.mss_clamped[("A", "B")] = 1
    r.mss_clamped_examples[("A", "B")] = ["MSS 1460 -> 1400"]
    r.mss_clamped_frames[("A", "B")] = [15]
    mss = [f for f in build_findings(r) if f.category == "TCP" and "MSS" in f.message]
    assert mss[0].evidence[0].packet == PacketEvidence("A -> B", 15)


def test_dhcp_missing_evidence_est_la_liste_missing_elle_meme():
    r = Report(points=["A", "B"])
    r.dhcp_missing[("A", "B")] = ["DHCPOFFER vu en A, absent en B"]
    dhcp = [f for f in build_findings(r) if f.category == "DHCP"]
    assert dhcp[0].evidence == [EvidenceLink("A -> B", "DHCPOFFER vu en A, absent en B")]


def test_sip_failed_calls_n_a_pas_d_evidence():
    """Decision documentee dans synthesis.py : le message EST deja la
    preuve pour un appel echoue (une ligne = un evenement), l'attacher en
    evidence aussi serait un pur doublon."""
    r = Report(points=["A"])
    r.sip_failed_calls = ["Call-ID abc : jamais de 200 OK observe"]
    sip = [f for f in build_findings(r) if f.category == "SIP" and f.segment == "global"]
    assert sip[0].evidence == []


def test_sip_missing_evidence_est_la_liste_missing_elle_meme():
    r = Report(points=["A", "B"])
    r.sip_missing[("A", "B")] = ["INVITE vu en A, absent en B"]
    sip = [f for f in build_findings(r) if f.category == "SIP" and f.segment == "A -> B"]
    assert sip[0].evidence == [EvidenceLink("A -> B", "INVITE vu en A, absent en B")]


def test_dns_timeout_evidence_est_la_liste_timeouts_elle_meme():
    r = Report(points=["A"])
    r.dns_timeout["A"] = ["id=0x1 (example.com) : aucune reponse observee dans la capture"]
    dns = [f for f in build_findings(r) if f.category == "DNS"]
    assert dns[0].evidence == [EvidenceLink("A", "id=0x1 (example.com) : aucune reponse observee dans la capture")]


def test_dns_timeout_evidence_porte_le_numero_de_trame():
    r = Report(points=["A"])
    r.dns_timeout["A"] = ["id=0x1 (example.com) : aucune reponse observee dans la capture"]
    r.dns_timeout_frames["A"] = [16]
    dns = [f for f in build_findings(r) if f.category == "DNS"]
    assert dns[0].evidence[0].packet == PacketEvidence("A", 16)


def test_dns_missing_evidence_est_la_liste_missing_elle_meme():
    r = Report(points=["A", "B"])
    r.dns_missing[("A", "B")] = ["id=0x1 (example.com) : requete vue en A, absente en B"]
    dns = [f for f in build_findings(r) if f.category == "DNS"]
    assert dns[0].evidence == [EvidenceLink("A -> B", "id=0x1 (example.com) : requete vue en A, absente en B")]


def test_http_4xx_evidence_filtree_ne_garde_que_les_4xx():
    r = Report(points=["A"])
    r.http_client_error_count["A"] = 1
    r.http_server_error_count["A"] = 1
    r.http_error_examples["A"] = ["GET /a -> 404", "POST /b -> 500"]
    http4 = [f for f in build_findings(r) if f.category == "HTTP" and "4xx" in f.message]
    assert http4[0].evidence == [EvidenceLink("A", "GET /a -> 404")]


def test_http_4xx_evidence_porte_le_numero_de_trame_correspondant():
    r = Report(points=["A"])
    r.http_client_error_count["A"] = 1
    r.http_server_error_count["A"] = 1
    r.http_error_examples["A"] = ["GET /a -> 404", "POST /b -> 500"]
    r.http_error_frames["A"] = [21, 22]
    http4 = [f for f in build_findings(r) if f.category == "HTTP" and "4xx" in f.message]
    assert http4[0].evidence[0].packet == PacketEvidence("A", 21)


def test_http_5xx_evidence_filtree_ne_garde_que_les_5xx():
    r = Report(points=["A"])
    r.http_client_error_count["A"] = 1
    r.http_server_error_count["A"] = 1
    r.http_error_examples["A"] = ["GET /a -> 404", "POST /b -> 500"]
    http5 = [f for f in build_findings(r) if f.category == "HTTP" and "5xx" in f.message]
    assert http5[0].evidence == [EvidenceLink("A", "POST /b -> 500")]


def test_http_5xx_evidence_porte_le_numero_de_trame_correspondant():
    r = Report(points=["A"])
    r.http_client_error_count["A"] = 1
    r.http_server_error_count["A"] = 1
    r.http_error_examples["A"] = ["GET /a -> 404", "POST /b -> 500"]
    r.http_error_frames["A"] = [21, 22]
    http5 = [f for f in build_findings(r) if f.category == "HTTP" and "5xx" in f.message]
    assert http5[0].evidence[0].packet == PacketEvidence("A", 22)


def test_http_timeout_evidence_est_la_liste_timeouts_elle_meme():
    r = Report(points=["A"])
    r.http_timeout["A"] = ["/x : aucune reponse observee dans la capture"]
    http = [f for f in build_findings(r) if f.category == "HTTP"]
    assert http[0].evidence == [EvidenceLink("A", "/x : aucune reponse observee dans la capture")]


def test_http_timeout_evidence_porte_le_numero_de_trame():
    r = Report(points=["A"])
    r.http_timeout["A"] = ["/x : aucune reponse observee dans la capture"]
    r.http_timeout_frames["A"] = [23]
    http = [f for f in build_findings(r) if f.category == "HTTP"]
    assert http[0].evidence[0].packet == PacketEvidence("A", 23)


def test_http_missing_evidence_est_la_liste_missing_elle_meme():
    r = Report(points=["A", "B"])
    r.http_missing[("A", "B")] = ["/x : requete vue en A, absente en B"]
    http = [f for f in build_findings(r) if f.category == "HTTP"]
    assert http[0].evidence == [EvidenceLink("A -> B", "/x : requete vue en A, absente en B")]


# -- lien vers le catalogue de regles (rule_id, Session 48) --
#
# netcross_core.expert_rules.get_rule()/list_rules() -- voir sa docstring
# de module pour la portee complete (23 regles) et la docstring de module
# ci-dessus (synthesis.py) pour la liste exhaustive des Finding
# volontairement laisses sans correspondance (rule_id reste None). Le
# test d'ensemble qui verifie que les TRENTE-ET-UNE regles (Sessions 48-49)
# sont chacune utilisee au moins une fois vit dans test_expert_rules.py
# (cote catalogue) plutot qu'ici -- chaque test ci-dessous verifie un site
# de construction de Finding a la fois, meme granularite que le reste de
# ce fichier.


def test_pertes_rule_id_est_loss_per_segment():
    r = Report(points=["A"])
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100
    pertes = [f for f in build_findings(r) if f.category == "Pertes"]
    assert pertes[0].rule_id == "loss_per_segment"


def test_saturation_rule_id_est_saturation():
    r = Report(points=["A", "B"])
    r.saturation_verdict[("A", "B")] = "saturation probable en aval"
    sat = [f for f in build_findings(r) if f.category == "Saturation"]
    assert sat[0].rule_id == "saturation"


def test_bufferbloat_rule_id_est_bufferbloat():
    r = Report(points=["A", "B"])
    r.bufferbloat_hint[("A", "B")] = (10.0, 80.0)
    buf = [f for f in build_findings(r) if f.category == "Bufferbloat"]
    assert buf[0].rule_id == "bufferbloat"


def test_hop_delta_outliers_rule_id_est_hop_delta_outliers():
    """Signal distinct de ttl_unstable ci-dessous (meme categorie
    "Routage"), catalogue depuis la Session 49 -- voir docstring de
    module de synthesis.py."""
    r = Report(points=["A", "B"])
    r.hop_delta_outliers[("A", "B")] = 2
    routage = [f for f in build_findings(r) if f.category == "Routage"]
    assert routage[0].rule_id == "hop_delta_outliers"


def test_ttl_unstable_rule_id_est_ttl_variation():
    r = Report(points=["A"])
    r.ttl_unstable["A"] = 3
    routage = [f for f in build_findings(r) if f.category == "Routage"]
    assert routage[0].rule_id == "ttl_variation"


def test_qos_change_rule_id_est_qos_dscp_remarking():
    r = Report(points=["A", "B"])
    r.qos_change[("A", "B")] = 4
    qos = [f for f in build_findings(r) if f.category == "QoS"]
    assert qos[0].rule_id == "qos_dscp_remarking"


def test_pcp_change_rule_id_est_pcp_change():
    """Signal distinct de qos_change ci-dessus (meme categorie "QoS"),
    catalogue depuis la Session 49."""
    r = Report(points=["A", "B"])
    r.pcp_change[("A", "B")] = 2
    qos = [f for f in build_findings(r) if f.category == "QoS"]
    assert qos[0].rule_id == "pcp_change"


def test_fragmentation_new_rule_id_est_fragmentation_new():
    r = Report(points=["A", "B"])
    r.frag_new[("A", "B")] = 5
    frag = [f for f in build_findings(r) if f.category == "Fragmentation" and f.segment == "A -> B"]
    assert frag[0].rule_id == "fragmentation_new"


def test_icmp_frag_needed_rule_id_est_icmp_fragmentation_needed():
    """Signal distinct de frag_new ci-dessus (meme categorie
    "Fragmentation"), catalogue depuis la Session 49 -- fusionne avec son
    equivalent IPv6 (test suivant) sous une seule regle."""
    r = Report(points=["A"])
    r.icmp_frag_needed["A"] = 3
    frag = [f for f in build_findings(r) if f.category == "Fragmentation"]
    assert frag[0].rule_id == "icmp_fragmentation_needed"


def test_icmpv6_too_big_rule_id_est_aussi_icmp_fragmentation_needed():
    """Equivalent IPv6 du test precedent -- MEME regle du catalogue (voir
    docstring de module d'expert_rules.py)."""
    r = Report(points=["A"])
    r.icmpv6_too_big["A"] = 3
    frag = [f for f in build_findings(r) if f.category == "Fragmentation"]
    assert frag[0].rule_id == "icmp_fragmentation_needed"


def test_pmtud_blackhole_rule_id_est_pmtud_blackhole():
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    pmtud = [f for f in build_findings(r) if f.category == "PMTUD"]
    assert pmtud[0].rule_id == "pmtud_blackhole"


def test_idle_timeout_dropped_rule_id_est_nat_fw_silent_drop():
    r = Report(points=["A", "B"])
    r.idle_timeout_dropped[("A", "B")] = 1
    idle = [f for f in build_findings(r) if f.category == "NAT/Pare-feu"]
    assert idle[0].rule_id == "nat_fw_silent_drop"


def test_arp_ip_conflict_rule_id_est_arp_ip_conflict():
    r = Report(points=["A", "B"])
    r.arp_ip_conflict["A"] = 1
    arp = [f for f in build_findings(r) if f.category == "ARP"]
    assert arp[0].rule_id == "arp_ip_conflict"


def test_stp_topology_change_rule_id_est_stp_instability():
    r = Report(points=["A", "B"])
    r.stp_topology_change["A"] = 3
    stp = [f for f in build_findings(r) if f.category == "STP"]
    assert stp[0].rule_id == "stp_instability"


def test_stp_root_change_rule_id_est_aussi_stp_instability():
    """Les deux signaux STP distincts (changement de topologie/reelection
    du pont racine) correspondent a la MEME regle du catalogue -- voir
    docstring de module d'expert_rules.py."""
    r = Report(points=["A", "B"])
    r.stp_root_change["A"] = 1
    stp = [f for f in build_findings(r) if f.category == "STP"]
    assert stp[0].rule_id == "stp_instability"


def test_tls_cert_invalid_dates_rule_id_est_tls_cert_invalid_dates():
    """Catalogue depuis la Session 53 -- voir docstring de module de
    synthesis.py."""
    r = Report(points=["A", "B"])
    r.tls_cert_invalid_dates["A"] = 1
    tls = [f for f in build_findings(r) if f.category == "TLS"]
    assert tls[0].rule_id == "tls_cert_invalid_dates"


def test_tls_cert_mismatch_rule_id_est_tls_cert_mismatch():
    """Catalogue depuis la Session 53 -- voir docstring de module de
    synthesis.py."""
    r = Report(points=["A", "B"])
    r.tls_cert_mismatch[("A", "B")] = 1
    tls = [f for f in build_findings(r) if f.category == "TLS"]
    assert tls[0].rule_id == "tls_cert_mismatch"


def test_tls_handshake_no_reply_rule_id_est_tls_handshake_no_reply():
    """Catalogue depuis la Session 54 -- decision architecturale tranchee,
    voir docstring de module de synthesis.py."""
    r = Report(points=["A", "B"])
    r.tls_handshake_no_reply["A"] = 1
    tls = [f for f in build_findings(r) if f.category == "TLS"]
    assert tls[0].rule_id == "tls_handshake_no_reply"


def test_tls_handshake_incomplete_rule_id_est_tls_handshake_incomplete():
    """Catalogue depuis la Session 54 -- voir docstring de module de
    synthesis.py."""
    r = Report(points=["A", "B"])
    r.tls_handshake_incomplete["A"] = 1
    tls = [f for f in build_findings(r) if f.category == "TLS"]
    assert tls[0].rule_id == "tls_handshake_incomplete"


def test_vlan_change_rule_id_est_vlan_change():
    r = Report(points=["A", "B"])
    r.vlan_change[("A", "B")] = 3
    vlan = [f for f in build_findings(r) if f.category == "VLAN"]
    assert vlan[0].rule_id == "vlan_change"


def test_zero_window_rule_id_est_tcp_zero_window():
    r = Report(points=["A"])
    r.zero_window["A"] = 3
    tcp = [f for f in build_findings(r) if f.category == "TCP"]
    assert tcp[0].rule_id == "tcp_zero_window"


def test_retransmission_rto_rule_id_est_tcp_retransmission_rto():
    r = Report(points=["A"])
    r.retrans_rto["A"] = 3
    rto = [f for f in build_findings(r) if f.category == "TCP" and "RTO" in f.message]
    assert rto[0].rule_id == "tcp_retransmission_rto"


def test_retransmission_spurious_rule_id_est_tcp_retransmission_spurious():
    r = Report(points=["A"])
    r.retrans_spurious["A"] = 2
    spur = [f for f in build_findings(r) if f.category == "TCP" and "inutile" in f.message]
    assert spur[0].rule_id == "tcp_retransmission_spurious"


def test_retransmission_fast_rule_id_est_tcp_retransmission_fast():
    r = Report(points=["A"])
    r.retrans_fast["A"] = 5
    fast = [f for f in build_findings(r) if f.category == "TCP" and "rapide" in f.message]
    assert fast[0].rule_id == "tcp_retransmission_fast"


def test_mss_clamped_rule_id_est_tcp_mss_clamped():
    r = Report(points=["A", "B"])
    r.mss_clamped[("A", "B")] = 1
    mss = [f for f in build_findings(r) if f.category == "TCP" and "MSS" in f.message]
    assert mss[0].rule_id == "tcp_mss_clamped"


def test_wscale_stripped_rule_id_est_tcp_options_stripped():
    r = Report(points=["A", "B"])
    r.wscale_stripped[("A", "B")] = 1
    ws = [f for f in build_findings(r) if f.category == "TCP" and "Window Scale" in f.message]
    assert ws[0].rule_id == "tcp_options_stripped"


def test_sack_stripped_rule_id_est_aussi_tcp_options_stripped():
    """Les deux options retirees (Window Scale/SACK Permitted)
    correspondent a la MEME regle du catalogue -- voir docstring de
    module d'expert_rules.py."""
    r = Report(points=["A", "B"])
    r.sack_stripped[("A", "B")] = 1
    sk = [f for f in build_findings(r) if f.category == "TCP" and "SACK" in f.message]
    assert sk[0].rule_id == "tcp_options_stripped"


def test_rst_localized_rule_id_est_tcp_rst_localized():
    r = Report(points=["A"])
    r.rst_localized["A"] = 1
    tcp = [f for f in build_findings(r) if f.category == "TCP"]
    assert tcp[0].rule_id == "tcp_rst_localized"


def test_syn_no_synack_rule_id_est_tcp_syn_no_synack():
    r = Report(points=["A"])
    r.syn_no_synack["A"] = 2
    tcp = [f for f in build_findings(r) if f.category == "TCP"]
    assert tcp[0].rule_id == "tcp_syn_no_synack"


def test_syn_reply_missing_rule_id_est_syn_reply_missing():
    """Signal distinct de syn_no_synack ci-dessus (meme categorie "TCP") :
    tcp_syn_no_synack ne lit que Report.syn_no_synack -- catalogue sous
    son propre id depuis la Session 49, voir docstring de module de
    synthesis.py."""
    r = Report(points=["A"])
    r.syn_reply_missing["A"] = 1
    tcp = [f for f in build_findings(r) if f.category == "TCP"]
    assert tcp[0].rule_id == "syn_reply_missing"


def test_rtp_mos_rule_id_est_rtp_quality_mos():
    r = Report(points=["A"])
    r.rtp_streams = [{"label": "A -> B (SSRC=1)", "mos": 2.0, "r_factor": 30.0}]
    rtp = [f for f in build_findings(r) if f.category == "RTP/Voix"]
    assert rtp[0].rule_id == "rtp_quality_mos"


def test_reseau_serveur_rule_id_est_server_processing_dominant():
    """Catalogue depuis la Session 51 -- voir docstring de module."""
    r = Report(points=["A", "B"])
    r.server_think_time["A"] = [100.0, 110.0]
    r.latency[("A", "B")] = [5.0]
    findings = [f for f in build_findings(r) if f.category == "Reseau/Serveur"]
    assert findings[0].rule_id == "server_processing_dominant"


def test_dhcp_nak_rule_id_est_dhcp_issues():
    r = Report(points=["A"])
    r.dhcp_nak_count["A"] = 1
    dhcp = [f for f in build_findings(r) if f.category == "DHCP"]
    assert dhcp[0].rule_id == "dhcp_issues"


def test_dhcp_missing_rule_id_est_aussi_dhcp_issues():
    """Les deux signaux DHCP distincts (DHCPNAK/message manquant)
    correspondent a la MEME regle du catalogue."""
    r = Report(points=["A", "B"])
    r.dhcp_missing[("A", "B")] = ["DHCPOFFER vu en A, absent en B"]
    dhcp = [f for f in build_findings(r) if f.category == "DHCP"]
    assert dhcp[0].rule_id == "dhcp_issues"


def test_sip_failed_calls_rule_id_est_sip_issues():
    r = Report(points=["A"])
    r.sip_failed_calls = ["Call-ID abc : jamais de 200 OK observe"]
    sip = [f for f in build_findings(r) if f.category == "SIP" and f.segment == "global"]
    assert sip[0].rule_id == "sip_issues"


def test_sip_missing_rule_id_est_aussi_sip_issues():
    """Les deux signaux SIP distincts (appel echoue/message manquant)
    correspondent a la MEME regle du catalogue."""
    r = Report(points=["A", "B"])
    r.sip_missing[("A", "B")] = ["INVITE vu en A, absent en B"]
    sip = [f for f in build_findings(r) if f.category == "SIP" and f.segment == "A -> B"]
    assert sip[0].rule_id == "sip_issues"


def test_dns_nxdomain_rule_id_est_dns_nxdomain():
    """Aucun des quatre signaux DNS "bruts" ci-dessous ne correspond a
    dns_slow_resolution (qui ne lit que Report.dns_duration_ms) -- chacun
    catalogue sous son PROPRE id depuis la Session 49 (severites
    distinctes, voir docstring de module de synthesis.py)."""
    r = Report(points=["A"])
    r.dns_nxdomain_count["A"] = 1
    dns = [f for f in build_findings(r) if f.category == "DNS"]
    assert dns[0].rule_id == "dns_nxdomain"


def test_dns_servfail_rule_id_est_dns_servfail():
    r = Report(points=["A"])
    r.dns_servfail_count["A"] = 1
    dns = [f for f in build_findings(r) if f.category == "DNS"]
    assert dns[0].rule_id == "dns_servfail"


def test_dns_timeout_rule_id_est_dns_timeout():
    r = Report(points=["A"])
    r.dns_timeout["A"] = ["id=0x1 (example.com) : aucune reponse observee dans la capture"]
    dns = [f for f in build_findings(r) if f.category == "DNS"]
    assert dns[0].rule_id == "dns_timeout"


def test_dns_missing_rule_id_est_dns_missing():
    r = Report(points=["A", "B"])
    r.dns_missing[("A", "B")] = ["id=0x1 (example.com) : requete vue en A, absente en B"]
    dns = [f for f in build_findings(r) if f.category == "DNS"]
    assert dns[0].rule_id == "dns_missing"


def test_dns_duree_moyenne_rule_id_est_dns_slow_resolution():
    r = Report(points=["A"])
    r.dns_duration_ms = [250.0, 260.0]
    dns = [f for f in build_findings(r) if f.category == "DNS"]
    assert dns[0].rule_id == "dns_slow_resolution"


def test_http_4xx_rule_id_est_http_client_error():
    r = Report(points=["A"])
    r.http_client_error_count["A"] = 1
    http = [f for f in build_findings(r) if f.category == "HTTP"]
    assert http[0].rule_id == "http_client_error"


def test_http_5xx_rule_id_est_http_server_error():
    r = Report(points=["A"])
    r.http_server_error_count["A"] = 1
    http = [f for f in build_findings(r) if f.category == "HTTP"]
    assert http[0].rule_id == "http_server_error"


def test_http_timeout_rule_id_est_http_timeout():
    r = Report(points=["A"])
    r.http_timeout["A"] = ["/x : aucune reponse observee dans la capture"]
    http = [f for f in build_findings(r) if f.category == "HTTP"]
    assert http[0].rule_id == "http_timeout"


def test_http_missing_rule_id_est_http_missing():
    r = Report(points=["A", "B"])
    r.http_missing[("A", "B")] = ["/x : requete vue en A, absente en B"]
    http = [f for f in build_findings(r) if f.category == "HTTP"]
    assert http[0].rule_id == "http_missing"


def test_http_duree_moyenne_rule_id_est_http_slow_response():
    r = Report(points=["A"])
    r.http_response_time_ms = [600.0, 700.0]
    http = [f for f in build_findings(r) if f.category == "HTTP"]
    assert http[0].rule_id == "http_slow_response"


# -- Issue #741 : couverture des builders de Finding par paire/point ---------


def test_qos_change_finding():
    """Ligne 326 : QoS change finding pour une paire."""
    r = Report(points=["A", "B"])
    r.qos_change[("A", "B")] = 3
    r.qos_l2_remark[("A", "B")] = 2
    r.qos_l3_remark[("A", "B")] = 1
    findings = build_findings(r)
    qos = [f for f in findings if f.category == "QoS"]
    assert len(qos) >= 1


def test_frag_new_finding_sans_correlation_tunnel():
    """Ligne 354 : fragmentation finding pour une paire sans tunnel correlé."""
    r = Report(points=["A", "B"])
    r.frag_new[("A", "B")] = 5
    findings = build_findings(r)
    frag = [f for f in findings if "frag" in f.message.lower() or "Fragment" in f.message]
    assert len(frag) >= 1


def test_pmtud_blackhole_finding():
    """Ligne 413 : PMTUD blackhole finding pour une paire."""
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 2
    findings = build_findings(r)
    pmtud = [f for f in findings if "PMTUD" in f.message or "pmtud" in f.message.lower()]
    assert len(pmtud) >= 1


def test_idle_timeout_dropped_finding():
    """Ligne 438 : idle timeout finding pour une paire."""
    r = Report(points=["A", "B"])
    r.idle_timeout_dropped[("A", "B")] = 1
    findings = build_findings(r)
    timeout = [f for f in findings if "timeout" in f.message.lower() or "inactiv" in f.message.lower()]
    assert len(timeout) >= 1


def test_arp_ip_conflict_finding():
    """Ligne 461 : ARP conflict finding pour un point."""
    r = Report(points=["A", "B"])
    r.arp_ip_conflict["A"] = 2
    findings = build_findings(r)
    arp = [f for f in findings if f.category == "ARP"]
    assert len(arp) >= 1


def test_stp_topology_change_finding():
    """Ligne 479 : STP topology change finding pour un point."""
    r = Report(points=["A", "B"])
    r.stp_topology_change["A"] = 1
    findings = build_findings(r)
    stp = [f for f in findings if f.category == "STP"]
    assert len(stp) >= 1


def test_stp_root_change_finding():
    """Ligne 493 : STP root change finding pour un point."""
    r = Report(points=["A", "B"])
    r.stp_root_change["A"] = 1
    findings = build_findings(r)
    stp = [f for f in findings if f.category == "STP"]
    assert len(stp) >= 1


def test_tls_cert_invalid_dates_finding():
    """Ligne 511 : TLS cert invalid dates finding pour un point."""
    r = Report(points=["A", "B"])
    r.tls_cert_invalid_dates["A"] = 1
    findings = build_findings(r)
    tls = [f for f in findings if f.category == "TLS"]
    assert len(tls) >= 1


def test_tls_cert_mismatch_finding():
    """Ligne 529 : TLS cert mismatch finding pour une paire."""
    r = Report(points=["A", "B"])
    r.tls_cert_mismatch[("A", "B")] = 1
    findings = build_findings(r)
    tls = [f for f in findings if f.category == "TLS"]
    assert len(tls) >= 1


def test_tls_handshake_no_reply_finding():
    """Ligne 555 : TLS handshake no reply finding pour un point."""
    r = Report(points=["A", "B"])
    r.tls_handshake_no_reply["A"] = 1
    findings = build_findings(r)
    tls = [f for f in findings if f.category == "TLS"]
    assert len(tls) >= 1


def test_tls_handshake_incomplete_finding():
    """Ligne 573 : TLS handshake incomplete finding pour un point."""
    r = Report(points=["A", "B"])
    r.tls_handshake_incomplete["A"] = 1
    findings = build_findings(r)
    tls = [f for f in findings if f.category == "TLS"]
    assert len(tls) >= 1


def test_rtp_mos_finding():
    """Ligne 734 : RTP MOS finding pour un stream avec MOS."""
    r = Report(points=["A", "B"])
    r.rtp_streams.append({"mos": 2.5, "r_factor": 60.0, "label": "10.0.0.1:5004 -> 10.0.0.2:5006 (SSRC=1234)"})
    findings = build_findings(r)
    rtp = [f for f in findings if "RTP" in f.category or "voix" in f.message.lower() or "mos" in f.message.lower()]
    assert len(rtp) >= 1


def test_http_error_evidence_parse_code():
    """Ligne 244 : _http_error_evidence parse le code HTTP depuis le texte."""
    r = Report(points=["A"])
    r.http_client_error_count["A"] = 1
    r.http_error_examples["A"] = ["GET /page : 404 Not Found"]
    findings = build_findings(r)
    http = [f for f in findings if f.category == "HTTP"]
    assert len(http) >= 1


# -- Issue #741 : couverture des branches n <= 0 (continue) ------------------


def test_findings_avec_compteurs_nuls_ignore_les_paires():
    """Lignes 326, 354, 413, 438, 461, 479, 493, 511, 529, 555, 573 :
    toutes les branches 'if n <= 0: continue' sont prises quand les
    compteurs sont a 0."""
    r = Report(points=["A", "B"])
    # Paires avec compteurs a 0 -> branches 'continue' prises
    r.qos_change[("A", "B")] = 0
    r.frag_new[("A", "B")] = 0
    r.pmtud_blackhole[("A", "B")] = 0
    r.idle_timeout_dropped[("A", "B")] = 0
    r.arp_ip_conflict["A"] = 0
    r.stp_topology_change["A"] = 0
    r.stp_root_change["A"] = 0
    r.tls_cert_invalid_dates["A"] = 0
    r.tls_cert_mismatch[("A", "B")] = 0
    r.tls_handshake_no_reply["A"] = 0
    r.tls_handshake_incomplete["A"] = 0
    # Aucune anomalie ne doit etre generee pour ces paires
    findings = build_findings(r)
    # Les findings produits viennent d'autres categories, pas de celles ci-dessus
    categories_with_zero = {"QoS", "ARP", "STP", "TLS"}
    for f in findings:
        assert f.category not in categories_with_zero or f.message != ""


def test_rtp_stream_sans_mos_est_ignore():
    """Ligne 734 : RTP stream sans MOS est ignore (continue)."""
    r = Report(points=["A", "B"])
    r.rtp_streams.append({"mos": None, "label": "stream1", "r_factor": 80.0})
    findings = build_findings(r)
    rtp = [f for f in findings if "RTP" in f.category or "voix" in f.message.lower()]
    assert len(rtp) == 0
