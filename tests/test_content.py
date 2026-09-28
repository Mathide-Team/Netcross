from netcross_core.content import extract_http_objects
from netcross_core.models import Pkt


def _pkt(**kw):
    base = dict(  # noqa: C408
        point="LAN",
        ts=1.0,
        frame_number=None,
        proto="TCP",
        src="10.0.0.1",
        dst="10.0.0.2",
        sport=50000,
        dport=80,
        length=100,
        ttl=64,
        dscp=0,
        ecn=0,
        seq=1,
        ack=0,
        window=1000,
        flags=None,
        key_id=1,
        payload_hash=None,
        ip_id=1,
        is_fragment=False,
        df=False,
        is_retransmission=False,
        is_fast_retransmission=False,
        is_spurious_retransmission=False,
        mss_val=None,
        wscale_shift=None,
        sack_permitted=False,
        icmp_type=None,
        icmp_code=None,
        icmpv6_type=None,
        icmpv6_code=None,
        arp_opcode=None,
        arp_sender_mac=None,
        arp_is_gratuitous=False,
        stp_bpdu_type=None,
        stp_flags_tc=False,
        stp_root_id=None,
        tls_cert_not_before=None,
        tls_cert_not_after=None,
        tls_cert_san=None,
        tls_cert_serial=None,
        tls_cert_issuer=None,
        tls_cert_subject=None,
        tls_cert_sig_hash=None,
        tls_cert_key_type=None,
        tls_cert_key_bits=None,
        tls_cert_san_ip=None,
        tls_cert_chain_len=None,
        tls_client_hello=False,
        tls_server_hello=False,
        tls_application_data=False,
        vlan_id=None,
        vlan_prio=None,
        is_rtp=False,
        rtp_seq=None,
        rtp_ts=None,
        rtp_ssrc=None,
        encap_tags=(),
        dhcp_xid=None,
        dhcp_msg_type=None,
        dhcp_server_id=None,
        dhcp_vendor_class=None,
        sip_call_id=None,
        sip_msg_type=None,
        sip_cseq=None,
        sip_user_agent=None,
        sip_server=None,
        dns_txn_id=None,
        dns_is_response=False,
        dns_qry_name=None,
        dns_rcode=None,
        http_is_request=False,
        http_is_response=False,
        http_method=None,
        http_uri=None,
        http_status_code=None,
        http_response_time_ms=None,
        expert_flags=(),
        expert_details=(),
    )
    base.update(kw)
    return Pkt(**base)


def test_http_object_links_request_response_and_metadata():
    req = _pkt(
        ts=1.0,
        frame_number=10,
        http_is_request=True,
        http_method="GET",
        http_uri="http://example.test/file.pdf",
    )
    resp = _pkt(
        ts=1.1,
        frame_number=11,
        src="10.0.0.2",
        dst="10.0.0.1",
        sport=80,
        dport=50000,
        seq=2,
        http_is_response=True,
        http_uri="http://example.test/file.pdf",
        http_status_code=200,
        http_content_type="application/pdf",
        http_content_length=12345,
        http_response_time_ms=100.0,
        payload_hash="abc",
    )

    obj = extract_http_objects([resp, req])[0]
    assert obj.method == "GET"
    assert obj.uri == "http://example.test/file.pdf"
    assert obj.status_code == 200
    assert obj.content_type == "application/pdf"
    assert obj.content_length == 12345
    assert obj.volume_bytes == 12345
    assert obj.request_frame == 10
    assert obj.response_frame == 11
    assert obj.response_payload_hash is None


def test_http_object_forensic_keeps_hash_but_never_body():
    req = _pkt(ts=1.0, frame_number=1, http_is_request=True, http_method="GET", http_uri="/x")
    resp = _pkt(
        ts=1.2,
        frame_number=2,
        src="10.0.0.2",
        dst="10.0.0.1",
        sport=80,
        dport=50000,
        http_is_response=True,
        http_uri="/x",
        http_status_code=200,
        http_content_length=42,
        payload_hash="deadbeef",
    )
    obj = extract_http_objects([req, resp], privacy_mode="forensic")[0]
    assert obj.response_payload_hash == "deadbeef"
    assert not hasattr(obj, "payload")


def test_http_object_invalid_privacy_mode():
    assert _pkt(http_is_response=True)
    try:
        extract_http_objects([], privacy_mode="body")
    except ValueError as exc:
        assert "privacy_mode" in str(exc)
    else:
        raise AssertionError("ValueError attendu")


# -- Issue #692 : repli d'association, plafond et serialisation --------------


def _req(uri, seq, ts):
    return _pkt(ts=ts, seq=seq, http_is_request=True, http_method="GET", http_uri=uri)


def _resp(uri, seq, ts):
    return _pkt(
        ts=ts,
        src="10.0.0.2",
        dst="10.0.0.1",
        sport=80,
        dport=50000,
        seq=seq,
        http_is_response=True,
        http_uri=uri,
        http_status_code=200,
    )


def test_reponse_sans_requete_homonyme_prend_la_plus_ancienne():
    """Ligne 108 : aucune requete en attente n'a le meme URI -> la plus
    ancienne est associee."""
    objs = extract_http_objects([_req("/a", 1, 1.0), _resp("/autre", 2, 1.1)])
    assert len(objs) == 1
    assert objs[0].method == "GET"


def test_plafond_max_objects_et_serialisation():
    """Lignes 129-130 : max_objects arrete l'inventaire ; lignes 48-49 :
    identifiant de connexion ; lignes 143-144 : serialisation en dicts."""
    from netcross_core.content import objects_to_dicts

    pkts = [_req("/a", 1, 1.0), _resp("/a", 2, 1.1), _req("/b", 3, 2.0), _resp("/b", 4, 2.1)]
    objs = extract_http_objects(pkts, max_objects=1)
    assert len(objs) == 1
    assert objs[0].flow == (objs[0].src, objs[0].sport, objs[0].dst, objs[0].dport)
    dicts = objects_to_dicts(objs)
    assert dicts[0]["uri"] == objs[0].uri
