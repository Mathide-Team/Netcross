"""
tests/test_forensic_search.py -- tests du moteur de recherche analytique
post-capture transversal (netcross_core.forensic_search, Job 17 / issue #16,
section 6.13 de FEATURES.md).

Couvre les criteres d'acceptation de l'issue : recherche par SNI, URI, code
HTTP, adresse, Call-ID, DNS name, plus les filtres (point, protocole, plage
temporelle) et la recherche en texte libre.
"""

from conftest import make_pkt

from netcross_core.content import HttpObject
from netcross_core.expert_model import ExpertEvent
from netcross_core.forensic_search import (
    ForensicSearchIndex,
    ForensicSearchQuery,
)
from netcross_core.models import Pkt
from netcross_core.quic_diagnostics import QuicEvent
from netcross_core.tls_diagnostics import TlsEvent

# -- Fabriques --------------------------------------------------------------


def _pkt(**overrides) -> Pkt:
    return make_pkt(**overrides)


def _http(
    *,
    point: str = "A",
    uri: str | None = None,
    status: int | None = None,
    method: str | None = None,
    content_type: str | None = None,
    request_frame: int | None = None,
    response_frame: int | None = None,
) -> HttpObject:
    return HttpObject(
        point=point,
        src="10.0.0.1",
        sport=50000,
        dst="10.0.0.2",
        dport=80,
        method=method,
        uri=uri,
        status_code=status,
        content_type=content_type,
        content_length=0,
        response_time_ms=None,
        request_frame=request_frame,
        response_frame=response_frame,
    )


def _tls(*, point: str = "A", sni: str | None = None, ts: float = 1.0) -> TlsEvent:
    return TlsEvent(
        point=point,
        ts=ts,
        src="10.0.0.1",
        sport=50000,
        dst="10.0.0.2",
        dport=443,
        record_type="handshake",
        handshake_type="ClientHello",
        sni=sni,
        tls_version="TLS 1.3",
    )


def _quic(*, point: str = "B", sni: str | None = None, ts: float = 2.0) -> QuicEvent:
    return QuicEvent(
        point=point,
        ts=ts,
        src="10.0.0.3",
        dst="10.0.0.4",
        sport=50000,
        dport=443,
        dcid=b"\x00\x01\x02\x03\x04\x05\x06\x07",
        decryptable=True,
        sni=sni,
        tls_version="TLS 1.3",
    )


def _event(
    *,
    message: str = "Retransmission TCP",
    protocol: str = "TCP",
    segment: str = "A",
    first_seen: float = 1.5,
) -> ExpertEvent:
    return ExpertEvent(
        category="retransmission",
        severity="a_surveiller",
        segment=segment,
        message=message,
        protocol=protocol,
        first_seen=first_seen,
    )


def _index(
    packets=None,
    http_objects=None,
    tls_events=None,
    quic_events=None,
    events=None,
) -> ForensicSearchIndex:
    return ForensicSearchIndex(
        all_packets=packets or [],
        http_objects=http_objects,
        tls_events=tls_events,
        quic_events=quic_events,
        events=events,
    )


# -- SNI --------------------------------------------------------------------


def test_recherche_sni_via_tls_event():
    idx = _index(tls_events=[_tls(sni="api.example.com")])
    res = idx.search(ForensicSearchQuery(field="sni", field_value="example.com"))
    assert len(res) == 1
    assert res[0].kind == "tls"
    assert "sni" in res[0].matched_fields


def test_recherche_sni_via_quic_event():
    idx = _index(quic_events=[_quic(sni="cdn.example.org")])
    res = idx.search(ForensicSearchQuery(field="sni", field_value="cdn.example"))
    assert len(res) == 1
    assert res[0].kind == "quic"


def test_recherche_sni_absent_ne_renvoie_rien():
    idx = _index(tls_events=[_tls(sni=None)])
    res = idx.search(ForensicSearchQuery(field="sni", field_value="example"))
    assert res == []


def test_recherche_sni_texte_libre():
    idx = _index(
        tls_events=[_tls(sni="mail.example.com")],
        quic_events=[_quic(sni="video.example.com")],
    )
    res = idx.search(ForensicSearchQuery(text="example.com"))
    kinds = {r.kind for r in res}
    assert kinds == {"tls", "quic"}


# -- URI --------------------------------------------------------------------


def test_recherche_uri_via_paquet():
    pk = _pkt(http_uri="/api/v1/users")
    idx = _index(packets=[pk])
    res = idx.search(ForensicSearchQuery(field="uri", field_value="/api/v1"))
    assert len(res) == 1
    assert res[0].kind == "packet"
    assert res[0].frame_number == pk.frame_number


def test_recherche_uri_via_http_object():
    idx = _index(http_objects=[_http(uri="/login", response_frame=42)])
    res = idx.search(ForensicSearchQuery(field="uri", field_value="login"))
    assert len(res) == 1
    assert res[0].kind == "http_object"
    assert res[0].frame_number == 42


# -- Code HTTP --------------------------------------------------------------


def test_recherche_code_http_via_paquet():
    pk = _pkt(http_status_code=503)
    idx = _index(packets=[pk])
    res = idx.search(ForensicSearchQuery(field="http_status", field_value="503"))
    assert len(res) == 1
    assert res[0].kind == "packet"


def test_recherche_code_http_via_http_object():
    idx = _index(http_objects=[_http(status=404)])
    res = idx.search(ForensicSearchQuery(field="http_status", field_value="404"))
    assert len(res) == 1
    assert res[0].kind == "http_object"


def test_recherche_code_http_distinct_des_champs_textuels():
    """Un code 200 ne doit pas matcher une recherche sur l'URI."""
    pk = _pkt(http_uri="/api/users", http_status_code=200)
    idx = _index(packets=[pk])
    res = idx.search(ForensicSearchQuery(field="uri", field_value="200"))
    assert res == []


# -- Adresse / endpoint -----------------------------------------------------


def test_recherche_par_adresse_src_ou_dst():
    pks = [
        _pkt(src="10.0.0.1", dst="10.0.0.2"),
        _pkt(src="10.0.0.3", dst="10.0.0.4"),
    ]
    idx = _index(packets=pks)
    res = idx.search(ForensicSearchQuery(address="10.0.0.1"))
    assert len(res) == 1
    assert res[0].frame_number == pks[0].frame_number


def test_recherche_par_adresse_aucune_correspondance():
    idx = _index(packets=[_pkt(src="10.0.0.1", dst="10.0.0.2")])
    assert idx.search(ForensicSearchQuery(address="10.0.0.99")) == []


# -- Call-ID ----------------------------------------------------------------


def test_recherche_call_id_sip():
    pk = _pkt(sip_call_id="abc123@10.0.0.1")
    idx = _index(packets=[pk])
    res = idx.search(ForensicSearchQuery(field="call_id", field_value="abc123"))
    assert len(res) == 1
    assert "call_id" in res[0].matched_fields


# -- DNS name ---------------------------------------------------------------


def test_recherche_dns_name():
    pk = _pkt(dns_qry_name="www.example.com")
    idx = _index(packets=[pk])
    res = idx.search(ForensicSearchQuery(field="dns_name", field_value="example"))
    assert len(res) == 1
    assert res[0].kind == "packet"


# -- Filtres ----------------------------------------------------------------


def test_filtre_point_limite_les_resultats():
    pks = [
        _pkt(point="A", dns_qry_name="a.example.com"),
        _pkt(point="B", dns_qry_name="b.example.com"),
    ]
    idx = _index(packets=pks)
    res = idx.search(ForensicSearchQuery(text="example.com", point="B"))
    assert len(res) == 1
    assert res[0].point == "B"


def test_filtre_protocole():
    pks = [
        _pkt(proto="TCP", http_uri="/api"),
        _pkt(proto="UDP", dns_qry_name="x.example"),
    ]
    idx = _index(packets=pks)
    res = idx.search(ForensicSearchQuery(text="example", protocol="UDP"))
    assert len(res) == 1


def test_filtre_plage_temporelle():
    tls = [_tls(ts=1.0, sni="a.example"), _tls(ts=5.0, sni="b.example")]
    idx = _index(tls_events=tls)
    res = idx.search(ForensicSearchQuery(text="example", time_start=3.0, time_end=6.0))
    assert len(res) == 1
    assert "b.example" in res[0].snippet


def test_filtre_combine_point_et_protocole():
    idx = _index(
        tls_events=[_tls(point="A", sni="api.example")],
        quic_events=[_quic(point="B", sni="api.example")],
    )
    res = idx.search(ForensicSearchQuery(text="api.example", protocol="QUIC"))
    assert len(res) == 1
    assert res[0].kind == "quic"


# -- Texte libre et tri -----------------------------------------------------


def test_recherche_texte_libre_tous_champs():
    pks = [
        _pkt(http_uri="/admin"),
        _pkt(dns_qry_name="admin.example"),
        _pkt(sip_call_id="admin-call"),
    ]
    idx = _index(packets=pks)
    res = idx.search(ForensicSearchQuery(text="admin"))
    assert len(res) == 3


def test_resultats_tries_par_ts_croissant():
    tls = [
        _tls(ts=5.0, sni="late.example"),
        _tls(ts=1.0, sni="early.example"),
    ]
    idx = _index(tls_events=tls)
    res = idx.search(ForensicSearchQuery(text="example"))
    assert res[0].ts == 1.0
    assert res[1].ts == 5.0


def test_requete_vide_avec_filtre_seul():
    """Sans critere textuel, un filtre seul renvoie les docs correspondants."""
    pks = [_pkt(point="A"), _pkt(point="B")]
    idx = _index(packets=pks)
    res = idx.search(ForensicSearchQuery(point="A"))
    assert len(res) == 1


def test_aucun_resultat_renvoie_liste_vide():
    idx = _index(packets=[_pkt(http_uri="/api")])
    assert idx.search(ForensicSearchQuery(text="inexistant")) == []


def test_champ_present_sans_valeur():
    pk = _pkt(http_uri="/api")
    idx = _index(packets=[pk])
    res = idx.search(ForensicSearchQuery(field="uri"))
    assert len(res) == 1


def test_index_vide_supporte_recherche():
    idx = _index()
    assert len(idx) == 0
    assert idx.search(ForensicSearchQuery(text="anything")) == []


def test_evenement_indexe_par_message():
    idx = _index(events=[_event(message="TCP out-of-order")])
    res = idx.search(ForensicSearchQuery(text="out-of-order"))
    assert len(res) == 1
    assert res[0].kind == "event"


# -- Issue #723 : champs optionnels indexes et branches de recherche ----------


def test_documents_indexent_les_champs_optionnels():
    """Lignes 142, 144, 201, 228, 257 : user-agent SIP, type DHCP, cause
    d'evenement, methode HTTP et suite TLS sont indexes."""
    from netcross_core.forensic_search import (
        _doc_from_event,
        _doc_from_http_object,
        _doc_from_packet,
        _doc_from_tls_event,
    )

    doc = _doc_from_packet(make_pkt(sip_user_agent="Yealink", dhcp_msg_type="1"))
    assert doc.fields["sip_user_agent"] == "Yealink"
    assert doc.fields["dhcp_msg_type"] == "1"

    ev = _event()
    ev.cause = "congestion"
    assert _doc_from_event(ev).fields["cause"] == "congestion"

    assert _doc_from_http_object(_http(method="POST")).fields["method"] == "POST"

    tls = _tls(sni="example.com")
    tls.cipher = "TLS_AES_128_GCM_SHA256"
    assert _doc_from_tls_event(tls).fields["cipher"] == "TLS_AES_128_GCM_SHA256"


def test_index_ignore_flux_sans_paquet_et_valeur_de_champ_diffuse():
    """Lignes 333 et 450 : un flux sans paquet n'est pas indexe ; une
    field_value sans field est cherchee en texte libre."""
    pk = make_pkt(dns_qry_name="intranet.example")
    idx = ForensicSearchIndex([pk], flows={("k",): {"A": []}})
    res = idx.search(ForensicSearchQuery(field_value="intranet"))
    assert len(res) >= 1
