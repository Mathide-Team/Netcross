"""#441, lot 2 : la dissection par paquet ne trace que les cas particuliers,
au niveau TRACE, et les calculs par flux au niveau DEBUG."""

from __future__ import annotations

import pytest
from loguru import logger

from pcap_parser import protocols
from pcap_parser.ek_fields import as_bool, checksum_is_bad, expert_flag_names


@pytest.fixture
def journal():
    logger.enable("pcap_parser")
    lignes: list[tuple[str, str]] = []
    sink = logger.add(lambda m: lignes.append((m.record["level"].name, m.record["message"])), level="TRACE")
    yield lignes
    logger.remove(sink)
    logger.disable("pcap_parser")


def test_rtp_heuristique_csrc_trop_long(journal):
    # version 2, 15 CSRC annonces : en-tete de 72 octets pour 12 disponibles
    payload = bytes([0x8F]) + bytes(11)
    assert protocols._parse_rtp_heuristic(payload) is None
    assert any(n == "TRACE" and "CSRC" in m for n, m in journal)


def test_sip_couche_sans_methode_repli_heuristique(journal):
    layers = {"sip": {"sip_sip_Call-ID": "abc"}}
    res = protocols.extract_sip(layers, b"INVITE sip:bob@example.org SIP/2.0\r\nCall-ID: x\r\n\r\n")
    assert res is not None and res["msg_type"] == "INVITE"
    assert any(n == "TRACE" and "repli heuristique" in m for n, m in journal)


def test_compute_mos_trace_en_debug(journal):
    _r, mos = protocols.compute_mos(20.0, 0.0)
    assert 4.0 < mos <= 4.5
    assert any(n == "DEBUG" and "compute_mos" in m for n, m in journal)


def test_chemin_commun_sans_trace(journal):
    assert expert_flag_names({}) == ()
    assert as_bool(True) is True
    assert checksum_is_bad("1") is False
    assert journal == []


def test_tls_handshake_en_clair_trace(journal):
    res = protocols.extract_tls_handshake({"tls": {"tls_tls_record_content_type": "22", "tls_tls_handshake_type": "1"}})
    assert res == {"client_hello": True, "server_hello": False, "application_data": False}
    assert any(n == "TRACE" and "handshake" in m for n, m in journal)
