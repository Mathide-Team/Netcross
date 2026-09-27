"""#441, lot 5 : journalisation de tls_diagnostics et quic_diagnostics."""

from __future__ import annotations

import pytest
from loguru import logger

from netcross_core import quic_diagnostics as quic
from netcross_core import tls_diagnostics as tls


@pytest.fixture
def journal():
    logger.enable("netcross_core")
    lignes: list[tuple[str, str]] = []
    sink = logger.add(lambda m: lignes.append((m.record["level"].name, m.record["message"])), level="TRACE")
    yield lignes
    logger.remove(sink)


def _vu(journal, niveau, fragment):
    return any(n == niveau and fragment in m for n, m in journal)


def test_cas_particuliers_tls_en_trace(journal):
    assert tls.parse_alert(b"\x02") == {}
    assert tls.parse_client_hello(b"\x03\x03") == {}
    assert tls.parse_server_hello(b"") == {}
    assert _vu(journal, "TRACE", "alerte tronquee")
    assert _vu(journal, "TRACE", "parse_client_hello: corps trop court")
    assert _vu(journal, "TRACE", "parse_server_hello: corps trop court")


def test_resumes_tls_en_debug(journal):
    status = tls.build_handshake_status([])
    tls.diagnose_tls(status)
    assert _vu(journal, "DEBUG", "build_handshake_status: 0 evenement(s)")
    assert _vu(journal, "DEBUG", "ordre alphabetique")
    assert _vu(journal, "DEBUG", "diagnose_tls: 0 constat(s)")


def test_quic_version_non_geree_et_resume(journal):
    paquet = bytes([0xC0]) + (2).to_bytes(4, "big") + b"\x00" * 10
    assert quic._parse_long_header(paquet) is None
    assert quic.diagnose_quic([]) == []
    assert _vu(journal, "TRACE", "version QUIC 0x00000002 non geree")
    assert _vu(journal, "DEBUG", "sans ordre des points")
