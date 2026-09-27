"""#441, lot 3 : journalisation de netcross_core.forensic et forensic_search."""

from __future__ import annotations

import dataclasses

import pytest
from conftest import make_pkt
from loguru import logger

from netcross_core.expert_model import ExpertEvent, Flow
from netcross_core.forensic import validate_checksums
from netcross_core.forensic_search import (
    ForensicSearchIndex,
    ForensicSearchQuery,
    _doc_from_event,
    _doc_from_flow,
    _doc_from_quic_event,
    _doc_from_tls_event,
)
from netcross_core.quic_diagnostics import QuicEvent
from netcross_core.tls_diagnostics import TlsEvent


@pytest.fixture
def journal():
    logger.enable("netcross_core")
    lignes: list[tuple[str, str]] = []
    sink = logger.add(lambda m: lignes.append((m.record["level"].name, m.record["message"])), level="TRACE")
    yield lignes
    logger.remove(sink)


def _vu(journal, niveau, fragment):
    return any(n == niveau and fragment in m for n, m in journal)


def test_validate_checksums_resume(journal):
    pk = dataclasses.replace(make_pkt(), ip_checksum="0x1234", ip_checksum_bad=True)
    assert len(validate_checksums([pk])) == 1
    assert _vu(journal, "DEBUG", "1 checksum(s) invalide(s)")


def test_flux_sans_extremites(journal):
    _doc_from_flow(Flow(key=(), points=["A"], endpoints=None))
    assert _vu(journal, "TRACE", "sans extremites")


def test_evenement_sans_message(journal):
    ev = ExpertEvent(category="retransmission", severity="info", segment="A", message="", protocol="TCP")
    _doc_from_event(ev)
    assert _vu(journal, "TRACE", "sans message")


def test_alerte_tls_et_quic_sans_sni(journal):
    tls = TlsEvent(
        point="A", ts=1.0, src="10.0.0.1", sport=1, dst="10.0.0.2", dport=443,
        record_type="alert", handshake_type=None, sni=None, tls_version="TLS 1.2",
        alert_description="handshake_failure",
    )  # fmt: skip
    assert _doc_from_tls_event(tls).fields["alert"] == "handshake_failure"
    quic = QuicEvent(
        point="B", ts=2.0, src="10.0.0.3", dst="10.0.0.4", sport=1, dport=443,
        dcid=b"\\x00", decryptable=False, sni=None, tls_version=None,
    )  # fmt: skip
    _doc_from_quic_event(quic)
    assert _vu(journal, "TRACE", "alerte TLS")
    assert _vu(journal, "TRACE", "QUIC sans SNI")


def test_recherche_resume_en_debug(journal):
    idx = ForensicSearchIndex([make_pkt()])
    idx.search(ForensicSearchQuery(text="introuvable"))
    assert _vu(journal, "DEBUG", "1 document(s) indexe(s)")
    assert _vu(journal, "DEBUG", "0 resultat(s) sur 1 document(s)")
