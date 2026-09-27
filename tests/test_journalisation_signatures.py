"""#441, lot 6 : journalisation de exploit_signatures et application/banners."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from loguru import logger

from netcross_core.application.banners import build_service_fingerprints, extract_banners
from netcross_core.exploit_signatures import ExploitScanner, detections_to_dicts


@pytest.fixture
def journal():
    logger.enable("netcross_core")
    lignes: list[tuple[str, str]] = []
    sink = logger.add(lambda m: lignes.append((m.record["level"].name, m.record["message"])), level="TRACE")
    yield lignes
    logger.remove(sink)


def _vu(journal, niveau, fragment):
    return any(n == niveau and fragment in m for n, m in journal)


def test_scanner_resume_en_debug(journal):
    scanner = ExploitScanner()
    pkt = SimpleNamespace(
        payload=b"GET / HTTP/1.1\\r\\n\\r\\n", proto="TCP", src="10.0.0.1", sport=50000,
        dst="10.0.0.2", dport=80, ts=1.0, frame_number=1, payload_hash=None,
    )  # fmt: skip
    detections = scanner.scan_packets([pkt], point="A")
    detections_to_dicts(detections)
    assert _vu(journal, "DEBUG", "base par defaut")
    assert _vu(journal, "DEBUG", "scan_packets: point 'A', 1 paquet(s)")
    assert _vu(journal, "DEBUG", "detections_to_dicts:")


def test_bannieres_trace_et_resume(journal):
    banners = extract_banners("TCP", 22, 50000, b"SSH-2.0-OpenSSH_9.6\\r\\n")
    assert banners
    assert _vu(journal, "TRACE", "extract_banners: 1 banniere(s)")
    build_service_fingerprints([])
    assert _vu(journal, "DEBUG", "build_service_fingerprints: 0 logiciel(s)")


def test_charge_utile_malformee_sans_traceback(journal):
    # reponse DNS tronquee sur le port 53 : parsee puis rejetee
    assert extract_banners("UDP", 53, 40000, b"\\x00\\x01\\x85\\x00\\x00\\x01\\x00\\x01") == ()
    assert not any(n in ("ERROR", "CRITICAL") for n, _m in journal)
