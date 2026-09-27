"""#441, lot 8 : traces d'entrée des points d'analyse une fois par capture."""

from __future__ import annotations

import pytest
from loguru import logger

from netcross_core.compliance import evaluate_compliance
from netcross_core.models import Report
from netcross_core.redact import redact_packets


@pytest.fixture
def journal():
    logger.enable("netcross_core")
    lignes: list[tuple[str, str]] = []
    sink = logger.add(lambda m: lignes.append((m.record["level"].name, m.record["message"])), level="TRACE")
    yield lignes
    logger.remove(sink)


def test_traces_d_entree_resument_les_arguments(journal):
    redact_packets([])
    evaluate_compliance(Report(points=["A"]))
    messages = [m for n, m in journal if n == "DEBUG"]
    assert "redact_packets: packets=<list 0>" in messages
    assert any(m.startswith("evaluate_compliance: report=<Report> references=None") for m in messages)
