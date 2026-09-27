"""#441, lot 7 : journalisation de netcross_report (moteur de règles, rapport sécurité)."""

from __future__ import annotations

import pytest
from loguru import logger

from netcross_core.models import Report
from netcross_report.rule_engine import available_rule_ids, evaluate
from netcross_report.security_report import build_security_report


@pytest.fixture
def journal():
    logger.enable("netcross_report")
    lignes: list[tuple[str, str]] = []
    sink = logger.add(lambda m: lignes.append((m.record["level"].name, m.record["message"])), level="TRACE")
    yield lignes
    logger.remove(sink)


def _vu(journal, niveau, fragment):
    return any(n == niveau and fragment in m for n, m in journal)


def test_evaluate_trace_chaque_regle(journal):
    r = Report(points=["A"])
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100
    evaluate("loss_per_segment", r)
    available_rule_ids()
    assert _vu(journal, "DEBUG", "evaluate: regle 'loss_per_segment' -> 1 constat(s) (anomalie)")
    assert _vu(journal, "DEBUG", "available_rule_ids:")
    with pytest.raises(KeyError):
        evaluate("regle_inexistante", r)
    assert _vu(journal, "DEBUG", "inconnue du catalogue")


def test_rapport_securite_resume_et_entree_ignoree(journal):
    r = Report(points=["A"])
    r.security_findings = ["pas un dict"]
    build_security_report(r)
    assert _vu(journal, "TRACE", "_to_item: entree de type str ignoree")
    assert _vu(journal, "DEBUG", "build_security_report: 0/1 constat(s)")
