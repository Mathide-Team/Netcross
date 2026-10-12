"""_opt_int / _opt_float : une valeur absente n'est pas une erreur (pas de
trace ERROR dans le journal à chaque rapport de sécurité)."""

from __future__ import annotations

import pytest
from loguru import logger

from netcross_report.security_report import _opt_float, _opt_int


@pytest.fixture
def niveaux():
    vus: list[str] = []
    ident = logger.add(lambda m: vus.append(m.record["level"].name), level="DEBUG")
    yield vus
    logger.remove(ident)


def test_none_sans_erreur(niveaux):
    assert _opt_int(None) is None
    assert _opt_float(None) is None
    assert "ERROR" not in niveaux
    assert "WARNING" not in niveaux


def test_conversion(niveaux):
    assert _opt_int("3") == 3
    assert _opt_float("2.5") == 2.5
    assert _opt_int("x") is None
    assert _opt_float([]) is None
    assert "ERROR" not in niveaux
    assert niveaux.count("WARNING") == 2
