"""Outil d'instrumentation « un logger.debug() à chaque sortie » (suite #441)."""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _load(name: str):
    sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SOURCE = """
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


def f(x, items):
    if x is None:
        raise ValueError("x manquant")
    if not items:
        return []
    for it in items:
        if it == x: return it
    total = len(items)
    return total


def g(path):
    try:
        open(path).close()
    except OSError:
        raise
    print(path)
"""


def test_toutes_les_sorties_sont_instrumentees():
    instr = _load("instrument_sorties")
    audit = _load("audit_debug_sorties")
    out, n, _notes = instr.instrument_text(SOURCE, set())
    assert n == 6
    tree = ast.parse(out)
    for fn in [node for node in tree.body if isinstance(node, ast.FunctionDef)]:
        _exits, bad = audit.audit_function(fn)
        assert bad == [], (fn.name, bad)
    assert "from netcross_core.logging_config import get_logger, summarize" in out
    assert "f: si not items -> retour liste vide" in out
    assert "f: si it == x -> retour it={}" in out
    assert "f: retour total={}" in out
    assert "f: si x is None -> levée ValueError" in out
    assert "g: except OSError -> relance de l'exception en cours" in out
    assert "g: fin" in out


def test_idempotent():
    instr = _load("instrument_sorties")
    once, _n, _ = instr.instrument_text(SOURCE, set())
    twice, n2, _ = instr.instrument_text(once, set())
    assert n2 == 0
    assert twice == once


def test_module_sans_logger_inchange():
    instr = _load("instrument_sorties")
    src = "def f():\n    return 1\n"
    out, n, notes = instr.instrument_text(src, set())
    assert (out, n) == (src, 0)
    assert notes
