#!/usr/bin/env python3
"""Contrôle AST : une trace logger.debug() en entrée des fonctions éligibles.

Issue #954 : la consigne « debug() en entrée et à chaque sortie » doit aussi
être vérifiée sur l'entrée, pas seulement la sortie (audit_debug_sorties.py).
L'entrée est conforme si la première instruction du corps (après la
docstring) est un appel ``logger.debug(...)``.

Éligibilité : une fonction non triviale, qui n'est pas un bouchon
(``pass``/``...``), une méthode spéciale (hors ``__init__``), une propriété,
une fonction décorée (hors staticmethod/classmethod) ou un **chemin chaud** —
la classification des chemins chauds est celle de
``scripts/instrument_loguru.py`` (issue #441) : ces fonctions sont
volontairement non instrumentées, les compter serait un faux positif.

Usage : python3 scripts/audit_debug_entrees.py [--total] [--details]
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

import instrument_loguru
from audit_debug_sorties import _is_stub
from instrument_loguru import _is_excluded, hot_names
from loguru import logger  # noqa: E402

BASES = (
    Path(__file__).resolve().parent.parent / "src",
    Path(__file__).resolve().parent.parent / "scripts",
    Path(__file__).resolve().parent.parent / "tools",
)
TRIVIAL_LINES = instrument_loguru.TRIVIAL_LINES


def _body_start(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.stmt | None:
    """Première instruction du corps, après une éventuelle docstring."""
    body = fn.body
    first = body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        return body[1] if len(body) > 1 else None
    return first


def _is_debug_entry(stmt: ast.stmt | None) -> bool:
    """Vrai si l'instruction est un appel logger.debug(...) (ou logger.opt(...).debug(...))."""
    if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
        return False
    func = stmt.value.func
    if not isinstance(func, ast.Attribute) or func.attr != "debug":
        return False
    base = func.value
    while isinstance(base, ast.Call) and isinstance(base.func, ast.Attribute):
        base = base.func.value
    return isinstance(base, ast.Name) and base.id in instrument_loguru.LOGGER_NAMES


def audit_entrees() -> tuple[int, int]:
    """Renvoie (fonctions éligibles, fonctions sans trace d'entrée)."""
    hot = hot_names()
    logger.debug("audit_entrees() appelée | {} nom(s) de chemin chaud", len(hot))
    eligibles = manquantes = 0
    for base in BASES:
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts or "egg-info" in str(path):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError as exc:
                logger.debug("{} : syntaxe invalide, ignore : {}", path, exc)
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if _is_stub(node):
                    continue
                if (node.end_lineno or node.lineno) - node.lineno + 1 <= TRIVIAL_LINES:
                    continue
                if _is_excluded(node, hot) is not None:
                    continue
                eligibles += 1
                if not _is_debug_entry(_body_start(node)):
                    manquantes += 1
    logger.debug("audit_entrees() retourne | {}/{} conformes", eligibles - manquantes, eligibles)
    return eligibles, manquantes


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--total", action="store_true", help="affiche uniquement le total des entrées non conformes")
    args = ap.parse_args()
    eligibles, manquantes = audit_entrees()
    if args.total:
        print(manquantes)
        return
    print(f"entrées : {eligibles - manquantes}/{eligibles} conformes ({manquantes} sans logger.debug en entrée)")


if __name__ == "__main__":
    main()
