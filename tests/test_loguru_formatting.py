"""
Test de lint AST (issue #390) : interdit les appels logger.* dont le message
contient des accolades de format sans arguments correspondants, et les
logger.exception avec un message générique sans contexte opérationnel.

Suit la proposition de l'issue :
  1. Les traces d'entrée ne doivent pas écrire des accolades brutes.
  2. logger.exception doit décrire l'opération, pas juste « erreur: e ».
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"

# Dossiers/fichiers exclus du balayage (générés, egg-info, etc.)
_EXCLUDED_DIRS = {".eggs", "netcross.egg-info", "__pycache__", ".venv"}

# Regex pour détecter un message d'exception générique du type « erreur: e »
# ou « erreur: exc » ou « erreur inattendue » — sans contexte opérationnel.
_GENERIC_EXCEPTION_RE = re.compile(
    r"^(erreur\s*[:\s]*(e|exc|exception|valueerror|notifyerror|filenotfounderror)?\s*"
    r"|erreur inattendue\s*)$",
    re.IGNORECASE,
)


def _is_string_with_braces(node: ast.Constant | ast.JoinedStr) -> bool:
    """True si le littéral contient des accolades de format (mais n'est pas une f-string)."""
    if isinstance(node, ast.JoinedStr):
        # f-string : les accolades sont déjà interpolées → OK
        return False
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    return "{" in node.value


def _has_format_braces_without_args(call: ast.Call) -> bool:
    """
    True si l'appel logger.*(msg, ...) a un msg littéral avec accolades
    mais aucun argument positionnel supplémentaire pour les remplir.
    """
    args = call.args
    if not args:
        return False
    first = args[0]
    if not _is_string_with_braces(first):
        return False
    # Des arguments positionnels supplémentaires sont fournis → loguru les
    # substitue → OK. Les kwargs ne sont pas du formatage positionnel.
    return len(args) <= 1


def _is_generic_exception(call: ast.Call) -> bool:
    """True si logger.exception(msg) a un message générique sans contexte."""
    args = call.args
    if not args:
        return False
    first = args[0]
    if isinstance(first, ast.JoinedStr):
        return False  # f-string → contexte présent
    if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
        return False
    msg = first.value.strip()
    return bool(_GENERIC_EXCEPTION_RE.match(msg))


def _iter_logger_calls(tree: ast.AST):
    """Génère (node, method_name) pour chaque appel logger.<method>(...)."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # logger.debug(...), logger.info(...), etc.
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "logger":
            yield node, func.attr


def _collect_violations() -> list[tuple[str, int, str, str]]:
    """Parcourt src/ et collecte toutes les violations."""
    violations: list[tuple[str, int, str, str]] = []
    for py_file in sorted(SRC_DIR.rglob("*.py")):
        if any(part in _EXCLUDED_DIRS for part in py_file.parts):
            continue
        rel = py_file.relative_to(SRC_DIR)
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except SyntaxError:
            continue
        for call, method in _iter_logger_calls(tree):
            if method in ("debug", "info", "warning", "error", "exception") and _has_format_braces_without_args(call):
                msg = call.args[0].value if isinstance(call.args[0], ast.Constant) else "?"
                violations.append((str(rel), call.lineno, method, f"accolades sans args: {msg[:80]}"))
            if method == "exception" and _is_generic_exception(call):
                msg = call.args[0].value if isinstance(call.args[0], ast.Constant) else "?"
                violations.append((str(rel), call.lineno, method, f"exception générique: {msg[:80]}"))
    return violations


def test_no_logger_calls_with_raw_braces():
    """Aucun logger.* ne doit écrire des accolades brutes sans arguments."""
    violations = _collect_violations()
    if violations:
        lines = [f"  {f}:{line} [{method}] {desc}" for f, line, method, desc in violations]
        pytest.fail(
            f"{len(violations)} appel(s) logger.* avec accolades brutes ou exception générique :\n" + "\n".join(lines)
        )


_PERCENT_RE = re.compile(r"%(?:\([^)]*\))?[-+ #0]*\d*(?:\.\d+)?[sdifrx]")


def test_no_logger_calls_with_percent_format():
    """Loguru n'interprète pas ``%s``/``%d`` (format de ``logging``) : avec
    des arguments positionnels, le message s'afficherait sans leurs valeurs.
    Placeholders ``{}`` seulement (SOCLE §8, règle 5). Un message sans
    argument qui cite un format (``strftime('%Y')``) est affiché tel quel :
    il n'est pas visé."""
    violations = []
    for py_file in sorted(SRC_DIR.rglob("*.py")):
        if any(part in _EXCLUDED_DIRS for part in py_file.parts):
            continue
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for call, _method in _iter_logger_calls(tree):
            first = call.args[0] if call.args else None
            if (
                len(call.args) > 1
                and isinstance(first, ast.Constant)
                and isinstance(first.value, str)
                and _PERCENT_RE.search(first.value)
                and "{" not in first.value
            ):
                violations.append(f"  {py_file.relative_to(SRC_DIR)}:{call.lineno} {first.value[:80]}")
    assert violations == [], "messages loguru au format %s/%d :\n" + "\n".join(violations)
