"""
Regles loguru de l'issue #245, verifiees sur tout ``src/`` :

- chaque ``except`` contient un appel loguru (logger.debug/warning/error/
  exception/...) -- « Nouvelle regle : chaque except doit contenir un appel
  loguru » ;
- plus aucun ``import logging`` : « les logger de loguru remplacent les
  anciens logger (logging) » ;
- tout module qui definit des fonctions dispose d'un logger loguru.

Analyse AST uniquement (aucun import des modules : GTK n'est pas requis).
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
LOG_METHODS = {"trace", "debug", "info", "success", "warning", "error", "exception", "critical", "log"}


def _modules():
    return sorted(SRC.rglob("*.py"))


def _is_loguru_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in LOG_METHODS
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"logger", "_logger"}
    )


def test_chaque_except_contient_un_appel_loguru():
    fautifs = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        fautifs.extend(
            f"{path.relative_to(ROOT)}:{node.lineno}"
            for node in ast.walk(tree)
            if isinstance(node, ast.ExceptHandler) and not any(_is_loguru_call(n) for n in ast.walk(node))
        )
    assert fautifs == [], "except sans appel loguru :\n" + "\n".join(fautifs)


def test_aucun_import_logging():
    fautifs = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name.split(".")[0] == "logging" for a in node.names):
                fautifs.append(f"{path.relative_to(ROOT)}:{node.lineno}")
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "logging":
                fautifs.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert fautifs == [], "import logging (remplace par loguru) :\n" + "\n".join(fautifs)


def test_chaque_module_avec_fonctions_a_un_logger():
    """Le logger doit etre defini au niveau module (pas dans un docstring :
    cas reel corrige dans duplicate_view.py, PR #439)."""
    fautifs = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(tree)):
            continue
        defini = False
        for node in tree.body:
            noms = {"logger", "_logger"}
            if isinstance(node, ast.Assign) and any(getattr(t, "id", None) in noms for t in node.targets):
                defini = True
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == "loguru"
                and any((a.asname or a.name) in {"logger", "_logger"} for a in node.names)
            ):
                defini = True
        if not defini:
            fautifs.append(str(path.relative_to(ROOT)))
    assert fautifs == [], "modules sans logger loguru :\n" + "\n".join(fautifs)
