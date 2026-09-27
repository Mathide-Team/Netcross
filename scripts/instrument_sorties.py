#!/usr/bin/env python3
"""Instrumentation « un logger.debug() à chaque sortie » (issues de suite #441).

Pour chaque fonction d'un module, ajoute un ``logger.debug(...)`` juste
avant chaque sortie qui n'en a pas encore :

- ``return`` : message ``"<fonction>: <branche> -> retour <valeur>"`` ;
- ``raise`` : message ``"<fonction>: <branche> -> levée <Exception>"`` ;
- fin implicite (fonction qui peut se terminer sans return) : ``"<fonction>: fin"``.

La branche décrit la condition qui mène à la sortie (``si <test>``,
``sinon (<test>)``, ``except <Type>``, ``dans la boucle``...), pour qu'un
lecteur des traces sache quelle sortie a été prise.

La valeur n'est résumée que si l'expression renvoyée est un nom, un
attribut simple ou une constante, et seulement hors chemin chaud :
``summarize()`` (tailles et types, jamais d'objet entier, secrets
masqués) quand le module importe déjà ``netcross_core.logging_config``.
Sur un chemin chaud (fonction appelée par paquet / par élément, voir
``instrument_loguru.hot_names``), méthode spéciale ou fonction imbriquée,
le message ne porte aucun argument : un appel loguru sous le niveau
actif est quasi gratuit, et aucun calcul n'est fait pour le préparer.

Usage : ``python3 scripts/instrument_sorties.py [--dry-run] FICHIER...``
puis ``ruff format`` / ``ruff check --fix`` sur les fichiers modifiés.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_debug_sorties import LOGGER_NAMES, RAISE_OK, _can_fall_through, _is_stub, _log_level  # noqa: E402
from instrument_loguru import hot_names  # noqa: E402

MAX_DESC = 60
_SKIP = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _short(node: ast.AST, limit: int = MAX_DESC) -> str:
    text = " ".join(ast.unparse(node).split())
    text = text.replace("{", "(").replace("}", ")")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _exc_name(node: ast.Raise) -> str:
    exc = node.exc
    if exc is None:
        return "relance de l'exception en cours"
    if isinstance(exc, ast.Call):
        exc = exc.func
    if isinstance(exc, ast.Name):
        return f"levée {exc.id}"
    if isinstance(exc, ast.Attribute):
        return f"levée {exc.attr}"
    return "levée d'exception"


def _handler_desc(h: ast.ExceptHandler) -> str:
    return f"except {_short(h.type, 40)}" if h.type is not None else "except"


class _Exit:
    __slots__ = ("block", "context", "index", "stmt")

    def __init__(self, stmt, block, index, context):
        self.stmt = stmt
        self.block = block
        self.index = index
        self.context = context


def _walk_blocks(node: ast.AST, context: list[str]):
    """(bloc, contexte) pour chaque bloc d'instructions de la fonction,
    sans descendre dans les fonctions/classes imbriquées."""

    def sub(stmts, ctx):
        yield stmts, ctx
        for s in stmts:
            if isinstance(s, _SKIP):
                continue
            yield from _children(s, ctx)

    def _children(s, ctx):
        if isinstance(s, ast.If):
            yield from sub(s.body, [*ctx, f"si {_short(s.test)}"])
            if s.orelse:
                if len(s.orelse) == 1 and isinstance(s.orelse[0], ast.If):
                    yield from sub(s.orelse, [*ctx, f"sinon ({_short(s.test, 40)})"][:])
                else:
                    yield from sub(s.orelse, [*ctx, f"sinon ({_short(s.test, 40)})"])
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            yield from sub(s.body, [*ctx, f"boucle sur {_short(s.iter, 40)}"])
            if s.orelse:
                yield from sub(s.orelse, [*ctx, "boucle terminée"])
        elif isinstance(s, ast.While):
            yield from sub(s.body, [*ctx, f"boucle tant que {_short(s.test, 40)}"])
            if s.orelse:
                yield from sub(s.orelse, [*ctx, "boucle terminée"])
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            yield from sub(s.body, ctx)
        elif isinstance(s, ast.Try) or (hasattr(ast, "TryStar") and isinstance(s, ast.TryStar)):
            yield from sub(s.body, ctx)
            for h in s.handlers:
                yield from sub(h.body, [*ctx, _handler_desc(h)])
            if s.orelse:
                yield from sub(s.orelse, [*ctx, "sans exception"])
            if s.finalbody:
                yield from sub(s.finalbody, [*ctx, "finally"])
        elif isinstance(s, ast.Match):
            for c in s.cases:
                yield from sub(c.body, [*ctx, f"cas {_short(c.pattern, 40)}"])

    yield from sub(node.body, context)


def _exits(fn):
    for block, ctx in _walk_blocks(fn, []):
        for i, s in enumerate(block):
            if isinstance(s, (ast.Return, ast.Raise)):
                yield _Exit(s, block, i, ctx)


def _conform(ex: _Exit) -> bool:
    prev = ex.block[ex.index - 1] if ex.index > 0 else None
    lvl = _log_level(prev)
    return lvl == "debug" if isinstance(ex.stmt, ast.Return) else lvl in RAISE_OK


def _branch(ctx: list[str]) -> str:
    if not ctx:
        return ""
    # la condition la plus proche est la plus informative
    return ctx[-1]


def _fit(msg: str, col: int, width: int = 120) -> str:
    """Tronque le message pour que la ligne formatée par ruff tienne dans
    ``width`` (chaîne seule sur sa ligne, indentée de col + 4, suivie
    d'une virgule), sans jamais couper le placeholder ``{}`` final."""
    budget = width - (col + 4) - 3
    if len(repr(msg)) - 2 <= budget:
        return msg
    tail = ""
    if msg.endswith("={}"):
        head, name = msg[:-3].rsplit(" retour ", 1)
        tail = " retour " + name + "={}"
        msg = head
    keep = max(10, budget - len(tail) - 1)
    return msg[:keep].rstrip() + "…" + tail


def _lit(text: str) -> str:
    return repr(text)


def _module_logger(tree: ast.Module) -> str | None:
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in LOGGER_NAMES
        ):
            return node.targets[0].id
        if isinstance(node, ast.ImportFrom) and node.module == "loguru":
            for a in node.names:
                if a.name == "logger" and (a.asname or "logger") in LOGGER_NAMES:
                    return a.asname or "logger"
    return None


def _imports_logging_config(tree: ast.Module) -> bool:
    return any(isinstance(n, ast.ImportFrom) and n.module == "netcross_core.logging_config" for n in ast.walk(tree))


def _has_summarize(tree: ast.Module) -> bool:
    return any(
        isinstance(n, ast.ImportFrom)
        and n.module == "netcross_core.logging_config"
        and any(a.name == "summarize" and a.asname is None for a in n.names)
        for n in ast.walk(tree)
    ) or any(isinstance(n, ast.FunctionDef) and n.name == "summarize" for n in tree.body)


def _qualfuncs(tree: ast.Module):
    def rec(node, prefix, nested, cls):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}{child.name}"
                yield q, child, nested, cls
                yield from rec(child, q + ".", True, None)
            elif isinstance(child, ast.ClassDef):
                yield from rec(child, f"{prefix}{child.name}.", nested, child)
            else:
                yield from rec(child, prefix, nested, cls)

    yield from rec(tree, "", False, None)


def _describe(expr: ast.expr) -> str:
    """Description courte d'une expression renvoyée, sans la recopier."""
    if isinstance(expr, ast.Call):
        return f"{_short(expr.func, 40)}(…)"
    if isinstance(expr, ast.Tuple):
        return f"tuple de {len(expr.elts)}"
    if isinstance(expr, ast.List) and not expr.elts:
        return "liste vide"
    if isinstance(expr, ast.Dict) and not expr.keys:
        return "dictionnaire vide"
    if isinstance(expr, (ast.List, ast.ListComp)):
        return "liste"
    if isinstance(expr, (ast.Dict, ast.DictComp)):
        return "dictionnaire"
    if isinstance(expr, (ast.Set, ast.SetComp)):
        return "ensemble"
    if isinstance(expr, ast.GeneratorExp):
        return "générateur"
    if isinstance(expr, ast.JoinedStr):
        return "chaîne formatée"
    return _short(expr, 50)


def _simple_value(expr: ast.expr | None) -> bool:
    node = expr
    while isinstance(node, ast.Attribute):
        node = node.value
    return isinstance(node, ast.Name)


def instrument_text(text: str, hot: set[str], path: str = "") -> tuple[str, int, list[str]]:
    tree = ast.parse(text)
    log = _module_logger(tree)
    if log is None:
        return text, 0, ["module sans logger au niveau du module"]
    can_summarize = _imports_logging_config(tree)
    has_summarize = _has_summarize(tree)
    uses_summarize = False
    lines = text.splitlines(keepends=True)
    edits: list[tuple[int, int, str, str]] = []  # (ligne 1-based, col, texte, mode)
    notes: list[str] = []
    if path.endswith("netcross_core/logging_config.py"):
        return text, 0, ["logging_config : instrumentation manuelle (logger non configuré à l'import)"]

    for qual, fn, nested, _cls in _qualfuncs(tree):
        if _is_stub(fn):
            continue
        special = fn.name.startswith("__") and fn.name.endswith("__")
        # summarize() ne coûte que quelques isinstance/len : utilisé aussi sur
        # les chemins chauds, jamais dans une méthode spéciale ni une fermeture
        cold = not (nested or special)
        for ex in _exits(fn):
            if _conform(ex):
                continue
            s = ex.stmt
            branch = _branch(ex.context)
            prefix = f"{qual}: " + (f"{branch} -> " if branch else "")
            args = ""
            if isinstance(s, ast.Return):
                if s.value is None:
                    msg = prefix + "retour"
                elif isinstance(s.value, ast.Constant):
                    msg = prefix + f"retour {_short(s.value, 40)}"
                elif cold and _simple_value(s.value) and (has_summarize or can_summarize):
                    name = _short(s.value, 40)
                    msg = prefix + f"retour {name}={{}}"
                    args = f", summarize({ast.unparse(s.value)}, {_lit(name.split('.')[-1])})"
                    uses_summarize = True
                else:
                    msg = prefix + f"retour {_describe(s.value)}"
            else:
                msg = prefix + _exc_name(s)
            msg = _fit(msg, s.col_offset)
            call = f"{log}.debug({_lit(msg)}{args})"
            edits.append((s.lineno, s.col_offset, call, "before"))
        if _can_fall_through(fn.body) and _log_level(fn.body[-1]) != "debug":
            last = fn.body[-1]
            call = f"{log}.debug({_lit(qual + ': fin')})"
            if last.lineno == fn.lineno:
                edits.append((last.end_lineno, last.end_col_offset, call, "after-inline"))
            else:
                first = fn.body[0]
                indent = lines[first.lineno - 1][: first.col_offset]
                if indent.strip():
                    indent = " " * first.col_offset
                edits.append((last.end_lineno, len(lines[last.end_lineno - 1]), indent + call, "after-line"))

    for lineno, col, call, mode in sorted(edits, key=lambda e: (e[0], e[1]), reverse=True):
        line = lines[lineno - 1]
        if mode == "before":
            head = line[:col]
            if head.strip() == "":
                lines.insert(lineno - 1, head + call + "\n")
            else:
                lines[lineno - 1] = head + call + "; " + line[col:]
        elif mode == "after-inline":
            lines[lineno - 1] = line[:col] + "; " + call + line[col:]
        else:
            if not line.endswith("\n"):
                lines[lineno - 1] = line + "\n"
            lines.insert(lineno, call + "\n")

    out = "".join(lines)
    if uses_summarize and not has_summarize:
        out = _add_summarize_import(out)
    ast.parse(out)  # garde-fou : le résultat doit rester du Python valide
    return out, len(edits), notes


def _add_summarize_import(text: str) -> str:
    tree = ast.parse(text)
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "netcross_core.logging_config":
            lines = text.splitlines(keepends=True)
            start, end = node.lineno - 1, node.end_lineno
            names = [a.name if a.asname is None else f"{a.name} as {a.asname}" for a in node.names]
            names.append("summarize")
            seg = "".join(lines[start:end])
            comment = ""
            if "#" in lines[end - 1]:
                comment = "  #" + lines[end - 1].split("#", 1)[1].rstrip("\n")
            indent = lines[start][: node.col_offset]
            new = f"{indent}from netcross_core.logging_config import {', '.join(names)}{comment}\n"
            del seg
            lines[start:end] = [new]
            return "".join(lines)
    # import niché (dans une fonction) seulement : import de module en tête
    lines = text.splitlines(keepends=True)
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            lines.insert(node.lineno - 1, "from netcross_core.logging_config import summarize\n")
            return "".join(lines)
    return text


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()
    hot = hot_names()
    for f in args.files:
        p = Path(f)
        text = p.read_text(encoding="utf-8")
        out, n, notes = instrument_text(text, hot, str(p))
        print(f"{f}: {n} sortie(s) instrumentée(s)" + (f" ({'; '.join(notes)})" if notes else ""))
        if not args.dry_run and out != text:
            p.write_text(out, encoding="utf-8")


if __name__ == "__main__":
    main()
