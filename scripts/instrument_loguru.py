#!/usr/bin/env python3
"""Instrumentation Loguru assistée (issue #441).

Ajoute, dans les fonctions non triviales qui n'ont encore aucun appel
``logger.*`` :

- une trace DEBUG d'entrée, avec un résumé sûr de chaque argument
  (``netcross_core.logging_config.summarize`` : tailles et types, jamais
  d'objet entier, secrets masqués) ;
- une trace DEBUG avant chaque ``raise`` explicite (refus), avec le type
  de l'exception.

Chemins chauds exclus : une fonction appelée dans une boucle ou une
compréhension, passée comme rappel (clé de tri, signal GTK...), appelée
depuis une fonction elle-même chaude (fermeture transitive), une fonction
imbriquée, une méthode spéciale ou une propriété n'est PAS instrumentée.
L'analyse se fait par nom sur tout ``src/`` : une homonymie classe la
fonction comme chaude, jamais l'inverse -- aucun log n'est ajouté par
erreur dans une boucle par paquet.

Usage : ``python3 scripts/instrument_loguru.py [--dry-run] FICHIER...``
(affiche les fonctions instrumentées et les chemins chauds écartés).
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
TRIVIAL_LINES = 3
IMPORT_LINE = "from netcross_core.logging_config import summarize"
LOGGER_NAMES = ("logger", "_logger", "log")
# Iterables consideres comme « fins » (une iteration par paquet, enregistrement,
# ligne, octet, flux, evenement, document...) : leurs corps sont des chemins chauds.
_HOT_ITER_RE = re.compile(
    r"pkt|packet|paquet|record|frame|trame|line|ligne|row|byte|octet|payload|layer|field|champ|"
    r"flow|flux|event|evenement|doc|entr|item|answer|query|queries|match|conv|sample|char|token|block|chunk|"
    r"stream|segment|session|message|msg|host|addr|ip|port|cert|header|key|value|values|keys|finding|rule|"
    r"transaction|request|response|call|stat|node|edge|objects|objs|children|iter|enumerate|zip|range|sorted|"
    r"reader|walk|glob|rglob|listdir|splitlines|split",
    re.IGNORECASE,
)


def _calls_logger(node: ast.AST) -> bool:
    return any(
        isinstance(c, ast.Call)
        and isinstance(c.func, ast.Attribute)
        and isinstance(c.func.value, ast.Name)
        and c.func.value.id in LOGGER_NAMES
        for c in ast.walk(node)
    )


def _called_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


class _Usage(ast.NodeVisitor):
    """Collecte, sur tout src/, les noms appelés en boucle, passés en rappel,
    et le graphe « fonction -> noms appelés »."""

    def __init__(self) -> None:
        self.in_loop: set[str] = set()
        self.referenced: set[str] = set()
        self.calls: dict[str, set[str]] = {}
        self._loop_depth = 0
        self._func: list[str] = []

    def _visit_loop(self, node: ast.AST) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def _visit_iter(self, node: ast.AST, iters: list[ast.expr]) -> None:
        """Boucle chaude seulement si elle parcourt des unites fines (paquets,
        enregistrements, lignes, flux...) -- une boucle sur quelques
        captures ou points de capture reste froide."""
        if any(_HOT_ITER_RE.search(ast.unparse(it)) for it in iters):
            self._visit_loop(node)
        else:
            self.generic_visit(node)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:  # noqa: N802
        self._visit_iter(node, [node.iter])

    visit_AsyncFor = visit_For  # noqa: N815

    def visit_While(self, node: ast.While) -> None:  # noqa: N802
        # boucle de lecture/reception : toujours supposee chaude
        self._visit_loop(node)

    def _visit_comp(self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp) -> None:
        self._visit_iter(node, [g.iter for g in node.generators])

    visit_ListComp = visit_SetComp = visit_DictComp = visit_GeneratorExp = _visit_comp  # noqa: N815

    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._func.append(node.name)
        depth, self._loop_depth = self._loop_depth, 0
        self.calls.setdefault(node.name, set())
        self.generic_visit(node)
        self._loop_depth = depth
        self._func.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = _visit_func  # noqa: N815

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        # corps de lambda : rappel potentiellement appelé en boucle
        self._visit_loop(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = _called_name(node.func)
        if name:
            if self._loop_depth:
                self.in_loop.add(name)
            if self._func:
                self.calls[self._func[-1]].add(name)
        # le nom appele lui-meme n'est pas une « reference » : on ne visite
        # que la cible de l'attribut, puis les arguments
        if isinstance(node.func, ast.Attribute):
            self.visit(node.func.value)
        elif not isinstance(node.func, ast.Name):
            self.visit(node.func)
        for arg in [*node.args, *(k.value for k in node.keywords)]:
            self.visit(arg)

    def _reference(self, name: str, ctx: ast.expr_context) -> None:
        # toute reference non appelee (rappel, valeur de dict de dispatch,
        # clé de tri, gestionnaire de signal...) : potentiellement chaude
        if isinstance(ctx, ast.Load):
            self.referenced.add(name)

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        self._reference(node.id, node.ctx)

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        self._reference(node.attr, node.ctx)
        self.visit(node.value)


def _parse_or_empty(path: Path) -> ast.Module:
    try:
        return ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        print(f"{path}: syntaxe invalide, ignore", file=sys.stderr)
        return ast.Module(body=[], type_ignores=[])


def hot_names(src: Path = SRC) -> set[str]:
    usage = _Usage()
    for path in src.rglob("*.py"):
        usage.visit(_parse_or_empty(path))
    hot = set(usage.in_loop) | set(usage.referenced)
    frontier = list(hot)
    while frontier:
        name = frontier.pop()
        for callee in usage.calls.get(name, ()):
            if callee not in hot:
                hot.add(callee)
                frontier.append(callee)
    return hot


def _params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    a = fn.args
    names = [p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    return [n for n in names if n not in ("self", "cls")]


def _is_excluded(fn: ast.FunctionDef | ast.AsyncFunctionDef, hot: set[str]) -> str | None:
    if fn.name.startswith("__") and fn.name.endswith("__") and fn.name != "__init__":
        return "méthode spéciale"
    for dec in fn.decorator_list:
        if _called_name(dec) in ("property", "setter", "cached_property", "getter"):
            return "propriété"
        if isinstance(dec, ast.Call) or _called_name(dec) not in ("staticmethod", "classmethod", None):
            return "décorée"
    if fn.name in hot:
        return "chemin chaud"
    return None


def _body_start(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.stmt | None:
    body = fn.body
    first = body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        return body[1] if len(body) > 1 else None
    return first


def _raises(fn: ast.AST) -> list[ast.Raise]:
    found: list[ast.Raise] = []

    def walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                continue
            if isinstance(child, ast.Raise) and child.exc is not None:
                found.append(child)
            walk(child)

    walk(fn)
    return found


def _exc_name(node: ast.Raise) -> str:
    exc = node.exc
    if isinstance(exc, ast.Call):
        exc = exc.func
    return _called_name(exc) if isinstance(exc, (ast.Name, ast.Attribute)) else "exception"


def _split_message(msg: str, width: int = 90) -> list[str]:
    """Coupe un message long en litteraux concatenes (un espace en fin de
    morceau), pour tenir dans la limite de 120 colonnes."""
    chunks: list[str] = []
    current = ""
    for word in msg.split(" "):
        if current and len(current) + len(word) + 1 > width:
            chunks.append(current + " ")
            current = word
        else:
            current = f"{current} {word}" if current else word
    chunks.append(current)
    return chunks


def _qualname(stack: list[str], name: str) -> str:
    return ".".join([*stack, name])


def instrument_source(
    text: str, hot: set[str], force: frozenset[str] = frozenset()
) -> tuple[str, list[str], list[str]]:
    tree = ast.parse(text)
    lines = text.splitlines(keepends=True)
    if not any(
        isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "logger" for t in n.targets)
        for n in tree.body
    ) and not any(
        isinstance(n, ast.ImportFrom) and any((a.asname or a.name) == "logger" for a in n.names) for n in tree.body
    ):
        return text, [], ["module sans logger"]

    inserts: list[tuple[int, str]] = []  # (index de ligne 0-based, texte), inséré avant
    done: list[str] = []
    done_hot: list[str] = []
    skipped: list[str] = []

    def visit(node: ast.AST, stack: list[str], nested: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, [*stack, child.name], nested)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                handle(child, stack, nested)
                visit(child, [*stack, child.name], True)

    def handle(fn: ast.FunctionDef | ast.AsyncFunctionDef, stack: list[str], nested: bool) -> None:
        if (fn.end_lineno or fn.lineno) - fn.lineno <= TRIVIAL_LINES or _calls_logger(fn):
            return
        qual = _qualname(stack, fn.name)
        forced = bool(force & {fn.name, qual})
        reason = "fonction imbriquée" if nested else _is_excluded(fn, hot - {fn.name, qual} if forced else hot)
        if reason == "chemin chaud":
            # pas de trace d'entree, mais un refus (raise) reste un evenement
            # rare meme sur un chemin chaud : TRACE juste avant, cout nul sinon
            added = _raise_logs(fn, qual, "trace")
            if added:
                inserts.extend(added)
                done_hot.append(qual)
                return
        if reason:
            skipped.append(f"{qual} ({reason})")
            return
        start = _body_start(fn)
        if start is None or start.lineno == fn.lineno:
            skipped.append(f"{qual} (corps sur la ligne du def)")
            return
        indent = lines[start.lineno - 1][: start.col_offset]
        if indent.strip():
            skipped.append(f"{qual} (indentation non standard)")
            return
        params = _params(fn)
        if params:
            fmt = " ".join(f"{p}={{}}" for p in params)
            args = ", ".join(f'summarize({p}, "{p}")' for p in params)
            line = f'{indent}logger.debug("{qual}: {fmt}", {args})\n'
            if len(line.rstrip("\n")) > 120:
                args_lines = "".join(f'{indent}    summarize({p}, "{p}"),\n' for p in params)
                msg_lines = "".join(f'{indent}    "{chunk}"\n' for chunk in _split_message(f"{qual}: {fmt}"))
                line = f"{indent}logger.debug(\n{msg_lines.rstrip()},\n{args_lines}{indent})\n"
        else:
            line = f'{indent}logger.debug("{qual}()")\n'
        inserts.append((start.lineno - 1, line))
        inserts.extend(_raise_logs(fn, qual, "debug"))
        done.append(qual)

    def _raise_logs(fn: ast.AST, qual: str, level: str) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        for r in _raises(fn):
            r_line = lines[r.lineno - 1]
            r_indent = r_line[: r.col_offset]
            if r_indent.strip():
                continue  # `if x: raise ...` sur une ligne : laisse tel quel
            out.append((r.lineno - 1, f'{r_indent}logger.{level}("{qual}: refus, {_exc_name(r)}")\n'))
        return out

    visit(tree, [], False)
    done.extend(f"{q} (chemin chaud : refus en TRACE seulement)" for q in done_hot)
    if not inserts:
        return text, done, skipped
    for index, line in sorted(inserts, key=lambda x: x[0], reverse=True):
        lines.insert(index, line)
    out = "".join(lines)
    if IMPORT_LINE not in out and any("summarize(" in line for _i, line in inserts):
        out = _add_import(out)
    return out, done, skipped


def _add_import(text: str) -> str:
    tree = ast.parse(text)
    last = None
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            last = node
        elif last is not None and not isinstance(node, (ast.Expr, ast.If, ast.Try)):
            break
    lines = text.splitlines(keepends=True)
    at = (last.end_lineno if last else 0) or 0
    lines.insert(at, IMPORT_LINE + "\n")
    return "".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--force",
        default="",
        help="noms (ou Classe.methode) separes par des virgules, classes a tort en chemin chaud "
        "(fonction appelee une fois par rapport, par exemple) : instrumentes quand meme",
    )
    args = parser.parse_args(argv)
    hot = hot_names()
    force = frozenset(n for n in args.force.split(",") if n)
    for path in args.files:
        text = path.read_text(encoding="utf-8")
        new, done, skipped = instrument_source(text, hot, force)
        print(f"{path}: {len(done)} instrumentée(s), {len(skipped)} écartée(s)")
        for s in skipped:
            print(f"    écartée : {s}")
        if not args.dry_run and new != text:
            path.write_text(new, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
