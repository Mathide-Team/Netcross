#!/usr/bin/env python3
"""
scripts/generate_class_diagram.py -- genere docs/class-diagram.md depuis le code.

Issue #140 : le diagramme de classes vivait a la main dans la section 3 de
docs/features-backlog.md et avait derive (fige pendant 21 sessions, voir
docs/sessions/session-36.md). Il est desormais un fichier a part entiere,
GENERE par ce script et rafraichi par le hook pre-commit `class-diagram`
(.pre-commit-config.yaml) des qu'un fichier de src/ change.

Principe : analyse statique (module `ast`), aucun import du code de netcross
-> pas besoin de tshark/GTK4/matplotlib, s'execute partout ou Python tourne,
uniquement avec la bibliotheque standard. Sortie deterministe (aucune date,
aucun chemin absolu) : le fichier ne change que si le code change.

Contenu genere :
  1. un graphe de dependances entre packages (depuis les `import`) ;
  2. par package : une table des modules (premiere phrase de leur docstring)
     et un ou plusieurs blocs mermaid `classDiagram` (classes, champs annotes,
     methodes publiques, fonctions publiques des modules, heritage, associations
     deduites des annotations de champs). Un bloc mermaid est plafonne a
     MAX_BLOCK_CHARS caracteres (limite de rendu de mermaid : 50 000) ; au-dela,
     le package est coupe en plusieurs blocs par modules entiers.

Usage :
    python3 scripts/generate_class_diagram.py           # (re)ecrit le fichier
    python3 scripts/generate_class_diagram.py --check   # code 1 si obsolete
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    from loguru import logger
except ImportError:  # invoqué par la CI avec le python système, sans loguru
    class _logger:  # noqa: N801 -- repli muet, mêmes méthodes que loguru
        def _mute(self, *_args, **_kwargs):
            pass

        trace = debug = info = success = warning = error = exception = critical = log = _mute

    logger = _logger()

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SRC = REPO_ROOT / "src"
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "class-diagram.md"

# Ordre des couches, de la plus basse a la plus haute (contrat import-linter de
# pyproject.toml, lu a l'envers). Tout module de src/ hors de ces packages est
# range dans le groupe CLI.
LAYER_ORDER = ["pcap_parser", "netcross_core", "netcross_ai", "netcross_report", "netcross_api", "netcross_gtk4"]
CLI_GROUP = "CLI"

# Marge sous la limite de 50 000 caracteres par defaut de mermaid (maxTextSize).
MAX_BLOCK_CHARS = 40_000

ENUM_BASES = {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"}
DOC_MAX_CHARS = 200


# --------------------------------------------------------------------------- #
# Modele                                                                      #
# --------------------------------------------------------------------------- #


@dataclass
class ClassInfo:
    name: str
    module: str
    bases: list[str]
    is_dataclass: bool = False
    dataclass_options: list[str] = field(default_factory=list)
    has_slots: bool = False
    fields: list[str] = field(default_factory=list)  # lignes deja formatees
    methods: list[str] = field(default_factory=list)  # lignes deja formatees
    # nom de classe reference dans les annotations -> noms des champs concernes
    refs: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class ModuleInfo:
    name: str  # nom pointe (netcross_core.models)
    group: str  # groupe de rendu (netcross_core, netcross_core.application, CLI...)
    doc: str
    classes: list[ClassInfo] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)  # noms pointes importes


# --------------------------------------------------------------------------- #
# Formatage des annotations                                                   #
# --------------------------------------------------------------------------- #


def _flatten_union(node: ast.expr) -> list[ast.expr]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _flatten_union(node.left) + _flatten_union(node.right)
    return [node]


def _join_union(parts: list[str]) -> str:
    non_none = [p for p in parts if p != "None"]
    if len(non_none) == 1 and len(parts) == 2:
        return non_none[0] + "?"
    return " or ".join(parts)


def _annotation_text(node: ast.expr | None) -> str:
    """Rend une annotation en syntaxe mermaid (`list~str~`, `int?`)."""
    if node is None:
        return ""
    if isinstance(node, ast.Constant):
        if node.value is None:
            return "None"
        if node.value is Ellipsis:
            return "..."
        if isinstance(node.value, str):
            try:
                return _annotation_text(ast.parse(node.value, mode="eval").body)
            except SyntaxError as exc:
                logger.debug("annotation non parsable, valeur brute conservee : {}", exc)
                return _safe(node.value)
        return _safe(repr(node.value))
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _safe(ast.unparse(node))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _join_union([_annotation_text(p) for p in _flatten_union(node)])
    if isinstance(node, ast.Subscript):
        base = _annotation_text(node.value)
        inner = node.slice
        args = [_annotation_text(e) for e in inner.elts] if isinstance(inner, ast.Tuple) else [_annotation_text(inner)]
        if base == "Optional" and len(args) == 1:
            return args[0] + "?"
        if base == "Union":
            return _join_union(args)
        return f"{base}~{', '.join(args)}~"
    if isinstance(node, ast.List):
        return "(" + ", ".join(_annotation_text(e) for e in node.elts) + ")"
    if isinstance(node, ast.Tuple):
        return ", ".join(_annotation_text(e) for e in node.elts)
    return _safe(ast.unparse(node))


def _safe(text: str) -> str:
    """Retire ce que mermaid interpreterait dans une ligne de membre."""
    for ch in ('"', "'", "`", "{", "}", "<", ">", "|", "\n", "\r"):
        text = text.replace(ch, " " if ch in "\n\r|" else "")
    return " ".join(text.split())


def _annotation_names(node: ast.expr | None) -> set[str]:
    """Tous les identifiants cites dans une annotation (y compris `\"Foo\"`)."""
    names: set[str] = set()
    if node is None:
        return names
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            names.add(sub.id)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            try:
                names |= _annotation_names(ast.parse(sub.value, mode="eval").body)
            except SyntaxError as exc:
                logger.debug("sous-annotation non parsable, ignoree : {}", exc)
                continue
    return names


# --------------------------------------------------------------------------- #
# Extraction                                                                  #
# --------------------------------------------------------------------------- #


def _iter_toplevel(body: list[ast.stmt]):
    """Instructions de premier niveau, y compris sous `if`/`try` (gardes d'import)."""
    for node in body:
        yield node
        if isinstance(node, ast.If):
            yield from _iter_toplevel(node.body)
            yield from _iter_toplevel(node.orelse)
        elif isinstance(node, ast.Try):
            yield from _iter_toplevel(node.body)
            for handler in node.handlers:
                yield from _iter_toplevel(handler.body)
            yield from _iter_toplevel(node.orelse)
            yield from _iter_toplevel(node.finalbody)


def _decorator_name(dec: ast.expr) -> str:
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return ""


def _is_true(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _function_line(fn: ast.FunctionDef | ast.AsyncFunctionDef, *, is_method: bool) -> str:
    params = [a.arg for a in (*fn.args.posonlyargs, *fn.args.args)]
    if is_method and params and params[0] in ("self", "cls"):
        params = params[1:]
    if fn.args.vararg:
        params.append(fn.args.vararg.arg)
    params.extend(a.arg for a in fn.args.kwonlyargs)
    if fn.args.kwarg:
        params.append(fn.args.kwarg.arg)
    ret = _annotation_text(fn.returns)
    decos = {_decorator_name(d) for d in fn.decorator_list}
    static = "$" if decos & {"staticmethod", "classmethod"} else ""
    return f"+{fn.name}({', '.join(params)}){static}" + (f" {ret}" if ret else "")


def _extract_class(node: ast.ClassDef, module: str) -> ClassInfo:
    info = ClassInfo(
        name=node.name,
        module=module,
        bases=[b for b in (_safe(ast.unparse(b)) for b in node.bases) if b != "object"],
    )
    for dec in node.decorator_list:
        if _decorator_name(dec) == "dataclass":
            info.is_dataclass = True
            if isinstance(dec, ast.Call):
                info.dataclass_options = [k.arg for k in dec.keywords if k.arg and _is_true(k.value)]
    is_enum = any(b.split(".")[-1] in ENUM_BASES for b in info.bases)
    seen_methods: set[str] = set()
    for item in node.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            fname = item.target.id
            vis = "-" if fname.startswith("_") else "+"
            ftype = _annotation_text(item.annotation)
            info.fields.append(f"{vis}{ftype} {fname}")
            for ref in _annotation_names(item.annotation):
                info.refs.setdefault(ref, []).append(fname)
        elif isinstance(item, ast.Assign):
            names = [t.id for t in item.targets if isinstance(t, ast.Name)]
            if "__slots__" in names:
                info.has_slots = True
            elif is_enum:
                info.fields.extend(f"+{n}" for n in names if not n.startswith("_"))
        elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            not item.name.startswith("_") and item.name not in seen_methods
        ):
            seen_methods.add(item.name)
            info.methods.append(_function_line(item, is_method=True))
    return info


def _first_sentence(doc: str | None, module_name: str) -> str:
    if not doc:
        return ""
    paragraph = " ".join(doc.strip().split("\n\n")[0].split())
    for sep in (" -- ", " - ", " : "):
        head, found, tail = paragraph.partition(sep)
        if found and head.strip().rstrip(".") == module_name:
            paragraph = tail.strip()
            break
    cut = paragraph.find(". ")
    if 0 < cut < DOC_MAX_CHARS:
        paragraph = paragraph[: cut + 1]
    elif len(paragraph) > DOC_MAX_CHARS:
        paragraph = paragraph[:DOC_MAX_CHARS].rsplit(" ", 1)[0] + "…"
    return paragraph.replace("|", "\\|")


def _module_name(rel: Path) -> str:
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _group_of(rel: Path) -> str:
    dirs = rel.parts[:-1]
    return ".".join(dirs[:2]) if dirs else CLI_GROUP


def extract_module(path: Path, src: Path) -> ModuleInfo:
    rel = path.relative_to(src)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    name = _module_name(rel)
    info = ModuleInfo(name=name, group=_group_of(rel), doc=_first_sentence(ast.get_docstring(tree), name))
    for node in _iter_toplevel(tree.body):
        if isinstance(node, ast.ClassDef):
            info.classes.append(_extract_class(node, name))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            info.functions.append(_function_line(node, is_method=False))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            info.imports.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            info.imports.append(node.module)
    return info


def collect_modules(src: Path) -> list[ModuleInfo]:
    files = sorted(p for p in src.rglob("*.py") if "__pycache__" not in p.parts)
    return [extract_module(p, src) for p in files]


# --------------------------------------------------------------------------- #
# Rendu                                                                       #
# --------------------------------------------------------------------------- #


def _group_sort_key(group: str) -> tuple[int, str]:
    top = group.split(".")[0]
    if top in LAYER_ORDER:
        return (LAYER_ORDER.index(top), group)
    return (len(LAYER_ORDER), group)


def _stereotype(cls: ClassInfo, local_names: set[str]) -> str:
    parts: list[str] = []
    if cls.is_dataclass:
        parts.append("dataclass")
    if cls.has_slots:
        parts.append("__slots__")
    parts.extend(cls.dataclass_options)
    parts.extend(b for b in cls.bases if b not in local_names)
    return f"<<{', '.join(parts)}>>" if parts else ""


def _class_ids(modules: list[ModuleInfo]) -> dict[tuple[str, str], str]:
    """Identifiant mermaid par (module, classe) : le nom seul s'il est unique dans src/."""
    counts: dict[str, int] = {}
    for m in modules:
        for c in m.classes:
            counts[c.name] = counts.get(c.name, 0) + 1
    ids: dict[tuple[str, str], str] = {}
    for m in modules:
        for c in m.classes:
            unique = counts[c.name] == 1
            ids[(m.name, c.name)] = c.name if unique else f"{m.name.replace('.', '_')}_{c.name}"
    return ids


def _render_class(cls: ClassInfo, cid: str, local_names: set[str], indent: str = "    ") -> list[str]:
    head = f"{indent}class {cid}" if cid == cls.name else f'{indent}class {cid}["{cls.module}.{cls.name}"]'
    stereo = _stereotype(cls, local_names)
    members = [*cls.fields, *cls.methods]
    if not stereo and not members:
        return [head]
    lines = [head + " {"]
    if stereo:
        lines.append(f"{indent}    {stereo}")
    lines.extend(f"{indent}    {m}" for m in members)
    lines.append(f"{indent}}}")
    return lines


def _render_block(modules: list[ModuleInfo], ids: dict[tuple[str, str], str]) -> str:
    lines = ["classDiagram", "    direction LR"]
    local: dict[str, tuple[ModuleInfo, ClassInfo]] = {}
    for m in modules:
        for c in m.classes:
            local[c.name] = (m, c)
    local_names = set(local)

    for m in modules:
        if not m.classes and not m.functions:
            continue
        lines.append("")
        lines.append(f"    %% ===== {m.name} =====")
        for c in m.classes:
            lines.extend(_render_class(c, ids[(m.name, c.name)], local_names))
        if m.functions:
            mid = "mod_" + m.name.replace(".", "_")
            lines.append(f'    class {mid}["{m.name}"] {{')
            lines.append("        <<module>>")
            lines.extend(f"        {fn}" for fn in m.functions)
            lines.append("    }")

    relations: list[str] = []
    for m in modules:
        for c in m.classes:
            cid = ids[(m.name, c.name)]
            for base in c.bases:
                if base in local:
                    bm, bc = local[base]
                    relations.append(f"    {ids[(bm.name, bc.name)]} <|-- {cid}")
            for target, fields_ in sorted(c.refs.items()):
                if target in local and target != c.name and target not in c.bases:
                    tm, tc = local[target]
                    label = ", ".join(sorted(set(fields_)))
                    relations.append(f"    {cid} --> {ids[(tm.name, tc.name)]} : {label}")
    if relations:
        lines.append("")
        lines.append("    %% ===== relations =====")
        lines.extend(relations)
    return "\n".join(lines)


def _chunk_modules(modules: list[ModuleInfo], ids: dict[tuple[str, str], str]) -> list[str]:
    """Blocs mermaid d'un groupe, coupes par modules entiers sous MAX_BLOCK_CHARS."""
    drawable = [m for m in modules if m.classes or m.functions]
    blocks: list[str] = []
    chunk: list[ModuleInfo] = []
    for m in drawable:
        if chunk and len(_render_block([*chunk, m], ids)) > MAX_BLOCK_CHARS:
            blocks.append(_render_block(chunk, ids))
            chunk = []
        chunk.append(m)
    if chunk:
        blocks.append(_render_block(chunk, ids))
    return blocks


def _top_level(dotted: str) -> str | None:
    top = dotted.split(".")[0]
    return top if top in LAYER_ORDER else None


def _render_inter_module_relations(modules: list[ModuleInfo], ids: dict[tuple[str, str], str]) -> str:
    """Flowchart des relations de classes ENTRE modules (inter-modules).

    Contrairement aux blocs `classDiagram` par package (qui ne peuvent
    référencer que les classes qu'ils déclarent), cette section centrale
    liste TOUTES les associations de classes détectées via les annotations
    de champs lorsqu'elles franchissent une frontière de module
    (source_module != target_module), y compris au sein d'un même package
    (ex. `netcross_report.synthesis` -> `netcross_core.expert_model`).
    Complément indispensable du graphe de dépendances entre packages (qui
    ne compte que des `import`) : ici on sait QUELLE classe référence
    quelle autre, et par quels champs.
    """
    # Index global : nom de classe -> (module, ClassInfo) pour résolution
    # des références (un nom peut exister dans plusieurs modules).
    global_index: dict[str, list[tuple[ModuleInfo, ClassInfo]]] = {}
    for m in modules:
        for c in m.classes:
            global_index.setdefault(c.name, []).append((m, c))

    relations: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for m in modules:
        for c in m.classes:
            cid = ids[(m.name, c.name)]
            for target, fields_ in sorted(c.refs.items()):
                if target == c.name or target in c.bases:
                    continue
                # Toutes les classes cibles dans d'autres modules.
                for tm, tc in global_index.get(target, []):
                    if tm.name == m.name:
                        continue  # intra-module : déjà dans le bloc du module
                    tid = ids[(tm.name, tc.name)]
                    label = ", ".join(sorted(set(fields_)))
                    key = (cid, tid, label)
                    if key in seen:
                        continue
                    seen.add(key)
                    relations.append(f"    {cid} -->|{label}| {tid}")

    if not relations:
        return ""  # aucune relation inter-module détectée

    # Nœuds déclarés (pour que le flowchart soit autonome) : on liste chaque
    # classe impliquée avec son nom complet (module.Class) entre crochets,
    # pour lever l'ambiguïté quand une classe existe dans plusieurs modules.
    node_lines: list[str] = []
    declared: set[str] = set()
    for line in relations:
        parts = line.strip().split(" -->|")
        src = parts[0].strip()
        if src not in declared:
            declared.add(src)
            # Cherche le module d'origine pour le label
            src_label = src
            for m in modules:
                for c in m.classes:
                    if ids[(m.name, c.name)] == src:
                        src_label = f"{m.name}.{c.name}"
                        break
            node_lines.append(f'    {src}["{src_label}"]')
        dst = parts[-1].rsplit("| ", 1)[-1].strip()
        if dst not in declared:
            declared.add(dst)
            dst_label = dst
            for m in modules:
                for c in m.classes:
                    if ids[(m.name, c.name)] == dst:
                        dst_label = f"{m.name}.{c.name}"
                        break
            node_lines.append(f'    {dst}["{dst_label}"]')

    return "\n".join(["flowchart LR", *sorted(node_lines), *sorted(relations)])


def _render_package_graph(modules: list[ModuleInfo]) -> str:
    counts: dict[tuple[str, str], int] = {}
    for m in modules:
        origin = m.group.split(".")[0] if m.group != CLI_GROUP else CLI_GROUP
        for imported in m.imports:
            target = _top_level(imported)
            if target and target != origin:
                counts[(origin, target)] = counts.get((origin, target), 0) + 1
    nodes = [CLI_GROUP, *reversed(LAYER_ORDER)]
    lines = ["flowchart TD"]
    for n in nodes:
        label = "CLI (src/*.py)" if n == CLI_GROUP else n
        lines.append(f'    {n}["{label}"]')
    for (a, b), n in sorted(counts.items(), key=lambda kv: (nodes.index(kv[0][0]), nodes.index(kv[0][1]))):
        lines.append(f'    {a} -->|"{n} import{"s" if n > 1 else ""}"| {b}')
    return "\n".join(lines)


def render_document(modules: list[ModuleInfo]) -> str:
    ids = _class_ids(modules)
    groups: dict[str, list[ModuleInfo]] = {}
    for m in modules:
        groups.setdefault(m.group, []).append(m)

    n_classes = sum(len(m.classes) for m in modules)
    n_functions = sum(len(m.functions) for m in modules)
    out = [
        "<!-- FICHIER GENERE par scripts/generate_class_diagram.py -- NE PAS EDITER A LA MAIN. -->",
        "<!-- Regenere par le hook pre-commit `class-diagram` ; voir .pre-commit-config.yaml. -->",
        "",
        "# netcross — diagramme de classes",
        "",
        "> ⚠️ **Fichier généré depuis le code** (`src/`) par `scripts/generate_class_diagram.py` : toute",
        "> modification manuelle sera écrasée. Il est mis à jour automatiquement par le hook pre-commit",
        "> `class-diagram` dès qu'un fichier `src/**/*.py` change ; pour le régénérer à la main :",
        "> `python3 scripts/generate_class_diagram.py` (ou `--check` pour vérifier qu'il est à jour).",
        ">",
        "> Il remplace l'ancienne section 3 de `docs/features-backlog.md`, tenue à la main, qui avait dérivé",
        "> (voir `docs/sessions/session-36.md`, issue #140).",
        "",
        f"{len(modules)} modules · {n_classes} classes · {n_functions} fonctions publiques de module.",
        "",
        "Conventions : `+` public, `-` privé (préfixe `_`) ; `int?` = `int | None` ; `list~str~` = `list[str]` ;",
        "`<<module>>` regroupe les fonctions publiques d'un module ; `A --> B : champ` = `A` a un champ annoté",
        "avec `B` ; `<<…>>` liste le type de classe (dataclass, `__slots__`…) et les bases hors du bloc.",
        "Les fonctions/méthodes privées (préfixe `_`) et les classes imbriquées ne sont pas représentées.",
        "",
        "## Dépendances entre packages",
        "",
        "Nombre d'instructions `import` d'un package vers un autre (contrat de couches vérifié par",
        "`import-linter` : `netcross_gtk4 → netcross_report → netcross_core → pcap_parser`).",
        "",
        "```mermaid",
        _render_package_graph(modules),
        "```",
    ]

    # Section inter-modules : relations de classes entre packages
    # (issue #140 suite) — complète le graphe de dépendances entre packages
    # en montrant QUELLE classe référence quelle autre, par quels champs.
    inter_module = _render_inter_module_relations(modules, ids)
    if inter_module:
        out += [
            "",
            "## Relations inter-modules",
            "",
            "Associations de classes détectées via les annotations de champs lorsqu'elles franchissent",
            "une frontière de module (source_module != target_module). Chaque flèche indique la classe",
            "source, le ou les champs concernés, et la classe cible (dans un autre module). Complément",
            "du graphe de dépendances ci-dessus (qui ne compte que des `import`).",
            "",
            "```mermaid",
            inter_module,
            "```",
        ]

    for group in sorted(groups, key=_group_sort_key):
        mods = groups[group]
        title = "CLI (`src/*.py`)" if group == CLI_GROUP else f"`{group}`"
        out += ["", f"## {title}", "", "| Module | Rôle |", "|---|---|"]
        for m in mods:
            out.append(f"| `{m.name}` | {m.doc or '—'} |")
        blocks = _chunk_modules(mods, ids)
        for i, block in enumerate(blocks, start=1):
            out += ["", f"### Diagramme ({i}/{len(blocks)})" if len(blocks) > 1 else "### Diagramme", ""]
            out += ["```mermaid", block, "```"]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Genere docs/class-diagram.md depuis src/.")
    parser.add_argument("--src", type=Path, default=DEFAULT_SRC, help="racine des sources (defaut : src/)")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="fichier genere")
    parser.add_argument("--check", action="store_true", help="ne rien ecrire ; code 1 si le fichier est obsolete")
    args = parser.parse_args(argv)

    text = render_document(collect_modules(args.src))
    current = args.output.read_text(encoding="utf-8") if args.output.exists() else None

    if args.check:
        if current == text:
            return 0
        print(
            f"{args.output} est obsolete ou absent : lancer `python3 scripts/generate_class_diagram.py`.",
            file=sys.stderr,
        )
        return 1

    if current != text:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"{args.output} regenere.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
