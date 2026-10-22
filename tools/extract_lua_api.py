#!/usr/bin/env python3
"""
Extraction de l'API Lua Wireshark vers JSON structure (issue #386).

Source officielle : les commentaires ``WSLUA_*`` des fichiers C
``epan/wslua/*.c`` du depot Wireshark, transformes en AsciiDoc par le
generateur officiel ``tools/make-wsluarm.py`` (celui qui produit le
chapitre "Lua API Reference Manual" du Developer's Guide). Ce script
parse ensuite cet AsciiDoc, dont la structure est fixe : ancres
``[#lua_module_*]`` / ``[#lua_class_*]`` / ``[#lua_fn_*]`` /
``[#lua_class_attrib_*]`` et marqueurs de fin ``// function_footer:``,
``// function_arg_footer:``, ``// End ...``, ``// class_footer:``.
On ne lit pas le HTML publie.

Trois modes d'entree (un seul a la fois) :

    # 1. depuis un tag Wireshark (clone partiel, ~quelques Mo)
    python3 tools/extract_lua_api.py --tag v4.6.9

    # 2. depuis un checkout Wireshark existant
    python3 tools/extract_lua_api.py --wireshark-src ~/src/wireshark

    # 3. depuis des .adoc deja generes par make-wsluarm.py
    python3 tools/extract_lua_api.py --adoc-dir build/docbook/wsluarm_src --version 4.6.9

Sortie : ``data/lua_api.json`` (voir ``--output``), chargee ensuite dans
SQLite par ``scripts/build_lua_db.py`` (#387).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from loguru import logger

ROOT = Path(__file__).resolve().parent.parent
WIRESHARK_GIT = "https://gitlab.com/wireshark/wireshark.git"
GLOBAL_CLASS = "GlobalFunctions"

_ANCHOR_RE = re.compile(r"^\[#(lua_module|lua_class_attrib|lua_class|lua_fn|global_functions)_([^\]]+)\]$")
_ARG_RE = re.compile(r"^(.+?)(\s+\(optional\))?::$")
_VERSION_RE = re.compile(
    r"(?:since:?|starting in|starting with|new in|introduced in|added in)\s+"
    r"(?:wireshark\s+)?(?:version\s+)?v?(\d+\.\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
_XREF_RE = re.compile(r"<<[^,>]+,\s*([^>]+?)\s*>>")
_BARE_XREF_RE = re.compile(r"<<([^,>]+)>>")
_LINK_RE = re.compile(r"(?:link:)?(https?://[^\s\[]+)\[([^\]]*)\]")
_PASS_RE = re.compile(r"\$\$(.*?)\$\$")
_EXAMPLE_TITLE_RE = re.compile(r"^(?:=+\s*|\.)?examples?:?\s*$", re.IGNORECASE)
_BOLD_RE = re.compile(r"(?<![\w*])\*{1,2}([^*\s](?:[^*]*?[^*\s])?)\*{1,2}(?![\w*])")
_ITALIC_RE = re.compile(r"(?<![\w_])_([^_\s](?:[^_]*?[^_\s])?)_(?![\w_])")
_MACRO_RE = re.compile(r"\b(menu|kbd|btn):([^\[\]]*?)\[([^\]]*)\]")
_ATTR_REF_RE = re.compile(r"\{set:[^}]*\}\s*")
_BLOCK_ATTR_RE = re.compile(r"^\[[^\]]*=[^\]]*\]$")
_LIST_RE = re.compile(r"^(\*+|-|\.+|\d+\.)\s+(.*)$")
_ADMONITIONS = {"NOTE": "Note", "TIP": "Tip", "IMPORTANT": "Important", "WARNING": "Warning", "CAUTION": "Caution"}


# --------------------------------------------------------------------------
# Nettoyage du balisage AsciiDoc
# --------------------------------------------------------------------------


def clean_inline(text: str) -> str:
    """Convertit le balisage inline AsciiDoc en texte lisible."""
    text = _XREF_RE.sub(r"\1", text)
    text = _BARE_XREF_RE.sub(r"\1", text)
    text = _LINK_RE.sub(lambda m: f"{m.group(2)} ({m.group(1)})" if m.group(2) else m.group(1), text)
    text = _PASS_RE.sub(r"\1", text)
    text = _MACRO_RE.sub(_macro, text)
    text = re.sub(r"``([^`]+)``", r"`\1`", text)
    text = _ATTR_REF_RE.sub("", text)
    text = _BOLD_RE.sub(r"\1", text)
    return _ITALIC_RE.sub(r"\1", text)


def _macro(m: re.Match[str]) -> str:
    """menu:Tools[Lua > Reload] -> 'Tools > Lua > Reload' ; kbd:[Ctrl+L] -> 'Ctrl+L'."""
    cible, contenu = m.group(2).strip(), m.group(3).strip()
    if m.group(1) == "menu":
        return " > ".join(x for x in (cible, contenu) if x)
    return contenu or cible


def _table(rows: list[str]) -> str:
    """Tableau AsciiDoc ``|===`` -> lignes alignees (retrait de 2 espaces)."""
    cells = [[clean_inline(c.strip()) for c in r.split("|")[1:]] for r in rows]
    width = max((len(r) for r in cells), default=0)
    cells = [r + [""] * (width - len(r)) for r in cells]
    cols = [max(len(r[k]) for r in cells) for k in range(width)]
    return "\n".join("  " + "  ".join(c.ljust(w) for c, w in zip(r, cols)).rstrip() for r in cells)


def render_blocks(lines: list[str]) -> str:
    """Texte AsciiDoc (sans blocs [source]) -> paragraphes lisibles.

    Paragraphes separes par une ligne vide ; a l'interieur, une ligne par
    element de liste (``- ...``) ou rangee de tableau. Les lignes
    preformatees (tableaux, blocs ``----``) commencent par deux espaces.
    Les encadres ``[NOTE]`` / ``[WARNING]``... deviennent ``Note: ...``.
    """
    paragraphes: list[str] = []
    courant: list[str] = []  # lignes logiques du paragraphe en cours

    def flush() -> None:
        if courant:
            paragraphes.append("\n".join(clean_inline(c) for c in courant))
            courant.clear()

    i = 0
    while i < len(lines):
        brut = lines[i]
        line = brut.strip()
        adm = re.fullmatch(r"\[([A-Z]+)\]", line)
        if adm and adm.group(1) in _ADMONITIONS:
            flush()
            j = i + 1
            corps: list[str] = []
            if j < len(lines) and lines[j].strip() == "====":
                j += 1
                while j < len(lines) and lines[j].strip() != "====":
                    corps.append(lines[j])
                    j += 1
                j += 1
            else:  # admonition sur le paragraphe suivant
                while j < len(lines) and lines[j].strip():
                    corps.append(lines[j])
                    j += 1
            texte = " ".join(render_blocks(corps).split())
            paragraphes.append(f"{_ADMONITIONS[adm.group(1)]}: {texte}")
            i = j
            continue
        if line == "|===":
            flush()
            j = i + 1
            rows: list[str] = []
            while j < len(lines) and lines[j].strip() != "|===":
                cell = lines[j].strip()
                if cell.startswith("|"):
                    rows.append(cell)
                elif cell and rows:  # suite de la cellule precedente
                    rows[-1] += " " + cell
                elif not cell and j + 1 < len(lines) and not lines[j + 1].strip().startswith("|"):
                    break  # tableau non ferme (cas reel : Columns:__newindex)
                j += 1
            paragraphes.append(_table(rows))
            i = j + 1
            continue
        if line in ("----", "...."):
            flush()
            j = i + 1
            bloc: list[str] = []
            while j < len(lines) and lines[j].strip() != line:
                bloc.append(lines[j].rstrip())
                j += 1
            paragraphes.append("\n".join("  " + b if b else "" for b in bloc).strip("\n"))
            i = j + 1
            continue
        if line in ("====", "****", "--", "+") or _BLOCK_ATTR_RE.match(line):
            i += 1
            continue
        if re.match(r"^\.[A-Za-z]", line):  # titre de bloc (.Default colors)
            flush()
            courant.append(line[1:] + ":")
            flush()
            i += 1
            continue
        if not line:
            flush()
        elif m := _LIST_RE.match(line):
            courant.append("- " + m.group(2))
        elif courant:
            courant[-1] += " " + line
        else:
            courant.append(line)
        i += 1
    flush()
    return "\n\n".join(p for p in paragraphes if p.strip())


def split_description(lines: list[str]) -> tuple[str, list[str]]:
    """Separe le texte descriptif des blocs de code ``[source,...]``.

    Retourne ``(description, exemples)``. Les titres "Example" qui
    precedent un bloc de code sont retires de la description.
    """
    texte: list[str] = []
    exemples: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r"^\[source.*\]$", line.strip()) and i + 1 < len(lines):
            delim = lines[i + 1].strip()
            j = i + 2
            code: list[str] = []
            while j < len(lines) and lines[j].strip() != delim:
                code.append(lines[j])
                j += 1
            # dedent commun
            non_vides = [c for c in code if c.strip()]
            indent = min((len(c) - len(c.lstrip()) for c in non_vides), default=0)
            exemples.append("\n".join(c[indent:] for c in code).strip("\n"))
            # retirer un titre "Example" juste avant
            while texte and not texte[-1].strip():
                texte.pop()
            if texte and _EXAMPLE_TITLE_RE.match(texte[-1].strip()):
                texte.pop()
            i = j + 1
            continue
        if line.startswith("//") or line.strip() == "[float]":
            i += 1
            continue
        texte.append(line)
        i += 1

    # "===== Example" suivi de code brut (sans [source]) : cas reel Columns:__newindex
    for k, line in enumerate(texte):
        if line.strip().startswith("=") and _EXAMPLE_TITLE_RE.match(line.strip()):
            code = "\n".join(texte[k + 1 :]).strip("\n")
            if code:
                exemples.append(code)
            texte = texte[:k]
            break
    description = render_blocks(texte)
    return description, exemples


def paragraphs(lines: list[str]) -> list[str]:
    """Decoupe des lignes en paragraphes nettoyes."""
    return [p for p in split_description(lines)[0].split("\n\n") if p]


def extract_version(text: str) -> str:
    """Version Wireshark d'introduction mentionnee dans un texte, ou ''."""
    m = _VERSION_RE.search(text)
    return m.group(1) if m else ""


# --------------------------------------------------------------------------
# Parsing de l'AsciiDoc genere par make-wsluarm.py
# --------------------------------------------------------------------------


def _split_name(signature: str) -> tuple[str, str]:
    """``bytearray:len()`` -> (``len``, ``methode``) ; ``ByteArray.new()`` -> (``new``, ``constructeur``)."""
    ident = signature.split("(", 1)[0].strip()
    if ":" in ident:
        nom = ident.rsplit(":", 1)[1]
        return nom, "metamethode" if nom.startswith("__") else "methode"
    if "." in ident:
        return ident.rsplit(".", 1)[1], "constructeur"
    return ident, "fonction"


def parse_function(anchor: str, block: list[str]) -> dict[str, Any]:
    """Parse un bloc ``[#lua_fn_*]`` jusqu'a ``// function_footer:`` (exclu)."""
    signature = block[0].lstrip("=").strip() if block else ""
    nom, genre = _split_name(signature)
    desc_lines: list[str] = []
    arguments: list[dict[str, Any]] = []
    retours: list[str] = []
    erreurs: list[str] = []
    section = "description"
    arg_courant: dict[str, Any] | None = None
    arg_lines: list[str] = []
    ret_lines: list[str] = []
    exemples: list[str] = []

    for line in block[1:]:
        s = line.strip()
        if s in ("===== Arguments", "===== Returns", "===== Errors"):
            section = s.split()[1].lower()
            if desc_lines and desc_lines[-1].strip() == "[float]":
                desc_lines.pop()
            continue
        if section == "description":
            desc_lines.append(line)
        elif section == "arguments":
            if s.startswith("// function_arg_footer:"):
                if arg_courant is not None:
                    arg_courant["description"], ex = split_description(arg_lines)
                    exemples.extend(ex)
                    arguments.append(arg_courant)
                arg_courant, arg_lines = None, []
            elif arg_courant is None and (m := _ARG_RE.match(s)):
                arg_courant = {"nom": m.group(1), "type": "", "optionnel": bool(m.group(2)), "description": ""}
            elif arg_courant is not None:
                arg_lines.append(line)
        elif section == "returns":
            if not s.startswith("// function_returns_footer:"):
                ret_lines.append(line)
        elif section == "errors" and s.startswith("* "):
            erreurs.append(clean_inline(s[2:].strip()))

    description, ex_desc = split_description(desc_lines)
    retours = paragraphs(ret_lines)
    return {
        "nom": nom,
        "genre": genre,
        "signature": clean_inline(signature),
        "description": description,
        "arguments": arguments,
        "retours": retours,
        "erreurs": erreurs,
        "exemples": ex_desc + exemples,
        "section": f"lua_fn_{anchor}",
        "depuis_version": extract_version(description),
    }


def parse_attribute(anchor: str, block: list[str]) -> dict[str, Any]:
    """Parse un bloc ``[#lua_class_attrib_*]`` jusqu'a ``// End ...`` (exclu)."""
    nom_complet = block[0].lstrip("=").strip() if block else anchor
    description, exemples = split_description(block[1:])
    mode = ""
    m = re.match(r"^Mode:\s*(.+?)(?:\n\n|$)", description, re.DOTALL)
    if m:
        mode = {"Retrieve only.": "RO", "Assign only.": "WO", "Retrieve or assign.": "RW"}.get(m.group(1).strip(), "")
        description = description[m.end() :].strip()
    return {
        "nom": nom_complet.rsplit(".", 1)[-1],
        "nom_complet": nom_complet,
        "mode": mode,
        "description": description,
        "exemples": exemples,
        "section": f"lua_class_attrib_{anchor}",
        "depuis_version": extract_version(description),
    }


def _new_class(nom: str, module: str) -> dict[str, Any]:
    return {"nom": nom, "module": module, "description": "", "exemples": [], "methodes": [], "attributs": []}


def parse_adoc(text: str, classes: dict[str, dict[str, Any]] | None = None) -> dict[str, dict[str, Any]]:
    """Parse un fichier AsciiDoc produit par make-wsluarm.py.

    Accumule dans ``classes`` (nom de classe -> fiche) et le retourne.
    """
    classes = {} if classes is None else classes
    lines = text.splitlines()
    module = ""
    classe: dict[str, Any] | None = None
    class_desc: list[str] | None = None

    def fermer_description() -> None:
        nonlocal class_desc
        if classe is not None and class_desc is not None:
            desc, ex = split_description(class_desc)
            classe["description"] = "\n\n".join(p for p in (classe["description"], desc) if p)
            classe["exemples"].extend(ex)
        class_desc = None

    i = 0
    while i < len(lines):
        line = lines[i]
        m = _ANCHOR_RE.match(line.strip())
        if not m:
            if line.strip().startswith("// class_footer:") or line.strip() == "// end of module":
                fermer_description()
            elif class_desc is not None:
                class_desc.append(line)
            i += 1
            continue

        kind, anchor = m.groups()
        titre = lines[i + 1] if i + 1 < len(lines) else ""
        if kind == "lua_module":
            fermer_description()
            module, classe = anchor, None
            i += 2
        elif kind == "global_functions":
            fermer_description()
            classe = classes.setdefault(GLOBAL_CLASS, _new_class(GLOBAL_CLASS, ""))
            i += 2
        elif kind == "lua_class":
            fermer_description()
            nom = titre.lstrip("=").strip() or anchor
            classe = classes.setdefault(nom, _new_class(nom, module))
            class_desc = []
            i += 2
        else:
            fermer_description()
            fin = "// function_footer:" if kind == "lua_fn" else "// End "
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith(fin):
                j += 1
            block = lines[i + 1 : j]
            if classe is None:
                classe = classes.setdefault(GLOBAL_CLASS, _new_class(GLOBAL_CLASS, ""))
            if kind == "lua_fn":
                classe["methodes"].append(parse_function(anchor, block))
            else:
                classe["attributs"].append(parse_attribute(anchor, block))
            i = j + 1
    fermer_description()
    return classes


# --------------------------------------------------------------------------
# Generation de l'AsciiDoc depuis les sources Wireshark
# --------------------------------------------------------------------------


def wireshark_version(src: Path) -> str:
    """Lit ``PROJECT_{MAJOR,MINOR,PATCH}_VERSION`` dans le CMakeLists.txt racine."""
    text = (src / "CMakeLists.txt").read_text(encoding="utf-8")
    parts = [re.search(rf"set\(PROJECT_{k}_VERSION\s+(\d+)\)", text) for k in ("MAJOR", "MINOR", "PATCH")]
    if not all(parts):
        return ""
    return ".".join(p.group(1) for p in parts if p)


def wslua_modules(src: Path) -> list[Path]:
    """Liste ``WSLUA_MODULES`` de ``epan/wslua/CMakeLists.txt`` (meme liste que le build Wireshark)."""
    cmake = (src / "epan" / "wslua" / "CMakeLists.txt").read_text(encoding="utf-8")
    m = re.search(r"set\(WSLUA_MODULES(.*?)\)", cmake, re.DOTALL)
    if not m:
        raise ValueError("WSLUA_MODULES introuvable dans epan/wslua/CMakeLists.txt")
    noms = re.findall(r"([\w.-]+\.c)", m.group(1))
    return [src / "epan" / "wslua" / n for n in noms]


def generate_adoc(src: Path, out_dir: Path) -> list[Path]:
    """Lance ``tools/make-wsluarm.py`` du checkout Wireshark ; retourne les .adoc produits."""
    script = src / "tools" / "make-wsluarm.py"
    if not script.exists():
        raise FileNotFoundError(f"{script} introuvable (checkout Wireshark incomplet ?)")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(script), "--output-directory", str(out_dir), *map(str, wslua_modules(src))]
    subprocess.run(cmd, check=True, capture_output=True, text=True)  # noqa: S603
    return sorted(out_dir.glob("*.adoc"))


def clone_tag(tag: str, dest: Path) -> tuple[Path, str]:
    """Clone partiel (epan/wslua + tools) d'un tag Wireshark ; retourne (chemin, commit)."""
    git = ["git", "-c", "advice.detachedHead=false"]
    subprocess.run(  # noqa: S603
        [
            *git,
            "clone",
            "-q",
            "--depth",
            "1",
            "--branch",
            tag,
            "--filter=blob:none",
            "--sparse",
            WIRESHARK_GIT,
            str(dest),
        ],
        check=True,
    )
    subprocess.run([*git, "-C", str(dest), "sparse-checkout", "set", "epan/wslua", "tools"], check=True)  # noqa: S603
    commit = subprocess.run(  # noqa: S603
        [*git, "-C", str(dest), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    return dest, commit


# --------------------------------------------------------------------------
# Assemblage
# --------------------------------------------------------------------------


def build_api(adoc_files: list[Path], version: str, source: str) -> dict[str, Any]:
    """Parse les .adoc et assemble le JSON final (classes triees)."""
    classes: dict[str, dict[str, Any]] = {}
    for f in sorted(adoc_files):
        parse_adoc(f.read_text(encoding="utf-8"), classes)
    return {
        "version_wireshark": version,
        "date_generation": _dt.date.today().isoformat(),
        "source": source,
        "classes": {k: classes[k] for k in sorted(classes)},
    }


def main(argv: list[str] | None = None) -> int:
    logger.debug("main: entrée")
    parser = argparse.ArgumentParser(description="Extrait l'API Lua Wireshark (make-wsluarm.py) vers JSON.")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--tag", help="tag Wireshark a cloner (ex: v4.6.9)")
    src.add_argument("--wireshark-src", type=Path, help="checkout Wireshark existant")
    src.add_argument("--adoc-dir", type=Path, help="dossier de .adoc deja generes par make-wsluarm.py")
    parser.add_argument("--version", default="", help="version Wireshark (auto-detectee sauf avec --adoc-dir)")
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "lua_api.json")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="wslua-") as tmp:
        tmp_path = Path(tmp)
        if args.adoc_dir:
            adoc_files = sorted(args.adoc_dir.glob("*.adoc"))
            version = args.version
            source = f"make-wsluarm.py (AsciiDoc : {args.adoc_dir.name})"
        else:
            if args.tag:
                ws_src, commit = clone_tag(args.tag, tmp_path / "wireshark")
                ref = f"{args.tag} ({commit[:12]})"
            else:
                ws_src, ref = args.wireshark_src, str(args.wireshark_src)
            version = args.version or wireshark_version(ws_src)
            adoc_files = generate_adoc(ws_src, tmp_path / "adoc")
            source = f"wireshark {ref} : tools/make-wsluarm.py sur epan/wslua/*.c"
        if not adoc_files:
            print("Aucun fichier .adoc a parser", file=sys.stderr)
            return 1
        api = build_api(adoc_files, version, source)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(api, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    n_meth = sum(len(c["methodes"]) for c in api["classes"].values())
    n_attr = sum(len(c["attributs"]) for c in api["classes"].values())
    print(
        f"{args.output} : Wireshark {version or '?'}, {len(api['classes'])} classes, "
        f"{n_meth} fonctions/methodes, {n_attr} attributs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
