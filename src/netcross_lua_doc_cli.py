#!/usr/bin/env python3
"""netcross_lua_doc_cli -- consultation hors ligne de l'API Lua Wireshark
(issue #388, rattachee a #331).

    # recherche libre (FTS) sur les classes, methodes, fonctions et attributs
    netcross-lua-doc tvb range
    netcross lua-doc "source port"          # meme chose depuis la CLI principale

    # fiche complete d'une classe : methodes, arguments, retours, exemples, attributs
    netcross-lua-doc --class Tvb

    # detail complet de chaque resultat, sortie JSON pour les scripts
    netcross-lua-doc --full ProtoField.uint32
    netcross-lua-doc --json --class Pinfo | jq '.attributs[].nom_complet'

    # liste des classes
    netcross-lua-doc --classes

La banque SQLite (netcross_core.lua_doc, #387) est construite a la volee
dans ~/.cache/netcross/lua_api.db depuis data/lua_api.json (#386), puis
reconstruite automatiquement quand ce JSON change. Aucun acces reseau.

Codes de retour : 0 = resultat affiche, 1 = aucun resultat / classe
inconnue / JSON introuvable, 2 = erreur d'usage (argparse).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import textwrap
from dataclasses import asdict
from pathlib import Path
from typing import Any

from loguru import logger

from netcross_core import lua_doc
from netcross_core.logging_config import add_debug_argument, apply_debug_argument, is_debug_enabled
from netcross_core.lua_doc import Attribut, FicheClasse, Methode, ResultatRecherche

_INDENT = "    "


# ---------------------------------------------------------------------------
# Rendu texte
# ---------------------------------------------------------------------------


def _largeur() -> int:
    return max(60, min(shutil.get_terminal_size((100, 24)).columns, 120))


def _wrap(texte: str, indent: str) -> list[str]:
    """Replie un texte au format de data/lua_api.json, avec un retrait.

    Paragraphes separes par une ligne vide ; une ligne par puce (``- ``) ;
    les lignes commencant par deux espaces (tableaux, blocs litteraux)
    sont preformatees et ne sont pas repliees.
    """
    lignes: list[str] = []
    for i, para in enumerate(p for p in texte.split("\n\n") if p.strip()):
        if i:
            lignes.append("")
        for ligne in para.split("\n"):
            if ligne.startswith("  ") or not ligne.strip():
                lignes.append((indent + ligne).rstrip())
                continue
            suite = indent + ("  " if ligne.startswith("- ") else "")
            lignes += textwrap.wrap(ligne, _largeur(), initial_indent=indent, subsequent_indent=suite) or [indent]
    return lignes


def _resume(texte: str, n: int = 110) -> str:
    """Premiere phrase (ou debut) d'une description, sur une ligne."""
    premier = " ".join(texte.split("\n\n", 1)[0].split())
    phrase = premier.split(". ", 1)[0]
    phrase = phrase if phrase.endswith(".") or len(phrase) == len(premier) else phrase + "."
    return phrase if len(phrase) <= n else phrase[: n - 1].rstrip() + "…"


def _code(code: str, indent: str) -> list[str]:
    return [indent + ligne if ligne else "" for ligne in code.splitlines()]


def render_methode(m: Methode, indent: str = "") -> list[str]:
    """Fiche d'une methode ou fonction, en texte."""
    sous = indent + _INDENT
    lignes = [f"{indent}{m.signature}"]
    if m.description:
        lignes += _wrap(m.description, sous)
    if m.parametres:
        lignes.append(f"{sous}Arguments :")
        for p in m.parametres:
            nom = p.nom + (" (optionnel)" if p.optionnel else "") + (f" : {p.type}" if p.type else "")
            lignes.append(f"{sous}{_INDENT}{nom}")
            if p.description:
                lignes += _wrap(p.description, sous + _INDENT * 2)
    for r in m.retours:
        lignes += _wrap(f"Retourne : {r}", sous)
    for e in m.erreurs:
        lignes += _wrap(f"Erreur : {e}", sous)
    if m.depuis_version:
        lignes.append(f"{sous}Depuis Wireshark {m.depuis_version}")
    for ex in m.exemples:
        lignes.append(f"{sous}Exemple :")
        lignes += _code(ex, sous + _INDENT)
    return lignes


_MODES = {"RO": "lecture seule", "WO": "ecriture seule", "RW": "lecture/ecriture"}


def render_attribut(a: Attribut, indent: str = "") -> list[str]:
    """Fiche d'un attribut, en texte."""
    mode = f"  [{_MODES.get(a.mode, a.mode)}]" if a.mode else ""
    lignes = [f"{indent}{a.nom_complet}{mode}"]
    if a.description:
        lignes += _wrap(a.description, indent + _INDENT)
    if a.depuis_version:
        lignes.append(f"{indent}{_INDENT}Depuis Wireshark {a.depuis_version}")
    return lignes


def render_fiche(f: FicheClasse, version: str) -> list[str]:
    """Fiche complete d'une classe, en texte."""
    entete = f.nom + (f"  (module {f.module})" if f.module else "") + (f"  -- Wireshark {version}" if version else "")
    lignes = [entete, "=" * len(entete)]
    if f.description:
        lignes += ["", *_wrap(f.description, "")]
    for ex in f.exemples:
        lignes += ["", "Exemple :", *_code(ex, _INDENT)]
    if f.methodes:
        titre = "Fonctions" if f.nom == "GlobalFunctions" else "Methodes"
        lignes += ["", f"{titre} ({len(f.methodes)})", ""]
        for m in f.methodes:
            lignes += [*render_methode(m, _INDENT), ""]
    if f.attributs:
        lignes += ["", f"Attributs ({len(f.attributs)})", ""]
        for a in f.attributs:
            lignes += [*render_attribut(a, _INDENT), ""]
    return lignes


def render_resultats(conn: sqlite3.Connection, terme: str, res: list[ResultatRecherche], full: bool) -> list[str]:
    """Liste des resultats de recherche, en texte."""
    version = lua_doc.get_meta(conn).get("version_wireshark", "")
    lignes = [f"{len(res)} resultat(s) pour « {terme} »" + (f" -- Wireshark {version}" if version else ""), ""]
    for r in res:
        if full:
            detail = lua_doc.get_attribut(conn, r.ref_id) if r.est_attribut else lua_doc.get_methode(conn, r.ref_id)
            if isinstance(detail, Methode):
                lignes += [f"[{r.classe}]", *render_methode(detail, _INDENT), ""]
                continue
            if isinstance(detail, Attribut):
                lignes += [f"[{r.classe}]", *render_attribut(detail, _INDENT), ""]
                continue
        genre = "attribut" if r.est_attribut else r.genre
        lignes.append(f"  {r.signature}   [{r.classe}, {genre}]")
        if r.description:
            lignes.append(f"      {_resume(r.description)}")
    classes = sorted({r.classe for r in res})
    if not full and classes:
        lignes += ["", f"Fiche complete : --class {classes[0]}" + (" (ou --full)" if len(res) > 1 else "")]
    return lignes


# ---------------------------------------------------------------------------
# Sortie JSON
# ---------------------------------------------------------------------------


def _json_resultats(conn: sqlite3.Connection, terme: str, res: list[ResultatRecherche], full: bool) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for r in res:
        item = asdict(r)
        item["est_attribut"] = r.est_attribut
        if full:
            detail = lua_doc.get_attribut(conn, r.ref_id) if r.est_attribut else lua_doc.get_methode(conn, r.ref_id)
            item["detail"] = asdict(detail) if detail else None
        items.append(item)
    return {"meta": lua_doc.get_meta(conn), "terme": terme, "resultats": items}


# ---------------------------------------------------------------------------
# Point d'entree
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netcross-lua-doc",
        description="Documentation hors ligne de l'API Lua Wireshark (issue #388).",
        epilog="Exemples : netcross-lua-doc tvb range | netcross-lua-doc --class Tvb | netcross-lua-doc --classes",
    )
    parser.add_argument("terme", nargs="*", help="recherche libre (classes, methodes, fonctions, attributs)")
    quoi = parser.add_mutually_exclusive_group()
    quoi.add_argument("--class", dest="classe", metavar="NOM", help="fiche complete d'une classe (ex: Tvb)")
    quoi.add_argument("--classes", action="store_true", help="liste les classes disponibles")
    parser.add_argument("--full", action="store_true", help="detail complet de chaque resultat de recherche")
    parser.add_argument("--limit", type=int, default=20, help="nombre maximal de resultats (defaut 20)")
    parser.add_argument("--json", action="store_true", help="sortie JSON (usage scripte)")
    parser.add_argument(
        "--source", type=Path, help=f"JSON de l'API (defaut : ${lua_doc.ENV_JSON}, data/lua_api.json du depot/paquet)"
    )
    parser.add_argument("--db", type=Path, default=lua_doc.DEFAULT_DB_PATH, help="banque SQLite (cache)")
    return parser


def _emit(lignes: list[str]) -> None:
    print("\n".join(lignes).rstrip())


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    add_debug_argument(parser)
    args = parser.parse_args(argv)
    apply_debug_argument(args)
    terme = " ".join(args.terme).strip()
    if not (terme or args.classe or args.classes):
        parser.error("indiquer un terme de recherche, --class NOM ou --classes")
    if args.classes and terme:
        parser.error("--classes ne prend pas de terme de recherche")
    if args.limit < 1:
        parser.error("--limit doit etre >= 1")

    if "NETCROSS_LOG_LEVEL" not in os.environ and not is_debug_enabled():
        # sortie propre ; --debug ou NETCROSS_LOG_LEVEL=DEBUG pour diagnostiquer
        logger.disable("netcross_core.lua_doc")
    source = args.source or lua_doc.find_json()
    if source is None or not source.is_file():
        emplacements = ", ".join(str(p) for p in lua_doc.json_candidates())
        print(
            f"JSON de l'API Lua introuvable ({args.source or emplacements}). "
            "Le generer avec : python3 tools/extract_lua_api.py --tag vX.Y.Z",
            file=sys.stderr,
        )
        return 1

    conn = lua_doc.ensure_db(args.db, source)
    try:
        return _run(conn, args, terme)
    finally:
        conn.close()


def _run(conn: sqlite3.Connection, args: argparse.Namespace, terme: str) -> int:
    meta = lua_doc.get_meta(conn)
    version = meta.get("version_wireshark", "")

    if args.classes:
        noms = lua_doc.list_classes(conn)
        if args.json:
            print(json.dumps({"meta": meta, "classes": noms}, ensure_ascii=False, indent=2))
        else:
            _emit([f"{len(noms)} classes -- Wireshark {version}", "", *(f"  {n}" for n in noms)])
        return 0

    if args.classe:
        fiche = lua_doc.get_class(conn, args.classe)
        if fiche is None:
            proches = [r.classe for r in lua_doc.search(conn, args.classe, 50)]
            suggestion = sorted(set(proches))[:5]
            msg = f"Classe inconnue : {args.classe}"
            if suggestion:
                msg += f" (voir : {', '.join(suggestion)})"
            print(msg, file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps({"meta": meta, "classe": asdict(fiche)}, ensure_ascii=False, indent=2))
        else:
            _emit(render_fiche(fiche, version))
        return 0

    res = lua_doc.search(conn, terme, args.limit)
    if args.json:
        print(json.dumps(_json_resultats(conn, terme, res, args.full), ensure_ascii=False, indent=2))
        return 0 if res else 1
    if not res:
        print(f"Aucun resultat pour « {terme} » (Wireshark {version}).", file=sys.stderr)
        return 1
    _emit(render_resultats(conn, terme, res, args.full))
    return 0


if __name__ == "__main__":
    sys.exit(main())
