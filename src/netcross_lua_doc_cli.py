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
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path

from loguru import logger

from netcross_core import lua_doc
from netcross_core.logging_config import add_debug_argument, apply_debug_argument, is_debug_enabled, summarize
from netcross_report.lua_doc_text import render_attribut, render_fiche, render_methode, render_resultats

# Rendu texte : netcross_report.lua_doc_text (partage avec la GUI, issue #873).
__all__ = ["build_parser", "main", "render_attribut", "render_fiche", "render_methode", "render_resultats"]


# ---------------------------------------------------------------------------
# Point d'entree
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    logger.debug("build_parser()")
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
    logger.debug("build_parser: retour parser={}", summarize(parser, "parser"))
    return parser


def _emit(lignes: list[str]) -> None:
    print("\n".join(lignes).rstrip())
    logger.debug("_emit: fin")


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
        logger.debug("main: si source is None or not source.is_file() -> retour 1")
        return 1

    conn = lua_doc.ensure_db(args.db, source)
    try:
        logger.debug("main: retour _run(…)")
        return _run(conn, args, terme)
    finally:
        conn.close()


def _run(conn: sqlite3.Connection, args: argparse.Namespace, terme: str) -> int:
    logger.debug(
        "_run: conn={} args={} terme={}",
        summarize(conn, "conn"),
        summarize(args, "args"),
        summarize(terme, "terme"),
    )
    meta = lua_doc.get_meta(conn)
    version = meta.get("version_wireshark", "")

    if args.classes:
        noms = lua_doc.list_classes(conn)
        if args.json:
            print(json.dumps({"meta": meta, "classes": noms}, ensure_ascii=False, indent=2))
        else:
            _emit([f"{len(noms)} classes -- Wireshark {version}", "", *(f"  {n}" for n in noms)])
        logger.debug("_run: si args.classes -> retour 0")
        return 0

    if args.classe:
        fiche = lua_doc.get_class(conn, args.classe)
        if fiche is None:
            suggestion = lua_doc.suggest_classes(conn, args.classe)
            msg = f"Classe inconnue : {args.classe}"
            if suggestion:
                msg += f" (voir : {', '.join(suggestion)})"
            print(msg, file=sys.stderr)
            logger.debug("_run: si fiche is None -> retour 1")
            return 1
        if args.json:
            print(json.dumps({"meta": meta, "classe": asdict(fiche)}, ensure_ascii=False, indent=2))
        else:
            _emit(render_fiche(fiche, version))
        logger.debug("_run: si args.classe -> retour 0")
        return 0

    if args.json:
        # meme document que GET /lua-doc/search (issue #873)
        doc = lua_doc.search_document(conn, terme, args.limit, args.full)
        print(json.dumps(doc, ensure_ascii=False, indent=2))
        logger.debug("_run: si args.json -> retour 0 if resultats else 1")
        return 0 if doc["resultats"] else 1
    res = lua_doc.search(conn, terme, args.limit)
    if not res:
        print(f"Aucun resultat pour « {terme} » (Wireshark {version}).", file=sys.stderr)
        logger.debug("_run: si not res -> retour 1")
        return 1
    _emit(render_resultats(conn, terme, res, args.full))
    logger.debug("_run: retour 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
