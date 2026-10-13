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

from netcross_core import lua_dissectors, lua_doc
from netcross_core.logging_config import add_debug_argument, apply_debug_argument, is_debug_enabled, summarize
from netcross_report.lua_dissectors_text import render_dissecteurs, render_domaines
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
        epilog="Exemples : netcross-lua-doc tvb range | netcross-lua-doc --class Tvb | netcross-lua-doc --classes"
        " | netcross-lua-doc --dissectors modbus | netcross-lua-doc --dissectors --domain jeux --non-native",
    )
    parser.add_argument("terme", nargs="*", help="recherche libre (classes, methodes, fonctions, attributs)")
    quoi = parser.add_mutually_exclusive_group()
    quoi.add_argument("--class", dest="classe", metavar="NOM", help="fiche complete d'une classe (ex: Tvb)")
    quoi.add_argument("--classes", action="store_true", help="liste les classes disponibles")
    quoi.add_argument(
        "--dissectors",
        action="store_true",
        help="catalogue des dissecteurs Wireshark en Lua (issue #917) : TERME cherche dans le depot, "
        "le protocole, le domaine et les topics",
    )
    quoi.add_argument("--domains", action="store_true", help="domaines du catalogue des dissecteurs, avec leur nombre")
    parser.add_argument("--domain", metavar="TEXTE", help="avec --dissectors : domaine contenant TEXTE (ex: jeux)")
    parser.add_argument(
        "--non-native",
        action="store_true",
        help="avec --dissectors : seulement les protocoles sans dissecteur natif dans Wireshark",
    )
    parser.add_argument("--full", action="store_true", help="detail complet de chaque resultat de recherche")
    parser.add_argument("--limit", type=int, default=20, help="nombre maximal de resultats (defaut 20)")
    parser.add_argument("--json", action="store_true", help="sortie JSON (usage scripte)")
    parser.add_argument(
        "--source", type=Path, help=f"JSON de l'API (defaut : ${lua_doc.ENV_JSON}, data/lua_api.json du depot/paquet)"
    )
    parser.add_argument("--db", type=Path, default=lua_doc.DEFAULT_DB_PATH, help="banque SQLite (cache)")
    parser.add_argument(
        "--catalog",
        type=Path,
        help=f"CSV des dissecteurs (defaut : ${lua_dissectors.ENV_CSV}, data/lua_dissectors.csv du depot/paquet)",
    )
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
    if (args.domain or args.non_native) and not args.dissectors:
        parser.error("--domain et --non-native s'utilisent avec --dissectors")
    if not (terme or args.classe or args.classes or args.dissectors or args.domains):
        parser.error("indiquer un terme de recherche, --class NOM, --classes, --dissectors ou --domains")
    if (args.classes or args.domains) and terme:
        parser.error("--classes et --domains ne prennent pas de terme de recherche")
    if args.limit < 1:
        parser.error("--limit doit etre >= 1")

    if "NETCROSS_LOG_LEVEL" not in os.environ and not is_debug_enabled():
        # sortie propre ; --debug ou NETCROSS_LOG_LEVEL=DEBUG pour diagnostiquer
        logger.disable("netcross_core.lua_doc")
        logger.disable("netcross_core.lua_dissectors")
    if args.dissectors or args.domains:
        logger.debug("main: catalogue des dissecteurs -> retour _run_dissectors(…)")
        return _run_dissectors(args, terme)
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


def _run_dissectors(args: argparse.Namespace, terme: str) -> int:
    """``--dissectors`` / ``--domains`` (issue #917) : n'a pas besoin du JSON de l'API."""
    args.db.parent.mkdir(parents=True, exist_ok=True)
    conn = lua_doc.connect(args.db)
    try:
        if not lua_dissectors.ensure_catalogue(conn, args.catalog):
            emplacements = ", ".join(str(p) for p in lua_dissectors.csv_candidates())
            print(f"Catalogue des dissecteurs Lua introuvable ({args.catalog or emplacements}).", file=sys.stderr)
            logger.debug("_run_dissectors: CSV introuvable -> retour 1")
            return 1
        if args.domains:
            doc = lua_dissectors.domains_document(conn)
            print(json.dumps(doc, ensure_ascii=False, indent=2) if args.json else "\n".join(render_domaines(doc)))
            logger.debug("_run_dissectors: --domains -> retour 0")
            return 0
        doc = lua_dissectors.search_document(conn, terme, args.domain, args.non_native, args.limit)
        if args.json:
            print(json.dumps(doc, ensure_ascii=False, indent=2))
        elif doc["total"]:
            _emit(render_dissecteurs(doc))
        else:
            print(f"Aucun dissecteur Lua pour « {terme or args.domain or ''} ».", file=sys.stderr)
        logger.debug("_run_dissectors: retour 0 if total else 1")
        return 0 if doc["total"] else 1
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
