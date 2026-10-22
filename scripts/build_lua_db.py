#!/usr/bin/env python3
"""
scripts/build_lua_db.py -- charge le JSON de l'API Lua Wireshark (#386)
dans la banque SQLite locale (netcross_core.lua_doc), issue #387.

Aucun acces reseau : le JSON est produit en amont par
tools/extract_lua_api.py. La base est videe puis rechargee a chaque
execution, pour pouvoir la regenerer a chaque nouvelle version de
Wireshark.

Usage :
    python3 scripts/build_lua_db.py
    python3 scripts/build_lua_db.py --input data/lua_api.json --db data/lua_api.db
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from loguru import logger

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from netcross_core.lua_doc import connect, get_meta, load_json_file  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    logger.debug("main: entrée")
    parser = argparse.ArgumentParser(description="Construit la banque SQLite de l'API Lua Wireshark.")
    parser.add_argument("--input", type=Path, default=ROOT / "data" / "lua_api.json", help="JSON produit par #386")
    parser.add_argument("--db", type=Path, default=ROOT / "data" / "lua_api.db", help="fichier SQLite de sortie")
    args = parser.parse_args(argv)

    if not args.input.exists():
        print(f"JSON introuvable : {args.input} (lancer tools/extract_lua_api.py)", file=sys.stderr)
        return 1

    args.db.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(args.db)
    try:
        counts = load_json_file(conn, args.input)
        meta = get_meta(conn)
    finally:
        conn.close()

    print(f"Banque Lua ecrite dans {args.db} (Wireshark {meta.get('version_wireshark', '?')})")
    for table, n in counts.items():
        print(f"  {table}: {n}")
    logger.debug("main: retour")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
