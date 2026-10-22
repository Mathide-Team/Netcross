#!/usr/bin/env python3
"""Normalise le recensement des dissecteurs Lua (dépôt Mathilde-Team/wireshark-lua,
CSV joint à l'issue #559) en ``data/lua_dissectors.csv`` (issue #917).

    python3 scripts/import_lua_dissectors.py recensement.csv [autre.csv ...]
    python3 scripts/import_lua_dissectors.py --check   # le CSV versionné est-il normalisé ?

Plusieurs CSV peuvent être fusionnés (nouvelles listes) : une URL déjà vue
garde sa première ligne. Sortie triée par domaine puis dépôt, colonnes du
recensement, fins de ligne LF ; la banque Lua se recharge seule au prochain
appel (empreinte du CSV).
"""

from __future__ import annotations

import argparse
import csv
import io
import sys
from pathlib import Path

from loguru import logger  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from netcross_core.lua_dissectors import COLONNES, CatalogueError, read_csv  # noqa: E402

CIBLE = ROOT / "data" / "lua_dissectors.csv"


def normaliser(textes: list[str]) -> str:
    vus: dict[str, dict[str, str]] = {}
    for texte in textes:
        bruts = {r["url"].strip().rstrip("/").lower(): r for r in csv.DictReader(io.StringIO(texte.lstrip("\ufeff")))}
        for ligne in read_csv(texte):  # valide chaque ligne
            cle = ligne["url"].lower()
            if cle not in vus:
                brut = bruts[cle]
                vus[cle] = {c: (brut.get(c) or "").strip() for c in COLONNES} | {"url": ligne["url"]}
    sortie = io.StringIO()
    ecrivain = csv.DictWriter(sortie, fieldnames=COLONNES, lineterminator="\n")
    ecrivain.writeheader()
    for ligne in sorted(vus.values(), key=lambda r: (r["domaine"].lower(), r["url"].lower())):
        ecrivain.writerow(ligne)
    return sortie.getvalue()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("csv", nargs="*", type=Path, help="CSV du recensement (défaut : le CSV versionné)")
    ap.add_argument("--check", action="store_true", help="vérifie que data/lua_dissectors.csv est normalisé")
    ap.add_argument("--output", type=Path, default=CIBLE)
    args = ap.parse_args(argv)
    sources = args.csv or [CIBLE]
    try:
        texte = normaliser([p.read_text(encoding="utf-8") for p in sources])
    except (OSError, CatalogueError) as exc:
        logger.error("Import impossible : {}", exc)
        print(f"Import impossible : {exc}", file=sys.stderr)
        return 1
    if args.check:
        if CIBLE.read_text(encoding="utf-8") != texte:
            print(f"{CIBLE} n'est pas normalisé : relancer scripts/import_lua_dissectors.py", file=sys.stderr)
            return 1
        print(f"{CIBLE} est normalisé ({texte.count(chr(10)) - 1} dissecteurs).")
        return 0
    args.output.write_text(texte, encoding="utf-8")
    print(f"{args.output} : {texte.count(chr(10)) - 1} dissecteurs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
