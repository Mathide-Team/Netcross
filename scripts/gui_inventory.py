#!/usr/bin/env python3
"""Inventaire mesure de ``src/netcross_gtk4/app.py`` (issue #285).

Classe chaque methode selon qu'elle nomme directement ``Gtk``/``Gio``/
``GLib``/``Gdk``/``Pango`` (ou est un ``__init__`` de construction de
widgets), et compte ses instructions. Sert a chiffrer la part du fichier
qu'aucun test sans serveur graphique ne peut executer.

Usage : ``python3 scripts/gui_inventory.py [chemin] [--top N]``
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

from loguru import logger

GUI_NAMES = frozenset({"Gtk", "Gio", "GLib", "Gdk", "Pango"})
DEFAULT_PATH = Path(__file__).resolve().parents[1] / "src" / "netcross_gtk4" / "app.py"


def _instructions(node: ast.AST) -> int:
    return sum(isinstance(n, ast.stmt) for n in ast.walk(node)) - 1


def _touche_gtk(node: ast.AST) -> bool:
    return any(isinstance(n, ast.Name) and n.id in GUI_NAMES for n in ast.walk(node))


def inventaire(source: str) -> dict:
    arbre = ast.parse(source)
    gtk: list[tuple[int, str]] = []
    sans_gtk: list[tuple[int, str]] = []
    for classe in (n for n in arbre.body if isinstance(n, ast.ClassDef)):
        for methode in (m for m in classe.body if isinstance(m, ast.FunctionDef)):
            entree = (_instructions(methode), f"{classe.name}.{methode.name}")
            (gtk if methode.name == "__init__" or _touche_gtk(methode) else sans_gtk).append(entree)
    return {
        "lignes": len(source.splitlines()),
        "gtk": sorted(gtk, reverse=True),
        "sans_gtk": sorted(sans_gtk, reverse=True),
    }


def main(argv: list[str] | None = None) -> int:
    logger.debug("main: entrée")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", nargs="?", type=Path, default=DEFAULT_PATH)
    parser.add_argument("--top", type=int, default=15, help="methodes sans GTK a lister (defaut : 15)")
    args = parser.parse_args(argv)
    inv = inventaire(args.path.read_text(encoding="utf-8"))
    for cle, titre in (("gtk", "touchant GTK ou __init__"), ("sans_gtk", "sans objet GTK nomme")):
        methodes = inv[cle]
        print(f"Methodes {titre} : {len(methodes)} -- {sum(n for n, _ in methodes)} instructions")
    print(f"Lignes : {inv['lignes']}")
    print(f"\nPlus grosses methodes sans objet GTK nomme (top {args.top}) :")
    for nombre, nom in inv["sans_gtk"][: args.top]:
        print(f"  {nombre:4d}  {nom}")
    logger.debug("main: retour")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
