#!/usr/bin/env python3
"""netcross annotations -- etiquettes et signets sur des trames, en CLI
(issue #910).

Meme fichier que la GUI (issue #363) : le sidecar
``<capture>.annotations.json`` pose a cote de la capture. Une annotation
posee ici apparait donc dans le panneau « Annotations / signets » de la GUI,
et inversement.

Usage :
    netcross annotations list CAPTURE [--tag T] [--json]
    netcross annotations add CAPTURE --frame N --tag T [--comment C] [--color COULEUR]
    netcross annotations remove CAPTURE --frame N --tag T

Code de sortie : 0 = succes, 1 = annotation absente / sidecar illisible /
capture introuvable, 2 = erreur d'usage (argparse).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from loguru import logger

from netcross_core.annotations import (
    add_annotation,
    annotation_to_dict,
    make_annotation,
    remove_annotation,
    sort_annotations,
)
from netcross_core.forensic import annotations_sidecar_path, read_annotations, write_annotations
from netcross_core.logging_config import add_debug_argument, apply_debug_argument


def build_parser() -> argparse.ArgumentParser:
    logger.debug("build_parser()")
    parser = argparse.ArgumentParser(
        prog="netcross annotations",
        description="Etiquettes et signets sur des trames, dans le sidecar <capture>.annotations.json "
        "partage avec la GUI (issue #910).",
        epilog="Exemples : netcross annotations add a.pcapng --frame 42 --tag suspect --comment 'RST inattendu' | "
        "netcross annotations list a.pcapng --json",
    )
    commun = argparse.ArgumentParser(add_help=False)
    commun.add_argument("--json", action="store_true", help="sortie JSON (liste du sidecar, usage scripte)")
    sub = parser.add_subparsers(dest="action", required=True, metavar="{list,add,remove}")

    lister = sub.add_parser("list", parents=[commun], help="affiche les annotations d'une capture")
    lister.add_argument("capture", help="fichier de capture (pcap/pcapng)")
    lister.add_argument("--tag", help="seulement cette etiquette")

    ajouter = sub.add_parser("add", parents=[commun], help="ajoute (ou met a jour) une annotation")
    ajouter.add_argument("capture", help="fichier de capture (pcap/pcapng)")
    ajouter.add_argument("--frame", required=True, help="numero de trame (>= 1, celui de Wireshark)")
    ajouter.add_argument("--tag", required=True, help="etiquette")
    ajouter.add_argument("--comment", default="", help="commentaire libre")
    ajouter.add_argument("--color", help="couleur d'affichage (ex. #ff0000)")

    retirer = sub.add_parser("remove", parents=[commun], help="supprime une annotation")
    retirer.add_argument("capture", help="fichier de capture (pcap/pcapng)")
    retirer.add_argument("--frame", required=True, help="numero de trame")
    retirer.add_argument("--tag", required=True, help="etiquette")
    return parser


def _print_list(annotations, as_json: bool) -> None:
    if as_json:
        print(json.dumps([annotation_to_dict(a) for a in annotations], ensure_ascii=False, indent=2))
        return
    if not annotations:
        print("aucune annotation")
        return
    for ann in annotations:
        suffix = f" -- {ann.comment}" if ann.comment else ""
        print(f"trame #{ann.frame_number} [{ann.tag}]{suffix}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    add_debug_argument(parser)
    args = parser.parse_args(argv)
    apply_debug_argument(args)
    if not os.path.isfile(args.capture):
        print(f"Capture introuvable : {args.capture}", file=sys.stderr)
        logger.debug("main: capture absente -> retour 1")
        return 1
    try:
        annotations = read_annotations(args.capture)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # sidecar corrompu : jamais reecrit (l'analyste peut vouloir le recuperer)
        logger.warning("annotations: sidecar illisible {} ({})", annotations_sidecar_path(args.capture), exc)
        print(f"Sidecar illisible : {annotations_sidecar_path(args.capture)} ({exc})", file=sys.stderr)
        return 1

    if args.action == "list":
        if args.tag:
            annotations = [a for a in annotations if a.tag == args.tag.strip()]
        _print_list(sort_annotations(annotations), args.json)
        return 0

    try:
        if args.action == "add":
            nouvelle = make_annotation(args.frame, args.tag, args.comment, args.color)
            annotations = add_annotation(annotations, nouvelle)
        else:
            annotations = remove_annotation(annotations, args.frame, args.tag)
    except ValueError as exc:
        logger.debug("main: saisie invalide ({})", exc)
        parser.error(str(exc))
    except KeyError as exc:
        logger.debug("main: annotation absente ({})", exc)
        print(f"Annotation introuvable : {exc.args[0]}", file=sys.stderr)
        return 1
    write_annotations(args.capture, annotations)
    _print_list(sort_annotations(annotations), args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
