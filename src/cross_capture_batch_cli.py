#!/usr/bin/env python3
"""
Mode batch (issue #277) : expertise de toutes les captures d'un dossier,
et analyse croisee automatique des captures qui semblent etre plusieurs
points de vue d'un meme evenement.

    python3 src/cross_capture_batch_cli.py --input /data/incident-4412 --output rapports/

Deroulement :

1. inventaire : chaque capture est decodee une fois pour en extraire la
   fenetre temporelle, les IP et les conversations (netcross_core.batch) ;
   une capture illisible n'arrete PAS le lot, elle est listee en echec avec
   son motif ;
2. regroupement conservateur (trois criteres, tous requis -- voir
   netcross_core.batch) avec justification ecrite de chaque decision ;
3. un rapport par capture, un rapport croise par groupe ;
4. un index de lot (index.txt) : groupes + justification, captures isolees
   + motif, echecs + motif, synthese.

Code de sortie : 0 si tout a ete traite, 2 si au moins une capture est en
echec (le lot est quand meme alle au bout), 1 sur erreur d'utilisation.
"""

import argparse
import os
import sys

from netcross_core.logging_config import add_debug_argument, apply_debug_argument, get_logger, summarize

# Moteur commun CLI / API / GUI (issue #872) : noms re-exportés pour les
# appels existants (``cross_capture_batch_cli.list_captures`` ...).
from netcross_report import batch_runner
from netcross_report.batch_runner import (  # noqa: F401 -- re-exports
    CACHE_DIR,
    CAPTURE_EXTENSIONS,
    DEFAULT_GROUP_WINDOW,
    DEFAULT_MIN_COMMON_IPS,
    DEFAULT_MIN_OVERLAP,
    SERIOUS_SEVERITIES,
    BatchOptions,
    analyse_and_write,
    build_inventory,
    build_synthesis,
    check_options,
    collect_inventories,
    list_captures,
    load_cached_inventory,
    make_labels,
    run_analyses,
    run_batch,
    save_cached_inventory,
)

logger = get_logger(__name__)


def main(argv=None):
    logger.debug("main: argv={}", summarize(argv, "argv"))
    ap = argparse.ArgumentParser(
        description="Expertise toutes les captures d'un dossier et tente l'analyse croisee des captures "
        "qui semblent observer le meme evenement (issue #277)."
    )
    ap.add_argument("--input", required=True, metavar="DOSSIER", help="Dossier contenant les captures.")
    ap.add_argument("--output", required=True, metavar="DOSSIER", help="Dossier des rapports (cree si absent).")
    ap.add_argument("--recursive", action="store_true", help="Parcourt aussi les sous-dossiers.")
    ap.add_argument("--no-group", action="store_true", help="Aucun regroupement : chaque capture est analysee seule.")
    ap.add_argument(
        "--group-window",
        type=float,
        default=DEFAULT_GROUP_WINDOW,
        metavar="SECONDES",
        help=f"Decalage d'horloge maximal tolere entre deux captures (defaut {DEFAULT_GROUP_WINDOW:g} s). "
        "Un decalage estime dans cette fenetre est corrige avant le calcul du recouvrement, et mentionne.",
    )
    ap.add_argument(
        "--min-overlap",
        type=float,
        default=DEFAULT_MIN_OVERLAP,
        metavar="RATIO",
        help=f"Recouvrement temporel minimal, en fraction de la plus courte capture (defaut {DEFAULT_MIN_OVERLAP}).",
    )
    ap.add_argument(
        "--min-common-ips",
        type=int,
        default=DEFAULT_MIN_COMMON_IPS,
        metavar="N",
        help=f"Nombre minimal d'IP communes hors infrastructure (defaut {DEFAULT_MIN_COMMON_IPS}).",
    )
    ap.add_argument(
        "--jobs",
        type=int,
        default=1,
        metavar="N",
        help="Captures inventoriees en parallele (defaut 1 : le decodage est deja parallelise en interne, "
        "empiler les deux niveaux sur un gros lot sature la memoire -- voir #283).",
    )
    ap.add_argument(
        "--skip-existing",
        action="store_true",
        help="Reprise d'un lot interrompu : reutilise les inventaires en cache et les rapports deja ecrits.",
    )
    ap.add_argument("--security-report", action="store_true", help="Ajoute l'analyse de securite a chaque rapport.")
    add_debug_argument(ap)
    args = ap.parse_args(argv)
    apply_debug_argument(args)

    if not os.path.isdir(args.input):
        print(f"--input : dossier introuvable : {args.input}", file=sys.stderr)
        sys.exit(1)
    options = BatchOptions(
        recursive=args.recursive,
        group=not args.no_group,
        group_window=args.group_window,
        min_overlap=args.min_overlap,
        min_common_ips=args.min_common_ips,
        jobs=args.jobs,
        skip_existing=args.skip_existing,
        security_report=args.security_report,
    )
    refus = check_options(options)
    if refus:
        print(refus, file=sys.stderr)
        sys.exit(1)

    captures, ignored = list_captures(args.input, args.recursive)
    if not captures:
        print(f"Aucune capture ({', '.join(CAPTURE_EXTENSIONS)}) dans {args.input}.", file=sys.stderr)
        sys.exit(1)
    result = batch_runner.run_batch(captures, ignored, args.output, options, args.input, _progress)
    print()
    print(result.index, end="")
    print(f"\nIndex du lot ecrit dans {result.index_path}")
    if result.has_failures:
        sys.exit(2)
    logger.debug("main: fin")


def _progress(message: str) -> None:
    """Avancement : échecs d'analyse sur stderr, le reste sur stdout (comme avant #872)."""
    print(message, file=sys.stderr if " : ECHEC -- " in message and "inventaire" not in message else sys.stdout)


if __name__ == "__main__":
    main()
