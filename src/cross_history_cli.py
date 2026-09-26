#!/usr/bin/env python3
"""
cross_history_cli.py -- interroge une base d'historique SQLite deja
alimentee par cross_capture_analyzer_cli.py/cross_capture_diff_cli.py
(--history-db), sans relancer d'analyse ni de comparaison.

Piste laissee ouverte en Session 29 (voir FEATURES.md section 5.2 et
claude.md Session 29, "Non traite dans cette passe") : --history-show
sur les deux autres CLI n'affiche l'historique qu'APRES un run normal
(--capture/--baseline/--current y restent obligatoires) -- ce script est
le point d'entree dedie a la consultation seule, pour verifier une
tendance sans avoir de nouvelles captures sous la main.

Toute la logique (lecture, filtrage, rendu texte) vit deja dans
netcross_report.history (list_history/print_history), ecrit en Session
29 : ce fichier ne fait que lire les arguments et appeler ce module, ni
plus ni moins que cross_capture_analyzer_cli.py vis-a-vis de
netcross_core.

Prerequis : aucun -- sqlite3/json/datetime sont dans la bibliotheque
standard, comme le reste de netcross_report.history. Pas besoin de
tshark : ce script ne lit jamais de capture, seulement une base .db deja
alimentee par les deux autres CLI.

Exemple d'utilisation (tout l'historique d'un fichier) :
    python3 cross_history_cli.py --db suivi_site_a.db

Exemple d'utilisation (10 derniers runs d'un site donne, tous types
confondus) :
    python3 cross_history_cli.py --db suivi_partage.db \
        --label Site-A --limit 10

Exemple d'utilisation (seulement les comparaisons -- pas les runs
d'analyse simple -- d'un fichier partage entre plusieurs sites) :
    python3 cross_history_cli.py --db suivi_partage.db --run-type diff
"""

import argparse
import sys

from netcross_core.logging_config import add_debug_argument, apply_debug_argument, get_logger
from netcross_report import HistoryDatabaseError, list_history, print_history

logger = get_logger(__name__)


def main():
    ap = argparse.ArgumentParser(description="Interroge un historique netcross (--history-db) sans relancer d'analyse.")
    ap.add_argument(
        "--db",
        required=True,
        metavar="CHEMIN",
        help="Base SQLite alimentee par --history-db sur cross_capture_analyzer_cli.py/"
        "cross_capture_diff_cli.py. Un chemin inexistant n'est pas une erreur : affiche "
        "simplement un historique vide (aucun run n'y a encore ete enregistre).",
    )
    ap.add_argument(
        "--label",
        metavar="ETIQUETTE",
        help="Ne montre que les runs portant cette etiquette exacte (voir --history-label "
        "sur les deux autres CLI) -- utile sur un fichier .db partage entre plusieurs "
        "sites/scenarios.",
    )
    ap.add_argument(
        "--run-type",
        choices=["analyse", "diff"],
        help="Ne montre que les runs de ce type -- par defaut, analyses et comparaisons "
        "sont melangees dans l'ordre plus recent d'abord, comme --history-show sur les "
        "deux autres CLI.",
    )
    ap.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="Nombre maximum de runs affiches (defaut : tous). Toujours les plus recents "
        "en premier (voir netcross_report.history.list_history).",
    )
    add_debug_argument(ap)
    args = ap.parse_args()
    apply_debug_argument(args)

    if args.limit is not None and args.limit <= 0:
        print("--limit doit etre un entier strictement positif.", file=sys.stderr)
        sys.exit(1)

    try:
        entries = list_history(args.db, limit=args.limit, label=args.label, run_type=args.run_type)
    except HistoryDatabaseError as exc:
        # Un fichier qui existe mais n'est pas une base netcross : message
        # nommant le chemin plutot qu'une trace sqlite3 brute (issue #287).
        logger.exception(f"échec dans main: {exc}")
        print(exc, file=sys.stderr)
        sys.exit(1)
    print_history(entries)


if __name__ == "__main__":
    main()
