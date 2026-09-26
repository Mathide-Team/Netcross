#!/usr/bin/env python3
"""netcross_ai_models_cli -- paquets de modeles IA partageables et boite
d'envoi hors connexion (issue #271).

    # 1. exporter la baseline locale (bon etat transactionnel) en paquet ZIP
    python3 src/netcross_ai_models_cli.py export --baseline base.json --name bureau-lan --consent -o bureau-lan.zip
    # 2. le verifier, le mettre en file pour une remontee ulterieure
    python3 src/netcross_ai_models_cli.py inspect bureau-lan.zip
    python3 src/netcross_ai_models_cli.py outbox add bureau-lan.zip
    # 3. une fois connecte : ticket « modeles » pre-rempli, archive a joindre
    python3 src/netcross_ai_models_cli.py outbox send --open
    python3 src/netcross_ai_models_cli.py outbox done bureau-lan
    # 4. enrichir sa base locale avec un paquet de la base commune
    python3 src/netcross_ai_models_cli.py import commun.zip --baseline base.json --training entrainement.json

Aucune donnee n'est envoyee par Netcross : ``outbox send`` teste seulement la
connectivite et prepare l'URL du ticket (voir netcross_ai.outbox).
Ne necessite pas scikit-learn (seuls des fichiers JSON/ZIP sont manipules).
"""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from netcross_ai.anomaly import Baseline, BaselineError
from netcross_ai.flow_classifier import TrainingSetError, load_training_set
from netcross_ai.model_pack import ModelPackError, build_pack, import_pack, read_pack
from netcross_ai.outbox import (
    DEFAULT_OUTBOX,
    DEFAULT_REPO,
    is_online,
    mark_sent,
    pending,
    queue_pack,
    submission,
)
from netcross_core.logging_config import add_debug_argument, apply_debug_argument, get_logger

logger = get_logger(__name__)

EXIT_OFFLINE = 3


def _print_pack(summary: dict) -> None:
    labels = ", ".join(f"{k}={v}" for k, v in summary["labels"].items()) or "-"
    print(f"Paquet {summary['name']} (cree le {summary['created']})")
    if summary["description"]:
        print(f"  {summary['description']}")
    print(f"  baseline : {summary['baseline_vectors']} flux ({summary['baseline_label'] or 'sans libelle'})")
    print(f"  exemples etiquetes : {summary['training_samples']} ({labels})")


def _cmd_export(args) -> int:
    baseline = Baseline.load(args.baseline) if args.baseline else None
    training = load_training_set(args.training) if args.training else None
    pack = build_pack(
        args.output,
        name=args.name,
        consent=args.consent,
        baseline=baseline,
        training=training,
        description=args.description,
    )
    print(f"Paquet ecrit : {args.output}")
    _print_pack(pack.summary())
    if args.queue:
        print(f"Mis en file : {queue_pack(args.output, args.outbox)}")
    return 0


def _cmd_inspect(args) -> int:
    pack = read_pack(args.pack)
    if args.json:
        print(json.dumps(pack.summary(), ensure_ascii=False, indent=1))
    else:
        print("Archive verifiee (contenu attendu, empreintes SHA-256, schemas).")
        _print_pack(pack.summary())
    return 0


def _cmd_import(args) -> int:
    result = import_pack(args.pack, baseline_path=args.baseline, training_path=args.training)
    _print_pack(result["pack"])
    if "baseline" in result:
        print(f"Baseline enrichie : {result['baseline']['path']} ({result['baseline']['vectors']} flux)")
    if "training" in result:
        print(f"Jeu enrichi : {result['training']['path']} ({result['training']['samples']} exemples)")
    if "baseline" not in result and "training" not in result:
        print("Rien a importer pour les fichiers demandes (le paquet ne contient pas ce type de modele).")
    return 0


def _cmd_outbox(args) -> int:
    if args.action == "add":
        if not args.target:
            raise ModelPackError("outbox add : chemin du paquet ZIP attendu")
        print(f"Mis en file : {queue_pack(args.target, args.outbox)}")
        return 0
    if args.action == "list":
        packs = pending(args.outbox)
        if not packs:
            print(f"Boite d'envoi vide ({args.outbox}).")
        for pack in packs:
            _print_pack(pack.summary())
        return 0
    if args.action == "done":
        if not args.target:
            raise ModelPackError("outbox done : nom du paquet attendu")
        print(f"Marque comme envoye : {mark_sent(args.target, args.outbox)}")
        return 0
    # send
    names = [args.target] if args.target else [p.name for p in pending(args.outbox)]
    if not names:
        print(f"Boite d'envoi vide ({args.outbox}).")
        return 0
    if not args.skip_check and not is_online():
        print(f"Hors connexion : {len(names)} paquet(s) en attente dans {args.outbox}, a soumettre plus tard.")
        return EXIT_OFFLINE
    for name in names:
        sub = submission(name, args.outbox, args.repo)
        print(f"\n[{sub.name}] ticket « modeles » : {sub.url}")
        print(f"  archive a joindre au ticket : {sub.archive}")
        if not sub.body_in_url:
            print("  corps trop long pour l'URL : coller le contenu de TICKET.md de l'archive")
        if args.open:
            webbrowser.open(sub.url)
    print(f"\nUne fois le ticket cree : outbox done NOM (range le paquet dans {Path(args.outbox) / 'envoyes'}).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netcross_ai_models_cli", description="Paquets de modeles IA partageables (issue #271)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    exp = sub.add_parser("export", help="exporter baseline et/ou exemples etiquetes en paquet ZIP anonyme")
    exp.add_argument("--baseline", help="baseline netcross.ai.baseline/1 (--ai-baseline-save)")
    exp.add_argument("--training", help="jeu netcross.ai.training/1 (--ai-training-export, corrige)")
    exp.add_argument("--name", required=True, help="nom du paquet (minuscules, chiffres, - et _)")
    exp.add_argument("--description", default="", help="description (anonymisee automatiquement)")
    exp.add_argument("--consent", action="store_true", help="autorise l'export d'un paquet destine au partage")
    exp.add_argument("-o", "--output", required=True, help="archive ZIP a ecrire")
    exp.add_argument("--queue", action="store_true", help="mettre aussi le paquet dans la boite d'envoi")
    exp.add_argument("--outbox", default=str(DEFAULT_OUTBOX), help="boite d'envoi (defaut %(default)s)")
    exp.set_defaults(func=_cmd_export)

    ins = sub.add_parser("inspect", help="verifier et decrire un paquet")
    ins.add_argument("pack")
    ins.add_argument("--json", action="store_true")
    ins.set_defaults(func=_cmd_inspect)

    imp = sub.add_parser("import", help="enrichir la base locale avec un paquet verifie")
    imp.add_argument("pack")
    imp.add_argument("--baseline", help="baseline locale a enrichir (creee si absente)")
    imp.add_argument("--training", help="jeu d'entrainement local a enrichir (cree si absent)")
    imp.set_defaults(func=_cmd_import)

    box = sub.add_parser("outbox", help="boite d'envoi hors connexion (add, list, send, done)")
    box.add_argument("action", choices=("add", "list", "send", "done"))
    box.add_argument("target", nargs="?", help="add : chemin du ZIP ; send/done : nom du paquet")
    box.add_argument("--outbox", default=str(DEFAULT_OUTBOX), help="repertoire (defaut %(default)s)")
    box.add_argument("--repo", default=DEFAULT_REPO, help="depot GitHub des tickets (defaut %(default)s)")
    box.add_argument("--open", action="store_true", help="ouvrir le formulaire de ticket dans le navigateur")
    box.add_argument("--skip-check", action="store_true", help="ne pas tester la connectivite avant send")
    box.set_defaults(func=_cmd_outbox)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    add_debug_argument(parser)
    args = parser.parse_args(argv)
    apply_debug_argument(args)
    try:
        return int(args.func(args))
    except (ModelPackError, BaselineError, TrainingSetError, OSError) as exc:
        logger.exception(f"échec dans main: {exc}")
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
