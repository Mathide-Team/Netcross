#!/usr/bin/env python3
"""check_branch_protection.py -- verifie la protection d'une branche (#334).

La regle de protection de ``dev`` est versionnee dans
``.github/branch-protection/dev.json`` : c'est la charge utile exacte de
l'API GitHub, appliquee par un administrateur du depot avec ::

    gh api -X PUT repos/MathildeDec/Netcross/branches/dev/protection \\
        --input .github/branch-protection/dev.json

Ce script compare la protection reelle de la branche a ce fichier et
echoue sur tout ecart. Il existe parce qu'une protection de branche est un
reglage du depot, invisible dans le code : elle peut ne jamais avoir ete
creee (c'etait le cas, alors que CONTRIBUTING.md la decrivait deja), etre
desactivee, ou perdre un check requis sans que personne ne le remarque.

Deux verifications :

- ``--hors-ligne`` : coherence du fichier de regle avec les workflows.
  Chaque check requis doit etre le nom d'un job qui tourne sur les
  ``pull_request`` vers la branche -- sinon GitHub attendrait un statut
  qui n'arrive jamais et bloquerait toutes les PR. Sans reseau : execute
  par la suite de tests.
- par defaut : etat reel via l'API GitHub. ``GET /branches/{branche}``
  est lisible sans droit d'administration et donne l'activation, les
  checks requis et leur application aux administrateurs. L'exigence de
  branche a jour (``strict``) n'est exposee que par
  ``GET /branches/{branche}/protection``, reserve aux administrateurs :
  avec un jeton sans ce droit, elle est signalee comme non verifiable,
  jamais supposee conforme.

Codes de sortie : 0 conforme, 1 ecart detecte, 2 erreur (fichier de
regle invalide, API injoignable).

Volontairement stdlib seule pour la partie API (urllib), comme
scripts/pr_coverage_comment.py. PyYAML n'est importe que pour
``--hors-ligne``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Iterable
from pathlib import Path

API = "https://api.github.com"
RACINE = Path(__file__).resolve().parent.parent
REGLE_PAR_DEFAUT = RACINE / ".github" / "branch-protection" / "dev.json"
WORKFLOWS = RACINE / ".github" / "workflows"

CONFORME, ECART, ERREUR = 0, 1, 2


class RegleInvalideError(ValueError):
    """Fichier de regle absent, illisible ou incomplet."""


def charger_regle(chemin: Path) -> dict:
    """Lit le fichier de regle et controle les champs dont depend la
    verification (le reste est transmis tel quel a l'API)."""
    try:
        regle = json.loads(chemin.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RegleInvalideError(f"fichier de regle introuvable : {chemin}") from exc
    except json.JSONDecodeError as exc:
        raise RegleInvalideError(f"fichier de regle illisible {chemin} : {exc}") from exc
    statuts = regle.get("required_status_checks") if isinstance(regle, dict) else None
    if not isinstance(statuts, dict) or not isinstance(statuts.get("checks"), list):
        raise RegleInvalideError(f"{chemin} : required_status_checks.checks absent")
    if not statuts["checks"]:
        raise RegleInvalideError(f"{chemin} : aucun check requis -- la regle ne protegerait rien")
    for check in statuts["checks"]:
        if not isinstance(check, dict) or not str(check.get("context", "")).strip():
            raise RegleInvalideError(f"{chemin} : check sans 'context' : {check!r}")
    if not isinstance(statuts.get("strict"), bool):
        raise RegleInvalideError(f"{chemin} : required_status_checks.strict doit etre un booleen")
    if not isinstance(regle.get("enforce_admins"), bool):
        raise RegleInvalideError(f"{chemin} : enforce_admins doit etre un booleen")
    return regle


def contextes_requis(regle: dict) -> set[str]:
    return {check["context"] for check in regle["required_status_checks"]["checks"]}


# ----------------------------------------------------------------------
# verification hors ligne : regle <-> workflows
# ----------------------------------------------------------------------


def _declencheurs(workflow: dict) -> object:
    # YAML 1.1 : une cle `on` non quotee est lue comme le booleen True.
    return workflow.get("on", workflow.get(True))


def _branches_couvertes(filtre: object, branche: str) -> bool:
    """Un declencheur pull_request sans filtre `branches` couvre toutes les
    branches ; avec un filtre, seul un nom exact est reconnu (les motifs
    glob ne sont pas utilises dans ce depot, et les accepter sans les
    evaluer risquerait un faux positif)."""
    if not isinstance(filtre, dict):
        return True
    branches = filtre.get("branches")
    if branches is None:
        return "branches-ignore" not in filtre or branche not in filtre["branches-ignore"]
    return branche in branches


def tourne_sur_pr(workflow: dict, branche: str) -> bool:
    on = _declencheurs(workflow)
    if on == "pull_request":
        return True
    if isinstance(on, list):
        return "pull_request" in on
    if isinstance(on, dict) and "pull_request" in on:
        return _branches_couvertes(on["pull_request"], branche)
    return False


def jobs_de_pr(workflows: Iterable[dict], branche: str) -> set[str]:
    """Noms affiches (``name:``, sinon l'identifiant du job) des jobs
    executes sur une pull_request vers ``branche``. Un job conditionne par
    ``if:`` est exclu : il peut ne jamais publier de statut, et le rendre
    obligatoire bloquerait les PR ou il est saute."""
    noms: set[str] = set()
    for workflow in workflows:
        if not isinstance(workflow, dict) or not tourne_sur_pr(workflow, branche):
            continue
        for ident, job in (workflow.get("jobs") or {}).items():
            if not isinstance(job, dict) or "if" in job:
                continue
            noms.add(str(job.get("name", ident)))
    return noms


def lire_workflows(dossier: Path) -> list[dict]:
    import yaml  # dependance de dev (pyproject.toml), inutile hors de ce mode

    return [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(dossier.glob("*.y*ml"))]


def verifier_hors_ligne(regle: dict, workflows: list[dict], branche: str) -> list[str]:
    disponibles = jobs_de_pr(workflows, branche)
    return [
        f"check requis « {ctx} » : aucun job de ce nom ne tourne sur les PR vers {branche} "
        "(renomme, supprime ou conditionne ?) -- toutes les PR resteraient bloquees"
        for ctx in sorted(contextes_requis(regle) - disponibles)
    ]


# ----------------------------------------------------------------------
# verification de l'etat reel (API GitHub)
# ----------------------------------------------------------------------


def comparer(regle: dict, branche_api: dict, protection_api: dict | None) -> tuple[list[str], list[str]]:
    """Compare la regle a l'etat renvoye par l'API.

    ``branche_api`` : reponse de ``GET /branches/{b}`` (lisible sans droit
    d'administration). ``protection_api`` : reponse de
    ``GET /branches/{b}/protection``, ou None quand le jeton n'a pas acces.
    Retourne (ecarts, non_verifiables)."""
    ecarts: list[str] = []
    non_verifiables: list[str] = []
    nom = branche_api.get("name", "?")
    protection = branche_api.get("protection") or {}
    if not branche_api.get("protected") or not protection.get("enabled"):
        return [f"la branche {nom} n'est pas protegee"], []

    statuts = protection.get("required_status_checks") or {}
    reels = set(statuts.get("contexts") or [])
    ecarts.extend(
        f"check requis absent de la protection : « {ctx} »" for ctx in sorted(contextes_requis(regle) - reels)
    )
    ecarts.extend(
        f"check requis en plus de la regle versionnee : « {ctx} »" for ctx in sorted(reels - contextes_requis(regle))
    )

    niveau_attendu = "everyone" if regle["enforce_admins"] else "non_admins"
    niveau = statuts.get("enforcement_level", "off")
    if niveau != niveau_attendu:
        ecarts.append(f"application des checks : « {niveau} » au lieu de « {niveau_attendu} » (enforce_admins)")

    strict_attendu = regle["required_status_checks"]["strict"]
    if protection_api is None:
        non_verifiables.append(
            "branche a jour exigee (strict) : lisible uniquement avec un jeton administrateur du depot"
        )
    else:
        strict = bool((protection_api.get("required_status_checks") or {}).get("strict"))
        if strict != strict_attendu:
            ecarts.append(f"branche a jour exigee (strict) : {strict} au lieu de {strict_attendu}")
        lineaire = bool((protection_api.get("required_linear_history") or {}).get("enabled"))
        if lineaire != bool(regle.get("required_linear_history", False)):
            ecarts.append(
                f"historique lineaire exige : {lineaire} -- incompatible avec les merge commits de release"
                if lineaire
                else "historique lineaire exige : False au lieu de True"
            )
    return ecarts, non_verifiables


def _get(url: str, jeton: str | None) -> dict | None:
    """GET JSON ; None sur 401/403/404 : ressource reservee ou inexistante.
    Sans jeton, l'API repond 401 sur /protection ; avec un jeton sans droit
    d'administration, 403 ou 404 selon le type de jeton."""
    requete = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    if jeton:
        requete.add_header("Authorization", f"Bearer {jeton}")
    try:
        with urllib.request.urlopen(requete, timeout=30) as reponse:
            return json.load(reponse)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 404):
            return None
        raise


def verifier_en_ligne(regle: dict, depot: str, branche: str, jeton: str | None) -> tuple[list[str], list[str]]:
    branche_api = _get(f"{API}/repos/{depot}/branches/{branche}", jeton)
    if branche_api is None:
        raise RuntimeError(f"branche {branche} introuvable sur {depot} (ou depot inaccessible)")
    protection_api = _get(f"{API}/repos/{depot}/branches/{branche}/protection", jeton)
    return comparer(regle, branche_api, protection_api)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--branche", default="dev")
    parser.add_argument("--regle", type=Path, default=REGLE_PAR_DEFAUT)
    parser.add_argument("--depot", default=os.environ.get("GITHUB_REPOSITORY", "MathildeDec/Netcross"))
    parser.add_argument(
        "--hors-ligne",
        action="store_true",
        help="verifie seulement la coherence regle <-> workflows (sans reseau)",
    )
    parser.add_argument("--workflows", type=Path, default=WORKFLOWS)
    args = parser.parse_args(argv)

    try:
        regle = charger_regle(args.regle)
        if args.hors_ligne:
            ecarts, non_verifiables = verifier_hors_ligne(regle, lire_workflows(args.workflows), args.branche), []
        else:
            ecarts, non_verifiables = verifier_en_ligne(regle, args.depot, args.branche, os.environ.get("GITHUB_TOKEN"))
    except (RegleInvalideError, RuntimeError, OSError, urllib.error.URLError) as exc:
        print(f"::error::{exc}")
        return ERREUR

    for message in non_verifiables:
        print(f"::warning::{message}")
    for message in ecarts:
        print(f"::error::{message}")
    if ecarts:
        print(
            f"Protection de {args.branche} non conforme a {args.regle.name}. Pour l'appliquer "
            f"(administrateur du depot) : gh api -X PUT repos/{args.depot}/branches/{args.branche}"
            f"/protection --input .github/branch-protection/{args.regle.name}"
        )
        return ECART
    print(f"Protection de {args.branche} conforme a {args.regle.name}.")
    return CONFORME


if __name__ == "__main__":
    sys.exit(main())
