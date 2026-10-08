#!/usr/bin/env python3
"""pr_coverage_comment.py -- publie le commentaire de couverture d'une PR.

Suite de l'issue #224 (suivi de couverture en CI) : le workflow
.github/workflows/pr-coverage.yml execute pytest --cov deux fois (ref de
fusion de la PR, puis SHA de base de `dev`) et passe les deux rapports
JSON de coverage.py a ce script, qui publie ou met a jour un commentaire
sur la PR avec la couverture totale et le delta vs la base.

Appel :
    GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo \
    python3 scripts/pr_coverage_comment.py \
        --pr-json coverage-pr.json \
        --base-json coverage-base.json \
        --pr-number 123

Volontairement stdlib seule (urllib), meme modele que le reste du
projet (voir scripts/generate_class_diagram.py). Le seuil bloquant
(``fail_under`` de pyproject.toml, issue #246) est applique par ci.yml ;
ce script le rappelle et signale une PR qui passe dessous.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

# Marqueur HTML invisible qui identifie le commentaire de couverture a
# mettre a jour (plutot qu'a dupliquer) d'un push a l'autre.
MARQUEUR = "<!-- netcross:couverture-pr -->"

API = "https://api.github.com"

PYPROJECT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pyproject.toml")


def lire_seuil(chemin: str = PYPROJECT) -> float | None:
    """``fail_under`` de la section [tool.coverage.report], ou None.

    Lecture par expression reguliere plutot que tomllib : le script tourne
    avec le python3 systeme du runner et reste compatible 3.9 (cible ruff).
    """
    try:
        with open(chemin, encoding="utf-8") as f:
            texte = f.read()
    except OSError:
        return None
    section = re.search(r"^\[tool\.coverage\.report\]\s*$(.*?)(?=^\[|\Z)", texte, re.M | re.S)
    if section is None:
        return None
    valeur = re.search(r"^fail_under\s*=\s*([0-9.]+)\s*$", section.group(1), re.M)
    return float(valeur.group(1)) if valeur else None


def _lire_totaux(chemin: str) -> dict:
    """Extrait les totaux d'un rapport JSON de coverage.py."""
    with open(chemin, encoding="utf-8") as f:
        return json.load(f)["totals"]


def _pct(valeur: float) -> str:
    """76.7421... -> '76.7 %'."""
    return f"{valeur:.1f} %"


def _delta(pr: float, base: float) -> str:
    """Difference en points de pourcentage, signee, 1 decimale."""
    return f"{pr - base:+.1f} pt"


def _ligne_seuil(pourcentage_pr: float, seuil: float | None) -> str:
    if seuil is None:
        return "Aucun seuil bloquant configuré (`fail_under` absent de pyproject.toml)."
    if pourcentage_pr < seuil:
        return f"**Sous le seuil bloquant** de {_pct(seuil)} (`fail_under`, #246) : le job Tests de la CI échouera."
    return f"Seuil bloquant : {_pct(seuil)} (`fail_under`, #246), marge {pourcentage_pr - seuil:.1f} pt."


def _construire_commentaire(totaux_pr: dict, totaux_base: dict, seuil: float | None = None) -> str:
    """Construit le corps du commentaire de couverture (Markdown)."""
    lignes = [
        MARQUEUR,
        "## Couverture de tests (delta vs `dev`)",
        "",
        "| Métrique | Base (`dev`) | PR | Δ |",
        "|---|---|---|---|",
        "| Couverture | "
        f"{_pct(totaux_base['percent_covered'])} | "
        f"{_pct(totaux_pr['percent_covered'])} | "
        f"{_delta(totaux_pr['percent_covered'], totaux_base['percent_covered'])} |",
        "| Instructions couvertes | "
        f"{totaux_base['covered_lines']}/{totaux_base['num_statements']} | "
        f"{totaux_pr['covered_lines']}/{totaux_pr['num_statements']} | "
        f"{totaux_pr['covered_lines'] - totaux_base['covered_lines']:+d} |",
        "| Branches couvertes | "
        f"{totaux_base['covered_branches']}/{totaux_base['num_branches']} | "
        f"{totaux_pr['covered_branches']}/{totaux_pr['num_branches']} | "
        f"{totaux_pr['covered_branches'] - totaux_base['covered_branches']:+d} |",
        "",
        _ligne_seuil(totaux_pr["percent_covered"], seuil),
    ]
    return "\n".join(lignes)


def _appel_api(chemin: str, token: str, methode: str = "GET", corps: str | None = None) -> dict:
    """Appel REST GitHub minimal (urllib, pas de dependance tierce)."""
    requete = urllib.request.Request(
        f"{API}{chemin}",
        data=corps.encode() if corps else None,
        method=methode,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(requete) as reponse:
        return json.loads(reponse.read())


def _publier(repo: str, pr: int, corps: str, token: str) -> str:
    """Met a jour le commentaire existant (marqueur) ou en cree un."""
    commentaires = _appel_api(f"/repos/{repo}/issues/{pr}/comments?per_page=100", token)
    for c in commentaires:
        if MARQUEUR in c.get("body", ""):
            _appel_api(
                f"/repos/{repo}/issues/comments/{c['id']}",
                token,
                methode="PATCH",
                corps=json.dumps({"body": corps}),
            )
            return f"commentaire existant mis a jour ({c['html_url']})"
    cree = _appel_api(
        f"/repos/{repo}/issues/{pr}/comments",
        token,
        methode="POST",
        corps=json.dumps({"body": corps}),
    )
    return f"commentaire cree ({cree['html_url']})"


def main(argv: list[str]) -> int:
    parseur = argparse.ArgumentParser(description=__doc__)
    parseur.add_argument("--pr-json", required=True, help="rapport coverage.py de la PR")
    parseur.add_argument("--base-json", required=True, help="rapport coverage.py de la base")
    parseur.add_argument("--pr-number", required=True, type=int)
    arguments = parseur.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        print("GITHUB_TOKEN et GITHUB_REPOSITORY sont requis", file=sys.stderr)
        return 2

    corps = _construire_commentaire(
        _lire_totaux(arguments.pr_json),
        _lire_totaux(arguments.base_json),
        lire_seuil(),
    )
    resume = os.environ.get("GITHUB_STEP_SUMMARY")
    if resume:
        # Le rapport est toujours lisible dans le resume du job, meme quand
        # le commentaire ne peut pas etre publie.
        with open(resume, "a", encoding="utf-8") as sortie:
            sortie.write(corps + "\n")
    try:
        print(_publier(repo, arguments.pr_number, corps, token))
    except urllib.error.HTTPError as erreur:
        if erreur.code != 403:
            raise
        # PR ouverte depuis un fork : GitHub fournit un GITHUB_TOKEN en
        # lecture seule, l'API refuse le commentaire. Ce n'est pas un echec
        # de couverture : avertissement, rapport dans le resume du job.
        print(
            "::warning::commentaire de couverture non publie (HTTP 403, jeton en lecture seule : "
            "PR ouverte depuis un fork) -- rapport dans le resume du job",
            file=sys.stderr,
        )
        print(corps)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
