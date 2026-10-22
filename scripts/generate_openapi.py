#!/usr/bin/env python3
"""
Génère la spécification OpenAPI depuis l'application FastAPI (issue #209).

Usage :
    python scripts/generate_openapi.py

Écrit docs/openapi.yaml à la racine du dépôt. À appeler en CI pour
vérifier que la spec est à jour (comme le diagramme de classes).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from loguru import logger  # noqa: E402

# PYTHONPATH=src pour importer netcross_api
src = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(src))

from fastapi.openapi.utils import get_openapi  # noqa: E402

from netcross_api.app import app  # noqa: E402


def _render() -> tuple[Path, str]:
    """``(chemin_de_sortie, contenu)`` de la spec, sans rien ecrire.

    Isole du rendu pour que ``--check`` puisse comparer sans toucher au
    disque -- meme discipline que scripts/generate_class_diagram.py.
    """
    spec = get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        description=app.description,
        routes=app.routes,
    )

    output = Path(__file__).resolve().parent.parent / "docs" / "openapi.yaml"
    try:
        import yaml

        return output, yaml.dump(spec, default_flow_style=False, sort_keys=False, allow_unicode=True)
    except ImportError as exc:
        # Repli : JSON si pyyaml n'est pas disponible.
        logger.debug("pyyaml absent, sortie JSON : {}", exc)
        return output.with_suffix(".json"), json.dumps(spec, indent=2, ensure_ascii=False)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Genere docs/openapi.yaml depuis FastAPI")
    parser.add_argument(
        "--check",
        action="store_true",
        help="N'ecrit rien : verifie que la spec versionnee correspond au code "
        "et sort en erreur sinon (utilise en CI, comme le diagramme de classes).",
    )
    args = parser.parse_args(argv)

    output, contenu = _render()

    if args.check:
        if not output.exists():
            print(
                f"{output} est absent alors que l'API expose des routes : "
                "lancer `python3 scripts/generate_openapi.py`.",
                file=sys.stderr,
            )
            return 1
        actuel = output.read_text(encoding="utf-8")
        if actuel != contenu:
            print(
                f"{output} n'est plus a jour avec le code de netcross_api : "
                "lancer `python3 scripts/generate_openapi.py` et commiter le resultat.",
                file=sys.stderr,
            )
            return 1
        print(f"{output} est a jour.")
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(contenu, encoding="utf-8")
    print(f"OpenAPI spec écrite dans {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
