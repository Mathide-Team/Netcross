"""Issue #465 / #841 lot 4 : chaque champ cité dans le tableau « Options
d'analyse » du guide API existe réellement dans l'API.

Le guide reporté depuis la chaîne orpheline décrivait un champ
``rotation=true`` que ``dev`` n'a jamais eu : ce test l'aurait refusé.
"""

import re
from pathlib import Path

import pytest

try:
    from netcross_api.app import app
except ImportError:
    pytest.skip("fastapi non installe (extra [api])", allow_module_level=True)

GUIDE = Path(__file__).resolve().parents[1] / "docs" / "guide" / "api.md"


def _champs_du_guide() -> set[str]:
    texte = GUIDE.read_text(encoding="utf-8")
    section = texte.split("## Options d'analyse", 1)[1].split("\n## ", 1)[0]
    champs: set[str] = set()
    for ligne in section.splitlines():
        if not ligne.startswith("| `"):
            continue
        premiere_colonne = ligne.split("|")[1]
        champs.update(re.findall(r"`([a-z_]+)`", premiere_colonne))
    return champs


def _champs_de_l_api() -> set[str]:
    schema = app.openapi()
    champs: set[str] = set()
    for route in ("/captures", "/captures/multi"):
        operation = schema["paths"][route]["post"]
        ref = operation["requestBody"]["content"]["multipart/form-data"]["schema"]["$ref"]
        corps = schema["components"]["schemas"][ref.rsplit("/", 1)[1]]
        champs.update(corps["properties"])
        champs.update(p["name"] for p in operation.get("parameters", []))
    return champs


def test_le_guide_cite_des_champs():
    assert {"nat_tolerant", "split_interfaces", "extra_files"} <= _champs_du_guide()


def test_chaque_champ_du_guide_existe_dans_l_api():
    inconnus = sorted(_champs_du_guide() - _champs_de_l_api())
    assert not inconnus, f"champs du guide absents de POST /captures et /captures/multi : {inconnus}"
