"""
Regles loguru de l'issue #245, verifiees sur tout ``src/``
(issue #954 : ``scripts/`` et ``tools/`` inclus) :

- chaque ``except`` contient un appel loguru (logger.debug/warning/error/
  exception/...) -- « Nouvelle regle : chaque except doit contenir un appel
  loguru » ;
- plus aucun ``import logging`` : « les logger de loguru remplacent les
  anciens logger (logging) » ;
- tout module qui definit des fonctions dispose d'un logger loguru.

Analyse AST uniquement (aucun import des modules : GTK n'est pas requis).
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
# Issue #954 : les regles §8 portent sur tout le Python suivi par git,
# pas seulement src/ — scripts/ et tools/ sont couverts aussi.
BASES = (ROOT / "src", ROOT / "scripts", ROOT / "tools")
LOG_METHODS = {"trace", "debug", "info", "success", "warning", "error", "exception", "critical", "log"}


def _modules():
    fichiers = []
    for base in BASES:
        fichiers.extend(base.rglob("*.py"))
    return sorted(f for f in fichiers if "__pycache__" not in f.parts)


def _est_repli_muet(handler: ast.ExceptHandler) -> bool:
    """Vrai si le handler se contente d'installer un repli de logger."""
    return any(
        isinstance(st, ast.Assign) and any(getattr(t, "id", None) in {"logger", "_logger"} for t in st.targets)
        for st in handler.body
    )


def _is_loguru_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in LOG_METHODS
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"logger", "_logger"}
    )


def test_chaque_except_contient_un_appel_loguru():
    fautifs = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        fautifs.extend(
            f"{path.relative_to(ROOT)}:{node.lineno}"
            for node in ast.walk(tree)
            if isinstance(node, ast.ExceptHandler)
            # toléré : le repli muet « logger = ... » quand loguru est absent
            # (scripts invoqués par la CI avec le python système) — rien à
            # journaliser, le logger n'existe pas encore (issue #954).
            and not _est_repli_muet(node)
            and not any(_is_loguru_call(n) for n in ast.walk(node))
        )
    assert fautifs == [], "except sans appel loguru :\n" + "\n".join(fautifs)


def test_aucun_import_logging():
    fautifs = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name.split(".")[0] == "logging" for a in node.names):
                fautifs.append(f"{path.relative_to(ROOT)}:{node.lineno}")
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "logging":
                fautifs.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert fautifs == [], "import logging (remplace par loguru) :\n" + "\n".join(fautifs)


def _charger_module(nom: str):
    """Charge un module de scripts/ par son chemin (scripts/ n'est pas un paquet)."""
    script = ROOT / "scripts" / f"{nom}.py"
    if str(script.parent) not in sys.path:
        sys.path.insert(0, str(script.parent))
    spec = importlib.util.spec_from_file_location(nom, script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_audit_debug_sorties_ne_doit_pas_augmenter():
    """Issue #954 : le total des sorties sans logger.debug ne peut qu'augmenter.

    La référence est scripts/audit_debug_sorties.baseline ; une PR qui
    ajoute une sortie non tracée fait échouer ce test.
    """
    module = _charger_module("audit_debug_sorties")
    texte_baseline = (ROOT / "scripts" / "audit_debug_sorties.baseline").read_text(encoding="utf-8")
    reference = int(texte_baseline.strip().splitlines()[-1])
    # réutiliser la boucle de main() sans argparse : appeler les fonctions internes
    chemins = []
    for base in module.BASES:
        chemins.extend(base.rglob("*.py"))
    total = 0
    for path in sorted(chemins):
        if "__pycache__" in path.parts or "egg-info" in str(path):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for _q, fn in module.qualname_walk(tree):
            if module._is_stub(fn):
                continue
            _exits, bad = module.audit_function(fn)
            total += len(bad)
    assert total <= reference, (
        f"{total} sorties sans logger.debug (référence : {reference}) — "
        "instrumentez les fonctions que vous ajoutez/modifiez, puis baissez la référence"
    )


def test_audit_debug_entrees_ne_doit_pas_augmenter():
    """Issue #954 : idem pour la trace d'entrée (hors chemins chauds, #441)."""
    module = _charger_module("audit_debug_entrees")
    texte_baseline = (ROOT / "scripts" / "audit_debug_entrees.baseline").read_text(encoding="utf-8")
    reference = int(texte_baseline.strip().splitlines()[-1])
    _eligibles, manquantes = module.audit_entrees()
    assert manquantes <= reference, (
        f"{manquantes} entrées sans logger.debug (référence : {reference}) — "
        "instrumentez les fonctions que vous ajoutez/modifiez, puis baissez la référence"
    )


def test_chaque_module_avec_fonctions_a_un_logger():
    """Le logger doit etre defini au niveau module (pas dans un docstring :
    cas reel corrige dans duplicate_view.py, PR #439)."""
    fautifs = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(tree)):
            continue
        defini = False
        noms = {"logger", "_logger"}
        for node in ast.walk(tree):
            # import loguru direct ou dans un try/except (repli muet, #954)
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == "loguru"
                and any((a.asname or a.name) in noms for a in node.names)
            ):
                defini = True
            if isinstance(node, ast.Assign) and any(getattr(t, "id", None) in noms for t in node.targets):
                defini = True
        if not defini:
            fautifs.append(str(path.relative_to(ROOT)))
    assert fautifs == [], "modules sans logger loguru :\n" + "\n".join(fautifs)
