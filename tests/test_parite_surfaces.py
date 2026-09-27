"""Issue #330 : la matrice de parité GUI / CLI / API reste fidèle au code.

``docs/parite-surfaces.md`` répond à la question « toutes les fonctions sont-
elles accessibles partout ? ». Ce test extrait les surfaces réelles et
échoue si l'une d'elles n'est pas classée dans la page, ou si les décomptes
annoncés en tête ne correspondent plus :

- options des CLI : parseur argparse réel, capturé au moment de
  ``parse_args`` (aucune analyse n'est lancée) ;
- routes et paramètres de l'API : application FastAPI ;
- cases à cocher et réglages numériques de la GUI : AST de
  ``netcross_gtk4/`` (sans importer GTK).
"""

from __future__ import annotations

import argparse
import ast
import importlib
import re
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
PAGE = RACINE / "docs" / "parite-surfaces.md"
GUI = RACINE / "src" / "netcross_gtk4"

# module -> appel de main (certaines prennent argv, d'autres lisent sys.argv)
CLIS = {
    "cross_capture_analyzer_cli": False,
    "cross_capture_diff_cli": False,
    "cross_capture_batch_cli": True,
    "cross_history_cli": False,
    "netcross_lua_doc_cli": True,
    "netcross_ai_models_cli": True,
}


class _ParseurCaptureError(Exception):
    def __init__(self, parseur: argparse.ArgumentParser) -> None:
        super().__init__("parseur capturé")
        self.parseur = parseur


def _options_cli(module: str, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Options longues du parseur réel de ``module`` (sans --help)."""

    def _capturer(self, *_args, **_kwargs):
        raise _ParseurCaptureError(self)

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", _capturer)
    monkeypatch.setattr(argparse.ArgumentParser, "parse_known_args", _capturer)
    monkeypatch.setattr(sys, "argv", [module])
    mod = importlib.import_module(module)
    with pytest.raises(_ParseurCaptureError) as capture:
        mod.main([]) if CLIS[module] else mod.main()
    return [
        action.option_strings[-1]
        for action in capture.value.parseur._actions
        if action.option_strings and action.dest != "help"
    ]


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _cite(page: str, texte: str) -> bool:
    """``texte`` apparaît entre backticks (seul ou en tête d'un exemple)."""
    return re.search(r"`" + re.escape(texte) + r"(`|[ =])", page) is not None


@pytest.mark.parametrize("module", sorted(CLIS))
def test_chaque_option_cli_est_classee(module, monkeypatch):
    page = _page()
    absentes = [opt for opt in _options_cli(module, monkeypatch) if not _cite(page, opt)]
    assert not absentes, f"{module} : options absentes de docs/parite-surfaces.md : {absentes}"


@pytest.mark.parametrize(
    ("module", "annonce"),
    [
        ("cross_capture_analyzer_cli", r"`cross_capture_analyzer_cli\.py` \((\d+) options\)"),
        ("cross_capture_diff_cli", r"`cross_capture_diff_cli\.py` \((\d+)\)"),
        ("cross_capture_batch_cli", r"`cross_capture_batch_cli\.py` \((\d+)\)"),
    ],
)
def test_decompte_des_options_a_jour(module, annonce, monkeypatch):
    trouve = re.search(annonce, _page())
    assert trouve, f"décompte de {module} introuvable dans l'en-tête"
    assert int(trouve.group(1)) == len(_options_cli(module, monkeypatch))


def _routes_api() -> list:
    # L'extra [api] n'est pas installe dans tous les jobs (job Couverture) :
    # sans FastAPI, la surface API n'est pas mesurable, on saute.
    pytest.importorskip("fastapi", reason="extra [api] non installe")
    from fastapi.routing import APIRoute

    from netcross_api.app import app

    return [r for r in app.routes if isinstance(r, APIRoute)]


def test_chaque_route_api_est_classee():
    page = _page()
    absentes = [
        f"{methode} {route.path}"
        for route in _routes_api()
        for methode in sorted(route.methods)
        if f"`{methode} {route.path}`" not in page
    ]
    assert not absentes, f"routes absentes de docs/parite-surfaces.md : {absentes}"


def test_chaque_parametre_api_est_classe():
    page = _page()
    absents = [
        f"{route.path}:{param.name}"
        for route in _routes_api()
        for param in route.dependant.query_params + route.dependant.body_params
        if f"`{param.name}`" not in page
    ]
    assert not absents, f"paramètres absents de docs/parite-surfaces.md : {absents}"


def test_decompte_des_routes_a_jour():
    trouve = re.search(r"\| (\d+) routes FastAPI \|", _page())
    assert trouve, "décompte des routes introuvable dans l'en-tête"
    assert int(trouve.group(1)) == len(_routes_api())


def _appels_gtk(nom: str) -> list[ast.Call]:
    """Appels ``Gtk.<nom>(...)`` et ``Gtk.<nom>.new_*(...)`` de la GUI."""
    appels = []
    for fichier in sorted(GUI.glob("*.py")):
        for noeud in ast.walk(ast.parse(fichier.read_text(encoding="utf-8"))):
            if not isinstance(noeud, ast.Call) or not isinstance(noeud.func, ast.Attribute):
                continue
            cible = noeud.func
            if isinstance(cible.value, ast.Attribute) and cible.attr.startswith("new"):
                cible = cible.value
            if cible.attr == nom and isinstance(cible.value, ast.Name) and cible.value.id == "Gtk":
                appels.append(noeud)
    return appels


def _libelles_cases() -> list[str]:
    return [
        mot.value.value
        for appel in _appels_gtk("CheckButton")
        for mot in appel.keywords
        if mot.arg == "label" and isinstance(mot.value, ast.Constant)
    ]


def test_chaque_case_gui_est_classee():
    page = _page()
    libelles = _libelles_cases()
    assert libelles, "extraction des cases GUI vide : l'AST a changé de forme"
    absentes = sorted({lib for lib in libelles if f"| {lib} |" not in page})
    assert not absentes, f"cases GUI absentes de l'inventaire : {absentes}"


def test_decompte_gui_a_jour():
    trouve = re.search(r"(\d+) cases à cocher, (\d+) réglages numériques", _page())
    assert trouve, "décompte GUI introuvable dans l'en-tête"
    assert int(trouve.group(1)) == len(_libelles_cases())
    assert int(trouve.group(2)) == len(_appels_gtk("SpinButton"))


def test_page_dans_la_navigation():
    assert "parite-surfaces.md" in (RACINE / "mkdocs.yml").read_text(encoding="utf-8")
