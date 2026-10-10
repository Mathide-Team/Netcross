"""netcross_report.lua_doc_text -- rendu texte de la documentation Lua
Wireshark (``netcross-lua-doc``, issue #388), partage avec la fenetre
« Documentation Lua » de la GUI (issue #873)."""

from __future__ import annotations

import shutil
import sqlite3
import textwrap

from netcross_core import lua_doc
from netcross_core.logging_config import get_logger, summarize
from netcross_core.lua_doc import Attribut, FicheClasse, Methode, ResultatRecherche

logger = get_logger(__name__)

_INDENT = "    "


# ---------------------------------------------------------------------------
# Rendu texte
# ---------------------------------------------------------------------------


def _largeur() -> int:
    logger.debug("_largeur: retour max(…)")
    return max(60, min(shutil.get_terminal_size((100, 24)).columns, 120))


def _wrap(texte: str, indent: str) -> list[str]:
    """Replie un texte au format de data/lua_api.json, avec un retrait.

    Paragraphes separes par une ligne vide ; une ligne par puce (``- ``) ;
    les lignes commencant par deux espaces (tableaux, blocs litteraux)
    sont preformatees et ne sont pas repliees.
    """
    lignes: list[str] = []
    for i, para in enumerate(p for p in texte.split("\n\n") if p.strip()):
        if i:
            lignes.append("")
        for ligne in para.split("\n"):
            if ligne.startswith("  ") or not ligne.strip():
                lignes.append((indent + ligne).rstrip())
                continue
            suite = indent + ("  " if ligne.startswith("- ") else "")
            lignes += textwrap.wrap(ligne, _largeur(), initial_indent=indent, subsequent_indent=suite) or [indent]
    logger.debug("_wrap: retour lignes={}", summarize(lignes, "lignes"))
    return lignes


def _resume(texte: str, n: int = 110) -> str:
    """Premiere phrase (ou debut) d'une description, sur une ligne."""
    premier = " ".join(texte.split("\n\n", 1)[0].split())
    phrase = premier.split(". ", 1)[0]
    phrase = phrase if phrase.endswith(".") or len(phrase) == len(premier) else phrase + "."
    logger.debug("_resume: retour phrase if len(phrase) <= n else phrase[:n - 1].rs…")
    return phrase if len(phrase) <= n else phrase[: n - 1].rstrip() + "…"


def _code(code: str, indent: str) -> list[str]:
    logger.debug("_code: retour liste")
    return [indent + ligne if ligne else "" for ligne in code.splitlines()]


def render_methode(m: Methode, indent: str = "") -> list[str]:
    """Fiche d'une methode ou fonction, en texte."""
    sous = indent + _INDENT
    lignes = [f"{indent}{m.signature}"]
    if m.description:
        lignes += _wrap(m.description, sous)
    if m.parametres:
        lignes.append(f"{sous}Arguments :")
        for p in m.parametres:
            nom = p.nom + (" (optionnel)" if p.optionnel else "") + (f" : {p.type}" if p.type else "")
            lignes.append(f"{sous}{_INDENT}{nom}")
            if p.description:
                lignes += _wrap(p.description, sous + _INDENT * 2)
    for r in m.retours:
        lignes += _wrap(f"Retourne : {r}", sous)
    for e in m.erreurs:
        lignes += _wrap(f"Erreur : {e}", sous)
    if m.depuis_version:
        lignes.append(f"{sous}Depuis Wireshark {m.depuis_version}")
    for ex in m.exemples:
        lignes.append(f"{sous}Exemple :")
        lignes += _code(ex, sous + _INDENT)
    logger.debug("render_methode: retour lignes={}", summarize(lignes, "lignes"))
    return lignes


_MODES = {"RO": "lecture seule", "WO": "ecriture seule", "RW": "lecture/ecriture"}


def render_attribut(a: Attribut, indent: str = "") -> list[str]:
    """Fiche d'un attribut, en texte."""
    mode = f"  [{_MODES.get(a.mode, a.mode)}]" if a.mode else ""
    lignes = [f"{indent}{a.nom_complet}{mode}"]
    if a.description:
        lignes += _wrap(a.description, indent + _INDENT)
    if a.depuis_version:
        lignes.append(f"{indent}{_INDENT}Depuis Wireshark {a.depuis_version}")
    logger.debug("render_attribut: retour lignes={}", summarize(lignes, "lignes"))
    return lignes


def render_fiche(f: FicheClasse, version: str) -> list[str]:
    """Fiche complete d'une classe, en texte."""
    logger.debug("render_fiche: f={} version={}", summarize(f, "f"), summarize(version, "version"))
    entete = f.nom + (f"  (module {f.module})" if f.module else "") + (f"  -- Wireshark {version}" if version else "")
    lignes = [entete, "=" * len(entete)]
    if f.description:
        lignes += ["", *_wrap(f.description, "")]
    for ex in f.exemples:
        lignes += ["", "Exemple :", *_code(ex, _INDENT)]
    if f.methodes:
        titre = "Fonctions" if f.nom == "GlobalFunctions" else "Methodes"
        lignes += ["", f"{titre} ({len(f.methodes)})", ""]
        for m in f.methodes:
            lignes += [*render_methode(m, _INDENT), ""]
    if f.attributs:
        lignes += ["", f"Attributs ({len(f.attributs)})", ""]
        for a in f.attributs:
            lignes += [*render_attribut(a, _INDENT), ""]
    logger.debug("render_fiche: retour lignes={}", summarize(lignes, "lignes"))
    return lignes


def render_resultats(conn: sqlite3.Connection, terme: str, res: list[ResultatRecherche], full: bool) -> list[str]:
    """Liste des resultats de recherche, en texte."""
    logger.debug(
        "render_resultats: conn={} terme={} res={} full={}",
        summarize(conn, "conn"),
        summarize(terme, "terme"),
        summarize(res, "res"),
        summarize(full, "full"),
    )
    version = lua_doc.get_meta(conn).get("version_wireshark", "")
    lignes = [f"{len(res)} resultat(s) pour « {terme} »" + (f" -- Wireshark {version}" if version else ""), ""]
    for r in res:
        if full:
            detail = lua_doc.get_attribut(conn, r.ref_id) if r.est_attribut else lua_doc.get_methode(conn, r.ref_id)
            if isinstance(detail, Methode):
                lignes += [f"[{r.classe}]", *render_methode(detail, _INDENT), ""]
                continue
            if isinstance(detail, Attribut):
                lignes += [f"[{r.classe}]", *render_attribut(detail, _INDENT), ""]
                continue
        genre = "attribut" if r.est_attribut else r.genre
        lignes.append(f"  {r.signature}   [{r.classe}, {genre}]")
        if r.description:
            lignes.append(f"      {_resume(r.description)}")
    classes = sorted({r.classe for r in res})
    if not full and classes:
        lignes += ["", f"Fiche complete : --class {classes[0]}" + (" (ou --full)" if len(res) > 1 else "")]
    logger.debug("render_resultats: retour lignes={}", summarize(lignes, "lignes"))
    return lignes
