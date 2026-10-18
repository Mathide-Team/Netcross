"""netcross_report.lua_dissectors_text -- rendu texte du catalogue des
dissecteurs Lua (issue #917), partagé par ``netcross-lua-doc --dissectors``
et la fenêtre « Documentation Lua » de la GUI. Prend les documents JSON de
``netcross_core.lua_dissectors`` (mêmes données que l'API)."""

from __future__ import annotations

from typing import Any

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


def render_dissecteurs(doc: dict[str, Any]) -> list[str]:
    """Texte de ``netcross-lua-doc --dissectors`` (partagé avec la GUI)."""
    logger.debug("render_dissecteurs()")
    criteres = [
        f"« {doc['terme']} »" if doc["terme"] else "",
        f"domaine « {doc['domaine']} »" if doc["domaine"] else "",
    ]
    criteres.append("sans dissecteur natif" if doc["non_natif"] else "")
    titre = ", ".join(c for c in criteres if c) or "tout le catalogue"
    lignes = [f"{doc['total']} dissecteur(s) Lua sur {doc['catalogue']} -- {titre}"]
    if len(doc["dissecteurs"]) < doc["total"]:
        lignes[0] += f" ({len(doc['dissecteurs'])} affichés, voir --limit)"
    for d in doc["dissecteurs"]:
        natif = f"natif Wireshark : {d['natif_protocole'] or 'oui'}" if d["natif"] else "pas de dissecteur natif"
        etat = " [archivé]" if d["archive"] else ""
        licence = d["licence"] if d["licence"] not in ("", "—", "-") else "licence inconnue"
        lignes += [
            "",
            f"{d['depot']}{etat}  ({d['etoiles']} étoiles, {licence}, MAJ {d['derniere_maj'] or '?'})",
            f"  {d['url']}",
            f"  {d['domaine']} -- {natif}",
            f"  {d['protocole']}",
        ]
    return lignes


def render_domaines(doc: dict[str, Any]) -> list[str]:
    logger.debug("render_domaines()")
    largeur = max((len(str(x["dissecteurs"])) for x in doc["domaines"]), default=1)
    return [
        f"{len(doc['domaines'])} domaines -- {doc['catalogue']} dissecteurs Lua",
        "",
        *(f"  {x['dissecteurs']:>{largeur}}  {x['domaine']}" for x in doc["domaines"]),
    ]
