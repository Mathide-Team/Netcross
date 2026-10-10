"""netcross_gtk4.lua_doc_view -- logique sans GTK de la fenetre
« Documentation Lua » (issue #873), equivalent de ``netcross-lua-doc``.

Meme banque SQLite (``netcross_core.lua_doc``), meme texte que la CLI
(``netcross_report.lua_doc_text``) : liste des classes (``--classes``),
fiche d'une classe (``--class``), recherche (``TERME``, ``--limit``,
``--full``) et document JSON (``--json``).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from netcross_core import lua_doc
from netcross_core.logging_config import get_logger
from netcross_report.lua_doc_text import render_fiche, render_resultats

logger = get_logger(__name__)

DEFAULT_LIMIT = 20


class LuaDocUnavailableError(Exception):
    """JSON de l'API Lua introuvable (meme message que la CLI)."""


class LuaDocBrowser:
    """Acces a la documentation Lua pour la GUI (une connexion, fermee par
    ``close``)."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        source: str | Path | None = None,
        find_json: Callable[[], Path | None] | None = None,
    ) -> None:
        json_path = Path(source) if source else (find_json or lua_doc.find_json)()
        if json_path is None or not json_path.is_file():
            emplacements = ", ".join(str(p) for p in lua_doc.json_candidates())
            logger.warning("LuaDocBrowser: JSON introuvable ({})", emplacements)
            raise LuaDocUnavailableError(
                f"JSON de l'API Lua introuvable ({source or emplacements}). "
                "Le generer avec : python3 tools/extract_lua_api.py --tag vX.Y.Z"
            )
        self.conn: sqlite3.Connection = lua_doc.ensure_db(db_path or lua_doc.DEFAULT_DB_PATH, json_path)
        self.version = lua_doc.get_meta(self.conn).get("version_wireshark", "")

    def close(self) -> None:
        self.conn.close()

    def classes(self) -> list[str]:
        return lua_doc.list_classes(self.conn)

    def classes_text(self) -> str:
        """Texte de ``netcross-lua-doc --classes``."""
        noms = self.classes()
        return "\n".join([f"{len(noms)} classes -- Wireshark {self.version}", "", *(f"  {n}" for n in noms)])

    def class_text(self, name: str) -> str:
        """Fiche de ``--class NOM``, ou message « Classe inconnue » de la CLI."""
        fiche = lua_doc.get_class(self.conn, name)
        if fiche is None:
            suggestion = lua_doc.suggest_classes(self.conn, name)
            logger.debug("class_text: classe inconnue {}", name)
            return f"Classe inconnue : {name}" + (f" (voir : {', '.join(suggestion)})" if suggestion else "")
        return "\n".join(render_fiche(fiche, self.version)).rstrip()

    def search(self, terme: str, limit: int = DEFAULT_LIMIT, full: bool = False) -> tuple[str, list[str]]:
        """(texte de ``netcross-lua-doc [--full] --limit N TERME``, classes
        trouvees dans l'ordre, pour ouvrir leur fiche)."""
        terme = terme.strip()
        if not terme:
            return "", []
        res = lua_doc.search(self.conn, terme, limit)
        if not res:
            return f"Aucun resultat pour « {terme} » (Wireshark {self.version}).", []
        classes = list(dict.fromkeys(r.classe for r in res))
        return "\n".join(render_resultats(self.conn, terme, res, full)).rstrip(), classes

    def json_text(
        self, terme: str = "", name: str | None = None, limit: int = DEFAULT_LIMIT, full: bool = False
    ) -> str:
        """JSON de ``--json`` : fiche (``name``), recherche (``terme``) ou
        liste des classes."""
        meta = lua_doc.get_meta(self.conn)
        doc: dict[str, Any]
        if name:
            fiche = lua_doc.get_class(self.conn, name)
            doc = {"meta": meta, "classe": asdict(fiche) if fiche else None}
        elif terme.strip():
            doc = lua_doc.search_document(self.conn, terme.strip(), limit, full)
        else:
            doc = {"meta": meta, "classes": self.classes()}
        return json.dumps(doc, ensure_ascii=False, indent=2)
