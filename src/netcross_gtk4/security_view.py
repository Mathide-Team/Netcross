"""netcross_gtk4.security_view -- section Securite de la GUI (issue #357).

Logique sans GTK : texte affiche et export du rapport de securite, a partir
du MEME `SecurityReport` que --security-report (CLI), pour que la GUI et la
CLI ne divergent pas.
"""

from __future__ import annotations

import json
from pathlib import Path

from netcross_core.logging_config import get_logger
from netcross_report.security_report import SecurityReport, format_security_report, security_report_to_dict

logger = get_logger(__name__)

EXPORT_FORMATS = (".html", ".json")


def security_view_text(sr: SecurityReport | None) -> str:
    """Texte de la section Securite : le rendu de --security-report."""
    logger.debug("security_view_text: rapport={}", sr is not None)
    if sr is None:
        return "Cocher « Rapport de securite » puis relancer l'analyse de fichiers."
    return "\n".join(format_security_report(sr))


def export_security_report(sr: SecurityReport, path: str) -> str:
    """Ecrit le rapport de securite en HTML (equivalent --security-html) ou
    en JSON (cle `security_report` de --json-report), selon l'extension.
    Retourne le chemin ecrit ; ValueError si l'extension est inconnue."""
    suffix = Path(path).suffix.lower()
    logger.debug("export_security_report: format={} path={}", suffix or "(aucun)", path)
    if suffix == ".html":
        from netcross_report.security_html import generate_security_html

        return generate_security_html(sr, path)
    if suffix == ".json":
        Path(path).write_text(
            json.dumps(security_report_to_dict(sr), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path
    logger.warning("export_security_report: extension non prise en charge {!r}", suffix)
    raise ValueError(f"format d'export inconnu ({suffix or 'sans extension'}) : .html ou .json attendu")
