"""netcross_gtk4.forensic_view -- recherche forensic de la GUI (issue #675).

Equivalent GUI de ``--forensic-search`` et des criteres ``--search-*`` de
la CLI : meme index (``netcross_core.forensic_search``), memes criteres,
meme fichier JSON exporte.

Module sans GTK (aucun import de gi) : lecture des champs saisis, mise en
forme des resultats et export, testables sans interface graphique.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netcross_core.forensic_search import ForensicSearchQuery, ForensicSearchResult
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

# Memes champs logiques que --search-field (cross_capture_analyzer_cli).
SEARCH_FIELDS = ("sni", "uri", "http_status", "call_id", "dns_name", "method", "content_type", "message")
# Premiere entree du menu « Champ » : aucun champ nomme.
ANY_FIELD_LABEL = "(tous les champs)"
# Au-dela, la liste affichee est tronquee (l'export JSON reste complet).
MAX_DISPLAYED = 500


class SearchInputError(ValueError):
    """Saisie invalide (port non numerique, aucun critere...)."""


def _clean(value: str | None) -> str | None:
    text = (value or "").strip()
    return text or None


def build_query(
    *,
    text: str = "",
    address: str = "",
    point: str = "",
    protocol: str = "",
    port: str = "",
    field_index: int = 0,
    value: str = "",
) -> ForensicSearchQuery:
    """Requete depuis les valeurs brutes des widgets.

    ``field_index`` : position dans le menu « Champ » (0 = tous les champs,
    puis ``SEARCH_FIELDS``). Un formulaire vide est refuse : il renverrait
    chaque paquet de l'analyse, ce qui n'est jamais une recherche."""
    port_text = _clean(port)
    port_value = None
    if port_text is not None:
        try:
            port_value = int(port_text)
        except ValueError as exc:
            logger.debug("build_query: port non numerique {!r}", port_text)
            raise SearchInputError(f"port invalide : {port_text!r} (nombre attendu)") from exc
        if not 0 <= port_value <= 65535:
            logger.debug("build_query: port hors plage {}", port_value)
            raise SearchInputError(f"port invalide : {port_value} (0 a 65535)")
    field = SEARCH_FIELDS[field_index - 1] if 0 < field_index <= len(SEARCH_FIELDS) else None
    query = ForensicSearchQuery(
        text=_clean(text),
        point=_clean(point),
        protocol=_clean(protocol),
        address=_clean(address),
        port=port_value,
        field=field,
        field_value=_clean(value),
    )
    if not any(v is not None for v in asdict(query).values()):
        logger.debug("build_query: aucun critere")
        raise SearchInputError("indiquez au moins un critere de recherche")
    logger.debug("build_query: {}", query)
    return query


def _format_ts(ts: float | None) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def format_result_row(result: ForensicSearchResult) -> str:
    """Une ligne lisible : horodatage UTC, type, point, trame, champs, extrait."""
    parts = [_format_ts(result.ts), result.kind]
    if result.point:
        parts.append(f"[{result.point}]")
    if result.frame_number is not None:
        parts.append(f"trame {result.frame_number}")
    if result.matched_fields:
        parts.append(f"({', '.join(result.matched_fields)})")
    line = " ".join(parts)
    return f"{line} -- {result.snippet}" if result.snippet else line


def summary_line(results: Sequence[ForensicSearchResult]) -> str:
    """Compte des resultats, par type, et troncature eventuelle."""
    if not results:
        return "Aucun resultat."
    kinds: dict[str, int] = {}
    for r in results:
        kinds[r.kind] = kinds.get(r.kind, 0) + 1
    detail = ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))
    line = f"{len(results)} resultat(s) : {detail}."
    if len(results) > MAX_DISPLAYED:
        line += f" {MAX_DISPLAYED} premiers affiches ; l'export JSON contient tout."
    return line


def search_payload(query: ForensicSearchQuery, results: Iterable[ForensicSearchResult]) -> dict[str, Any]:
    """Meme contenu que le fichier de ``--forensic-search`` (version 1) :
    la requete est rappelee pour qu'un resultat vide reste interpretable."""
    rows = [asdict(r) for r in results]
    return {
        "version": 1,
        "query": {k: v for k, v in asdict(query).items() if v is not None},
        "count": len(rows),
        "results": rows,
    }


def write_search_json(path: str | Path, query: ForensicSearchQuery, results: Sequence[ForensicSearchResult]) -> Path:
    """Ecrit l'export JSON ; renvoie le chemin ecrit."""
    target = Path(path)
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(search_payload(query, results), fh, ensure_ascii=False, indent=2)
    logger.debug("write_search_json: {} resultat(s) -> {}", len(results), target)
    return target


# -- Resultat -> trame (issue #675 : « resultats cliquables vers le flux ») --


def wireshark_filter(result: ForensicSearchResult) -> str | None:
    """Filtre d'affichage Wireshark qui isole la trame du resultat."""
    if result.frame_number is None:
        return None
    return f"frame.number == {result.frame_number}"


def capture_for_point(result: ForensicSearchResult, captures: Sequence[tuple[str, str]] | None) -> str | None:
    """Fichier de capture du point du resultat. None si le point est inconnu
    ou porte plusieurs fichiers (rotation) : le numero de trame ne dirait
    pas dans lequel aller."""
    if not captures or not result.point:
        return None
    paths = [path for label, path in captures if label == result.point]
    return paths[0] if len(paths) == 1 else None


def wireshark_command(path: str, frame_number: int, program: str = "wireshark") -> list[str]:
    """Ouvre ``path`` dans Wireshark, positionne sur la trame (option -g)."""
    return [program, "-r", path, "-g", str(frame_number)]


def describe_selection(result: ForensicSearchResult, path: str | None) -> str:
    """Ligne d'etat apres le choix d'un resultat."""
    if result.frame_number is None:
        return "Resultat sans numero de trame : pas de lien vers le paquet."
    where = f"point {result.point}" if result.point else "point inconnu"
    text = f"Trame {result.frame_number} ({where}) -- filtre Wireshark : {wireshark_filter(result)}"
    if path:
        text += f" -- fichier : {path}"
    return text
