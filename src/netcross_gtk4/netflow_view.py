"""netcross_gtk4.netflow_view -- resume NetFlow v5 dans la GUI (issue #675).

Equivalent GUI de ``--netflow [EXPORTATEUR=]FICHIER`` (repete),
``--netflow-top`` et du JSON ``{"netflow": ...}`` de ``--json-report`` :
memes fonctions (``netcross_core.netflow``), meme texte, meme JSON. Mode
autonome comme dans la CLI : les flux agreges ne se correlent pas entre
points de capture, ils ne se melangent donc pas a l'analyse courante.

Module sans GTK (aucun import de gi) : testable sans interface graphique.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

DEFAULT_TOP = 10


class NetflowFileError(ValueError):
    """Fichier illisible ou tronque (motif cite avec le chemin)."""


def summarize_files(files: Sequence[tuple[str | None, str]], top: int = DEFAULT_TOP) -> tuple[dict, list[str]]:
    """Lit les exports ``[(exportateur ou None, chemin), ...]`` ; renvoie
    ``(resume, lignes de texte)``. Leve NetflowFileError au premier fichier
    illisible, comme la CLI (un resume partiel serait trompeur)."""
    from netcross_core.netflow import (
        FlowRecord,
        NetflowV5Error,
        format_flow_summary,
        iter_netflow_v5_file,
        summarize_flow_records,
    )

    if not files:
        logger.debug("summarize_files: aucun fichier")
        raise NetflowFileError("ajoutez au moins un export NetFlow v5")
    if top < 1:
        logger.debug("summarize_files: top < 1")
        raise NetflowFileError("la taille des classements doit etre >= 1")
    records: list[FlowRecord] = []
    current = None
    try:
        for exporter, path in files:
            current = path
            records.extend(iter_netflow_v5_file(path, exporter=exporter))
    except (OSError, NetflowV5Error) as exc:
        logger.warning("summarize_files: {} illisible ({})", current, exc)
        raise NetflowFileError(f"{current} : {exc}") from exc
    summary = summarize_flow_records(records, top=top)
    logger.debug("summarize_files: {} fichier(s), {} enregistrement(s)", len(files), len(records))
    return summary, format_flow_summary(summary)


def write_netflow_json(path: str | Path, summary: dict) -> Path:
    """Meme structure que ``--netflow ... --json-report`` : ``{"netflow": ...}``."""
    target = Path(path)
    with open(target, "w", encoding="utf-8") as fh:
        json.dump({"netflow": summary}, fh, ensure_ascii=False, indent=2)
    logger.debug("write_netflow_json: {}", target)
    return target
