"""netcross_gtk4.extraction_view -- extraction des contenus depuis la GUI
(issue #675).

Equivalent GUI de ``--extract-contents DOSSIER`` et ``--extract-kinds`` :
meme moteur (``netcross_core.extract.contents.run_extraction``), memes
garde-fous (fichiers de capture uniquement, refus avec l'anonymisation,
repertoire vide, rappel d'usage), meme manifeste.

Module sans GTK (aucun import de gi) : testable sans interface graphique.
"""

from __future__ import annotations

from collections.abc import Sequence

from netcross_core.extract.contents import KINDS, prepare_out_dir
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

UNAVAILABLE_NO_FILES = (
    "Extraction indisponible : elle relit les fichiers d'une analyse de fichiers "
    "(pas apres une capture en direct ni une comparaison)."
)
UNAVAILABLE_REDACTED = (
    "Extraction indisponible : l'analyse etait anonymisee. Une voix, une video ou un document "
    "extrait ne peut pas etre anonymise (meme refus que --extract-contents avec --redact)."
)


def selected_kinds(flags: dict[str, bool]) -> tuple[str, ...]:
    """Types coches, dans l'ordre de KINDS ; ValueError si aucun."""
    kinds = tuple(k for k in KINDS if flags.get(k))
    if not kinds:
        logger.debug("selected_kinds: aucun type coche")
        raise ValueError("cochez au moins un type de contenu")
    return kinds


def unavailable_reason(captures: Sequence[tuple[str, str]] | None, redacted: bool) -> str | None:
    """Motif d'indisponibilite, ou None si l'extraction est possible."""
    if not captures:
        return UNAVAILABLE_NO_FILES
    if redacted:
        return UNAVAILABLE_REDACTED
    return None


def check_out_dir(path: str) -> str:
    """Valide (et cree en 0700) le repertoire de sortie, comme la CLI :
    un repertoire existant doit etre vide. Renvoie le chemin ; leve
    ValueError avec un motif lisible sinon."""
    prepare_out_dir(path)
    logger.debug("check_out_dir: {} pret", path)
    return path
