"""netcross_core.annotations -- annotations (etiquettes / signets sur des
trames) partagees par la CLI et l'API (issue #910).

La GUI (``netcross_gtk4.annotations_view``, issue #363) pose ses
annotations dans le sidecar ``<capture>.annotations.json``
(``netcross_core.forensic.read_annotations`` / ``write_annotations``). Ce
module ajoute les regles communes aux autres surfaces, sans E/S :

- validation d'une annotation recue (numero de trame >= 1, etiquette non
  vide, commentaire et couleur facultatifs) ;
- ajout : une meme paire (trame, etiquette) n'existe qu'une fois -- la
  reposer met a jour son commentaire et sa couleur, ce qui rend
  ``add`` idempotent pour la CLI et l'API ;
- suppression : ``KeyError`` si la paire est absente (la CLI renvoie 1,
  l'API 404) ;
- conversion vers / depuis le format JSON du sidecar.
"""

from __future__ import annotations

from typing import Any

from netcross_core.logging_config import get_logger
from netcross_core.models import PacketAnnotation

logger = get_logger(__name__)


def parse_frame_number(value: object) -> int:
    """Numero de trame (>= 1, comme dans Wireshark) depuis un entier ou un
    texte (``"12"``, ``"#12"``). ``ValueError`` avec un message affichable."""
    if isinstance(value, bool):
        logger.debug("parse_frame_number: booleen refuse")
        raise ValueError(f"numero de trame invalide : {value!r}")
    if isinstance(value, int):
        number = value
    else:
        text = str(value).strip().lstrip("#")
        try:
            number = int(text)
        except ValueError:
            logger.debug("parse_frame_number: saisie invalide {!r}", text)
            raise ValueError(f"numero de trame invalide : {text!r}") from None
    if number < 1:
        logger.debug("parse_frame_number: si number < 1 -> levée ValueError")
        raise ValueError("le numero de trame commence a 1")
    return number


def make_annotation(frame: object, tag: str, comment: str = "", color: str | None = None) -> PacketAnnotation:
    """Annotation validee (etiquette et commentaire nettoyes des blancs)."""
    if not isinstance(tag, str) or not tag.strip():
        logger.debug("make_annotation: etiquette vide -> levée ValueError")
        raise ValueError("l'etiquette d'une annotation ne peut pas etre vide")
    if comment is None:
        comment = ""
    if not isinstance(comment, str):
        logger.debug("make_annotation: commentaire non textuel -> levée ValueError")
        raise ValueError("le commentaire doit etre une chaine")
    if color is not None and (not isinstance(color, str) or not color.strip()):
        logger.debug("make_annotation: couleur invalide -> levée ValueError")
        raise ValueError("la couleur doit etre une chaine non vide (ou absente)")
    return PacketAnnotation(
        frame_number=parse_frame_number(frame),
        tag=tag.strip(),
        comment=comment.strip(),
        color=color.strip() if color else None,
    )


def add_annotation(annotations: list[PacketAnnotation], new: PacketAnnotation) -> list[PacketAnnotation]:
    """NOUVELLE liste avec ``new`` : remplace l'annotation de meme (trame,
    etiquette) a sa place, sinon l'ajoute a la fin."""
    result = list(annotations)
    for index, existing in enumerate(result):
        if existing.frame_number == new.frame_number and existing.tag == new.tag:
            result[index] = new
            logger.debug("add_annotation: trame={} tag={} mise a jour", new.frame_number, new.tag)
            return result
    result.append(new)
    logger.debug("add_annotation: trame={} tag={} ajoutee", new.frame_number, new.tag)
    return result


def remove_annotation(annotations: list[PacketAnnotation], frame: object, tag: str) -> list[PacketAnnotation]:
    """NOUVELLE liste sans les annotations (trame, etiquette) ; ``KeyError``
    si aucune ne correspond. ``ValueError`` si la trame est invalide."""
    number = parse_frame_number(frame)
    tag = (tag or "").strip()
    result = [a for a in annotations if not (a.frame_number == number and a.tag == tag)]
    if len(result) == len(annotations):
        logger.debug("remove_annotation: trame={} tag={} absente -> levée KeyError", number, tag)
        raise KeyError(f"trame #{number} [{tag}]")
    logger.debug("remove_annotation: trame={} tag={} supprimee", number, tag)
    return result


def sort_annotations(annotations: list[PacketAnnotation]) -> list[PacketAnnotation]:
    """Ordre d'affichage : trame croissante puis etiquette."""
    return sorted(annotations, key=lambda a: (a.frame_number, a.tag))


def annotation_to_dict(annotation: PacketAnnotation) -> dict[str, Any]:
    """Format JSON du sidecar (memes cles que ``write_annotations``)."""
    return {
        "frame_number": annotation.frame_number,
        "tag": annotation.tag,
        "comment": annotation.comment,
        "color": annotation.color,
    }


def annotation_from_dict(item: object) -> PacketAnnotation:
    """Annotation depuis un objet JSON (sidecar ou corps de requete)."""
    if not isinstance(item, dict):
        logger.debug("annotation_from_dict: objet attendu -> levée ValueError")
        raise ValueError(f"objet JSON attendu, pas {type(item).__name__}")
    return make_annotation(item.get("frame_number"), item.get("tag", ""), item.get("comment", ""), item.get("color"))
