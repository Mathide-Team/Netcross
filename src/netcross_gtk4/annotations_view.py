"""netcross_gtk4.annotations_view -- logique de presentation pour
l'etiquetage/signets sur paquets (Job 40 / issue #160, section
"Metadonnees et annotation").

Etat de PRESENTATION / interaction UI, mais pur Python (aucun import
Gtk) : testable sans display, meme discipline que stats_view.py et
dashboard_context.py. Le cablage des widgets GTK reels (clic droit ->
menu contextuel "ajouter une etiquette", vue filtrable par tag) est
dans annotations_panel.py (issue #363) -- ce module fournit les
fonctions pures necessaires (ajout/suppression d'annotation, filtrage
par tag, liste des tags disponibles pour peupler les toggles) pour que
ce cablage n'ait aucune logique metier a porter lui-meme.

Ne duplique pas `netcross_core.forensic.annotations_by_tag` (regroupement
utilise aussi par la section annotations du rapport texte) : ce module
construit dessus pour les besoins propres a l'UI (options de filtre,
ligne affichable, ajout/suppression avant ecriture du sidecar).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netcross_core.forensic import annotations_by_tag, annotations_sidecar_path, read_annotations, write_annotations
from netcross_core.logging_config import get_logger
from netcross_core.models import PacketAnnotation

logger = get_logger(__name__)


def available_tags(annotations: list[PacketAnnotation]) -> list[str]:
    """Liste triee des tags distincts presents, pour peupler la ListBox
    de filtre (un toggle par tag, voir docstring du module)."""
    return sorted(annotations_by_tag(annotations).keys())


def filter_by_tags(annotations: list[PacketAnnotation], selected_tags: set[str]) -> list[PacketAnnotation]:
    """Filtre les annotations dont le tag est dans `selected_tags`.

    Un `selected_tags` vide retourne la liste complete (aucun filtre
    actif) -- convention coherente avec les autres filtres de ce projet
    (ex. stats_view.build_query), plutot qu'une liste vide qui forcerait
    l'appelant a distinguer "aucun tag coche" de "aucune annotation"."""
    if not selected_tags:
        return list(annotations)
    return [ann for ann in annotations if ann.tag in selected_tags]


def format_annotation_row(annotation: PacketAnnotation) -> str:
    """Formate une annotation pour une ligne de ListBox."""
    suffix = f" -- {annotation.comment}" if annotation.comment else ""
    return f"[{annotation.tag}] trame #{annotation.frame_number}{suffix}"


def add_annotation(
    annotations: list[PacketAnnotation],
    frame_number: int,
    tag: str,
    comment: str = "",
    color: str | None = None,
) -> list[PacketAnnotation]:
    """Retourne une NOUVELLE liste avec l'annotation ajoutee (fonction
    pure, ne modifie pas `annotations` en place -- l'appelant ecrit le
    resultat via `netcross_core.forensic.write_annotations`).

    Un tag vide ou blanc est rejete (`ValueError`) : c'est la seule
    validation portee par ce module -- le clic droit GUI declenche cette
    fonction avec le texte saisi par l'analyste, qui peut etre vide."""
    tag = tag.strip()
    if not tag:
        raise ValueError("le tag d'une annotation ne peut pas etre vide")
    logger.debug("add_annotation: trame={} tag={}", frame_number, tag)
    return [*annotations, PacketAnnotation(frame_number=frame_number, tag=tag, comment=comment, color=color)]


def remove_annotation(annotations: list[PacketAnnotation], frame_number: int, tag: str) -> list[PacketAnnotation]:
    """Retourne une NOUVELLE liste sans l'annotation (frame_number, tag)
    -- supprime au plus une entree meme si plusieurs annotations
    partagent (frame_number, tag) par erreur amont (ecriture defensive,
    jamais cense arriver via `add_annotation` seul)."""
    result = list(annotations)
    for i, ann in enumerate(result):
        if ann.frame_number == frame_number and ann.tag == tag:
            del result[i]
            break
    logger.debug(
        "remove_annotation: trame={} tag={} supprimée={}",
        frame_number,
        tag,
        len(result) < len(annotations),
    )
    return result


def parse_frame_number(text: str) -> int:
    """Numero de trame saisi par l'analyste (>= 1, comme dans Wireshark).
    `ValueError` avec un message affichable sinon."""
    text = text.strip().lstrip("#")
    try:
        number = int(text)
    except ValueError:
        logger.debug("parse_frame_number: saisie invalide {!r}", text)
        raise ValueError(f"numero de trame invalide : {text!r}") from None
    if number < 1:
        raise ValueError("le numero de trame commence a 1")
    return number


@dataclass
class AnnotationStore:
    """Annotations des captures d'une analyse, une liste par point, chacune
    persistee dans le sidecar JSON de SA capture (issue #363).

    Chaque modification reecrit immediatement le sidecar concerne : pas
    d'etat en attente perdu a la fermeture de la fenetre. Un sidecar
    illisible n'empeche pas d'ouvrir les autres : l'erreur est gardee dans
    `errors` et ce point est en lecture seule (le reecrire effacerait les
    annotations que l'analyste voudra peut-etre recuperer a la main)."""

    captures: list[tuple[str, str]]
    by_label: dict[str, list[PacketAnnotation]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, captures) -> AnnotationStore:
        store = cls(captures=[(label, path) for label, path in captures])
        for label, path in store.captures:
            store._load_one(label, path)
        logger.debug(
            "AnnotationStore.load: {} capture(s), {} sidecar(s) illisible(s)", len(store.captures), len(store.errors)
        )
        return store

    def _load_one(self, label: str, path: str) -> None:
        logger.debug("_load_one: {} -> {}", label, annotations_sidecar_path(path))
        try:
            self.by_label[label] = read_annotations(path)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            # ValueError couvre json.JSONDecodeError ; KeyError/TypeError :
            # JSON valide mais pas une liste d'annotations
            self.errors[label] = f"{annotations_sidecar_path(path)} illisible : {exc}"
            logger.warning(f"annotations {label} : {self.errors[label]}")

    def labels(self) -> list[str]:
        return [label for label, _path in self.captures]

    def writable_labels(self) -> list[str]:
        return [label for label in self.labels() if label not in self.errors]

    def _path(self, label: str) -> str:
        for known, path in self.captures:
            if known == label:
                return path
        raise KeyError(f"point inconnu : {label}")

    def _save(self, label: str, annotations: list[PacketAnnotation]) -> None:
        if label in self.errors:
            raise ValueError(f"point {label} en lecture seule : {self.errors[label]}")
        write_annotations(self._path(label), annotations)  # OSError remonte : l'appelant l'affiche
        self.by_label[label] = annotations
        logger.debug("_save: {} annotation(s) écrite(s) pour {}", len(annotations), label)

    def add(self, label: str, frame_number: int, tag: str, comment: str = "") -> None:
        """Ajoute puis persiste. Un doublon exact (trame, tag) n'est pas
        ajoute une deuxieme fois : son commentaire est mis a jour."""
        logger.debug("AnnotationStore.add: point={} trame={} tag={}", label, frame_number, tag)
        current = self.by_label.get(label, [])
        updated = add_annotation(
            [a for a in current if not (a.frame_number == frame_number and a.tag == tag.strip())],
            frame_number,
            tag,
            comment.strip(),
        )
        self._save(label, updated)

    def remove(self, label: str, frame_number: int, tag: str) -> None:
        logger.debug("AnnotationStore.remove: point={} trame={} tag={}", label, frame_number, tag)
        self._save(label, remove_annotation(self.by_label.get(label, []), frame_number, tag))

    def tags(self) -> list[str]:
        return available_tags([a for anns in self.by_label.values() for a in anns])

    def rows(self, selected_tags: set[str] | None = None) -> list[tuple[str, PacketAnnotation]]:
        """(point, annotation) filtrees par tag (aucun tag coche : tout),
        dans l'ordre des points puis des trames."""
        return [
            (label, ann)
            for label in self.labels()
            for ann in sorted(filter_by_tags(self.by_label.get(label, []), selected_tags or set()), key=_ann_key)
        ]


def _ann_key(ann: PacketAnnotation) -> tuple[int, str]:
    return (ann.frame_number, ann.tag)
