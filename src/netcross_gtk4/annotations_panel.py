"""netcross_gtk4.annotations_panel -- panneau GTK des annotations (issue #363).

Cablage GTK de `annotations_view` (Job 40 / issue #160) :

* choix du point (une capture = un sidecar `<capture>.annotations.json`) ;
* formulaire trame / etiquette / commentaire ;
* clic droit sur une annotation -> menu contextuel « Ajouter une etiquette
  sur cette trame » (prerempli) / « Supprimer cette etiquette » ; clic droit
  sur la liste vide -> « Ajouter une etiquette » ;
* filtre par etiquette (une case par tag present, aucune cochee = tout).

Toute la logique (validation, persistance, filtrage) est dans
`annotations_view.AnnotationStore` ; ce module ne fait que la relier aux
widgets. L'interface n'a pas de liste paquet par paquet : l'etiquette se
pose sur un numero de trame, celui qu'affiche Wireshark ou un constat.
"""

from __future__ import annotations

from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, Gtk  # noqa: E402

from netcross_core.logging_config import get_logger  # noqa: E402
from netcross_gtk4.annotations_view import AnnotationStore, format_annotation_row, parse_frame_number  # noqa: E402

logger = get_logger(__name__)


class AnnotationsPanel(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        logger.debug("AnnotationsPanel: construction du panneau")
        for side in ("top", "bottom", "start", "end"):
            getattr(self, f"set_margin_{side}")(6)
        self.store: AnnotationStore | None = None
        self.selected_tags: set[str] = set()
        self._point_labels: list[str] = []

        self.status_label = Gtk.Label(label="(lancer une analyse de fichiers pour annoter)", halign=Gtk.Align.START)
        self.status_label.set_wrap(True)
        self.append(self.status_label)

        self.tags_box = Gtk.FlowBox()
        self.tags_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.append(self.tags_box)

        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(80)
        scroller.set_max_content_height(220)
        scroller.set_propagate_natural_height(True)
        scroller.set_child(self.list_box)
        self.append(scroller)
        # clic droit sur la liste (ligne ou zone vide) -> menu contextuel
        click = Gtk.GestureClick(button=3)
        click.connect("pressed", self._on_right_click)
        self.list_box.add_controller(click)

        form = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.point_drop = Gtk.DropDown.new_from_strings([])
        self.point_drop.set_tooltip_text("Point de capture : l'annotation est ecrite dans le sidecar de SA capture")
        self.frame_entry = Gtk.Entry(placeholder_text="Trame #", width_chars=8)
        self.tag_entry = Gtk.Entry(placeholder_text="Etiquette", width_chars=12)
        self.comment_entry = Gtk.Entry(placeholder_text="Commentaire (optionnel)", hexpand=True)
        self.add_btn = Gtk.Button(label="Ajouter")
        self.add_btn.connect("clicked", lambda _b: self.submit())
        for entry in (self.frame_entry, self.tag_entry, self.comment_entry):
            entry.connect("activate", lambda _e: self.submit())
        for widget in (self.point_drop, self.frame_entry, self.tag_entry, self.comment_entry, self.add_btn):
            form.append(widget)
        self.append(form)
        self._set_form_sensitive(False)

    # -- etat ---------------------------------------------------------------

    def load(self, captures) -> None:
        """Charge les sidecars des captures analysees (liste (label, chemin))."""
        logger.debug("AnnotationsPanel.load: {} capture(s)", len(captures))
        self.store = AnnotationStore.load(captures)
        self.selected_tags = set()
        self._point_labels = self.store.writable_labels()
        logger.debug(
            "AnnotationsPanel.load: {} point(s) inscriptible(s), {} en lecture seule",
            len(self._point_labels),
            len(self.store.errors),
        )
        self.point_drop.set_model(Gtk.StringList.new(self._point_labels))
        self._set_form_sensitive(bool(self._point_labels))
        self._status(None)
        self.refresh()

    def clear(self) -> None:
        """Analyse sans fichiers (capture en direct, diff) : rien a annoter."""
        logger.debug("AnnotationsPanel.clear: aucune capture fichier à annoter")
        self.store = None
        self._point_labels = []
        self.point_drop.set_model(Gtk.StringList.new([]))
        self._set_form_sensitive(False)
        self._status("Annotations disponibles pour une analyse de fichiers de capture.")
        self.refresh()

    def _set_form_sensitive(self, sensitive: bool) -> None:
        logger.debug("_set_form_sensitive: {}", sensitive)
        for widget in (self.point_drop, self.frame_entry, self.tag_entry, self.comment_entry, self.add_btn):
            widget.set_sensitive(sensitive)

    def _status(self, message: str | None) -> None:
        errors = list(self.store.errors.values()) if self.store else []
        lines = ([message] if message else []) + [f"Lecture seule : {e}" for e in errors]
        if not lines and self.store is not None:
            lines = ["Clic droit sur une annotation pour l'etendre ou la supprimer."]
        logger.debug("_status: {} ligne(s)", len(lines))
        self.status_label.set_text("\n".join(lines))

    # -- actions -------------------------------------------------------------

    def selected_point(self) -> str | None:
        idx = self.point_drop.get_selected()
        if 0 <= idx < len(self._point_labels):
            return self._point_labels[idx]
        return None

    def prefill(self, point: str | None, frame_number: int | None) -> None:
        """Preremplit le formulaire (menu contextuel) et place le focus sur
        l'etiquette : il ne reste qu'a la saisir."""
        logger.debug("prefill: point={} trame={}", point, frame_number)
        if point in self._point_labels:
            self.point_drop.set_selected(self._point_labels.index(point))
        self.frame_entry.set_text("" if frame_number is None else str(frame_number))
        self.tag_entry.set_text("")
        self.comment_entry.set_text("")
        (self.tag_entry if frame_number is not None else self.frame_entry).grab_focus()

    def submit(self) -> bool:
        """Valide le formulaire ; True si l'annotation est enregistree."""
        point = self.selected_point()
        logger.debug("submit: point={}", point)
        if self.store is None or point is None:
            return False
        try:
            frame_number = parse_frame_number(self.frame_entry.get_text())
            self.store.add(point, frame_number, self.tag_entry.get_text(), self.comment_entry.get_text())
        except (ValueError, OSError) as exc:
            logger.warning("submit: annotation non enregistrée sur {} ({})", point, exc)
            self._status(f"Annotation non enregistree : {exc}")
            return False
        self.frame_entry.set_text("")
        self.tag_entry.set_text("")
        self.comment_entry.set_text("")
        self._status(None)
        self.refresh()
        logger.debug("submit: annotation enregistrée sur {}", point)
        return True

    def remove(self, point: str, frame_number: int, tag: str) -> None:
        logger.debug("AnnotationsPanel.remove: point={} trame={} tag={}", point, frame_number, tag)
        if self.store is None:
            return
        try:
            self.store.remove(point, frame_number, tag)
        except (ValueError, OSError) as exc:
            logger.warning("remove: suppression impossible sur {} ({})", point, exc)
            self._status(f"Suppression impossible : {exc}")
            return
        self.selected_tags &= set(self.store.tags())
        self._status(None)
        self.refresh()

    def toggle_tag(self, tag: str, active: bool) -> None:
        logger.debug("toggle_tag: {} actif={}", tag, active)
        if active:
            self.selected_tags.add(tag)
        else:
            self.selected_tags.discard(tag)
        self._refresh_rows()

    # -- rendu ---------------------------------------------------------------

    def refresh(self) -> None:
        self._refresh_tags()
        self._refresh_rows()

    def _refresh_tags(self) -> None:
        while (child := self.tags_box.get_first_child()) is not None:
            self.tags_box.remove(child)
        tags = self.store.tags() if self.store else []
        logger.debug("_refresh_tags: {} étiquette(s)", len(tags))
        if tags:
            self.tags_box.append(Gtk.Label(label="Filtrer :"))
        for tag in tags:
            check = Gtk.CheckButton(label=tag, active=tag in self.selected_tags)
            check.connect("toggled", lambda b, t=tag: self.toggle_tag(t, b.get_active()))
            self.tags_box.append(check)

    def visible_rows(self):
        return self.store.rows(self.selected_tags) if self.store else []

    def _refresh_rows(self) -> None:
        while (child := self.list_box.get_first_child()) is not None:
            self.list_box.remove(child)
        rows = self.visible_rows()
        logger.debug("_refresh_rows: {} annotation(s) visible(s)", len(rows))
        if not rows:
            self.list_box.append(Gtk.Label(label="(aucune annotation)", halign=Gtk.Align.START))
        for point, ann in rows:
            row = Gtk.ListBoxRow()
            row.annotation = (point, ann.frame_number, ann.tag)
            row.set_child(Gtk.Label(label=f"{point} {format_annotation_row(ann)}", halign=Gtk.Align.START, wrap=True))
            self.list_box.append(row)

    # -- menu contextuel -----------------------------------------------------

    def context_actions(self, target) -> list[tuple[str, Callable[[], None]]]:
        """Entrees du menu contextuel pour `target` = (point, trame, tag)
        ou None (zone vide). Extrait pour etre testable sans simuler le clic."""
        if not self._point_labels:
            return []
        if target is None:
            return [("Ajouter une etiquette", lambda: self.prefill(self.selected_point(), None))]
        point, frame_number, tag = target
        actions = []
        if point in self._point_labels:
            actions.append(("Ajouter une etiquette sur cette trame", lambda: self.prefill(point, frame_number)))
            actions.append(("Supprimer cette etiquette", lambda: self.remove(point, frame_number, tag)))
        logger.debug("context_actions: cible={} -> {} action(s)", target, len(actions))
        return actions

    def _on_right_click(self, gesture, _n_press, x, y) -> None:
        row = self.list_box.get_row_at_y(int(y))
        actions = self.context_actions(getattr(row, "annotation", None))
        logger.debug("_on_right_click: y={} -> {} action(s)", y, len(actions))
        if not actions:
            return
        gesture.set_state(Gtk.EventSequenceState.CLAIMED)
        popover = Gtk.Popover()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        for label, callback in actions:
            btn = Gtk.Button(label=label, has_frame=False, halign=Gtk.Align.FILL)
            btn.connect("clicked", lambda _b, cb=callback, p=popover: (p.popdown(), cb()))
            box.append(btn)
        popover.set_child(box)
        popover.set_parent(self.list_box)
        rect = Gdk.Rectangle()
        rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
        popover.set_pointing_to(rect)
        popover.connect("closed", lambda p: p.unparent())
        popover.popup()
