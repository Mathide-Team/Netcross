"""netcross_gtk4.file_option -- champ « fichier facultatif » de la
configuration : bouton de choix, « Retirer », nom du fichier retenu.

Utilise par les options avancees de l'issue #672 (destinations et hotes
connus, base CVE) ; ``set_path`` est expose pour les tests.
"""

from __future__ import annotations

import os

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gio, GLib, Gtk  # noqa: E402

from netcross_core.logging_config import get_logger  # noqa: E402

logger = get_logger(__name__)


class FileOption(Gtk.Box):
    def __init__(self, label: str, tooltip: str, patterns: tuple[str, ...], filter_name: str):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.path: str | None = None
        self._label = label
        self._patterns = patterns
        self._filter_name = filter_name
        self.choose_btn = Gtk.Button(label=label)
        self.choose_btn.set_tooltip_text(tooltip)
        self.choose_btn.connect("clicked", self._on_choose)
        self.clear_btn = Gtk.Button(label="Retirer")
        self.clear_btn.connect("clicked", lambda _b: self.set_path(None))
        self.name_label = Gtk.Label(label="(aucun)", halign=Gtk.Align.START)
        for widget in (self.choose_btn, self.clear_btn, self.name_label):
            self.append(widget)
        self.set_path(None)

    def set_path(self, path: str | None) -> None:
        self.path = path or None
        self.name_label.set_text(os.path.basename(path) if path else "(aucun)")
        self.name_label.set_tooltip_text(path)
        self.clear_btn.set_sensitive(self.path is not None)
        logger.debug("FileOption.set_path: {} -> {}", self._label, self.path)

    def _on_choose(self, _btn) -> None:
        dialog = Gtk.FileDialog()
        filt = Gtk.FileFilter()
        for pattern in self._patterns:
            filt.add_pattern(pattern)
        filt.set_name(self._filter_name)
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filt)
        dialog.set_filters(filters)
        root = self.get_root()
        dialog.open(root if isinstance(root, Gtk.Window) else None, None, self._on_chosen)

    def _on_chosen(self, dialog, result) -> None:
        try:
            gfile = dialog.open_finish(result)
        except GLib.Error as exc:
            logger.debug("FileOption._on_chosen: dialogue annule ({})", exc)
            return
        self.set_path(gfile.get_path())
