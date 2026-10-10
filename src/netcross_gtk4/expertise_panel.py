"""netcross_gtk4.expertise_panel -- panneau « Expertise (exports JSON) » de la
page Resultats (issue #673).

Exporte la chronologie des flux et les statistiques tshark calculees pendant
l'analyse (cases « Chronologie des flux » et « Statistiques tshark » de la
configuration) : memes fichiers que ``--flow-timeline`` et ``--tshark-stats``.
Les autres sections d'expertise (moteur de regles, section expertise,
qualite media) sont dans le rapport texte.
"""

from __future__ import annotations

from typing import Any

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gio, Gtk  # noqa: E402

from netcross_core.logging_config import get_logger  # noqa: E402
from netcross_gtk4.expertise_view import timeline_summary, tshark_stats_summary, write_json  # noqa: E402

logger = get_logger(__name__)


class ExpertisePanel(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        logger.debug("ExpertisePanel: construction du panneau")
        for side in ("top", "bottom", "start", "end"):
            getattr(self, f"set_margin_{side}")(6)
        self.exports: Any = None

        self.timeline_label = Gtk.Label(label=timeline_summary(None), halign=Gtk.Align.START, wrap=True)
        self.stats_label = Gtk.Label(label=tshark_stats_summary(None), halign=Gtk.Align.START, wrap=True)
        self.status_label = Gtk.Label(label="", halign=Gtk.Align.START, wrap=True)
        self.status_label.set_selectable(True)
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.timeline_btn = Gtk.Button(label="Exporter la chronologie (--flow-timeline)...")
        self.timeline_btn.connect("clicked", lambda _b: self._choose("flow_timelines", "chronologie-flux.json"))
        self.stats_btn = Gtk.Button(label="Exporter les statistiques tshark (--tshark-stats)...")
        self.stats_btn.connect("clicked", lambda _b: self._choose("tshark_stats", "statistiques-tshark.json"))
        buttons.append(self.timeline_btn)
        buttons.append(self.stats_btn)
        for widget in (self.timeline_label, self.stats_label, buttons, self.status_label):
            self.append(widget)
        self._sync()

    def set_exports(self, exports) -> None:
        """Documents de la derniere analyse (ExpertiseExports ou None)."""
        self.exports = exports
        self.status_label.set_text("")
        self._sync()
        logger.debug("ExpertisePanel.set_exports: {}", exports is not None)

    def _document(self, key: str):
        return getattr(self.exports, key, None) if self.exports is not None else None

    def _sync(self) -> None:
        timelines = self._document("flow_timelines")
        stats = self._document("tshark_stats")
        self.timeline_label.set_text(timeline_summary(timelines))
        self.stats_label.set_text(tshark_stats_summary(stats))
        self.timeline_btn.set_sensitive(timelines is not None)
        self.stats_btn.set_sensitive(stats is not None)

    def export_to(self, key: str, path) -> str:
        document = self._document(key)
        if document is None:
            raise ValueError("rien a exporter : relancez l'analyse avec la case correspondante")
        written = write_json(path, document)
        self.status_label.set_text(f"Ecrit dans {written}")
        return written

    def _choose(self, key: str, initial_name: str) -> None:
        dialog = Gtk.FileDialog()
        dialog.set_initial_name(initial_name)
        root = self.get_root()
        dialog.save(root if isinstance(root, Gtk.Window) else None, None, lambda d, res: self._on_chosen(d, res, key))

    def _on_chosen(self, dialog, result, key: str) -> None:
        try:
            gfile = dialog.save_finish(result)
        except Exception as exc:  # noqa: BLE001 -- annulation du dialogue
            logger.debug("ExpertisePanel._on_chosen: dialogue annule ({})", exc)
            return
        path = gfile.get_path() if isinstance(gfile, Gio.File) else None
        if not path:
            logger.debug("ExpertisePanel._on_chosen: pas de chemin local")
            return
        try:
            self.export_to(key, path)
        except (OSError, ValueError) as exc:
            logger.warning("ExpertisePanel: export impossible ({})", exc)
            self.status_label.set_text(f"Export impossible : {exc}")
