"""netcross_gtk4.client_compare_panel -- panneau GTK « Comparaison de
postes » de la page Resultats (issue #675).

Synthese de la comparaison (le detail est dans le rapport texte, comme
dans la CLI) et export CSV identique a ``--client-diff-csv``.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from netcross_core.logging_config import get_logger  # noqa: E402
from netcross_gtk4.client_compare_view import comparison_summary  # noqa: E402

logger = get_logger(__name__)


class ClientComparisonPanel(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        logger.debug("ClientComparisonPanel: construction du panneau")
        for side in ("top", "bottom", "start", "end"):
            getattr(self, f"set_margin_{side}")(6)
        self.comparison = None
        self.summary_label = Gtk.Label(label="", halign=Gtk.Align.START, wrap=True, xalign=0.0)
        self.summary_label.set_selectable(True)
        self.append(self.summary_label)
        self.csv_btn = Gtk.Button(label="Exporter CSV (--client-diff-csv)...")
        self.csv_btn.set_halign(Gtk.Align.START)
        self.csv_btn.connect("clicked", self._on_csv_clicked)
        self.append(self.csv_btn)
        self.status_label = Gtk.Label(label="", halign=Gtk.Align.START, wrap=True, xalign=0.0)
        self.append(self.status_label)
        self.set_comparison(None)

    def set_comparison(self, comparison) -> None:
        self.comparison = comparison
        self.summary_label.set_text(comparison_summary(comparison))
        self.status_label.set_text("")
        self.csv_btn.set_sensitive(comparison is not None)
        logger.debug("ClientComparisonPanel.set_comparison: {}", comparison is not None)

    def export_to(self, path) -> None:
        from netcross_core.client_diff import write_client_diff_csv

        write_client_diff_csv(self.comparison, str(path))
        self.status_label.set_text(f"Detail de la comparaison client vs client ecrit dans {path}")

    def _on_csv_clicked(self, _btn):
        if self.comparison is None:
            return
        dialog = Gtk.FileDialog()
        dialog.set_initial_name("comparaison-postes.csv")
        root = self.get_root()
        dialog.save(root if isinstance(root, Gtk.Window) else None, None, self._on_csv_chosen)

    def _on_csv_chosen(self, dialog, result):
        try:
            gfile = dialog.save_finish(result)
        except GLib.Error as exc:
            logger.debug("ClientComparisonPanel._on_csv_chosen: dialogue annule ({})", exc)
            return
        path = gfile.get_path() if gfile is not None else None
        if not path:
            return
        try:
            self.export_to(path)
        except OSError as exc:
            logger.warning("ClientComparisonPanel: export impossible ({})", exc)
            self.status_label.set_text(f"Export impossible : {exc}")
