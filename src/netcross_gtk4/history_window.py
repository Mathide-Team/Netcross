"""netcross_gtk4.history_window -- fenetre « Historique des runs »
(issue #874) : consultation d'une base ``--history-db`` sans relancer
d'analyse, avec les filtres de ``netcross-history`` (``--run-type``,
``--label``, ``--limit``). Analyses et comparaisons confondues.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from netcross_core.logging_config import get_logger  # noqa: E402
from netcross_gtk4.file_option import FileOption  # noqa: E402
from netcross_gtk4.report_exports import history_text  # noqa: E402

logger = get_logger(__name__)

RUN_TYPE_LABELS = ("Tous", "Analyses (analyse)", "Comparaisons (diff)")
RUN_TYPE_VALUES = (None, "analyse", "diff")


class HistoryWindow(Gtk.Window):
    def __init__(self, parent: Gtk.Window | None = None, db_path: str | None = None, label: str | None = None):
        super().__init__(title="Historique des runs", default_width=820, default_height=480)
        if parent is not None:
            self.set_transient_for(parent)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        for side in ("top", "bottom", "start", "end"):
            getattr(box, f"set_margin_{side}")(10)
        self.db_option = FileOption(
            "Base d'historique...",
            "Base SQLite alimentee par --history-db (analyses et comparaisons)",
            ("*.db", "*.sqlite", "*.sqlite3"),
            "Bases SQLite",
        )
        self.db_option.set_path(db_path)
        box.append(self.db_option)
        filters = Gtk.Box(spacing=8)
        filters.append(Gtk.Label(label="Type (--run-type) :"))
        self.run_type_dropdown = Gtk.DropDown.new_from_strings(list(RUN_TYPE_LABELS))
        filters.append(self.run_type_dropdown)
        filters.append(Gtk.Label(label="Etiquette (--label) :"))
        self.label_entry = Gtk.Entry(placeholder_text="etiquette exacte", text=label or "")
        filters.append(self.label_entry)
        filters.append(Gtk.Label(label="Runs max. (--limit, 0 = tous) :"))
        self.limit_spin = Gtk.SpinButton.new_with_range(0, 100000, 1)
        self.limit_spin.set_value(20)
        filters.append(self.limit_spin)
        self.show_btn = Gtk.Button(label="Afficher")
        self.show_btn.connect("clicked", lambda _b: self.show_history())
        filters.append(self.show_btn)
        box.append(filters)
        self.view = Gtk.TextView(editable=False, monospace=True, cursor_visible=False, vexpand=True)
        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_child(self.view)
        box.append(scroll)
        self.set_child(box)

    def selected_run_type(self) -> str | None:
        return RUN_TYPE_VALUES[self.run_type_dropdown.get_selected()]

    def show_history(self) -> str:
        """Meme texte que ``netcross-history --db ... [--run-type] [--label] [--limit]``."""
        from netcross_report import HistoryDatabaseError

        if not self.db_option.path:
            text = "Choisissez une base d'historique."
        else:
            try:
                text = history_text(
                    self.db_option.path,
                    self.limit_spin.get_value_as_int(),
                    self.label_entry.get_text().strip() or None,
                    self.selected_run_type(),
                )
            except HistoryDatabaseError as exc:
                logger.warning("HistoryWindow: historique illisible ({})", exc)
                text = str(exc)
        self.view.get_buffer().set_text(text)
        return text
