"""netcross_gtk4.netflow_panel -- panneau GTK « NetFlow v5 » de la page
Resultats (issue #675).

Cablage GTK de `netflow_view` : exports ajoutes (un exportateur par
fichier, etiquette = nom du fichier), taille des classements, resume dans
un thread d'arriere-plan, export JSON identique a la CLI. Independant de
l'analyse de captures, comme ``--netflow`` (mode autonome).
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from netcross_core.logging_config import get_logger  # noqa: E402
from netcross_gtk4.netflow_view import (  # noqa: E402
    DEFAULT_TOP,
    NetflowFileError,
    summarize_files,
    write_netflow_json,
)

logger = get_logger(__name__)

EMPTY_MESSAGE = "(ajoutez un ou plusieurs exports NetFlow v5 : datagrammes concatenes, un fichier par exportateur)"


class NetflowPanel(Gtk.Box):
    def __init__(self, start_thread: Callable[[Callable[[], None]], None] | None = None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        logger.debug("NetflowPanel: construction du panneau")
        for side in ("top", "bottom", "start", "end"):
            getattr(self, f"set_margin_{side}")(6)
        self._start_thread = start_thread or (lambda fn: threading.Thread(target=fn, daemon=True).start())
        self.files: list[tuple[str | None, str]] = []
        self.summary: dict | None = None
        self.running = False

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.add_btn = Gtk.Button(label="Ajouter des exports...")
        self.add_btn.connect("clicked", self._on_add_clicked)
        self.clear_btn = Gtk.Button(label="Vider")
        self.clear_btn.connect("clicked", lambda _b: self.clear_files())
        row.append(self.add_btn)
        row.append(self.clear_btn)
        row.append(Gtk.Label(label="Top (--netflow-top) :"))
        self.top_spin = Gtk.SpinButton.new_with_range(1, 100, 1)
        self.top_spin.set_value(DEFAULT_TOP)
        row.append(self.top_spin)
        self.summarize_btn = Gtk.Button(label="Resumer")
        self.summarize_btn.connect("clicked", lambda _b: self.start_summary())
        row.append(self.summarize_btn)
        self.json_btn = Gtk.Button(label="Exporter JSON...")
        self.json_btn.connect("clicked", self._on_json_clicked)
        row.append(self.json_btn)
        self.append(row)

        self.files_label = Gtk.Label(label=EMPTY_MESSAGE, halign=Gtk.Align.START, wrap=True, xalign=0.0)
        self.append(self.files_label)
        self.text_view = Gtk.TextView(editable=False, monospace=True)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(80)
        scroller.set_max_content_height(300)
        scroller.set_propagate_natural_height(True)
        scroller.set_child(self.text_view)
        self.append(scroller)
        self.status_label = Gtk.Label(label="", halign=Gtk.Align.START, wrap=True, xalign=0.0)
        self.append(self.status_label)
        self._sync()

    # -- etat --------------------------------------------------------------

    def _sync(self) -> None:
        idle = not self.running
        self.add_btn.set_sensitive(idle)
        self.clear_btn.set_sensitive(idle and bool(self.files))
        self.summarize_btn.set_sensitive(idle and bool(self.files))
        self.json_btn.set_sensitive(idle and self.summary is not None)
        if self.files:
            noms = ", ".join(f"{exp}={os.path.basename(p)}" if exp else os.path.basename(p) for exp, p in self.files)
            self.files_label.set_text(f"{len(self.files)} export(s) : {noms}")
        else:
            self.files_label.set_text(EMPTY_MESSAGE)

    def add_files(self, paths) -> None:
        """Ajoute des exports ; etiquette d'exportateur = nom du fichier
        (sans extension), comme ``EXPORTATEUR=FICHIER`` dans la CLI."""
        for path in paths:
            exporter = os.path.splitext(os.path.basename(path))[0] or None
            if all(p != path for _e, p in self.files):
                self.files.append((exporter, path))
        self.summary = None
        self._sync()

    def clear_files(self) -> None:
        self.files = []
        self.summary = None
        self.text_view.get_buffer().set_text("")
        self.status_label.set_text("")
        self._sync()

    # -- actions -----------------------------------------------------------

    def start_summary(self) -> bool:
        if self.running or not self.files:
            return False
        files = list(self.files)
        top = int(self.top_spin.get_value())
        self.running = True
        self._sync()
        self.status_label.set_text(f"Lecture de {len(files)} export(s)...")

        def work():
            try:
                summary, lines = summarize_files(files, top)
            except NetflowFileError as exc:
                logger.debug("NetflowPanel.start_summary: {}", exc)
                GLib.idle_add(self._on_summary_done, None, [], str(exc))
                return
            GLib.idle_add(self._on_summary_done, summary, lines, None)

        self._start_thread(work)
        return True

    def _on_summary_done(self, summary, lines, error):
        self.running = False
        if error is not None:
            self.summary = None
            self.status_label.set_text(f"NetFlow : {error}")
        else:
            self.summary = summary
            self.text_view.get_buffer().set_text("\n".join(lines))
            self.status_label.set_text("")
        self._sync()
        return False

    def export_to(self, path) -> None:
        if self.summary is None:
            self.status_label.set_text("Rien a exporter : lancez d'abord « Resumer ».")
            return
        written = write_netflow_json(path, self.summary)
        self.status_label.set_text(f"Rapport JSON ecrit : {written}")

    def _on_add_clicked(self, _btn):
        dialog = Gtk.FileDialog()
        dialog.set_title("Exports NetFlow v5")
        root = self.get_root()
        dialog.open_multiple(root if isinstance(root, Gtk.Window) else None, None, self._on_files_chosen)

    def _on_files_chosen(self, dialog, result):
        try:
            files = dialog.open_multiple_finish(result)
        except GLib.Error as exc:
            logger.debug("NetflowPanel._on_files_chosen: dialogue annule ({})", exc)
            return
        paths = [files.get_item(i).get_path() for i in range(files.get_n_items())]
        self.add_files([p for p in paths if p])

    def _on_json_clicked(self, _btn):
        if self.summary is None:
            return
        dialog = Gtk.FileDialog()
        dialog.set_initial_name("netflow.json")
        root = self.get_root()
        dialog.save(root if isinstance(root, Gtk.Window) else None, None, self._on_json_chosen)

    def _on_json_chosen(self, dialog, result):
        try:
            gfile = dialog.save_finish(result)
        except GLib.Error as exc:
            logger.debug("NetflowPanel._on_json_chosen: dialogue annule ({})", exc)
            return
        path = gfile.get_path() if gfile is not None else None
        if not path:
            return
        try:
            self.export_to(path)
        except OSError as exc:
            logger.warning("NetflowPanel: export impossible ({})", exc)
            self.status_label.set_text(f"Export impossible : {exc}")
