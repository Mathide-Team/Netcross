"""netcross_gtk4.batch_window -- fenetre « Analyse d'un dossier » (issue
#872), equivalent de ``cross_capture_batch_cli.py`` : choix du dossier,
regroupement, nombre de taches, sortie, avancement ligne a ligne.

Moteur partage avec la CLI et l'API : ``netcross_report.batch_runner``
(``list_captures``, ``check_options``, ``run_batch``), donc memes groupes,
memes rapports, memes refus. ``run_batch_now`` est synchrone (tests) ; le
bouton le lance dans un thread, l'avancement est poste via ``GLib.idle_add``.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from netcross_core.batch import DEFAULT_GROUP_WINDOW, DEFAULT_MIN_COMMON_IPS, DEFAULT_MIN_OVERLAP  # noqa: E402
from netcross_core.logging_config import get_logger  # noqa: E402
from netcross_gtk4.capture_tools_window import PathChooser, _grid, _row  # noqa: E402
from netcross_report import batch_runner  # noqa: E402

logger = get_logger(__name__)


class BatchWindow(Gtk.Window):
    def __init__(
        self, parent: Gtk.Window | None = None, start_thread: Callable[[Callable[[], None]], None] | None = None
    ):
        super().__init__(title="Analyse d'un dossier", default_width=780, default_height=560)
        if parent is not None:
            self.set_transient_for(parent)
        self._start_thread = start_thread or (lambda fn: threading.Thread(target=fn, daemon=True).start())
        self.running = False
        self.result: batch_runner.BatchResult | None = None
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        grid = _grid()
        self.input_dir = PathChooser("Dossier de captures...", "folder")
        _row(grid, 0, "Captures (--input) :", self.input_dir)
        self.recursive = Gtk.CheckButton(label="Inclure les sous-dossiers (--recursive)")
        grid.attach(self.recursive, 1, 1, 1, 1)
        self.group = Gtk.CheckButton(label="Regrouper les captures d'un meme incident (sans --no-group)")
        self.group.set_active(True)
        grid.attach(self.group, 1, 2, 1, 1)
        self.group_window = Gtk.SpinButton.new_with_range(0, 86400, 1)
        self.group_window.set_digits(1)
        self.group_window.set_value(DEFAULT_GROUP_WINDOW)
        _row(grid, 3, "Fenetre de regroupement en s (--group-window) :", self.group_window)
        self.min_overlap = Gtk.SpinButton.new_with_range(0.01, 1.0, 0.05)
        self.min_overlap.set_digits(2)
        self.min_overlap.set_value(DEFAULT_MIN_OVERLAP)
        _row(grid, 4, "Recouvrement minimal (--min-overlap) :", self.min_overlap)
        self.min_common_ips = Gtk.SpinButton.new_with_range(1, 1000, 1)
        self.min_common_ips.set_value(DEFAULT_MIN_COMMON_IPS)
        _row(grid, 5, "Adresses communes minimales (--min-common-ips) :", self.min_common_ips)
        self.jobs = Gtk.SpinButton.new_with_range(1, max(1, os.cpu_count() or 1) * 4, 1)
        self.jobs.set_value(1)
        _row(grid, 6, "Taches en parallele (--jobs) :", self.jobs)
        self.skip_existing = Gtk.CheckButton(label="Reprendre un lot interrompu (--skip-existing)")
        grid.attach(self.skip_existing, 1, 7, 1, 1)
        self.security_report = Gtk.CheckButton(label="Analyse de securite dans chaque rapport (--security-report)")
        grid.attach(self.security_report, 1, 8, 1, 1)
        self.output_dir = PathChooser("Dossier de sortie...", "folder")
        _row(grid, 9, "Rapports (--output) :", self.output_dir)
        self.run_btn = Gtk.Button(label="Analyser le dossier", halign=Gtk.Align.START)
        self.run_btn.connect("clicked", lambda _b: self.launch())
        grid.attach(self.run_btn, 1, 10, 1, 1)
        root.append(grid)

        self.progress_view = Gtk.TextView(editable=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_child(self.progress_view)
        for side in ("start", "end"):
            getattr(scroller, f"set_margin_{side}")(10)
        root.append(scroller)
        self.status_label = Gtk.Label(label="", xalign=0.0, wrap=True, selectable=True)
        for side in ("start", "end", "bottom"):
            getattr(self.status_label, f"set_margin_{side}")(10)
        root.append(self.status_label)
        self.set_child(root)

    # -- reglages --------------------------------------------------------------

    def options(self) -> batch_runner.BatchOptions:
        return batch_runner.BatchOptions(
            recursive=self.recursive.get_active(),
            group=self.group.get_active(),
            group_window=self.group_window.get_value(),
            min_overlap=self.min_overlap.get_value(),
            min_common_ips=self.min_common_ips.get_value_as_int(),
            jobs=self.jobs.get_value_as_int(),
            skip_existing=self.skip_existing.get_active(),
            security_report=self.security_report.get_active(),
        )

    def progress_text(self) -> str:
        buf = self.progress_view.get_buffer()
        return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)

    def _append_progress(self, message: str) -> bool:
        buf = self.progress_view.get_buffer()
        buf.insert(buf.get_end_iter(), message + "\n")
        return False

    # -- execution ---------------------------------------------------------------

    def run_batch_now(self, progress: Callable[[str], None] | None = None) -> str:
        """Lot complet, memes refus que la CLI ; renvoie le message de fin."""
        folder = self.input_dir.path
        if not folder or not os.path.isdir(folder):
            raise ValueError(f"--input : dossier introuvable : {folder or '(aucun)'}")
        output = self.output_dir.path
        if not output:
            raise ValueError("choisissez le dossier de sortie (--output)")
        options = self.options()
        refus = batch_runner.check_options(options)
        if refus:
            raise ValueError(refus)
        captures, ignored = batch_runner.list_captures(folder, options.recursive)
        if not captures:
            raise ValueError(f"Aucune capture ({', '.join(batch_runner.CAPTURE_EXTENSIONS)}) dans {folder}.")
        report = progress or (lambda msg: GLib.idle_add(self._append_progress, msg))
        result = batch_runner.run_batch(captures, ignored, output, options, folder, report)
        self.result = result
        plan = result.plan
        message = (
            f"{len(captures)} capture(s) : {len(plan.groups)} groupe(s), {len(plan.isolated)} isolee(s), "
            f"{len(plan.failures) + len(result.errors)} echec(s). Index : {result.index_path}"
        )
        logger.info("BatchWindow: {}", message)
        return message

    def launch(self) -> None:
        if self.running:
            return
        self.running = True
        self.run_btn.set_sensitive(False)
        self.progress_view.get_buffer().set_text("")
        self.status_label.set_text("En cours...")

        def _thread() -> None:
            try:
                message = self.run_batch_now()
            except (OSError, ValueError, RuntimeError) as exc:
                logger.warning("BatchWindow: {}", exc)
                message = f"Erreur : {exc}"
            GLib.idle_add(self._done, message)

        self._start_thread(_thread)

    def _done(self, message: str) -> bool:
        self.running = False
        self.run_btn.set_sensitive(True)
        self.status_label.set_text(message)
        return False
