"""netcross_gtk4.capture_tools_window -- fenetre « Outils de capture »
(issues #868, #869, #870, #886, #887) : fusion, decoupage, conversion,
export filtre et recalage temporel, equivalents des modes utilitaires de
la CLI (``--merge``, ``--split``, ``--convert``, ``--export-pcap``,
``--adjust-time-output``).

Validation, messages et traitements : ``netcross_core.capture_tools``,
partage avec la CLI et l'API. Aucune analyse n'est lancee. Les actions
``run_*`` sont synchrones (tests) ; les boutons les lancent dans un thread.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gio, GLib, Gtk  # noqa: E402

from netcross_core import capture_tools  # noqa: E402
from netcross_core.logging_config import get_logger  # noqa: E402

logger = get_logger(__name__)

CAPTURE_PATTERNS = ("*.pcap", "*.pcapng", "*.cap", "*.erf", "*.pcap.gz", "*.pcapng.gz")
SPLIT_LABELS = ("Duree (s) -- time", "Paquets -- count", "Taille (ex: 100M) -- size")
ADJUST_MODES = ("Decalage (--time-offset)", "Normaliser a t=0 (--normalize-time)", "Aligner sur (--align-to)")
OUTPUT_FORMATS = ("pcapng", "pcap")


class PathChooser(Gtk.Box):
    """Bouton de choix (ouvrir, enregistrer, dossier) + chemin retenu."""

    def __init__(self, label: str, mode: str = "open", initial_name: str = ""):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.mode = mode
        self.initial_name = initial_name
        self.path: str | None = None
        self.button = Gtk.Button(label=label)
        self.button.connect("clicked", self._on_clicked)
        self.name_label = Gtk.Label(label="(aucun)", halign=Gtk.Align.START, hexpand=True, xalign=0.0)
        self.append(self.button)
        self.append(self.name_label)

    def set_path(self, path: str | None) -> None:
        self.path = path or None
        self.name_label.set_text(path or "(aucun)")

    def _on_clicked(self, _btn) -> None:
        dialog = Gtk.FileDialog()
        root = self.get_root()
        parent = root if isinstance(root, Gtk.Window) else None
        if self.mode == "folder":
            dialog.select_folder(parent, None, self._on_done)
        elif self.mode == "save":
            if self.initial_name:
                dialog.set_initial_name(self.initial_name)
            dialog.save(parent, None, self._on_done)
        else:
            filt = Gtk.FileFilter()
            for pattern in CAPTURE_PATTERNS:
                filt.add_pattern(pattern)
            filt.set_name("Captures")
            filters = Gio.ListStore.new(Gtk.FileFilter)
            filters.append(filt)
            dialog.set_filters(filters)
            dialog.open(parent, None, self._on_done)

    def _on_done(self, dialog, result) -> None:
        finish = {"folder": dialog.select_folder_finish, "save": dialog.save_finish}.get(self.mode, dialog.open_finish)
        try:
            gfile = finish(result)
        except GLib.Error as exc:
            logger.debug("PathChooser: dialogue annule ({})", exc)
            return
        self.set_path(gfile.get_path())


def _optional_float(text: str, name: str) -> float | None:
    text = text.strip().replace(",", ".")
    if not text:
        return None
    try:
        return float(text)
    except ValueError as exc:
        logger.debug("_optional_float: {} invalide ({})", name, exc)
        raise ValueError(f"{name} : nombre attendu, recu {text!r}") from exc


def _grid() -> Gtk.Grid:
    grid = Gtk.Grid(column_spacing=8, row_spacing=6)
    for side in ("top", "bottom", "start", "end"):
        getattr(grid, f"set_margin_{side}")(10)
    return grid


def _row(grid: Gtk.Grid, row: int, label: str, widget: Gtk.Widget) -> None:
    grid.attach(Gtk.Label(label=label, xalign=0.0), 0, row, 1, 1)
    grid.attach(widget, 1, row, 1, 1)


class CaptureToolsWindow(Gtk.Window):
    def __init__(
        self, parent: Gtk.Window | None = None, start_thread: Callable[[Callable[[], None]], None] | None = None
    ):
        super().__init__(title="Outils de capture", default_width=760, default_height=420)
        if parent is not None:
            self.set_transient_for(parent)
        self._start_thread = start_thread or (lambda fn: threading.Thread(target=fn, daemon=True).start())
        self.running = False
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.notebook = Gtk.Notebook(vexpand=True)
        root.append(self.notebook)
        self.status_label = Gtk.Label(label="", xalign=0.0, wrap=True, selectable=True)
        for side in ("start", "end", "bottom"):
            getattr(self.status_label, f"set_margin_{side}")(10)
        root.append(self.status_label)
        self.set_child(root)
        self.buttons: list[Gtk.Button] = []
        self._build_merge()
        self._build_split()
        self._build_convert()
        self._build_export()
        self._build_adjust()

    # -- construction --------------------------------------------------------

    def _action(self, grid: Gtk.Grid, row: int, label: str, work: Callable[[], str]) -> Gtk.Button:
        btn = Gtk.Button(label=label, halign=Gtk.Align.START)
        btn.connect("clicked", lambda _b: self._launch(work))
        grid.attach(btn, 1, row, 1, 1)
        self.buttons.append(btn)
        return btn

    def _build_merge(self) -> None:
        grid = _grid()
        self.merge_files: list[str] = []
        files_box = Gtk.Box(spacing=6)
        add = Gtk.Button(label="Ajouter des captures...")
        add.connect("clicked", self._on_merge_add)
        clear = Gtk.Button(label="Vider")
        clear.connect("clicked", lambda _b: self.set_merge_files([]))
        self.merge_label = Gtk.Label(label="(aucune)", xalign=0.0, wrap=True, hexpand=True)
        for w in (add, clear, self.merge_label):
            files_box.append(w)
        _row(grid, 0, "Captures :", files_box)
        self.merge_dedup = Gtk.CheckButton(label="Dedupliquer les paquets identiques (--merge-dedup)")
        grid.attach(self.merge_dedup, 1, 1, 1, 1)
        self.merge_output = PathChooser("Fichier fusionne...", "save", "fusion.pcapng")
        _row(grid, 2, "Sortie (--merge) :", self.merge_output)
        self._action(grid, 3, "Fusionner", self.run_merge)
        self.notebook.append_page(grid, Gtk.Label(label="Fusion"))

    def _build_split(self) -> None:
        grid = _grid()
        self.split_source = PathChooser("Capture...")
        _row(grid, 0, "Capture :", self.split_source)
        crit = Gtk.Box(spacing=6)
        self.split_mode = Gtk.DropDown.new_from_strings(list(SPLIT_LABELS))
        self.split_value = Gtk.Entry(text="60", width_chars=10)
        crit.append(self.split_mode)
        crit.append(self.split_value)
        _row(grid, 1, "Critere (--split) :", crit)
        self.split_output = PathChooser("Dossier...", "folder")
        _row(grid, 2, "Dossier (--split-output-dir) :", self.split_output)
        self._action(grid, 3, "Decouper", self.run_split)
        self.notebook.append_page(grid, Gtk.Label(label="Decoupage"))

    def _build_convert(self) -> None:
        grid = _grid()
        self.convert_source = PathChooser("Capture...")
        _row(grid, 0, "Capture :", self.convert_source)
        self.convert_format = Gtk.DropDown.new_from_strings(list(capture_tools.CONVERT_FORMATS))
        self.convert_format.set_selected(capture_tools.CONVERT_FORMATS.index("pcapng"))
        _row(grid, 1, "Format (--convert-format) :", self.convert_format)
        self.convert_output = PathChooser("Fichier converti...", "save", "conversion.pcapng")
        _row(grid, 2, "Sortie (--convert) :", self.convert_output)
        self._action(grid, 3, "Convertir", self.run_convert)
        self.notebook.append_page(grid, Gtk.Label(label="Conversion"))

    def _build_export(self) -> None:
        grid = _grid()
        self.export_source = PathChooser("Capture...")
        _row(grid, 0, "Capture :", self.export_source)
        self.export_filter = Gtk.Entry(placeholder_text="ex : tcp.port == 443", hexpand=True)
        _row(grid, 1, "Filtre (--export-bpf) :", self.export_filter)
        self.export_start = Gtk.Entry(placeholder_text="secondes apres le 1er paquet")
        _row(grid, 2, "Debut (--export-time-start) :", self.export_start)
        self.export_end = Gtk.Entry(placeholder_text="secondes apres le 1er paquet")
        _row(grid, 3, "Fin (--export-time-end) :", self.export_end)
        self.export_endpoints = Gtk.Entry(placeholder_text="IP1,IP2,...")
        _row(grid, 4, "Extremites (--export-endpoints) :", self.export_endpoints)
        self.export_output = PathChooser("Fichier exporte...", "save", "extrait.pcapng")
        _row(grid, 5, "Sortie (--export-pcap) :", self.export_output)
        self._action(grid, 6, "Exporter", self.run_export)
        self.notebook.append_page(grid, Gtk.Label(label="Export filtre"))

    def _build_adjust(self) -> None:
        grid = _grid()
        self.adjust_source = PathChooser("Capture...")
        _row(grid, 0, "Capture :", self.adjust_source)
        self.adjust_mode = Gtk.DropDown.new_from_strings(list(ADJUST_MODES))
        _row(grid, 1, "Mode :", self.adjust_mode)
        self.adjust_offset = Gtk.Entry(text="0", placeholder_text="secondes, negatif admis")
        _row(grid, 2, "Decalage (s) :", self.adjust_offset)
        self.adjust_reference = PathChooser("Capture de reference...")
        _row(grid, 3, "Reference (--align-to) :", self.adjust_reference)
        self.adjust_output = PathChooser("Fichier recale...", "save", "recale.pcapng")
        _row(grid, 4, "Sortie (--adjust-time-output) :", self.adjust_output)
        self._action(grid, 5, "Recaler", self.run_adjust)
        self.notebook.append_page(grid, Gtk.Label(label="Recalage temporel"))

    # -- etat --------------------------------------------------------------

    def set_merge_files(self, paths: list[str]) -> None:
        self.merge_files = list(paths)
        self.merge_label.set_text(", ".join(os.path.basename(p) for p in paths) or "(aucune)")

    def _on_merge_add(self, _btn) -> None:
        dialog = Gtk.FileDialog()
        dialog.open_multiple(self, None, self._on_merge_chosen)

    def _on_merge_chosen(self, dialog, result) -> None:
        try:
            files = dialog.open_multiple_finish(result)
        except GLib.Error as exc:
            logger.debug("CaptureToolsWindow: dialogue annule ({})", exc)
            return
        paths = [files.get_item(i).get_path() for i in range(files.get_n_items())]
        self.set_merge_files(self.merge_files + [p for p in paths if p])

    @staticmethod
    def _need(path: str | None, what: str) -> str:
        if not path:
            raise ValueError(f"choisissez {what}")
        return path

    # -- actions (synchrones, pour les tests) -------------------------------

    def run_merge(self) -> str:
        if not self.merge_files:
            raise ValueError("ajoutez au moins une capture a fusionner")
        out = self._need(self.merge_output.path, "le fichier de sortie")
        return capture_tools.merge(self.merge_files, out, dedup=self.merge_dedup.get_active())

    def split_spec(self) -> str:
        mode = capture_tools.SPLIT_MODES[self.split_mode.get_selected()]
        return f"{mode}:{self.split_value.get_text().strip()}"

    def run_split(self) -> str:
        spec = self.split_spec()
        capture_tools.parse_split_spec(spec)  # refus avant de choisir quoi que ce soit d'autre
        source = self._need(self.split_source.path, "la capture a decouper")
        folder = self._need(self.split_output.path, "le dossier de sortie")
        segments = capture_tools.split(source, folder, spec)
        if not segments:
            return f"aucun paquet a decouper dans {source} -- aucun segment cree."
        return f"{len(segments)} segment(s) dans {folder}."

    def run_convert(self) -> str:
        fmt = capture_tools.CONVERT_FORMATS[self.convert_format.get_selected()]
        source = self._need(self.convert_source.path, "la capture a convertir")
        out = self._need(self.convert_output.path, "le fichier de sortie")
        return capture_tools.convert(source, out, fmt)

    def run_export(self) -> str:
        source = self._need(self.export_source.path, "la capture source")
        out = self._need(self.export_output.path, "le fichier de sortie")
        return capture_tools.export_subset(
            source,
            out,
            bpf_filter=self.export_filter.get_text().strip() or None,
            time_start=_optional_float(self.export_start.get_text(), "debut"),
            time_end=_optional_float(self.export_end.get_text(), "fin"),
            endpoints=capture_tools.parse_endpoints(self.export_endpoints.get_text()),
        )

    def run_adjust(self) -> str:
        source = self._need(self.adjust_source.path, "la capture a recaler")
        out = self._need(self.adjust_output.path, "le fichier de sortie")
        mode = self.adjust_mode.get_selected()
        if mode == 0:
            offset = _optional_float(self.adjust_offset.get_text(), "decalage")
            return capture_tools.adjust_time(source, out, offset=offset if offset is not None else 0.0)
        if mode == 1:
            return capture_tools.adjust_time(source, out, normalize=True)
        reference = self._need(self.adjust_reference.path, "la capture de reference")
        return capture_tools.adjust_time(source, out, align_to=reference)

    # -- execution en arriere-plan -------------------------------------------

    def _launch(self, work: Callable[[], str]) -> None:
        if self.running:
            return
        self.running = True
        for btn in self.buttons:
            btn.set_sensitive(False)
        self.status_label.set_text("En cours...")

        def _thread() -> None:
            try:
                message = work()
            except (OSError, ValueError, RuntimeError) as exc:  # TsharkError/TsharkNotFoundError : RuntimeError
                logger.warning("CaptureToolsWindow: {}", exc)
                message = f"Erreur : {exc}"
            GLib.idle_add(self._done, message)

        self._start_thread(_thread)

    def _done(self, message: str) -> bool:
        self.running = False
        for btn in self.buttons:
            btn.set_sensitive(True)
        self.status_label.set_text(message)
        logger.debug("CaptureToolsWindow: {}", message)
        return False
