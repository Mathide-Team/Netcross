"""netcross_gtk4.extraction_panel -- panneau GTK « Contenus (extraction) »
de la page Resultats (issue #675).

Cablage GTK de `extraction_view` : types a extraire (audio, video,
documents), choix d'un repertoire vide, extraction dans un thread
d'arriere-plan (tshark relit les fichiers), compte rendu identique a la
CLI. Le rappel d'usage raisonne est affiche en permanence.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from netcross_core.extract.contents import USAGE_REMINDER, format_extraction  # noqa: E402
from netcross_core.logging_config import get_logger  # noqa: E402
from netcross_gtk4.extraction_view import (  # noqa: E402
    check_out_dir,
    selected_kinds,
    unavailable_reason,
)

logger = get_logger(__name__)


def _default_runner(captures, *, out_dir, kinds):
    from netcross_core.extract.contents import run_extraction

    return run_extraction(captures, out_dir=out_dir, kinds=kinds)


class ExtractionPanel(Gtk.Box):
    def __init__(
        self,
        runner: Callable | None = None,
        start_thread: Callable[[Callable[[], None]], None] | None = None,
    ):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        logger.debug("ExtractionPanel: construction du panneau")
        for side in ("top", "bottom", "start", "end"):
            getattr(self, f"set_margin_{side}")(6)
        self._runner = runner or _default_runner
        self._start_thread = start_thread or (lambda fn: threading.Thread(target=fn, daemon=True).start())
        self.captures: list | None = None
        self.redacted = False
        self.running = False
        self.last_result = None

        reminder = Gtk.Label(label=USAGE_REMINDER, halign=Gtk.Align.START, wrap=True, xalign=0.0)
        reminder.add_css_class("dim-label")
        self.append(reminder)

        kinds_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        # libelles litteraux : inventories par tests/test_parite_surfaces.py
        self.kind_checks: dict[str, Gtk.CheckButton] = {
            "audio": Gtk.CheckButton(label="Audio (voix RTP)"),
            "video": Gtk.CheckButton(label="Video (RTP)"),
            "documents": Gtk.CheckButton(label="Documents (HTTP, SMB, courriel, TFTP, FTP)"),
        }
        for kind, check in self.kind_checks.items():
            check.set_active(True)
            check.set_tooltip_text(f"--extract-kinds {kind}")
            kinds_box.append(check)
        self.append(kinds_box)

        self.extract_btn = Gtk.Button(label="Extraire vers un dossier...")
        self.extract_btn.set_tooltip_text(
            "Equivalent de --extract-contents DOSSIER --extract-kinds ... : le dossier doit etre vide ; "
            "fichiers en 0600 sous un repertoire 0700, avec manifest.json et LISEZ-MOI.txt."
        )
        self.extract_btn.connect("clicked", self._on_extract_clicked)
        self.append(self.extract_btn)

        self.status_label = Gtk.Label(label="", halign=Gtk.Align.START, wrap=True, xalign=0.0)
        self.status_label.set_selectable(True)
        self.append(self.status_label)
        self.set_source(None, False)

    # -- etat --------------------------------------------------------------

    def set_source(self, captures, redacted: bool) -> None:
        """Captures de la derniere analyse (None : pas d'analyse de fichiers)."""
        self.captures = list(captures) if captures else None
        self.redacted = bool(redacted)
        self.last_result = None
        reason = unavailable_reason(self.captures, self.redacted)
        self.status_label.set_text(reason or f"{len(self.captures or [])} capture(s) a relire.")
        self._sync_sensitivity()
        logger.debug("ExtractionPanel.set_source: disponible={}", reason is None)

    def _sync_sensitivity(self) -> None:
        available = unavailable_reason(self.captures, self.redacted) is None
        self.extract_btn.set_sensitive(available and not self.running)
        for check in self.kind_checks.values():
            check.set_sensitive(available and not self.running)

    # -- actions -----------------------------------------------------------

    def start_extraction(self, out_dir: str) -> bool:
        """Valide puis lance l'extraction vers `out_dir` ; False (motif dans
        le statut) si elle ne peut pas demarrer."""
        reason = unavailable_reason(self.captures, self.redacted)
        if reason is not None or self.running:
            logger.debug("ExtractionPanel.start_extraction: refus ({})", reason or "deja en cours")
            return False
        try:
            kinds = selected_kinds({k: c.get_active() for k, c in self.kind_checks.items()})
            check_out_dir(out_dir)
        except (ValueError, OSError) as exc:
            logger.debug("ExtractionPanel.start_extraction: refus ({})", exc)
            self.status_label.set_text(f"Extraction impossible : {exc}.")
            return False
        captures = list(self.captures or [])
        logger.warning("extraction de contenus vers {} (types : {})", out_dir, ", ".join(kinds))
        self.running = True
        self._sync_sensitivity()
        self.status_label.set_text(f"Extraction en cours vers {out_dir} ({', '.join(kinds)})...")

        def work():
            try:
                result = self._runner(captures, out_dir=out_dir, kinds=kinds)
            except Exception as exc:  # noqa: BLE001 -- thread de fond : l'erreur va au statut
                logger.exception(f"échec de l'extraction: {exc}")
                GLib.idle_add(self._on_extraction_done, None, str(exc))
                return
            GLib.idle_add(self._on_extraction_done, result, None)

        self._start_thread(work)
        return True

    def _on_extraction_done(self, result, error):
        self.running = False
        self._sync_sensitivity()
        if error is not None:
            self.status_label.set_text(f"Extraction en echec : {error}")
        else:
            self.last_result = result
            self.status_label.set_text("\n".join(format_extraction(result)))
        logger.debug("ExtractionPanel._on_extraction_done: erreur={}", error)
        return False

    def _on_extract_clicked(self, _btn):
        dialog = Gtk.FileDialog()
        dialog.set_title("Dossier d'extraction (vide)")
        root = self.get_root()
        dialog.select_folder(root if isinstance(root, Gtk.Window) else None, None, self._on_folder_chosen)

    def _on_folder_chosen(self, dialog, result):
        try:
            gfile = dialog.select_folder_finish(result)
        except GLib.Error as exc:
            logger.debug("ExtractionPanel._on_folder_chosen: dialogue annule ({})", exc)
            return
        path = gfile.get_path() if gfile is not None else None
        if path:
            self.start_extraction(path)
