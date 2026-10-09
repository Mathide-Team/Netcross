"""netcross_gtk4.report_exports_panel -- panneau « SIEM, ticket de support,
historique » de la page Resultats (issue #674).

- Export SIEM CEF, LEEF ou STIX du rapport de securite (``--siem-export``) ;
- ticket de support anonymise, apres consentement explicite
  (``--support-ticket`` avec ``--support-consent``) ;
- historique SQLite choisi dans la configuration : message
  d'enregistrement et derniers runs (``--history-show N``).

Le diagramme de sequence (``--sequence-diagram``) va dans l'export PDF.
"""

from __future__ import annotations

from typing import Any

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gio, Gtk  # noqa: E402

from netcross_core.logging_config import get_logger  # noqa: E402
from netcross_gtk4.report_exports import (  # noqa: E402
    HISTORY_SHOW_MAX,
    SIEM_EXTENSIONS,
    export_siem,
    history_text,
    write_support_ticket,
)

logger = get_logger(__name__)

SIEM_FORMATS = ("cef", "leef", "stix")


class ReportExportsPanel(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        logger.debug("ReportExportsPanel: construction du panneau")
        for side in ("top", "bottom", "start", "end"):
            getattr(self, f"set_margin_{side}")(6)
        self.report: Any = None
        self.security_report: Any = None
        self.context: Any = None

        siem_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        siem_row.append(Gtk.Label(label="Format SIEM :"))
        self.siem_format = Gtk.DropDown.new_from_strings([f.upper() for f in SIEM_FORMATS])
        siem_row.append(self.siem_format)
        self.siem_btn = Gtk.Button(label="Exporter SIEM (--siem-export)...")
        self.siem_btn.set_tooltip_text(
            "Constats du rapport de securite en CEF, LEEF ou STIX 2.1, meme fichier que la CLI."
        )
        self.siem_btn.connect("clicked", lambda _b: self._choose("siem"))
        siem_row.append(self.siem_btn)

        ticket_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.consent_check = Gtk.CheckButton(label="J'autorise la remontee d'un ticket anonymise (--support-consent)")
        self.consent_check.set_tooltip_text(
            "Le ticket contient l'environnement et un journal rediges (adresses, noms d'hotes, chemins remplaces) ; "
            "rien n'est envoye, le fichier reste a transmettre par vous."
        )
        self.consent_check.connect("toggled", lambda _c: self._sync())
        self.ticket_btn = Gtk.Button(label="Ticket de support (--support-ticket)...")
        self.ticket_btn.connect("clicked", lambda _b: self._choose("ticket"))
        ticket_row.append(self.consent_check)
        ticket_row.append(self.ticket_btn)

        self.history_label = Gtk.Label(label="", halign=Gtk.Align.START, wrap=True)
        history_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        history_row.append(Gtk.Label(label="Derniers runs (--history-show, 0 = tous) :"))
        self.history_show_spin = Gtk.SpinButton.new_with_range(0, HISTORY_SHOW_MAX, 1)
        self.history_show_spin.set_value(10)
        history_row.append(self.history_show_spin)
        self.history_btn = Gtk.Button(label="Afficher l'historique")
        self.history_btn.connect("clicked", lambda _b: self.show_history())
        history_row.append(self.history_btn)
        self.history_view = Gtk.TextView(editable=False, monospace=True, cursor_visible=False)
        self.history_view.set_wrap_mode(Gtk.WrapMode.NONE)
        history_scroll = Gtk.ScrolledWindow(min_content_height=120)
        history_scroll.set_child(self.history_view)

        self.status_label = Gtk.Label(label="", halign=Gtk.Align.START, wrap=True)
        self.status_label.set_selectable(True)
        for widget in (siem_row, ticket_row, self.history_label, history_row, history_scroll, self.status_label):
            self.append(widget)
        self._sync()

    # -- etat --

    def set_context(self, report, security_report, context) -> None:
        """Derniere analyse de fichiers (contexte None : rien a exporter)."""
        self.report = report if context is not None else None
        self.security_report = security_report if context is not None else None
        self.context = context
        self.status_label.set_text("")
        self.history_view.get_buffer().set_text("")
        self.history_label.set_text(context.history_message if context is not None else "")
        self._sync()
        logger.debug("ReportExportsPanel.set_context: {}", context is not None)

    def _has_history(self) -> bool:
        return self.context is not None and bool(self.context.history.db_path)

    def _sync(self) -> None:
        self.siem_btn.set_sensitive(self.security_report is not None)
        self.ticket_btn.set_sensitive(self.context is not None and self.consent_check.get_active())
        self.history_btn.set_sensitive(self._has_history())

    def selected_siem_format(self) -> str:
        return SIEM_FORMATS[self.siem_format.get_selected()]

    # -- actions (exposees pour les tests) --

    def export_siem_to(self, path) -> str:
        if self.security_report is None:
            raise ValueError("rien a exporter : relancez l'analyse avec « Rapport de securite »")
        written = export_siem(self.report, str(path), self.selected_siem_format(), self.context)
        self.status_label.set_text(f"Export SIEM ({self.selected_siem_format()}) ecrit dans {written}")
        return written

    def write_ticket_to(self, path) -> str:
        if self.context is None:
            raise ValueError("aucune analyse de fichiers terminee")
        written, occurrences = write_support_ticket(str(path), self.context, consent=self.consent_check.get_active())
        self.status_label.set_text(
            f"Ticket de support anonymise ecrit : {written} (diagnostic, {occurrences} occurrence(s) redigee(s))"
        )
        return written

    def show_history(self) -> str:
        from netcross_report import HistoryDatabaseError

        if not self._has_history():
            raise ValueError("aucun historique choisi dans la configuration")
        history = self.context.history
        try:
            text = history_text(history.db_path, int(self.history_show_spin.get_value()), history.label)
        except HistoryDatabaseError as exc:
            logger.warning("ReportExportsPanel: historique illisible ({})", exc)
            text = str(exc)
        self.history_view.get_buffer().set_text(text)
        return text

    # -- dialogues --

    def _choose(self, what: str) -> None:
        dialog = Gtk.FileDialog()
        if what == "siem":
            fmt = self.selected_siem_format()
            dialog.set_initial_name(f"netcross-siem.{SIEM_EXTENSIONS[fmt]}")
        else:
            dialog.set_initial_name("netcross-ticket-support.json")
        root = self.get_root()
        dialog.save(root if isinstance(root, Gtk.Window) else None, None, lambda d, res: self._on_chosen(d, res, what))

    def _on_chosen(self, dialog, result, what: str) -> None:
        try:
            gfile = dialog.save_finish(result)
        except Exception as exc:  # noqa: BLE001 -- annulation du dialogue
            logger.debug("ReportExportsPanel._on_chosen: dialogue annule ({})", exc)
            return
        path = gfile.get_path() if isinstance(gfile, Gio.File) else None
        if not path:
            logger.debug("ReportExportsPanel._on_chosen: pas de chemin local")
            return
        try:
            if what == "siem":
                self.export_siem_to(path)
            else:
                self.write_ticket_to(path)
        except (OSError, ValueError, RuntimeError) as exc:
            logger.warning("ReportExportsPanel: export impossible ({})", exc)
            self.status_label.set_text(f"Export impossible : {exc}")
