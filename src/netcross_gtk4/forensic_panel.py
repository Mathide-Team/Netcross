"""netcross_gtk4.forensic_panel -- panneau GTK « Recherche forensic » de la
page Resultats (issue #675).

Cablage GTK de `forensic_view` : criteres de ``--search-*`` (texte, adresse,
point, protocole, port, champ decode et valeur), liste des resultats et
export JSON identique a ``--forensic-search``. L'index est construit par le
thread d'analyse quand la case « Index de recherche forensic » est cochee
(`set_index`) ; sans index, le panneau explique comment l'obtenir.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gio, Gtk  # noqa: E402

from netcross_core.logging_config import get_logger  # noqa: E402
from netcross_gtk4.forensic_view import (  # noqa: E402
    ANY_FIELD_LABEL,
    MAX_DISPLAYED,
    SEARCH_FIELDS,
    SearchInputError,
    build_query,
    format_result_row,
    summary_line,
    write_search_json,
)

logger = get_logger(__name__)

NO_INDEX_MESSAGE = "(cochez « Index de recherche forensic » dans la configuration, puis relancez l'analyse)"


class ForensicSearchPanel(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        logger.debug("ForensicSearchPanel: construction du panneau")
        for side in ("top", "bottom", "start", "end"):
            getattr(self, f"set_margin_{side}")(6)
        self.index = None
        self.last_query = None
        self.last_results: list = []

        grid = Gtk.Grid(column_spacing=8, row_spacing=4)
        self.text_entry = Gtk.Entry(placeholder_text="Texte libre (--search-text)", hexpand=True)
        self.address_entry = Gtk.Entry(placeholder_text="Adresse IP (--search-address)")
        self.point_entry = Gtk.Entry(placeholder_text="Point (--search-point)")
        self.protocol_entry = Gtk.Entry(placeholder_text="Protocole (--search-protocol)")
        self.port_entry = Gtk.Entry(placeholder_text="Port (--search-port)")
        self.field_drop = Gtk.DropDown.new_from_strings([ANY_FIELD_LABEL, *SEARCH_FIELDS])
        self.field_drop.set_tooltip_text("Champ decode (--search-field) ; sans valeur : presence du champ")
        self.value_entry = Gtk.Entry(placeholder_text="Valeur (--search-value)", hexpand=True)
        grid.attach(self.text_entry, 0, 0, 2, 1)
        grid.attach(self.address_entry, 2, 0, 1, 1)
        grid.attach(self.point_entry, 3, 0, 1, 1)
        grid.attach(self.protocol_entry, 0, 1, 1, 1)
        grid.attach(self.port_entry, 1, 1, 1, 1)
        grid.attach(self.field_drop, 2, 1, 1, 1)
        grid.attach(self.value_entry, 3, 1, 1, 1)
        self.append(grid)
        for entry in (
            self.text_entry,
            self.address_entry,
            self.point_entry,
            self.protocol_entry,
            self.port_entry,
            self.value_entry,
        ):
            entry.connect("activate", self._on_search_clicked)

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.search_btn = Gtk.Button(label="Rechercher")
        self.search_btn.connect("clicked", self._on_search_clicked)
        self.export_btn = Gtk.Button(label="Exporter JSON...")
        self.export_btn.set_tooltip_text("Meme fichier que --forensic-search (requete rappelee, tous les resultats)")
        self.export_btn.connect("clicked", self._on_export_clicked)
        buttons.append(self.search_btn)
        buttons.append(self.export_btn)
        self.append(buttons)

        self.status_label = Gtk.Label(label=NO_INDEX_MESSAGE, halign=Gtk.Align.START, wrap=True)
        self.status_label.set_selectable(True)
        self.append(self.status_label)

        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(80)
        scroller.set_max_content_height(300)
        scroller.set_propagate_natural_height(True)
        scroller.set_child(self.list_box)
        self.append(scroller)
        self._sync_sensitivity()

    # -- etat --------------------------------------------------------------

    def set_index(self, index) -> None:
        """Nouvel index (ou None) apres une analyse ; efface les resultats."""
        self.index = index
        self.last_query = None
        self.last_results = []
        self._show_rows([])
        if index is None:
            self.status_label.set_text(NO_INDEX_MESSAGE)
        else:
            self.status_label.set_text(f"{len(index)} element(s) indexe(s). Saisissez au moins un critere.")
        self._sync_sensitivity()
        logger.debug("ForensicSearchPanel.set_index: index={}", index is not None)

    def _sync_sensitivity(self) -> None:
        self.search_btn.set_sensitive(self.index is not None)
        self.export_btn.set_sensitive(self.last_query is not None)

    def _show_rows(self, results) -> None:
        child = self.list_box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.list_box.remove(child)
            child = nxt
        for result in results[:MAX_DISPLAYED]:
            label = Gtk.Label(label=format_result_row(result), halign=Gtk.Align.START, xalign=0.0)
            label.set_selectable(True)
            label.set_wrap(True)
            self.list_box.append(label)

    # -- actions -----------------------------------------------------------

    def run_search(self) -> list:
        """Lance la recherche avec les criteres saisis ; renvoie les resultats
        (liste vide si la saisie est invalide, motif dans le statut)."""
        if self.index is None:
            self.status_label.set_text(NO_INDEX_MESSAGE)
            logger.debug("ForensicSearchPanel.run_search: sans index -> retour []")
            return []
        try:
            query = build_query(
                text=self.text_entry.get_text(),
                address=self.address_entry.get_text(),
                point=self.point_entry.get_text(),
                protocol=self.protocol_entry.get_text(),
                port=self.port_entry.get_text(),
                field_index=self.field_drop.get_selected(),
                value=self.value_entry.get_text(),
            )
        except SearchInputError as exc:
            logger.debug("ForensicSearchPanel.run_search: saisie refusee ({})", exc)
            self.status_label.set_text(f"Recherche impossible : {exc}.")
            return []
        results = self.index.search(query)
        self.last_query = query
        self.last_results = results
        self._show_rows(results)
        self.status_label.set_text(summary_line(results))
        self._sync_sensitivity()
        logger.debug("ForensicSearchPanel.run_search: {} resultat(s)", len(results))
        return results

    def _on_search_clicked(self, *_args):
        self.run_search()

    def export_to(self, path) -> None:
        written = write_search_json(path, self.last_query, self.last_results)
        self.status_label.set_text(f"Recherche forensique ({len(self.last_results)} resultat(s)) ecrite dans {written}")

    def _on_export_clicked(self, _btn):
        if self.last_query is None:
            return
        dialog = Gtk.FileDialog()
        dialog.set_initial_name("recherche-forensic.json")
        root = self.get_root()
        dialog.save(root if isinstance(root, Gtk.Window) else None, None, self._on_export_chosen)

    def _on_export_chosen(self, dialog, result):
        try:
            gfile = dialog.save_finish(result)
        except Exception as exc:  # noqa: BLE001 -- annulation du dialogue
            logger.debug("ForensicSearchPanel._on_export_chosen: dialogue annule ({})", exc)
            return
        path = gfile.get_path() if isinstance(gfile, Gio.File) else None
        if not path:
            logger.debug("ForensicSearchPanel._on_export_chosen: pas de chemin local")
            return
        try:
            self.export_to(path)
        except OSError as exc:
            logger.warning("ForensicSearchPanel: export impossible ({})", exc)
            self.status_label.set_text(f"Export impossible : {exc}")
