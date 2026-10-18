"""netcross_gtk4.lua_doc_window -- fenetre « Documentation Lua » (issue
#873) : equivalent GUI de ``netcross-lua-doc``. Logique dans
``lua_doc_view``. Issue #917 : mode « Dissecteurs Lua » (catalogue,
equivalent de ``--dissectors``, ``--domain``, ``--non-native``, ``--domains``).
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from netcross_core.logging_config import get_logger  # noqa: E402
from netcross_gtk4.lua_doc_view import DEFAULT_LIMIT, LuaDocBrowser, LuaDocUnavailableError  # noqa: E402

logger = get_logger(__name__)


class LuaDocWindow(Gtk.Window):
    def __init__(self, parent: Gtk.Window | None = None, browser: LuaDocBrowser | None = None):
        super().__init__(title="Documentation de l'API Lua Wireshark", default_width=1000, default_height=700)
        if parent is not None:
            self.set_transient_for(parent)
        self.current_class: str | None = None
        self.browser: LuaDocBrowser | None = browser
        self.error: str | None = None
        if self.browser is None:
            try:
                self.browser = LuaDocBrowser()
            except LuaDocUnavailableError as exc:
                logger.warning("LuaDocWindow: {}", exc)
                self.error = str(exc)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        for side in ("top", "bottom", "start", "end"):
            getattr(root, f"set_margin_{side}")(8)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        # Issue #917 : on cherche dans l'API Lua ou dans le catalogue des dissecteurs
        self.mode_dropdown = Gtk.DropDown.new_from_strings(list(self.MODES))
        self.mode_dropdown.set_tooltip_text("API Lua (netcross-lua-doc) ou catalogue des dissecteurs (--dissectors)")
        self.mode_dropdown.connect("notify::selected", lambda *_a: self._on_mode_changed())
        row.append(self.mode_dropdown)
        self.search_entry = Gtk.SearchEntry(hexpand=True, placeholder_text="Rechercher (ex : tvb range)")
        self.search_entry.connect("activate", lambda _e: self.run_search())
        row.append(self.search_entry)
        row.append(Gtk.Label(label="Resultats max. :"))
        self.limit_spin = Gtk.SpinButton.new_with_range(1, 500, 1)
        self.limit_spin.set_value(DEFAULT_LIMIT)
        row.append(self.limit_spin)
        self.full_check = Gtk.CheckButton(label="Detail complet (--full)")
        row.append(self.full_check)
        self.domain_dropdown = Gtk.DropDown.new_from_strings([self.ALL_DOMAINS])
        self.domain_dropdown.set_tooltip_text("Domaine (--domain)")
        row.append(self.domain_dropdown)
        self.native_check = Gtk.CheckButton(label="Sans dissecteur natif (--non-native)")
        row.append(self.native_check)
        search_btn = Gtk.Button(label="Rechercher")
        search_btn.connect("clicked", lambda _b: self.run_search())
        row.append(search_btn)
        self.json_btn = Gtk.Button(label="JSON")
        self.json_btn.connect("clicked", lambda _b: self.show_json())
        row.append(self.json_btn)
        root.append(row)

        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL, vexpand=True)
        self.class_list = Gtk.ListBox()
        self.class_list.connect("row-activated", self._on_row_activated)
        left = Gtk.ScrolledWindow(min_content_width=220)
        left.set_child(self.class_list)
        paned.set_start_child(left)
        self.text_view = Gtk.TextView(editable=False, monospace=True, wrap_mode=Gtk.WrapMode.NONE)
        right = Gtk.ScrolledWindow(hexpand=True)
        right.set_child(self.text_view)
        paned.set_end_child(right)
        paned.set_position(240)
        root.append(paned)
        self.set_child(root)
        self.connect("close-request", self._on_close)

        if self.browser is None:
            self._set_text(self.error or "")
            for widget in (
                self.mode_dropdown,
                self.search_entry,
                self.limit_spin,
                self.full_check,
                search_btn,
                self.json_btn,
            ):
                widget.set_sensitive(False)
        else:
            self._domains = [self.ALL_DOMAINS, *self.browser.domains()]
            self.domain_dropdown.set_model(Gtk.StringList.new(self._domains))
            self._fill_classes(self.browser.classes())
            self._set_text(self.browser.classes_text())
        self._on_mode_changed()

    MODES = ("API Lua", "Dissecteurs Lua")
    ALL_DOMAINS = "Tous les domaines"

    def dissectors_mode(self) -> bool:
        return self.mode_dropdown.get_selected() == 1

    def _domain(self) -> str | None:
        i = self.domain_dropdown.get_selected()
        domaines = getattr(self, "_domains", [self.ALL_DOMAINS])
        return domaines[i] if 0 < i < len(domaines) else None

    def _on_mode_changed(self) -> None:
        """Options propres à chaque mode ; la liste de gauche donne les classes ou les domaines."""
        dissecteurs = self.dissectors_mode()
        self.full_check.set_visible(not dissecteurs)
        self.domain_dropdown.set_visible(dissecteurs)
        self.native_check.set_visible(dissecteurs)
        self.search_entry.set_placeholder_text(
            "Rechercher un dissecteur (ex : modbus, drone)" if dissecteurs else "Rechercher (ex : tvb range)"
        )
        if self.browser is None:
            return
        self.current_class = None
        if dissecteurs:
            self._fill_classes(self._domains[1:])
            self._set_text(self.browser.domains_text())
        else:
            self._fill_classes(self.browser.classes())
            self._set_text(self.browser.classes_text())

    # -- actions ------------------------------------------------------------

    def _set_text(self, text: str) -> None:
        self.text_view.get_buffer().set_text(text)

    def text(self) -> str:
        buf = self.text_view.get_buffer()
        return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)

    def _fill_classes(self, names: list[str]) -> None:
        self.class_list.remove_all()
        for name in names:
            self.class_list.append(Gtk.Label(label=name, xalign=0.0))

    def _on_row_activated(self, _box, row) -> None:
        label = row.get_child().get_label()
        if self.dissectors_mode():
            # liste de gauche = domaines : on filtre sur celui-ci
            self.domain_dropdown.set_selected(self._domains.index(label) if label in self._domains else 0)
            self.run_search()
            return
        self.open_class(label)

    def open_class(self, name: str) -> None:
        if self.browser is None:
            return
        self.current_class = name
        self._set_text(self.browser.class_text(name))

    def run_search(self) -> None:
        if self.browser is None:
            return
        terme = self.search_entry.get_text()
        self.current_class = None
        if self.dissectors_mode():
            self._set_text(
                self.browser.dissectors_text(
                    terme, self._domain(), self.native_check.get_active(), self.limit_spin.get_value_as_int()
                )
            )
            return
        if not terme.strip():
            # recherche vide : retour a la liste des classes (--classes)
            self._fill_classes(self.browser.classes())
            self._set_text(self.browser.classes_text())
            return
        text, classes = self.browser.search(terme, self.limit_spin.get_value_as_int(), self.full_check.get_active())
        self._fill_classes(classes)
        self._set_text(text)

    def show_json(self) -> None:
        if self.browser is None:
            return
        if self.dissectors_mode():
            self._set_text(
                self.browser.dissectors_json(
                    self.search_entry.get_text(),
                    self._domain(),
                    self.native_check.get_active(),
                    self.limit_spin.get_value_as_int(),
                )
            )
            return
        self._set_text(
            self.browser.json_text(
                terme="" if self.current_class else self.search_entry.get_text(),
                name=self.current_class,
                limit=self.limit_spin.get_value_as_int(),
                full=self.full_check.get_active(),
            )
        )

    def _on_close(self, _win) -> bool:
        if self.browser is not None:
            self.browser.close()
            self.browser = None
        return False
