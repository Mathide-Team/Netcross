"""netcross_gtk4.lua_doc_window -- fenetre « Documentation Lua » (issue
#873) : equivalent GUI de ``netcross-lua-doc``. Logique dans
``lua_doc_view``.
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
        self.search_entry = Gtk.SearchEntry(hexpand=True, placeholder_text="Rechercher (ex : tvb range)")
        self.search_entry.connect("activate", lambda _e: self.run_search())
        row.append(self.search_entry)
        row.append(Gtk.Label(label="Resultats max. :"))
        self.limit_spin = Gtk.SpinButton.new_with_range(1, 500, 1)
        self.limit_spin.set_value(DEFAULT_LIMIT)
        row.append(self.limit_spin)
        self.full_check = Gtk.CheckButton(label="Detail complet (--full)")
        row.append(self.full_check)
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
            for widget in (self.search_entry, self.limit_spin, self.full_check, search_btn, self.json_btn):
                widget.set_sensitive(False)
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
        self.open_class(row.get_child().get_label())

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
