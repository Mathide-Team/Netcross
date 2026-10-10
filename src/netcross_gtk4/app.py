#!/usr/bin/env python3
"""
netcross_gtk4.app -- interface GTK4 pour netcross_core / netcross_report.

Trois pages navigables (Gtk.Stack + Gtk.StackSwitcher) : Configuration,
Travail (journal d'avancement en temps reel), Resultats. L'analyse tourne
dans un thread d'arriere-plan avec GLib.idle_add pour les mises a jour
d'UI (meme pattern que le plugin Redfish de gnome-connection-manager).
Les zones de defilement utilisent des scrollbars classiques toujours
visibles (pas de survol/auto-masquage) pour qu'elles restent decouvrables.

Parite avec les CLIs (cross_capture_analyzer_cli.py / cross_capture_diff_cli.py) :
    - lecture parallele des captures (--parallel)
    - deduction automatique de topologie (points_order=None, equivalent
      a ne pas passer --order)
    - triage (--triage)
    - diagnostics TLS/QUIC (--tls/--quic), mode analyse simple uniquement
    - export CSV du detail par flux (--detail-csv) / des ecarts (--diff-csv)
    - mode comparaison baseline/courant (cross_capture_diff_cli.py),
      avec export PDF et CSV dedies

Au-dela des CLIs -- capture en direct (netcross_core.parse_live /
pcap_parser.iter_live, jusqu'ici orpheline, aucune CLI ne l'exposait) :
    - mode analyse simple uniquement (pas de diff), un thread par point
      de capture, arret propre via un stop_event partage qui termine le
      sous-processus tshark directement (reactif meme sans trafic sur
      l'interface -- cf. pcap_parser.ek_source._terminate_on_event)
    - une ligne peut porter plusieurs interfaces d'une meme machine
      ("eth0, eth1") : chacune devient un point "NOM:interface" (Job 48,
      voir netcross_gtk4.live_capture_points)
    - arret manuel (bouton) ou automatique (duree max optionnelle)
    - TLS/QUIC indisponibles dans ce mode : ces diagnostics relisent les
      fichiers passes a --capture, et une capture live n'en produit pas
    - filtres BPF (Job 47) : menu deroulant par point de capture (catalogue
      predefini + filtres sauvegardes dans ~/.netcross/bpf_filters.json) et
      bouton d'enregistrement du filtre courant
"""

import contextlib
import io
import os
import sys
import tempfile
import threading
import time

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, Gio, GLib, Gtk  # noqa: E402 -- doit suivre gi.require_version()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Les 2 imports suivants doivent rester apres l'ajout ci-dessus : c'est ce qui rend
# netcross_core/netcross_report importables si ce fichier est lance directement
# (python3 src/netcross_gtk4/app.py) sans PYTHONPATH=src prealable.
from netcross_core import (  # noqa: E402
    analyse,
    build_wireshark_expert_events,
    correlate,
    parse_capture,
    parse_captures_parallel,
    parse_live,
    print_report,
    write_detail_csv,
)
from netcross_core.baseline_diff import write_diff_csv  # noqa: E402
from netcross_core.bpf_filters import PREDEFINED_BPF_FILTERS, available_bpf_filters, upsert_bpf_filter  # noqa: E402
from netcross_core.forensic import DEFAULT_DUPLICATE_THRESHOLD_MS, detect_cross_capture_duplicates  # noqa: E402
from netcross_core.logging_config import DEBUG_FLAG, enable_debug, get_logger, is_debug_enabled, summarize  # noqa: E402
from netcross_gtk4 import capture_list, row_labels  # noqa: E402
from netcross_gtk4.advanced_options import (  # noqa: E402
    MAX_PACKETS_MAX,
    SAMPLE_MAX,
    WORKERS_MAX,
    AdvancedSettings,
    settings_from_values,
)
from netcross_gtk4.advanced_options import validate as validate_advanced  # noqa: E402
from netcross_gtk4.annotations_panel import AnnotationsPanel  # noqa: E402
from netcross_gtk4.bpf_panel import (  # noqa: E402
    doit_desolidariser_le_menu,
    indice_du_filtre_nomme,
    infobulle_du_menu,
    noms_du_menu,
    selection_apres_choix,
    valider_sauvegarde,
)
from netcross_gtk4.client_compare_panel import ClientComparisonPanel  # noqa: E402
from netcross_gtk4.client_compare_view import (  # noqa: E402
    ClientGroupError,
    parse_client_groups,
    validate_client_settings,
)
from netcross_gtk4.dashboard_context import (  # noqa: E402
    DashboardSelection,
    build_dashboard_snapshot,
)
from netcross_gtk4.expertise_panel import ExpertisePanel  # noqa: E402
from netcross_gtk4.expertise_view import (  # noqa: E402
    FLOW_TIMELINE_WINDOW_MAX,
    FLOW_TIMELINE_WINDOW_MIN,
    ExpertiseSettings,
)
from netcross_gtk4.extraction_panel import ExtractionPanel  # noqa: E402
from netcross_gtk4.file_option import FileOption  # noqa: E402
from netcross_gtk4.forensic_panel import ForensicSearchPanel  # noqa: E402
from netcross_gtk4.live_capture_points import duplicate_labels, expand_live_points, invalid_sources  # noqa: E402
from netcross_gtk4.live_report_session import LiveReportError, start_live_report  # noqa: E402
from netcross_gtk4.netflow_panel import NetflowPanel  # noqa: E402
from netcross_gtk4.notifications import (  # noqa: E402
    THRESHOLD_CHOICES,
    NotifySettings,
    settings_from_widgets,
    validate_settings,
)
from netcross_gtk4.panel_state import (  # noqa: E402
    apply_dashboard_selection,
    comm_map_filters,
    panel_visibility,
    run_button_state,
    selected_protocol,
)
from netcross_gtk4.report_exports import SEQUENCE_FLOWS_MAX, HistorySettings, sequence_views  # noqa: E402
from netcross_gtk4.report_exports_panel import ReportExportsPanel  # noqa: E402
from netcross_gtk4.ring_recorders import RingRecorderError, start_ring_recorders, stop_ring_recorders  # noqa: E402
from netcross_gtk4.run_outcome import analysis_outcome, diff_outcome  # noqa: E402
from netcross_gtk4.security_view import export_security_report, security_view_text  # noqa: E402
from netcross_gtk4.stats_view import (  # noqa: E402
    build_events_by_segment,
    build_query,
    flows_for_row,
    format_flow_summary,
    format_row,
    group_options,
    run_stats,
    sort_options,
)
from netcross_report.comm_map import (  # noqa: E402
    DEFAULT_TOP_N as COMM_MAP_DEFAULT_TOP_N,
)
from netcross_report.comm_map import (  # noqa: E402
    available_protocols,
    build_comm_map,
    format_comm_map,
)

logger = get_logger(__name__)


def _visible_scroller(vexpand=True):
    """ScrolledWindow avec scrollbar classique toujours visible (pas d'overlay
    qui disparait au survol) -- pour que le defilement reste decouvrable."""
    logger.debug("_visible_scroller: vexpand={}", summarize(vexpand, "vexpand"))
    scroller = Gtk.ScrolledWindow()
    scroller.set_vexpand(vexpand)
    scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scroller.set_overlay_scrolling(False)
    logger.debug("_visible_scroller: retour scroller={}", summarize(scroller, "scroller"))
    return scroller


# -- formateurs de lignes pour le dashboard analytique (issue #18) --
# Chaque paire (label, cle) : le label alimente le bouton cliquable, la cle
# est remontee a _dashboard_select pour piloter le contexte partage.
# Separes des methodes MainWindow pour rester testables sans instancier GTK.


class CaptureRow(Gtk.Box):
    """Une ligne = un point de capture (nom + fichier), reordonnable."""

    def __init__(self, path, default_label, on_change=None):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.path = path
        self._on_change = on_change
        logger.debug("CaptureRow: label={} path={}", default_label, path)
        self.set_margin_top(4)
        self.set_margin_bottom(4)
        self.set_margin_start(8)
        self.set_margin_end(8)

        self.label_entry = Gtk.Entry()
        self.label_entry.set_text(default_label)
        self.label_entry.set_width_chars(12)
        self.label_entry.set_tooltip_text("Nom du point de capture (ex: LAN, WAN, DC)")
        self.append(self.label_entry)

        path_label = Gtk.Label(label=os.path.basename(path))
        path_label.set_hexpand(True)
        path_label.set_halign(Gtk.Align.START)
        path_label.set_tooltip_text(path)
        self.append(path_label)

        up_btn = Gtk.Button(icon_name="go-up-symbolic")
        up_btn.set_tooltip_text("Monter (ordre = chemin physique reseau)")
        up_btn.connect("clicked", self._on_up)
        self.append(up_btn)

        down_btn = Gtk.Button(icon_name="go-down-symbolic")
        down_btn.set_tooltip_text("Descendre")
        down_btn.connect("clicked", self._on_down)
        self.append(down_btn)

        remove_btn = Gtk.Button(icon_name="user-trash-symbolic")
        remove_btn.set_tooltip_text("Retirer cette capture")
        remove_btn.connect("clicked", self._on_remove)
        self.append(remove_btn)
        logger.debug("CaptureRow.__init__: fin")

    def _on_up(self, _btn):
        self._deplacer(vers_le_haut=True)
        logger.debug("CaptureRow._on_up: fin")

    def _on_down(self, _btn):
        self._deplacer(vers_le_haut=False)
        logger.debug("CaptureRow._on_down: fin")

    def _deplacer(self, *, vers_le_haut):
        """Deplace la ligne d'un cran, ou ne fait rien si elle est au bord
        (voir `capture_list.deplacer_ligne`)."""
        logger.debug("CaptureRow._deplacer: vers_le_haut={} path={}", vers_le_haut, self.path)
        capture_list.deplacer_ligne(self.get_parent(), vers_le_haut=vers_le_haut)
        logger.debug("CaptureRow._deplacer: fin")

    def _on_remove(self, _btn):
        logger.debug("CaptureRow._on_remove: {}", self.path)
        capture_list.retirer_ligne(self.get_parent(), self._on_change)
        logger.debug("CaptureRow._on_remove: fin")

    @property
    def label(self):
        logger.debug("CaptureRow.label: retour self.label_entry.get_text().strip(…)")
        return self.label_entry.get_text().strip()


_FILTER_PICKER_TITLE = "Filtres..."
_FILTER_PICKER_HINT = "Charger un filtre BPF predefini ou sauvegarde"


class LiveCaptureRow(Gtk.Box):
    """Une ligne = un point de capture EN DIRECT (nom + interface + filtre
    BPF optionnel), reordonnable -- pendant de CaptureRow pour la source
    live plutot que fichier. Pas de chemin : rien a choisir via un
    selecteur de fichiers, les champs sont editables directement. Le champ
    interface accepte plusieurs interfaces separees par des virgules : la
    ligne represente alors une machine, chaque interface un point.

    Filtres BPF (Job 47) : ``filters`` est la liste de BPFFilter proposee par
    le menu deroulant (catalogue predefini + filtres sauvegardes) et
    ``on_save_filter(BPFFilter)`` persiste un nouveau filtre (la ligne affiche
    dans son popover l'erreur ValueError/OSError eventuelle). Les deux sont fournis
    par LiveCaptureListPanel ; sans eux la ligne se comporte comme avant."""

    def __init__(
        self,
        default_label,
        interface="",
        bpf_filter="",
        on_change=None,
        filters=None,
        on_save_filter=None,
    ):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._on_change = on_change
        logger.debug(
            "LiveCaptureRow: label={} interface={} filtre={} filtres_proposes={}",
            default_label,
            interface,
            bpf_filter,
            len(filters or []),
        )
        self.set_margin_top(4)
        self.set_margin_bottom(4)
        self.set_margin_start(8)
        self.set_margin_end(8)

        self.label_entry = Gtk.Entry()
        self.label_entry.set_text(default_label)
        self.label_entry.set_width_chars(12)
        self.label_entry.set_tooltip_text("Nom du point de capture (ex: LAN, WAN, DC)")
        self.append(self.label_entry)

        self.interface_entry = Gtk.Entry()
        self.interface_entry.set_text(interface)
        if on_change is not None:
            # une seule ligne "eth0, eth1" suffit a demarrer : la sensibilite du
            # bouton depend du contenu du champ, pas seulement du nombre de lignes
            self.interface_entry.connect("changed", lambda _entry: on_change())
        self.interface_entry.set_width_chars(10)
        self.interface_entry.set_placeholder_text("eth0, eth0, eth1 ou rpcap://hote/eth0")
        self.interface_entry.set_tooltip_text(
            "Nom de l'interface reseau a capturer (voir `tshark -D` ou "
            "`ip link` pour lister les interfaces disponibles). Plusieurs "
            "interfaces separees par des virgules (ex: eth0, eth1) sont "
            "capturees simultanement : chacune devient un point "
            "'NOM:interface', dans l'ordre saisi (= chemin physique reseau). "
            "Source distante possible : rpcap://hote[:port]/eth0 (rpcapd), "
            "sshdump://utilisateur@hote/eth0 (tcpdump via SSH), pipe:///chemin/fifo "
            "ou pipe://- (entree standard)."
        )
        self.interface_entry.set_hexpand(True)
        self.append(self.interface_entry)

        self.filter_entry = Gtk.Entry()
        self.filter_entry.set_text(bpf_filter)
        self.filter_entry.set_placeholder_text("filtre BPF optionnel, ex: tcp port 443")
        self.filter_entry.set_hexpand(True)
        self.filter_entry.connect("changed", self._on_filter_text_changed)
        self.append(self.filter_entry)

        # -- filtres BPF predefinis/sauvegardes (Job 47) --
        self._filters = []
        self._on_save_filter = on_save_filter
        self._syncing_dropdown = False  # vrai pendant qu'on modifie le menu nous-memes
        self.filter_dropdown = Gtk.DropDown.new_from_strings([_FILTER_PICKER_TITLE])
        self.filter_dropdown.connect("notify::selected", self._on_filter_picked)
        self.append(self.filter_dropdown)
        self.set_filters(filters or [])

        self.save_filter_btn = Gtk.MenuButton(icon_name="document-save-symbolic")
        self.save_filter_btn.set_tooltip_text("Enregistrer le filtre BPF courant sous un nom")
        self.save_filter_btn.set_popover(self._build_save_popover())
        self.append(self.save_filter_btn)

        up_btn = Gtk.Button(icon_name="go-up-symbolic")
        up_btn.set_tooltip_text("Monter (ordre = chemin physique reseau)")
        up_btn.connect("clicked", self._on_up)
        self.append(up_btn)

        down_btn = Gtk.Button(icon_name="go-down-symbolic")
        down_btn.set_tooltip_text("Descendre")
        down_btn.connect("clicked", self._on_down)
        self.append(down_btn)

        remove_btn = Gtk.Button(icon_name="user-trash-symbolic")
        remove_btn.set_tooltip_text("Retirer ce point de capture")
        remove_btn.connect("clicked", self._on_remove)
        self.append(remove_btn)
        logger.debug("LiveCaptureRow.__init__: fin")

    def set_filters(self, filters):
        """Remplace les filtres proposes par le menu deroulant ; la selection
        revient sur le titre (le texte du champ filtre n'est pas modifie)."""
        self._filters = list(filters)
        logger.debug("set_filters: {} filtre(s) proposé(s)", len(self._filters))
        self._syncing_dropdown = True
        try:
            noms = noms_du_menu(self._filters, _FILTER_PICKER_TITLE)
            self.filter_dropdown.set_model(Gtk.StringList.new(noms))
        finally:
            self._syncing_dropdown = False
        self._select_filter_index(0)
        logger.debug("LiveCaptureRow.set_filters: fin")

    def _select_filter_index(self, index):
        """Positionne le menu (0 = titre, i = i-eme filtre) SANS recharger le
        champ filtre, et aligne l'infobulle sur la description du filtre."""
        logger.debug("_select_filter_index: index={}", index)
        self._syncing_dropdown = True
        try:
            self.filter_dropdown.set_selected(index)
        finally:
            self._syncing_dropdown = False
        self.filter_dropdown.set_tooltip_text(infobulle_du_menu(index, self._filters, _FILTER_PICKER_HINT))
        logger.debug("LiveCaptureRow._select_filter_index: fin")

    def _on_filter_picked(self, dropdown, _pspec):
        if self._syncing_dropdown:
            logger.debug("LiveCaptureRow._on_filter_picked: si self._syncing_dropdown -> retour")
            return
        index, expression = selection_apres_choix(dropdown.get_selected(), self._filters)
        if index is None:
            logger.debug("LiveCaptureRow._on_filter_picked: si index is None -> retour")
            return
        logger.debug("_on_filter_picked: index={} expression={}", index, expression)
        self._select_filter_index(index)
        self.filter_entry.set_text(expression)
        logger.debug("LiveCaptureRow._on_filter_picked: fin")

    def _on_filter_text_changed(self, entry):
        """Le champ a ete edite a la main : le menu ne doit plus annoncer un
        filtre dont le texte n'est plus celui du champ."""
        if doit_desolidariser_le_menu(self.filter_dropdown.get_selected(), self._filters, entry.get_text()):
            logger.debug("_on_filter_text_changed: champ édité, menu désolidarisé")
            self._select_filter_index(0)
        logger.debug("LiveCaptureRow._on_filter_text_changed: fin")

    def _build_save_popover(self):
        logger.debug("_build_save_popover: construction du popover d'enregistrement")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.set_margin_start(8)
        box.set_margin_end(8)

        self._save_name_entry = Gtk.Entry()
        self._save_name_entry.set_placeholder_text("Nom du filtre (ex: web interne)")
        self._save_name_entry.set_width_chars(30)
        self._save_name_entry.connect("activate", self._on_save_filter_clicked)
        box.append(self._save_name_entry)

        self._save_desc_entry = Gtk.Entry()
        self._save_desc_entry.set_placeholder_text("Description (optionnelle)")
        self._save_desc_entry.connect("activate", self._on_save_filter_clicked)
        box.append(self._save_desc_entry)

        self._save_status = Gtk.Label(label="", halign=Gtk.Align.START, wrap=True, max_width_chars=40)
        self._save_status.add_css_class("error")
        box.append(self._save_status)

        save_btn = Gtk.Button(label="Enregistrer le filtre")
        save_btn.connect("clicked", self._on_save_filter_clicked)
        box.append(save_btn)

        self._save_popover = Gtk.Popover()
        self._save_popover.set_child(box)
        logger.debug(
            "LiveCaptureRow._build_save_popover: retour self._save_popover={}",
            summarize(self._save_popover, "_save_popover"),
        )
        return self._save_popover

    def _on_save_filter_clicked(self, _widget):
        name = self._save_name_entry.get_text().strip()
        logger.debug("_on_save_filter_clicked: nom={}", name)
        demande = valider_sauvegarde(
            self.filter_entry.get_text(),
            name,
            self._save_desc_entry.get_text(),
            sauvegarde_possible=self._on_save_filter is not None,
        )
        if not demande.acceptee:
            logger.debug("_on_save_filter_clicked: refusé ({})", demande.message)
            self._save_status.set_text(demande.message)
            logger.debug("LiveCaptureRow._on_save_filter_clicked: si not demande.acceptee -> retour")
            return
        try:
            self._on_save_filter(demande.filtre)
        except (OSError, ValueError) as exc:
            logger.exception(f"échec dans _on_save_filter_clicked: {exc}")
            self._save_status.set_text(str(exc))
            logger.debug("LiveCaptureRow._on_save_filter_clicked: except (OSError, ValueError) -> retour")
            return
        logger.debug("_on_save_filter_clicked: filtre {} enregistré", name)
        self._save_status.set_text("")
        self._save_name_entry.set_text("")
        self._save_desc_entry.set_text("")
        self._save_popover.popdown()
        # Le panneau a rafraichi les menus (selection sur le titre) : on
        # repositionne CETTE ligne sur le filtre qu'elle vient d'enregistrer.
        indice = indice_du_filtre_nomme(name, self._filters)
        if indice is not None:
            self._select_filter_index(indice)
        logger.debug("LiveCaptureRow._on_save_filter_clicked: fin")

    def _on_up(self, _btn):
        logger.debug("LiveCaptureRow._on_up: {}", self.label)
        capture_list.deplacer_ligne(self.get_parent(), vers_le_haut=True)
        logger.debug("LiveCaptureRow._on_up: fin")

    def _on_down(self, _btn):
        logger.debug("LiveCaptureRow._on_down: {}", self.label)
        capture_list.deplacer_ligne(self.get_parent(), vers_le_haut=False)
        logger.debug("LiveCaptureRow._on_down: fin")

    def _on_remove(self, _btn):
        logger.debug("LiveCaptureRow._on_remove: {}", self.label)
        capture_list.retirer_ligne(self.get_parent(), self._on_change)
        logger.debug("LiveCaptureRow._on_remove: fin")

    @property
    def label(self):
        logger.debug("LiveCaptureRow.label: retour self.label_entry.get_text().strip(…)")
        return self.label_entry.get_text().strip()

    @property
    def interface(self):
        logger.debug("LiveCaptureRow.interface: retour self.interface_entry.get_text().strip(…)")
        return self.interface_entry.get_text().strip()

    @property
    def bpf_filter(self):
        logger.debug("LiveCaptureRow.bpf_filter: retour self.filter_entry.get_text().strip() or None")
        return self.filter_entry.get_text().strip() or None


class CaptureListPanel(Gtk.Box):
    """Un panneau autonome liste-de-captures + bouton d'ajout. Utilise une
    fois en mode analyse simple, deux fois cote a cote (baseline/courant)
    en mode comparaison -- voir MainWindow._build_config_page."""

    def __init__(self, heading, on_change=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self._on_change = on_change
        logger.debug("CaptureListPanel: {}", heading)

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header.append(
            Gtk.Label(
                label=heading,
                halign=Gtk.Align.START,
                css_classes=["heading"],
                hexpand=True,
            )
        )
        add_btn = Gtk.Button(label="Ajouter une capture")
        # Issue #671 : rotation, comme --capture NOM=a,b de la CLI.
        add_btn.set_tooltip_text(
            "Sélection multiple possible. Deux lignes portant le même nom forment un seul point : "
            "les segments successifs d'une capture en rotation, lus dans l'ordre de la liste "
            "(équivalent de --capture NOM=a,b)."
        )
        add_btn.connect("clicked", self._on_add_clicked)
        header.append(add_btn)
        self.append(header)

        frame = Gtk.Frame()
        frame.set_size_request(-1, 160)
        scroller = _visible_scroller()
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        scroller.set_child(self.listbox)
        frame.set_child(scroller)
        self.append(frame)
        logger.debug("CaptureListPanel.__init__: fin")

    def _on_add_clicked(self, _btn):
        logger.debug("_on_add_clicked: ouverture du sélecteur de captures")
        dialog = Gtk.FileDialog()
        filt = Gtk.FileFilter()
        filt.add_pattern("*.pcap")
        filt.add_pattern("*.pcapng")
        filt.set_name("Captures Wireshark (*.pcap, *.pcapng)")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filt)
        dialog.set_filters(filters)
        dialog.open_multiple(self.get_root(), None, self._on_files_chosen)
        logger.debug("CaptureListPanel._on_add_clicked: fin")

    def _on_files_chosen(self, dialog, result):
        try:
            files = dialog.open_multiple_finish(result)
        except GLib.Error:
            logger.exception("échec dans _on_files_chosen")
            logger.debug("CaptureListPanel._on_files_chosen: except GLib.Error -> retour")
            return
        logger.debug("_on_files_chosen: {} fichier(s) choisi(s)", files.get_n_items())
        for i in range(files.get_n_items()):
            gfile = files.get_item(i)
            self.add_row(gfile.get_path())
        logger.debug("CaptureListPanel._on_files_chosen: fin")

    def add_row(self, path, default_label=None):
        """Expose separement du callback du selecteur pour pouvoir etre
        pilote sans dialogue (tests automatises, appel programmatique)."""
        if default_label is None:
            default_label = capture_list.nom_par_defaut_fichier(path)
        logger.debug("CaptureListPanel.add_row: label={} path={}", default_label, path)
        row = CaptureRow(path, default_label, on_change=self._on_change)
        self.listbox.append(row)
        if self._on_change:
            self._on_change()
        logger.debug("CaptureListPanel.add_row: retour row={}", summarize(row, "row"))
        return row

    def rows(self):
        logger.debug("CaptureListPanel.rows: retour capture_list.lignes(…)")
        return capture_list.lignes(self.listbox)

    def captures(self):
        """Liste de (label, path) dans l'ordre visuel courant -- cet ordre
        sert de topologie physique quand la deduction automatique est
        desactivee (voir MainWindow.auto_topology_check)."""
        logger.debug("CaptureListPanel.captures: retour capture_list.captures_fichiers(…)")
        return capture_list.captures_fichiers(self.rows())


class LiveCaptureListPanel(Gtk.Box):
    """Pendant de CaptureListPanel pour la capture en direct : meme forme
    (en-tete + liste reordonnable dans un cadre defilant), mais "Ajouter"
    insere directement une ligne vide (pas de selecteur de fichiers --
    rien a choisir sur le disque, l'utilisateur remplit interface/filtre
    a la main).

    ``filters_path`` : fichier des filtres BPF sauvegardes (defaut :
    ~/.netcross/bpf_filters.json). Le panneau charge le catalogue + les
    filtres sauvegardes une fois, les distribue aux lignes, et centralise
    l'enregistrement d'un nouveau filtre (menus de TOUTES les lignes mis a
    jour)."""

    def __init__(self, heading, on_change=None, filters_path=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self._on_change = on_change
        self._filters_path = filters_path
        self._filters = self._initial_filters()
        logger.debug("LiveCaptureListPanel: {} ({} filtre(s) BPF)", heading, len(self._filters))

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header.append(
            Gtk.Label(
                label=heading,
                halign=Gtk.Align.START,
                css_classes=["heading"],
                hexpand=True,
            )
        )
        add_btn = Gtk.Button(label="Ajouter un point de capture")
        add_btn.connect("clicked", lambda _b: self.add_row())
        header.append(add_btn)
        self.append(header)

        frame = Gtk.Frame()
        frame.set_size_request(-1, 160)
        scroller = _visible_scroller()
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        scroller.set_child(self.listbox)
        frame.set_child(scroller)
        self.append(frame)
        logger.debug("LiveCaptureListPanel.__init__: fin")

    def add_row(self, default_label=None, interface="", bpf_filter=""):
        if default_label is None:
            default_label = capture_list.nom_par_defaut_live(len(self.rows()))
        logger.debug("LiveCaptureListPanel.add_row: label={} interface={}", default_label, interface)
        row = LiveCaptureRow(
            default_label,
            interface,
            bpf_filter,
            on_change=self._on_change,
            filters=self._filters,
            on_save_filter=self._save_filter,
        )
        self.listbox.append(row)
        if self._on_change:
            self._on_change()
        logger.debug("LiveCaptureListPanel.add_row: retour row={}", summarize(row, "row"))
        return row

    def _initial_filters(self):
        logger.debug("_initial_filters: fichier={}", self._filters_path)
        try:
            logger.debug("LiveCaptureListPanel._initial_filters: retour available_bpf_filters(…)")
            return available_bpf_filters(self._filters_path)
        except (OSError, ValueError) as exc:
            # Fichier sidecar illisible : le catalogue predefini reste
            # utilisable et le fichier n'est PAS touche (upsert_bpf_filter
            # refuse d'ecraser un fichier qu'il ne sait pas relire).
            logger.exception(f"échec dans _initial_filters, filtres BPF sauvegardés ignorés : {exc}")
            logger.debug("LiveCaptureListPanel._initial_filters: except (OSError, ValueError) -> retour list(…)")
            return list(PREDEFINED_BPF_FILTERS)

    def _save_filter(self, flt):
        """Persiste ``flt`` puis rafraichit le menu de chaque ligne. Les
        erreurs (nom reserve au catalogue, fichier illisible, E/S) remontent
        a la ligne appelante, qui les affiche dans son popover."""
        logger.debug("_save_filter: {}", flt.name)
        self._filters = upsert_bpf_filter(flt, self._filters_path)
        logger.debug("_save_filter: {} filtre(s), {} ligne(s) rafraîchie(s)", len(self._filters), len(self.rows()))
        for row in self.rows():
            row.set_filters(self._filters)
        logger.debug("LiveCaptureListPanel._save_filter: fin")

    def rows(self):
        logger.debug("LiveCaptureListPanel.rows: retour capture_list.lignes(…)")
        return capture_list.lignes(self.listbox)

    def captures(self):
        """Liste de (label, interface, bpf_filter) dans l'ordre visuel
        courant -- meme role que CaptureListPanel.captures() pour la
        source live. `interface` est le texte brut du champ, qui peut
        contenir plusieurs interfaces : voir expand_live_points()."""
        logger.debug("LiveCaptureListPanel.captures: retour capture_list.captures_live(…)")
        return capture_list.captures_live(self.rows())


class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Analyse croisee de captures reseau")
        self.set_default_size(1080, 800)
        logger.debug("MainWindow: construction de la fenêtre principale")
        self.last_report = None
        # etat du dernier run, pour les exports (varie selon le mode) :
        self.last_mode = None  # "single" ou "diff"
        self.last_flows = None  # mode single : pour --detail-csv et la cartographie
        # Issue #453 : meme run, deux formes -- le dict brut de correlate()
        # ci-dessus (detail CSV, cartographie, objets de session lisent les Pkt)
        # et la liste de Flow ci-dessous (dashboard, statistiques, selection
        # de flux lisent .endpoints/.points/.packet_count). Renseigne par
        # RunOutcome (build_flow_objects), comme tous les last_*.
        self.last_flow_objects = None
        self.last_stats_rows = None  # mode single : StatRow pour export CSV/JSON
        # Fichier PNG temporaire de la cartographie : un seul par fenetre,
        # reecrit a chaque changement de filtre. Gtk.Picture lit le fichier,
        # il doit donc survivre a l'appel -- d'ou un attribut plutot qu'un
        # NamedTemporaryFile local.
        self._comm_map_png = None
        self.last_findings = None  # mode single : Finding, pour le PDF
        self.last_tls_findings = None  # mode single : TlsFinding, pour le PDF
        self.last_quic_findings = None  # mode single : TlsFinding (QUIC), pour le PDF
        # mode single : ExpertEvent de source "tshark", pour le JSON et le PDF
        # (issue #14). None = non calcule, [] = calcule et aucun signal.
        self.last_wireshark_expert_events = None
        # Issue #357 : SecurityReport du dernier run simple (None sinon)
        self.last_security_report = None
        self.last_rule_engine = None  # issue #864 : constats --rule-engine
        self.last_diff_findings = None  # mode diff : DiffFinding
        self.last_baseline_report = None
        self.last_current_report = None
        self.last_diff_tls_findings_baseline = None  # mode diff : TlsFinding (Session 37)
        self.last_diff_tls_findings_current = None
        self.last_diff_quic_findings_baseline = None
        self.last_diff_quic_findings_current = None

        # -- dashboard analytique interactif (issue #18, §6.17) --
        # Contexte de selection partage entre les six vues ; pur Python
        # (voir dashboard_context.py), testable sans display. Les widgets
        # GTK ci-dessous ne font que le cabler.
        self.dashboard_selection = DashboardSelection()

        # Issue #363 : captures (label, chemin) de la derniere analyse de
        # fichiers -- leurs sidecars d'annotations sont charges a la fin
        # de l'analyse (None : diff ou capture en direct, rien a annoter)
        self._annotation_captures: list | None = None

        # etat propre a la capture en direct (mode live, voir _begin_live_capture)
        self._live_capturing = False
        self._live_stop_event = None
        self._live_packets = None
        self._live_lock = None
        self._live_threads = None
        self._live_session_id = 0  # incremente a chaque demarrage -- distingue
        # un minuteur de duree max perime (session
        # precedente) d'un minuteur toujours valide

        header = Gtk.HeaderBar()
        self.set_titlebar(header)
        # Issue #874 : consultation de l'historique (analyses et comparaisons)
        self.history_btn = Gtk.Button(label="Historique des runs")
        self.history_btn.set_tooltip_text("Consulter une base --history-db (filtres type, etiquette, nombre)")
        self.history_btn.connect("clicked", lambda _b: self.open_history())
        header.pack_start(self.history_btn)
        self.history_window = None

        # Issues #868-#870, #886, #887 : fusion, decoupage, conversion...
        self.capture_tools_btn = Gtk.Button(label="Outils de capture")
        self.capture_tools_btn.set_tooltip_text(
            "Fusion, decoupage, conversion, export filtre, recalage temporel (sans analyse)"
        )
        self.capture_tools_btn.connect("clicked", lambda _b: self.open_capture_tools())
        header.pack_start(self.capture_tools_btn)
        self.capture_tools_window = None

        # Issue #873 : documentation Lua hors ligne (netcross-lua-doc)
        self.lua_doc_btn = Gtk.Button(label="Documentation Lua")
        self.lua_doc_btn.set_tooltip_text("API Lua de Wireshark, hors ligne (equivalent de netcross-lua-doc)")
        self.lua_doc_btn.connect("clicked", lambda _b: self.open_lua_doc())
        header.pack_end(self.lua_doc_btn)
        self.lua_doc_window = None

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.NONE)
        switcher = Gtk.StackSwitcher()
        switcher.set_stack(self.stack)
        header.set_title_widget(switcher)

        self.set_child(self.stack)

        self._build_config_page()
        self._build_work_page()
        self._build_results_page()

        self.stack.set_visible_child_name("config")
        logger.debug("MainWindow: fenêtre prête (3 pages construites)")

    def open_history(self):
        """Fenetre « Historique des runs » (base et etiquette de la configuration)."""
        from netcross_gtk4.history_window import HistoryWindow

        if self.history_window is None:
            settings = self.history_settings()
            self.history_window = HistoryWindow(parent=self, db_path=settings.db_path, label=settings.label)
            self.history_window.connect("close-request", self._on_history_closed)
        self.history_window.present()
        return self.history_window

    def _on_history_closed(self, _win):
        self.history_window = None
        return False

    def open_capture_tools(self):
        """Fenetre « Outils de capture », une seule a la fois."""
        from netcross_gtk4.capture_tools_window import CaptureToolsWindow

        if self.capture_tools_window is None:
            self.capture_tools_window = CaptureToolsWindow(parent=self)
            self.capture_tools_window.connect("close-request", self._on_capture_tools_closed)
        self.capture_tools_window.present()
        return self.capture_tools_window

    def _on_capture_tools_closed(self, _win):
        self.capture_tools_window = None
        return False

    def open_lua_doc(self):
        """Fenetre « Documentation Lua » (issue #873), une seule a la fois."""
        from netcross_gtk4.lua_doc_window import LuaDocWindow

        if self.lua_doc_window is not None and self.lua_doc_window.browser is not None:
            self.lua_doc_window.present()
            return self.lua_doc_window
        self.lua_doc_window = LuaDocWindow(parent=self)
        self.lua_doc_window.present()
        logger.debug("open_lua_doc: fenetre ouverte")
        return self.lua_doc_window

    # ================= PAGE 1 : CONFIGURATION =================

    def _build_config_page(self):
        logger.debug("_build_config_page: construction de la page Configuration")
        outer_scroller = _visible_scroller()
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        page.set_margin_top(16)
        page.set_margin_bottom(16)
        page.set_margin_start(16)
        page.set_margin_end(16)
        outer_scroller.set_child(page)

        mode_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        self.diff_check = Gtk.CheckButton(
            label="Mode comparaison (baseline / courant) -- equivalent de cross_capture_diff_cli.py"
        )
        self.diff_check.connect("toggled", self._on_diff_toggled)
        mode_row.append(self.diff_check)
        self.live_check = Gtk.CheckButton(label="Capture en direct (interfaces reseau, au lieu de fichiers)")
        self.live_check.set_tooltip_text(
            "Capture sur une ou plusieurs interfaces jusqu'a l'arret manuel "
            "ou la duree max. Mode analyse simple uniquement (pas de "
            "comparaison), TLS/QUIC indisponibles (necessitent un fichier "
            "a relire)."
        )
        self.live_check.connect("toggled", self._on_live_toggled)
        mode_row.append(self.live_check)
        page.append(mode_row)

        # -- panneau mode analyse simple (fichiers) --
        self.single_panel = CaptureListPanel(
            "Points de capture (ordre = chemin physique reseau)",
            on_change=self._update_run_sensitivity,
        )
        page.append(self.single_panel)

        # -- panneau mode capture en direct (cache par defaut) --
        self.live_panel = LiveCaptureListPanel(
            "Points de capture en direct (ordre = chemin physique reseau)",
            on_change=self._update_run_sensitivity,
        )
        self.live_panel.set_visible(False)
        page.append(self.live_panel)

        self.live_extra_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.live_extra_box.append(
            Gtk.Label(
                label="Duree max (s, 0 = illimitee -- arret manuel):",
                halign=Gtk.Align.START,
            )
        )
        self.live_duration_spin = Gtk.SpinButton.new_with_range(0, 86400, 10)
        self.live_duration_spin.set_value(0)
        self.live_extra_box.append(self.live_duration_spin)
        self.live_extra_box.set_visible(False)
        page.append(self.live_extra_box)

        # -- rotation de capture (ring buffer) --
        # Option de configuration pour les captures longues en mode live
        # (issue #157 / #264). Purement preparatoire a ce stade : ni la
        # capture live de cette page ni LiveDiffEngine ne s'appellent l'un
        # l'autre aujourd'hui -- le cablage reel est laisse a une session
        # qui raccordera les deux. Meme principe de visibilite que
        # live_extra_box : masque hors mode capture live.
        self.ring_buffer_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.ring_buffer_check = Gtk.CheckButton(label="Rotation de capture (ring buffer)")
        self.ring_buffer_check.set_tooltip_text(
            "Active la rotation des fichiers de capture : ecrit dans des "
            "fichiers de duree fixe et supprime automatiquement le plus "
            "ancien au-dela du nombre maximal. Enregistre la capture brute "
            "de chaque point (pcapng, tshark) en parallele de l'analyse ; "
            "incompatible avec une source pipe:// (issue #676)."
        )
        self.ring_buffer_check.connect("toggled", self._on_ring_buffer_toggled)
        self.ring_buffer_box.append(self.ring_buffer_check)
        self.ring_buffer_box.append(Gtk.Label(label="Fichiers max :", halign=Gtk.Align.START))
        self.ring_max_files_spin = Gtk.SpinButton.new_with_range(1, 1000, 1)
        self.ring_max_files_spin.set_value(10)
        self.ring_max_files_spin.set_sensitive(False)
        self.ring_max_files_spin.set_tooltip_text(
            "Nombre maximal de fichiers de capture conserves sur disque (defaut : 10)."
        )
        self.ring_buffer_box.append(self.ring_max_files_spin)
        self.ring_buffer_box.append(Gtk.Label(label="Duree/fichier (s) :", halign=Gtk.Align.START))
        self.ring_max_duration_spin = Gtk.SpinButton.new_with_range(1, 86400, 10)
        self.ring_max_duration_spin.set_value(60)
        self.ring_max_duration_spin.set_sensitive(False)
        self.ring_max_duration_spin.set_tooltip_text(
            "Duree maximale de chaque fichier de capture en secondes (defaut : 60)."
        )
        self.ring_buffer_box.append(self.ring_max_duration_spin)
        self.ring_buffer_box.set_visible(False)
        page.append(self.ring_buffer_box)

        # -- rapport HTML rafraichi en continu (issue #676) --
        # Equivalent de --live-report / --live-report-interval /
        # --live-report-serve : meme moteur que la CLI. Visible en mode
        # capture live uniquement, comme ring_buffer_box.
        self.live_report_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.live_report_check = Gtk.CheckButton(label="Rapport HTML en continu (--live-report)")
        self.live_report_check.set_tooltip_text(
            "Publie pendant la capture une page index.html (et live.json, live.jsonl) "
            "rafraichie a intervalle regulier : debit, protocoles, hotes, etat de chaque point."
        )
        self.live_report_check.connect("toggled", self._on_live_report_toggled)
        self.live_report_box.append(self.live_report_check)
        self.live_report_dir_entry = Gtk.Entry()
        self.live_report_dir_entry.set_placeholder_text("Repertoire (temporaire si vide)")
        self.live_report_dir_entry.set_hexpand(True)
        self.live_report_box.append(self.live_report_dir_entry)
        self.live_report_box.append(Gtk.Label(label="Intervalle (s) :", halign=Gtk.Align.START))
        self.live_report_interval_spin = Gtk.SpinButton.new_with_range(1, 3600, 1)
        self.live_report_interval_spin.set_value(5)
        self.live_report_box.append(self.live_report_interval_spin)
        self.live_report_serve_check = Gtk.CheckButton(label="Servir la page (--live-report-serve)")
        self.live_report_serve_check.set_tooltip_text(
            "Sert la page sur http://127.0.0.1:PORT/ pendant la capture (0 = port libre choisi par le systeme)."
        )
        self.live_report_serve_check.connect("toggled", self._on_live_report_toggled)
        self.live_report_box.append(self.live_report_serve_check)
        self.live_report_port_spin = Gtk.SpinButton.new_with_range(0, 65535, 1)
        self.live_report_port_spin.set_value(0)
        self.live_report_box.append(self.live_report_port_spin)
        self.live_report_box.set_visible(False)
        page.append(self.live_report_box)
        self._live_report_session = None
        self._on_live_report_toggled(None)

        # -- panneaux mode comparaison (caches par defaut) --
        self.diff_panels_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        self.baseline_panel = CaptureListPanel("Baseline (avant)", on_change=self._update_run_sensitivity)
        self.current_panel = CaptureListPanel("Courant (apres)", on_change=self._update_run_sensitivity)
        self.diff_panels_box.append(self.baseline_panel)
        self.diff_panels_box.append(self.current_panel)
        self.diff_panels_box.set_hexpand(True)
        self.baseline_panel.set_hexpand(True)
        self.current_panel.set_hexpand(True)
        self.diff_panels_box.set_visible(False)
        page.append(self.diff_panels_box)

        options_label = Gtk.Label(label="Options d'analyse", halign=Gtk.Align.START, css_classes=["heading"])
        options_label.set_margin_top(12)
        page.append(options_label)

        options = Gtk.Grid(column_spacing=12, row_spacing=8)
        page.append(options)

        options.attach(
            Gtk.Label(label="Fenetre temporelle (ms):", halign=Gtk.Align.START),
            0,
            0,
            1,
            1,
        )
        self.bucket_spin = Gtk.SpinButton.new_with_range(10, 60000, 10)
        self.bucket_spin.set_value(1000)
        options.attach(self.bucket_spin, 1, 0, 1, 1)

        options.attach(Gtk.Label(label="Cadence RTP (Hz):", halign=Gtk.Align.START), 2, 0, 1, 1)
        self.rtp_spin = Gtk.SpinButton.new_with_range(8000, 192000, 1000)
        self.rtp_spin.set_value(8000)
        options.attach(self.rtp_spin, 3, 0, 1, 1)

        self.nat_check = Gtk.CheckButton(label="Correlation tolérante au NAT")
        options.attach(self.nat_check, 0, 1, 2, 1)

        # Issue #330 (écart 3) : réglages fins de la CLI (--nat-window-ms,
        # --idle-timeout-seconds), mêmes défauts.
        options.attach(Gtk.Label(label="Fenêtre NAT (ms):", halign=Gtk.Align.START), 0, 6, 1, 1)
        self.nat_window_spin = Gtk.SpinButton.new_with_range(1, 60000, 10)
        self.nat_window_spin.set_value(200)
        self.nat_window_spin.set_tooltip_text(
            "Écart maximal entre deux observations d'un même paquet traduit par un NAT "
            "(--nat-window-ms). Utilisé seulement avec la corrélation tolérante au NAT."
        )
        self.nat_window_spin.set_sensitive(False)
        self.nat_check.connect("toggled", self._on_nat_toggled)
        options.attach(self.nat_window_spin, 1, 6, 1, 1)

        options.attach(Gtk.Label(label="Coupure silencieuse (s):", halign=Gtk.Align.START), 2, 6, 1, 1)
        self.idle_timeout_spin = Gtk.SpinButton.new_with_range(0, 86400, 1)
        self.idle_timeout_spin.set_value(0)
        self.idle_timeout_spin.set_tooltip_text(
            "Silence minimal entre deux paquets au point amont pour signaler une coupure "
            "NAT/pare-feu silencieuse (--idle-timeout-seconds). 0 = défaut (60 s)."
        )
        options.attach(self.idle_timeout_spin, 3, 6, 1, 1)

        # Issue #330 (écart 3) : table des noms logiques (--names), appliquée
        # aux exports CSV détaillé et JSON comme dans la CLI.
        self.names_table = None
        names_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.names_btn = Gtk.Button(label="Table des noms...")
        self.names_btn.set_tooltip_text(
            "Fichier JSON ou YAML de noms logiques des hôtes (--names), repris dans les exports CSV détaillé et JSON."
        )
        self.names_btn.connect("clicked", self._on_names_clicked)
        names_box.append(self.names_btn)
        self.names_clear_btn = Gtk.Button(label="Retirer")
        self.names_clear_btn.set_sensitive(False)
        self.names_clear_btn.connect("clicked", self._on_names_clear_clicked)
        names_box.append(self.names_clear_btn)
        self.names_label = Gtk.Label(label="Aucune table des noms", halign=Gtk.Align.START)
        names_box.append(self.names_label)
        options.attach(names_box, 0, 7, 4, 1)

        self.detect_duplicates_check = Gtk.CheckButton(label="Détecter les doublons inter-captures")
        self.detect_duplicates_check.set_tooltip_text(
            "Marque comme doublons les mêmes payloads vus à des points différents dans la fenêtre temporelle choisie."
        )
        self.detect_duplicates_check.connect("toggled", self._on_duplicate_detection_toggled)
        options.attach(self.detect_duplicates_check, 0, 2, 2, 1)

        options.attach(Gtk.Label(label="Seuil doublons (ms):", halign=Gtk.Align.START), 2, 2, 1, 1)
        self.duplicate_threshold_spin = Gtk.SpinButton.new_with_range(0, 1000, 0.1)
        self.duplicate_threshold_spin.set_value(DEFAULT_DUPLICATE_THRESHOLD_MS)
        self.duplicate_threshold_spin.set_digits(1)
        self.duplicate_threshold_spin.set_tooltip_text(
            "Deux observations d'un même payload sont considérées comme doublons si leur écart est "
            "strictement inférieur à ce seuil."
        )
        options.attach(self.duplicate_threshold_spin, 3, 2, 1, 1)

        self.exclude_duplicates_check = Gtk.CheckButton(label="Exclure les doublons des statistiques")
        self.exclude_duplicates_check.set_tooltip_text(
            "Active automatiquement la détection et retire les paquets marqués des compteurs et de la corrélation."
        )
        self.exclude_duplicates_check.connect("toggled", self._on_duplicate_exclusion_toggled)
        options.attach(self.exclude_duplicates_check, 0, 3, 2, 1)

        self.parallel_check = Gtk.CheckButton(label="Lecture parallele des captures")
        self.parallel_check.set_tooltip_text(
            "Un processus tshark par fichier au lieu d'un flux sequentiel "
            "(--parallel). Le gain depend du nombre de coeurs disponibles."
        )
        options.attach(self.parallel_check, 2, 1, 2, 1)

        self.redact_check = Gtk.CheckButton(label="Anonymiser les adresses IP/MAC (--redact)")
        self.redact_check.set_tooltip_text(
            "Remplace les adresses IP (plages RFC 5737/3849) et MAC (OUI localement "
            "administre) par des pseudonymes coherents avant l'analyse -- pour "
            "partager un rapport sans exposer l'adressage reel. Mutuellement "
            "exclusif avec Diagnostic TLS/QUIC (pipelines independants qui "
            "accedent aux adresses reelles, voir netcross_core.redact)."
        )
        self.redact_check.connect("toggled", self._on_redact_toggled)
        options.attach(self.redact_check, 0, 5, 4, 1)

        self.auto_topology_check = Gtk.CheckButton(
            label="Deduire la topologie automatiquement (ignore l'ordre de la liste)"
        )
        self.auto_topology_check.set_tooltip_text(
            "Equivalent a ne pas passer --order : deduction par delta TTL + "
            "Jaccard, gere les branchements/convergences. Sinon, l'ordre "
            "visuel des lignes ci-dessus est utilise comme chemin physique."
        )
        options.attach(self.auto_topology_check, 0, 4, 4, 1)

        # Issue #474 lot 2 : equivalent GUI de --split-interfaces.
        self.split_interfaces_check = Gtk.CheckButton(label="Séparer les interfaces d'un pcapng (--split-interfaces)")
        self.split_interfaces_check.set_tooltip_text(
            "Un fichier pcapng qui contient plusieurs interfaces ou sections devient un "
            "point par interface, nommé NOM:INTERFACE. Un fichier à une seule capture est "
            "lu tel quel. Une seule capture suffit alors pour une analyse croisée."
        )
        options.attach(self.split_interfaces_check, 0, 8, 4, 1)

        # -- options specifiques a l'analyse simple (masquees en mode diff) --
        self.single_options_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        single_checks = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        self.triage_check = Gtk.CheckButton(label="Triage (classement des segments)")
        triage_topn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        triage_topn_box.append(Gtk.Label(label="Top"))
        self.triage_topn_spin = Gtk.SpinButton.new_with_range(1, 50, 1)
        self.triage_topn_spin.set_value(5)
        self.triage_topn_spin.set_tooltip_text(
            "Nombre de segments affiches par le triage (equivalent --triage-top-n sur la CLI, defaut : 5)"
        )
        triage_topn_box.append(self.triage_topn_spin)
        self.tls_check = Gtk.CheckButton(label="Diagnostic TLS")
        self.tls_check.set_tooltip_text(
            "Relit les memes fichiers avec un pipeline de decodage independant (via tshark)."
        )
        self.quic_check = Gtk.CheckButton(label="Diagnostic QUIC/HTTP3")
        self.quic_check.set_tooltip_text("Necessite cryptography. Relit les memes fichiers.")
        # Issue #357 : analyse de securite dans la GUI
        self.security_check = Gtk.CheckButton(label="Rapport de securite")
        self.security_check.set_tooltip_text(
            "Detecteurs de securite (beaconing, exfiltration, DGA, fast flux, "
            "mouvements lateraux, flow_stats, tunneling DNS, audit TLS, CVE)."
        )
        topn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        topn_box.append(Gtk.Label(label="Top-N graphiques"))
        self.topn_spin = Gtk.SpinButton.new_with_range(1, 20, 1)
        self.topn_spin.set_value(5)
        self.topn_spin.set_tooltip_text(
            "Nombre de categories affichees par graphique temporel dans le rapport "
            "PDF (equivalent --topn-charts sur la CLI, defaut : 5). Sans effet sans "
            "export PDF."
        )
        topn_box.append(self.topn_spin)
        single_checks.append(self.triage_check)
        single_checks.append(triage_topn_box)
        single_checks.append(self.tls_check)
        single_checks.append(self.quic_check)
        single_checks.append(self.security_check)
        # Issue #675 : index pour le panneau « Recherche forensic » (Resultats)
        self.forensic_index_check = Gtk.CheckButton(label="Index de recherche forensic (--forensic-search)")
        self.forensic_index_check.set_tooltip_text(
            "Indexe paquets et flux pendant l'analyse pour la recherche par texte, adresse, point, "
            "protocole, port ou champ decode (SNI, URI, DNS...) sur la page Resultats. L'index reste "
            "en memoire jusqu'a l'analyse suivante."
        )
        single_checks.append(self.forensic_index_check)
        single_checks.append(topn_box)
        self.single_options_box.append(single_checks)

        # Issue #676 : notifications (webhook, Slack, courriel), equivalent de
        # --notify-on/--notify-webhook/--notify-slack/--notify-email/
        # --notify-detail. Portent sur le rapport de securite, comme la CLI.
        notify_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        notify_box.append(Gtk.Label(label="Notifier si (--notify-on) :", halign=Gtk.Align.START))
        self.notify_threshold_drop = Gtk.DropDown.new_from_strings([label for _val, label in THRESHOLD_CHOICES])
        self.notify_threshold_drop.set_tooltip_text(
            "Envoie un resume (jamais un message par constat) quand le pire constat du rapport de "
            "securite atteint ce niveau. Necessite « Rapport de securite ». Serveur SMTP et URL par "
            "defaut : .netcross.toml [notify] ou NETCROSS_SLACK_WEBHOOK / NETCROSS_SMTP_*."
        )
        self.notify_threshold_drop.connect("notify::selected", self._on_notify_threshold_changed)
        notify_box.append(self.notify_threshold_drop)
        self.notify_webhook_entry = Gtk.Entry(placeholder_text="URL webhook (--notify-webhook)")
        self.notify_slack_entry = Gtk.Entry(placeholder_text="Webhook Slack (--notify-slack)")
        self.notify_email_entry = Gtk.Entry(placeholder_text="Courriel(s) (--notify-email)")
        for entry in (self.notify_webhook_entry, self.notify_slack_entry, self.notify_email_entry):
            entry.set_hexpand(True)
            notify_box.append(entry)
        self.notify_complete_check = Gtk.CheckButton(label="Detail complet (--notify-detail complet)")
        self.notify_complete_check.set_tooltip_text(
            "Par defaut, adresses, noms d'hote et chemins sont anonymises dans le message. "
            "Detail complet : texte brut des constats, a reserver a un canal de confiance."
        )
        notify_box.append(self.notify_complete_check)
        self.single_options_box.append(notify_box)

        # Issue #675 : comparaison de postes (--client-group, --client-reference)
        clients_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        clients_box.append(Gtk.Label(label="Postes a comparer (--client-group) :", halign=Gtk.Align.START))
        self.client_groups_entry = Gtk.Entry(placeholder_text="PosteA=10.0.0.5; PosteB=10.0.0.12,10.0.0.13")
        self.client_groups_entry.set_hexpand(True)
        self.client_groups_entry.set_tooltip_text(
            "Un groupe par poste, NOM=IP1[,IP2...], separes par « ; » ; au moins deux postes. "
            "Compare chaque poste a la reference (pertes, latence, retransmissions...) ; resultat "
            "dans le rapport et export CSV sur la page Resultats."
        )
        clients_box.append(self.client_groups_entry)
        clients_box.append(Gtk.Label(label="Reference (--client-reference) :", halign=Gtk.Align.START))
        self.client_reference_entry = Gtk.Entry(placeholder_text="(premier poste)")
        clients_box.append(self.client_reference_entry)
        self.single_options_box.append(clients_box)

        # Issue #673 : sections d'expertise, equivalents des options CLI
        expertise_box = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=8)
        self.rule_engine_check = Gtk.CheckButton(label="Moteur de regles (--rule-engine)")
        self.rule_engine_check.set_tooltip_text("Evalue chaque regle du catalogue declaratif ; section du rapport.")
        self.expert_section_check = Gtk.CheckButton(label="Section expertise (--expert-section)")
        self.expert_section_check.set_tooltip_text(
            "Objets de session detailles (flux, segments, diagnostics, preuves) ; section du rapport."
        )
        self.media_quality_check = Gtk.CheckButton(label="Qualite media (--media-quality)")
        self.media_quality_check.set_tooltip_text(
            "Relit les fichiers : voix et video RTP, documents ; analyse sans rien ecrire (l'extraction "
            "vers un dossier est sur la page Resultats)."
        )
        self.tshark_stats_check = Gtk.CheckButton(label="Statistiques tshark (--tshark-stats)")
        self.tshark_stats_check.set_tooltip_text(
            "tshark -z sur chaque fichier : conversations, endpoints, hierarchie de protocoles, IO ; "
            "export JSON sur la page Resultats."
        )
        self.flow_timeline_check = Gtk.CheckButton(label="Chronologie des flux (--flow-timeline)")
        self.flow_timeline_check.set_tooltip_text(
            "Chronologie de chaque conversation, point par point ; export JSON sur la page Resultats."
        )
        window_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        window_box.append(Gtk.Label(label="Fenetre (s)"))
        self.flow_timeline_window_spin = Gtk.SpinButton.new_with_range(
            FLOW_TIMELINE_WINDOW_MIN, FLOW_TIMELINE_WINDOW_MAX, 0.1
        )
        self.flow_timeline_window_spin.set_value(1.0)
        self.flow_timeline_window_spin.set_tooltip_text(
            "Largeur des fenetres de la chronologie (--flow-timeline-window)."
        )
        window_box.append(self.flow_timeline_window_spin)
        for widget in (
            self.rule_engine_check,
            self.expert_section_check,
            self.media_quality_check,
            self.tshark_stats_check,
            self.flow_timeline_check,
            window_box,
        ):
            expertise_box.append(widget)
        self.single_options_box.append(expertise_box)

        # Issue #672 : limites de lecture (--max-packets, --sample,
        # --parallel-workers) ; 0 (ou 1/1) = pas de limite, automatique
        limits_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        limits_box.append(Gtk.Label(label="Paquets max. (--max-packets, 0 = tous) :"))
        self.max_packets_spin = Gtk.SpinButton.new_with_range(0, MAX_PACKETS_MAX, 1000)
        self.max_packets_spin.set_tooltip_text(
            "Analyse les N premiers paquets (apres echantillonnage) ; le rapport l'annonce toujours."
        )
        limits_box.append(self.max_packets_spin)
        limits_box.append(Gtk.Label(label="Echantillonnage 1/N (--sample) :"))
        self.sample_spin = Gtk.SpinButton.new_with_range(1, SAMPLE_MAX, 1)
        self.sample_spin.set_tooltip_text("Garde 1 paquet sur N (1 = tous) ; le rapport l'annonce toujours.")
        limits_box.append(self.sample_spin)
        limits_box.append(Gtk.Label(label="Lecteurs paralleles (--parallel-workers, 0 = auto) :"))
        self.parallel_workers_spin = Gtk.SpinButton.new_with_range(0, WORKERS_MAX, 1)
        self.parallel_workers_spin.set_tooltip_text(
            "Nombre de processus tshark avec « Lecture parallele des captures » (0 = un par coeur)."
        )
        limits_box.append(self.parallel_workers_spin)
        self.single_options_box.append(limits_box)

        # Issue #672 : contexte du rapport de securite (--test-net-external,
        # --known-destinations, --known-hosts, --cve-db)
        security_box = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=4)
        self.test_net_external_check = Gtk.CheckButton(label="Plages TEST-NET externes (--test-net-external)")
        self.test_net_external_check.set_tooltip_text(
            "Traite 192.0.2.0/24, 198.51.100.0/24 et 203.0.113.0/24 comme des adresses externes "
            "(laboratoires, captures de demonstration). Necessite « Rapport de securite »."
        )
        json_patterns = ("*.json",)
        self.known_destinations_option = FileOption(
            "Destinations connues...",
            "Liste JSON d'IP de destinations habituelles (--known-destinations) : les autres sont signalees.",
            json_patterns,
            "Liste d'IP (*.json)",
        )
        self.known_hosts_option = FileOption(
            "Hotes connus...",
            "Liste JSON d'hotes deja vus (--known-hosts) : un hote absent est signale comme nouveau.",
            json_patterns,
            "Liste d'IP (*.json)",
        )
        self.cve_db_option = FileOption(
            "Base CVE...",
            "Base CVE complete (--cve-db, SQLite construite par netcross) a la place de la base minimale embarquee.",
            ("*.db", "*.sqlite", "*.sqlite3"),
            "Base CVE (*.db, *.sqlite)",
        )
        for widget in (
            self.test_net_external_check,
            self.known_destinations_option,
            self.known_hosts_option,
            self.cve_db_option,
        ):
            security_box.append(widget)
        self.single_options_box.append(security_box)

        # Issue #674 : diagramme de sequence (export PDF) et historique SQLite
        report_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        report_box.append(Gtk.Label(label="Diagramme de sequence (--sequence-diagram, flux, 0 = aucun) :"))
        self.sequence_diagram_spin = Gtk.SpinButton.new_with_range(0, SEQUENCE_FLOWS_MAX, 1)
        self.sequence_diagram_spin.set_tooltip_text(
            "Ajoute a l'export PDF le diagramme de sequence des N flux les plus volumineux."
        )
        report_box.append(self.sequence_diagram_spin)
        self.history_option = FileOption(
            "Historique...",
            "Base SQLite (--history-db, creee si absente) : chaque analyse y ajoute son resume.",
            ("*.db", "*.sqlite", "*.sqlite3"),
            "Historique (*.db, *.sqlite)",
        )
        report_box.append(self.history_option)
        report_box.append(Gtk.Label(label="Etiquette (--history-label) :"))
        self.history_label_entry = Gtk.Entry(placeholder_text="site, scenario...")
        report_box.append(self.history_label_entry)
        self.single_options_box.append(report_box)
        self._on_notify_threshold_changed(None)
        page.append(self.single_options_box)

        # -- options specifiques au mode comparaison (masquees par defaut) --
        self.diff_options_box = Gtk.Grid(column_spacing=12, row_spacing=8)
        self.diff_options_box.attach(
            Gtk.Label(label="Seuil pertes (points de %):", halign=Gtk.Align.START),
            0,
            0,
            1,
            1,
        )
        self.loss_threshold_spin = Gtk.SpinButton.new_with_range(0, 100, 0.5)
        self.loss_threshold_spin.set_value(2.0)
        self.diff_options_box.attach(self.loss_threshold_spin, 1, 0, 1, 1)
        self.diff_options_box.attach(Gtk.Label(label="Seuil latence (ms):", halign=Gtk.Align.START), 2, 0, 1, 1)
        self.latency_threshold_spin = Gtk.SpinButton.new_with_range(0, 10000, 0.5)
        self.latency_threshold_spin.set_value(5.0)
        self.diff_options_box.attach(self.latency_threshold_spin, 3, 0, 1, 1)
        self.diff_tls_check = Gtk.CheckButton(label="Diagnostic TLS")
        self.diff_tls_check.set_tooltip_text(
            "Relit les fichiers baseline ET courant avec un pipeline de decodage "
            "independant (via tshark), affiche l'un sous l'autre (pas de vraie diff "
            "semantique possible entre les deux -- voir claude.md Session 8)."
        )
        self.diff_options_box.attach(self.diff_tls_check, 0, 1, 2, 1)
        self.diff_quic_check = Gtk.CheckButton(label="Diagnostic QUIC/HTTP3")
        self.diff_quic_check.set_tooltip_text("Necessite cryptography. Idem TLS, baseline et courant separement.")
        self.diff_options_box.attach(self.diff_quic_check, 2, 1, 2, 1)
        # Issue #330 (écart 4) : triage des écarts, equivalent --triage /
        # --triage-top-n de cross_capture_diff_cli.py
        self.diff_triage_check = Gtk.CheckButton(label="Triage des ecarts (classement des segments)")
        self.diff_triage_check.set_tooltip_text(
            "Classe les segments par ou commencer a regarder, sur les ecarts "
            "baseline/courant (equivalent --triage sur la CLI). Deja inclus en "
            "tete du PDF de comparaison ; cette case l'affiche aussi dans le rapport texte."
        )
        self.diff_options_box.attach(self.diff_triage_check, 0, 2, 2, 1)
        diff_triage_topn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        diff_triage_topn_box.append(Gtk.Label(label="Top"))
        self.diff_triage_topn_spin = Gtk.SpinButton.new_with_range(1, 50, 1)
        self.diff_triage_topn_spin.set_value(5)
        self.diff_triage_topn_spin.set_tooltip_text(
            "Nombre de segments affiches par le triage des ecarts (equivalent --triage-top-n, defaut : 5)"
        )
        diff_triage_topn_box.append(self.diff_triage_topn_spin)
        self.diff_options_box.attach(diff_triage_topn_box, 2, 2, 2, 1)
        self.diff_options_box.set_visible(False)
        page.append(self.diff_options_box)

        self.run_btn = Gtk.Button(label="Lancer l'analyse")
        self.run_btn.add_css_class("suggested-action")
        self.run_btn.add_css_class("pill")
        self.run_btn.set_halign(Gtk.Align.END)
        self.run_btn.set_margin_top(8)
        self.run_btn.connect("clicked", self.on_run_analysis)
        self.run_btn.set_sensitive(False)
        page.append(self.run_btn)

        self.stack.add_titled(outer_scroller, "config", "Configuration")
        logger.debug("MainWindow._build_config_page: fin")

    def _on_diff_toggled(self, _btn):
        # Issue #676 : comparaison et capture en direct se combinent (courant
        # capture en direct, --live-current) -- plus d'exclusion mutuelle.
        logger.debug("_on_diff_toggled: diff={}", self.diff_check.get_active())
        self._sync_panel_visibility()
        self._update_run_sensitivity()
        self._update_run_button_label()
        logger.debug("MainWindow._on_diff_toggled: fin")

    def _on_duplicate_detection_toggled(self, _btn):
        active = self.detect_duplicates_check.get_active()
        logger.debug("_on_duplicate_detection_toggled: detection={}", active)
        self.duplicate_threshold_spin.set_sensitive(active and not self.diff_check.get_active())
        self.exclude_duplicates_check.set_sensitive(active and not self.diff_check.get_active())
        if not active:
            self.exclude_duplicates_check.set_active(False)
        logger.debug("MainWindow._on_duplicate_detection_toggled: fin")

    def _on_duplicate_exclusion_toggled(self, _btn):
        if self.exclude_duplicates_check.get_active() and not self.detect_duplicates_check.get_active():
            self.detect_duplicates_check.set_active(True)
        logger.debug(
            "_on_duplicate_exclusion_toggled: exclusion={}",
            self.exclude_duplicates_check.get_active(),
        )

    def _on_live_toggled(self, _btn):
        logger.debug("_on_live_toggled: live={}", self.live_check.get_active())
        self._sync_panel_visibility()
        self._update_run_sensitivity()
        self._update_run_button_label()
        logger.debug("MainWindow._on_live_toggled: fin")

    def _on_nat_toggled(self, _btn):
        """La fenêtre NAT ne sert qu'avec la corrélation tolérante au NAT
        (même règle que --nat-window-ms) : réglable seulement dans ce cas."""
        active = self.nat_check.get_active()
        self.nat_window_spin.set_sensitive(active)
        logger.debug("MainWindow._on_nat_toggled: fin (fenêtre NAT réglable={})", active)

    def _on_names_clicked(self, _btn):
        logger.debug("_on_names_clicked: ouverture du sélecteur de table des noms")
        dialog = Gtk.FileDialog()
        filt = Gtk.FileFilter()
        for pattern in ("*.json", "*.yaml", "*.yml"):
            filt.add_pattern(pattern)
        filt.set_name("Table des noms (*.json, *.yaml, *.yml)")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filt)
        dialog.set_filters(filters)
        dialog.open(self, None, self._on_names_chosen)
        logger.debug("MainWindow._on_names_clicked: fin")

    def _on_names_chosen(self, dialog, result):
        try:
            gfile = dialog.open_finish(result)
        except GLib.Error:
            logger.exception("échec dans _on_names_chosen")
            logger.debug("MainWindow._on_names_chosen: except GLib.Error -> retour")
            return
        self.load_names_table(gfile.get_path())
        logger.debug("MainWindow._on_names_chosen: fin")

    def load_names_table(self, path):
        """Charge la table des noms (même format que --names). Exposée hors
        du dialogue pour les tests ; une erreur laisse l'ancienne table et
        s'affiche dans la barre de statut. Retourne True si chargée."""
        from netcross_core.naming import NameTable

        try:
            table = NameTable.load(path)
        except Exception as e:  # noqa: BLE001 -- callback GUI : erreur affichée plutôt que plantage
            logger.exception(f"échec du chargement de la table des noms {path}: {e}")
            self.status_label.set_text(f"Erreur table des noms : {e}")
            logger.debug("MainWindow.load_names_table: except Exception -> retour False")
            return False
        self.names_table = table
        self.names_label.set_text(f"{os.path.basename(path)} ({len(table)} entrée(s))")
        self.names_clear_btn.set_sensitive(True)
        logger.debug("MainWindow.load_names_table: retour True ({} entrée(s))", len(table))
        return True

    def _on_names_clear_clicked(self, _btn):
        self.names_table = None
        self.names_label.set_text("Aucune table des noms")
        self.names_clear_btn.set_sensitive(False)
        logger.debug("MainWindow._on_names_clear_clicked: fin")

    def _fine_settings(self):
        """Issue #330 (écart 3) : (nat_window_ms, idle_timeout_seconds) lus
        dans l'onglet ; 0 s de coupure silencieuse = défaut du cœur (None)."""
        nat_window_ms = float(self.nat_window_spin.get_value())
        idle = float(self.idle_timeout_spin.get_value())
        idle_timeout_seconds = idle if idle > 0 else None
        logger.debug(
            "MainWindow._fine_settings: retour nat_window_ms={} idle_timeout_seconds={}",
            nat_window_ms,
            idle_timeout_seconds,
        )
        return nat_window_ms, idle_timeout_seconds

    def _on_redact_toggled(self, _btn):
        """--redact n'est pas disponible avec TLS/QUIC (pipelines independants
        qui accedent aux adresses reelles, voir netcross_core.redact et
        cross_capture_analyzer_cli.py) -- meme contrainte appliquee aux deux
        modes (simple et comparaison), verifiee aussi a l'execution dans
        on_run_analysis (au cas ou l'ordre de coches inverse ait ete utilise)."""
        redact = self.redact_check.get_active()
        logger.debug("_on_redact_toggled: redact={}", redact)
        # issue #357 : le rapport de securite aussi (charge utile brute,
        # meme refus que --security-report --redact)
        for check in (self.tls_check, self.quic_check, self.diff_tls_check, self.diff_quic_check, self.security_check):
            check.set_sensitive(not redact)
            if redact:
                check.set_active(False)
        logger.debug("MainWindow._on_redact_toggled: fin")

    def _on_ring_buffer_toggled(self, _btn):
        """Active/desactive les SpinButton de configuration du ring buffer
        selon l'etat de la case a cocher -- meme schéma que
        `_on_duplicate_exclusion_toggled` pour les seuils de doublons : un
        controle reglable alors que la fonctionnalite n'est pas activee
        est une invitation a perdre du temps."""
        active = self.ring_buffer_check.get_active()
        logger.debug("_on_ring_buffer_toggled: ring_buffer={}", active)
        self.ring_max_files_spin.set_sensitive(active)
        self.ring_max_duration_spin.set_sensitive(active)
        logger.debug("MainWindow._on_ring_buffer_toggled: fin")

    def _on_notify_threshold_changed(self, *_args):
        """Canaux et niveau de detail reglables seulement avec un seuil."""
        active = self.notify_threshold_drop.get_selected() > 0
        for widget in (
            self.notify_webhook_entry,
            self.notify_slack_entry,
            self.notify_email_entry,
            self.notify_complete_check,
        ):
            widget.set_sensitive(active)
        logger.debug("MainWindow._on_notify_threshold_changed: actif={}", active)

    def _notify_settings(self) -> NotifySettings:
        """Reglages de notification, lus sur le thread principal."""
        return settings_from_widgets(
            self.notify_threshold_drop.get_selected(),
            self.notify_webhook_entry.get_text(),
            self.notify_slack_entry.get_text(),
            self.notify_email_entry.get_text(),
            self.notify_complete_check.get_active(),
        )

    def _on_live_report_toggled(self, _btn):
        """Reglages du rapport en continu actifs seulement si la case l'est."""
        active = self.live_report_check.get_active()
        self.live_report_dir_entry.set_sensitive(active)
        self.live_report_interval_spin.set_sensitive(active)
        self.live_report_serve_check.set_sensitive(active)
        self.live_report_port_spin.set_sensitive(active and self.live_report_serve_check.get_active())
        logger.debug("MainWindow._on_live_report_toggled: live_report={}", active)

    def _sync_panel_visibility(self):
        """Point unique qui decide, a partir des deux cases a cocher, quels
        panneaux/options sont visibles -- appele apres tout changement de
        mode pour eviter que diff_check et live_check ne divergent."""
        # Les regles sont dans netcross_gtk4.panel_state (issue #285, lot 3) :
        # cette methode ne fait plus que les appliquer aux widgets. Le
        # commentaire d'origine -- triage pertinent en live mais pas TLS/QUIC
        # -- y est documente avec sa raison.
        vue = panel_visibility(
            self.diff_check.get_active(),
            self.live_check.get_active(),
            self.detect_duplicates_check.get_active(),
        )
        self.single_panel.set_visible(vue.single_panel)
        self.live_panel.set_visible(vue.live_panel)
        self.live_extra_box.set_visible(vue.live_extra)
        # tampon circulaire et rapport en continu : capture en direct simple
        # seulement (pas d'equivalent avec --live-current)
        self.ring_buffer_box.set_visible(vue.ring_buffer)
        self.live_report_box.set_visible(vue.ring_buffer)
        self.diff_panels_box.set_visible(vue.diff_panels)
        self.current_panel.set_visible(vue.current_panel)
        self.single_options_box.set_visible(vue.single_options)
        self.diff_options_box.set_visible(vue.diff_options)
        logger.debug(
            "_sync_panel_visibility: single={} live={} diff={}",
            vue.single_panel,
            vue.live_panel,
            vue.diff_panels,
        )
        self.tls_check.set_sensitive(vue.tls_sensitive)
        self.quic_check.set_sensitive(vue.quic_sensitive)
        # memes regles pour les diagnostics du mode comparaison : un courant
        # capture en direct ne produit pas de fichier a relire
        self.diff_tls_check.set_sensitive(vue.tls_sensitive)
        self.diff_quic_check.set_sensitive(vue.quic_sensitive)
        self.parallel_check.set_sensitive(vue.parallel_sensitive)
        self.detect_duplicates_check.set_sensitive(vue.duplicate_detect_sensitive)
        self.duplicate_threshold_spin.set_sensitive(vue.duplicate_threshold_sensitive)
        self.exclude_duplicates_check.set_sensitive(vue.duplicate_exclude_sensitive)
        if vue.force_tls_off:
            self.tls_check.set_active(False)
            self.diff_tls_check.set_active(False)
        if vue.force_quic_off:
            self.quic_check.set_active(False)
            self.diff_quic_check.set_active(False)
        if vue.force_duplicate_detect_off:
            self.detect_duplicates_check.set_active(False)
        if vue.force_duplicate_exclude_off:
            self.exclude_duplicates_check.set_active(False)
        logger.debug("MainWindow._sync_panel_visibility: fin")

    def _run_button_state(self):
        """Decision d'etat du bouton Lancer, deleguee a panel_state.

        Les compteurs sont lus ici car ils viennent des panneaux GTK ; la
        regle qui les interprete est dans netcross_gtk4.panel_state (issue
        #285, lot 3).
        """
        logger.debug("MainWindow._run_button_state: retour run_button_state(…)")
        return run_button_state(
            live_capturing=self._live_capturing,
            diff_mode=self.diff_check.get_active(),
            live_mode=self.live_check.get_active(),
            single_rows=len(self.single_panel.rows()),
            baseline_rows=len(self.baseline_panel.rows()),
            current_rows=len(self.current_panel.rows()),
            # points apres eclatement : une seule ligne "eth0, eth1" en donne deux
            live_points=len(expand_live_points(self.live_panel.captures())),
            label_actuel=self.run_btn.get_label(),
        )

    def _update_run_button_label(self):
        if self._live_capturing:
            logger.debug("MainWindow._update_run_button_label: si self._live_capturing -> retour")
            return  # deja gere par _begin_live_capture/_end_live_capture
        etat = self._run_button_state()
        logger.debug("_update_run_button_label: label={}", etat.label)
        self.run_btn.set_label(etat.label)
        logger.debug("MainWindow._update_run_button_label: fin")

    def _update_run_sensitivity(self):
        if self._live_capturing:
            logger.debug("MainWindow._update_run_sensitivity: si self._live_capturing -> retour")
            return  # bouton deja dans le bon etat pendant une capture en cours
        etat = self._run_button_state()
        logger.debug("_update_run_sensitivity: enabled={} raison={}", etat.enabled, etat.raison)
        self.run_btn.set_sensitive(etat.enabled)
        # La raison du refus est affichee en infobulle plutot que gardee pour
        # nous : elle est connue au moment de la decision, et un bouton grise
        # sans explication oblige l'utilisateur a deviner combien de captures
        # il manque -- particulierement en mode live, ou le compte porte sur
        # les points APRES eclatement des interfaces et ne correspond donc pas
        # au nombre de lignes affichees.
        self.run_btn.set_tooltip_text(etat.raison)
        logger.debug("MainWindow._update_run_sensitivity: fin")

    # ================= compat retro (tests existants) =================
    # Certains appelants (tests) pilotaient directement l'ancienne API a
    # panneau unique : on la fait pointer vers single_panel.

    def add_capture_row(self, path, default_label=None):
        logger.debug("add_capture_row: {} (API de compatibilité)", path)
        return self.single_panel.add_row(path, default_label)

    # ================= PAGE 2 : TRAVAIL / JOURNAL =================

    def _build_work_page(self):
        logger.debug("_build_work_page: construction de la page Travail")
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        page.set_margin_top(16)
        page.set_margin_bottom(16)
        page.set_margin_start(16)
        page.set_margin_end(16)

        page.append(Gtk.Label(label="Avancement", halign=Gtk.Align.START, css_classes=["heading"]))

        progress_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.spinner = Gtk.Spinner()
        progress_row.append(self.spinner)
        self.work_status_label = Gtk.Label(
            label="En attente du lancement de l'analyse...",
            halign=Gtk.Align.START,
            hexpand=True,
        )
        progress_row.append(self.work_status_label)
        self.work_stop_btn = Gtk.Button(label="Arreter et analyser")
        self.work_stop_btn.add_css_class("suggested-action")
        self.work_stop_btn.set_tooltip_text(
            "Termine la capture en direct sur tous les points et lance l'analyse sur les paquets accumules jusqu'ici."
        )
        self.work_stop_btn.set_visible(False)
        self.work_stop_btn.connect("clicked", lambda _b: self._end_live_capture())
        progress_row.append(self.work_stop_btn)
        page.append(progress_row)

        log_frame = Gtk.Frame()
        log_scroller = _visible_scroller()
        self.log_view = Gtk.TextView()
        self.log_view.set_editable(False)
        self.log_view.set_monospace(True)
        self.log_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.log_view.set_top_margin(8)
        self.log_view.set_left_margin(8)
        self.log_view.set_right_margin(8)
        log_scroller.set_child(self.log_view)
        log_frame.set_child(log_scroller)
        log_frame.set_vexpand(True)
        page.append(log_frame)

        self.stack.add_titled(page, "log", "Travail")
        logger.debug("MainWindow._build_work_page: fin")

    def _log(self, message):
        logger.debug("journal: {}", message)
        buf = self.log_view.get_buffer()
        end = buf.get_end_iter()
        buf.insert(end, message + "\n")
        mark = buf.create_mark(None, buf.get_end_iter(), False)
        self.log_view.scroll_to_mark(mark, 0.0, False, 0.0, 1.0)
        logger.debug("MainWindow._log: retour False")
        return False

    # ================= PAGE 3 : RESULTATS =================

    def _build_results_page(self):
        logger.debug("_build_results_page: construction de la page Résultats")
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        page.set_margin_top(16)
        page.set_margin_bottom(16)
        page.set_margin_start(16)
        page.set_margin_end(16)

        page.append(Gtk.Label(label="Resultats", halign=Gtk.Align.START, css_classes=["heading"]))

        result_frame = Gtk.Frame()
        result_scroller = _visible_scroller()
        self.duplicate_indicator = Gtk.Label(
            label="Doublons inter-captures : non analysés.",
            halign=Gtk.Align.START,
            wrap=True,
        )
        self.duplicate_indicator.set_selectable(True)
        self.duplicate_indicator.set_margin_bottom(4)
        page.append(self.duplicate_indicator)

        self.result_view = Gtk.TextView()
        self.result_view.set_editable(False)
        self.result_view.set_monospace(True)
        self.result_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.result_view.set_top_margin(8)
        self.result_view.set_left_margin(8)
        self.result_view.set_right_margin(8)
        result_scroller.set_child(self.result_view)
        result_frame.set_child(result_scroller)
        result_frame.set_vexpand(True)
        page.append(result_frame)

        # -- cartographie des communications (issue #15) : vue exploratoire
        # repliee par defaut. Repliee et non absente : elle ne sert qu'a
        # certaines questions ("qui parle a qui ?"), mais elle doit rester
        # decouvrable sans lire la documentation.
        self.comm_map_expander = Gtk.Expander(label="Cartographie des communications")
        self.comm_map_expander.set_sensitive(False)
        map_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        map_box.set_margin_top(8)

        filters = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        filters.append(Gtk.Label(label="Protocole"))
        self.comm_proto_drop = Gtk.DropDown.new_from_strings(["Tous"])
        self.comm_proto_drop.connect("notify::selected", lambda *_a: self._refresh_comm_map())
        filters.append(self.comm_proto_drop)
        filters.append(Gtk.Label(label="Top-N aretes"))
        self.comm_topn_spin = Gtk.SpinButton.new_with_range(1, 200, 1)
        self.comm_topn_spin.set_value(COMM_MAP_DEFAULT_TOP_N)
        self.comm_topn_spin.connect("value-changed", lambda *_a: self._refresh_comm_map())
        filters.append(self.comm_topn_spin)
        self.comm_anomalies_check = Gtk.CheckButton(label="Anomalies seulement")
        self.comm_anomalies_check.connect("toggled", lambda *_a: self._refresh_comm_map())
        filters.append(self.comm_anomalies_check)
        map_box.append(filters)

        self.comm_map_picture = Gtk.Picture()
        self.comm_map_picture.set_can_shrink(True)
        self.comm_map_picture.set_size_request(-1, 320)
        map_box.append(self.comm_map_picture)

        self.comm_map_label = Gtk.Label(label="", halign=Gtk.Align.START, wrap=True)
        self.comm_map_label.set_selectable(True)
        map_box.append(self.comm_map_label)

        self.comm_map_expander.set_child(map_box)
        page.append(self.comm_map_expander)

        # Issue #363 : annotations (#160) -- sidecar JSON par capture,
        # menu contextuel et filtre par etiquette (voir annotations_panel)
        self.annotations_expander = Gtk.Expander(label="Annotations / signets")
        self.annotations_panel = AnnotationsPanel()
        self.annotations_expander.set_child(self.annotations_panel)
        page.append(self.annotations_expander)

        # -- dashboard analytique interactif (issue #18, §6.17) --
        # Six vues (timeline, segments, flows, endpoints, protocoles,
        # evenements) alimentees par les memes objets que le rapport, avec
        # selections lieees via un contexte partage (dashboard_context).
        # Replie par defaut, comme la cartographie : decouvrable sans
        # alourdir la lecture du rapport texte.
        self.dashboard_expander = Gtk.Expander(label="Dashboard analytique")
        self.dashboard_expander.set_sensitive(False)
        dash_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        dash_box.set_margin_top(8)
        self.dashboard_context_label = Gtk.Label(
            label="Contexte selectionne : aucun", halign=Gtk.Align.START, wrap=True
        )
        self.dashboard_context_label.set_selectable(True)
        dash_box.append(self.dashboard_context_label)
        clear_btn = Gtk.Button(label="Reinitialiser la selection")
        clear_btn.connect("clicked", lambda _b: self._dashboard_clear())
        dash_box.append(clear_btn)
        self.dashboard_sections_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        dash_box.append(self.dashboard_sections_box)
        self.dashboard_expander.set_child(dash_box)
        page.append(self.dashboard_expander)

        # -- exploration statistique interactive (issue #22, section 6.8) --
        # Vue parametrable : Top-N, tri multi-criteres, regroupement par
        # endpoint/protocole/segment/flux, drill-down vers les flows.
        # Replie par defaut, comme le dashboard et la cartographie.
        self.stats_expander = Gtk.Expander(label="Exploration statistique")
        self.stats_expander.set_sensitive(False)
        stats_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        stats_box.set_margin_top(8)

        # -- ligne de filtres --
        stats_filters = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        stats_filters.append(Gtk.Label(label="Grouper par"))
        self.stats_group_drop = Gtk.DropDown.new_from_strings([label for _val, label in group_options()])
        self.stats_group_drop.connect("notify::selected", lambda *_a: self._refresh_stats())
        stats_filters.append(self.stats_group_drop)

        stats_filters.append(Gtk.Label(label="Trier par"))
        self.stats_sort_drop = Gtk.DropDown.new_from_strings([label for _val, label in sort_options()])
        self.stats_sort_drop.connect("notify::selected", lambda *_a: self._refresh_stats())
        stats_filters.append(self.stats_sort_drop)

        stats_filters.append(Gtk.Label(label="Top-N"))
        self.stats_topn_spin = Gtk.SpinButton.new_with_range(0, 500, 1)
        self.stats_topn_spin.set_value(10)
        self.stats_topn_spin.connect("value-changed", lambda *_a: self._refresh_stats())
        stats_filters.append(self.stats_topn_spin)
        stats_box.append(stats_filters)

        # -- liste des resultats --
        self.stats_list_box = Gtk.ListBox()
        self.stats_list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.stats_list_box.append(
            Gtk.Label(label="(lancer une analyse pour voir les statistiques)", halign=Gtk.Align.START)
        )
        stats_frame = Gtk.Frame()
        stats_frame.set_child(self.stats_list_box)
        stats_box.append(stats_frame)

        # -- boutons d'export --
        stats_export_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.stats_csv_btn = Gtk.Button(label="Exporter CSV")
        self.stats_csv_btn.set_sensitive(False)
        self.stats_csv_btn.connect("clicked", self._on_stats_export_csv)
        stats_export_row.append(self.stats_csv_btn)
        self.stats_json_btn = Gtk.Button(label="Exporter JSON")
        self.stats_json_btn.set_sensitive(False)
        self.stats_json_btn.connect("clicked", self._on_stats_export_json)
        stats_export_row.append(self.stats_json_btn)
        stats_box.append(stats_export_row)

        self.stats_expander.set_child(stats_box)
        page.append(self.stats_expander)

        # Issue #357 : section securite dans la page resultats
        # Issue #675 : recherche forensic (--forensic-search, --search-*)
        self.forensic_expander = Gtk.Expander(label="Recherche forensic")
        self.forensic_panel = ForensicSearchPanel(on_annotate=self._annotate_from_search)
        self.forensic_expander.set_child(self.forensic_panel)
        page.append(self.forensic_expander)

        # Issue #675 : extraction des contenus (--extract-contents, --extract-kinds)
        self.extraction_expander = Gtk.Expander(label="Contenus (extraction)")
        self.extraction_panel = ExtractionPanel()
        self.extraction_expander.set_child(self.extraction_panel)
        page.append(self.extraction_expander)

        # Issue #675 : comparaison de postes (--client-group, --client-diff-csv)
        self.client_compare_expander = Gtk.Expander(label="Comparaison de postes")
        self.client_compare_panel = ClientComparisonPanel()
        self.client_compare_expander.set_child(self.client_compare_panel)
        page.append(self.client_compare_expander)

        # Issue #673 : chronologie des flux et statistiques tshark (JSON)
        self.expertise_expander = Gtk.Expander(label="Expertise (exports JSON)")
        self.expertise_panel = ExpertisePanel()
        self.expertise_expander.set_child(self.expertise_panel)
        page.append(self.expertise_expander)

        # Issue #674 : export SIEM, ticket de support, historique SQLite
        self.report_exports_expander = Gtk.Expander(label="SIEM, ticket de support, historique")
        self.report_exports_panel = ReportExportsPanel()
        self.report_exports_expander.set_child(self.report_exports_panel)
        page.append(self.report_exports_expander)

        # Issue #675 : resume NetFlow v5 (--netflow, --netflow-top), autonome
        self.netflow_expander = Gtk.Expander(label="NetFlow v5 (resume d'exports)")
        self.netflow_panel = NetflowPanel()
        self.netflow_expander.set_child(self.netflow_panel)
        page.append(self.netflow_expander)

        self.security_expander = Gtk.Expander(label="Securite")
        self.security_expander.set_sensitive(False)
        sec_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        sec_box.set_margin_top(6)
        sec_box.set_margin_bottom(6)
        sec_box.set_margin_start(6)
        sec_box.set_margin_end(6)
        self.security_view = Gtk.TextView()
        self.security_view.set_editable(False)
        self.security_view.set_monospace(True)
        self.security_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.security_view.set_top_margin(8)
        self.security_view.set_left_margin(8)
        self.security_view.set_right_margin(8)
        self.security_view.set_bottom_margin(8)
        sec_scroller = _visible_scroller()
        sec_scroller.set_child(self.security_view)
        sec_scroller.set_vexpand(False)
        sec_scroller.set_max_content_height(300)
        sec_box.append(sec_scroller)
        # export du rapport de securite (HTML = --security-html, JSON = cle
        # security_report de --json-report) ; le JSON et le PDF generaux
        # de la GUI portent aussi ce rapport
        sec_export_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.security_html_btn = Gtk.Button(label="Exporter le rapport de securite (HTML)")
        self.security_html_btn.connect("clicked", lambda _b: self.on_export_security(".html"))
        sec_export_row.append(self.security_html_btn)
        self.security_json_btn = Gtk.Button(label="Exporter le rapport de securite (JSON)")
        self.security_json_btn.connect("clicked", lambda _b: self.on_export_security(".json"))
        sec_export_row.append(self.security_json_btn)
        sec_box.append(sec_export_row)
        self.security_expander.set_child(sec_box)
        page.append(self.security_expander)

        bottom = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.status_label = Gtk.Label(label="", halign=Gtk.Align.START, hexpand=True)
        bottom.append(self.status_label)

        new_btn = Gtk.Button(label="Nouvelle analyse")
        new_btn.connect("clicked", lambda _b: self.stack.set_visible_child_name("config"))
        bottom.append(new_btn)

        self.csv_btn = Gtk.Button(label="Exporter en CSV")
        self.csv_btn.set_sensitive(False)
        self.csv_btn.connect("clicked", self.on_export_csv)
        bottom.append(self.csv_btn)

        self.pdf_btn = Gtk.Button(label="Exporter en PDF")
        self.pdf_btn.add_css_class("suggested-action")
        self.pdf_btn.set_sensitive(False)
        self.pdf_btn.connect("clicked", self.on_export_pdf)
        bottom.append(self.pdf_btn)

        self.json_btn = Gtk.Button(label="Exporter en JSON")
        self.json_btn.set_sensitive(False)
        self.json_btn.connect("clicked", self.on_export_json)
        bottom.append(self.json_btn)

        # Issue #864 : --md-report (analyse simple, comme la CLI)
        self.md_btn = Gtk.Button(label="Exporter en Markdown")
        self.md_btn.set_sensitive(False)
        self.md_btn.connect("clicked", self.on_export_markdown)
        bottom.append(self.md_btn)
        page.append(bottom)

        self.stack.add_titled(page, "results", "Resultats")
        logger.debug("MainWindow._build_results_page: fin")

    # ================= lancement de l'analyse =================

    def on_run_analysis(self, _btn):
        self._annotation_captures = None
        if self.live_check.get_active():
            if self._live_capturing:
                logger.debug("on_run_analysis: arrêt de la capture en direct")
                self._end_live_capture()
            else:
                logger.debug("on_run_analysis: démarrage de la capture en direct")
                self._begin_live_capture()
            logger.debug("MainWindow.on_run_analysis: si self.live_check.get_active() -> retour")
            return

        diff_mode = self.diff_check.get_active()
        bucket_ms = self.bucket_spin.get_value()
        rtp_rate = int(self.rtp_spin.get_value())
        nat_tolerant = self.nat_check.get_active()
        parallel = self.parallel_check.get_active()
        auto_topology = self.auto_topology_check.get_active()
        redact = self.redact_check.get_active()
        nat_window_ms, idle_timeout_seconds = self._fine_settings()

        if redact and (
            self.tls_check.get_active()
            or self.quic_check.get_active()
            or self.diff_tls_check.get_active()
            or self.diff_quic_check.get_active()
        ):
            # Filet de securite (voir _on_redact_toggled pour le cas normal,
            # deja empeche via la sensibilite des cases) -- ne devrait pas
            # arriver en pratique, mais mieux vaut refuser explicitement
            # qu'anonymiser partiellement le rapport sans le signaler.
            self.stack.set_visible_child_name("log")
            self._log("--redact n'est pas disponible avec Diagnostic TLS/QUIC (voir netcross_core.redact).")
            logger.debug(
                "MainWindow.on_run_analysis: si redact and (self.tls_check.get_active() or self.quic_check.… -> retour"
            )
            return

        notify = None
        client_groups: dict = {}
        client_reference = None
        advanced = None
        if not diff_mode:
            notify = self._notify_settings()
            notify_errors = validate_settings(notify, self.security_check.get_active())
            if notify_errors:
                # Echec immediat plutot qu'apres l'analyse, comme la CLI.
                self.stack.set_visible_child_name("log")
                self._log(f"Notifications : {'; '.join(notify_errors)} -- analyse non lancee.")
                logger.debug("MainWindow.on_run_analysis: si notify_errors -> retour")
                return
            try:
                client_groups = parse_client_groups(self.client_groups_entry.get_text())
                client_reference = self.client_reference_entry.get_text().strip() or None
                client_errors = validate_client_settings(client_groups, client_reference, redact)
            except ClientGroupError as exc:
                logger.debug("MainWindow.on_run_analysis: groupes de postes invalides ({})", exc)
                client_errors = [str(exc)]
            if client_errors:
                self.stack.set_visible_child_name("log")
                self._log(f"Comparaison de postes : {'; '.join(client_errors)} -- analyse non lancee.")
                logger.debug("MainWindow.on_run_analysis: si client_errors -> retour")
                return
            advanced = self.advanced_settings()  # issue #672
            advanced_errors = validate_advanced(advanced, security=self.security_check.get_active())
            if advanced_errors:
                self.stack.set_visible_child_name("log")
                self._log(f"Options avancees : {'; '.join(advanced_errors)} -- analyse non lancee.")
                logger.debug("MainWindow.on_run_analysis: si advanced_errors -> retour")
                return

        self.run_btn.set_sensitive(False)
        self.pdf_btn.set_sensitive(False)
        self.csv_btn.set_sensitive(False)
        self.json_btn.set_sensitive(False)
        self.md_btn.set_sensitive(False)
        self.log_view.get_buffer().set_text("")
        self.work_status_label.set_text("Analyse en cours...")
        self.spinner.start()
        self.stack.set_visible_child_name("log")

        if diff_mode:
            baseline_captures = self.baseline_panel.captures()
            current_captures = self.current_panel.captures()
            loss_min_pp = self.loss_threshold_spin.get_value()
            latency_min_ms = self.latency_threshold_spin.get_value()
            diff_tls = self.diff_tls_check.get_active()
            diff_quic = self.diff_quic_check.get_active()
            logger.debug(
                "on_run_analysis: mode diff, {} capture(s) baseline, {} capture(s) courant",
                len(baseline_captures),
                len(current_captures),
            )
            threading.Thread(
                target=self._run_diff_thread,
                args=(
                    baseline_captures,
                    current_captures,
                    bucket_ms,
                    rtp_rate,
                    nat_tolerant,
                    parallel,
                    auto_topology,
                    loss_min_pp,
                    latency_min_ms,
                    redact,
                    diff_tls,
                    diff_quic,
                ),
                kwargs={
                    "nat_window_ms": nat_window_ms,
                    "idle_timeout_seconds": idle_timeout_seconds,
                    "triage": self.diff_triage_check.get_active(),
                    "history": self.history_settings(),
                    "triage_topn": int(self.diff_triage_topn_spin.get_value()),
                },
                daemon=True,
            ).start()
        else:
            captures = self.single_panel.captures()
            self._annotation_captures = list(captures)
            self._extraction_redacted = redact  # issue #675 : extraction refusee si anonymise
            triage = self.triage_check.get_active()
            triage_topn = int(self.triage_topn_spin.get_value())
            tls = self.tls_check.get_active()
            quic = self.quic_check.get_active()
            security = self.security_check.get_active()
            topn = int(self.topn_spin.get_value())
            detect_duplicates = self.detect_duplicates_check.get_active()
            exclude_duplicates = self.exclude_duplicates_check.get_active()
            duplicate_threshold_ms = self.duplicate_threshold_spin.get_value()
            logger.debug("on_run_analysis: mode simple, {} capture(s)", len(captures))
            threading.Thread(
                target=self._run_analysis_thread,
                args=(
                    captures,
                    bucket_ms,
                    rtp_rate,
                    nat_tolerant,
                    parallel,
                    auto_topology,
                    triage,
                    triage_topn,
                    tls,
                    quic,
                    security,
                    redact,
                    topn,
                    detect_duplicates,
                    exclude_duplicates,
                    duplicate_threshold_ms,
                ),
                kwargs={
                    "nat_window_ms": nat_window_ms,
                    "idle_timeout_seconds": idle_timeout_seconds,
                    "split_interfaces": self.split_interfaces_check.get_active(),
                    "forensic_index": self.forensic_index_check.get_active(),
                    "client_groups": client_groups or None,
                    "client_reference": client_reference,
                    "notify": notify,
                    "expertise": self.expertise_settings(),
                    "advanced": advanced,
                    "history": self.history_settings(),
                },
                daemon=True,
            ).start()
        logger.debug("MainWindow.on_run_analysis: fin")

    # ================= capture en direct =================
    # Mode a part : pas de fichiers a lire, un thread par point tourne
    # jusqu'a l'arret (manuel ou duree max), puis les paquets accumules
    # rejoignent exactement le meme pipeline correlate/analyse/rapport
    # que le mode fichier (voir _join_live_and_analyze) -- CSV/PDF/triage
    # marchent donc sans rien y changer.

    def _begin_live_capture(self):
        # une ligne a plusieurs interfaces ("eth0, eth1") est eclatee en un
        # point par interface -- la suite (un thread par point, points_order,
        # compteurs du journal) n'a ainsi rien a savoir du multi-interfaces.
        rows_data = expand_live_points(self.live_panel.captures())  # [(label, interface, bpf_filter), ...]
        logger.debug("_begin_live_capture: {} point(s) de capture", len(rows_data))
        missing = [label for label, iface, _ in rows_data if not iface]
        if missing:
            self.stack.set_visible_child_name("log")
            self._log(
                f"Interface manquante pour : {', '.join(missing)} -- "
                f"capture annulee (renseignez une interface par point)."
            )
            logger.debug("MainWindow._begin_live_capture: si missing -> retour")
            return
        source_errors = invalid_sources(rows_data)
        if source_errors:
            self.stack.set_visible_child_name("log")
            self._log(f"Source de capture invalide -- capture annulee : {'; '.join(source_errors)}")
            logger.debug("MainWindow._begin_live_capture: si source_errors -> retour")
            return
        duplicates = duplicate_labels(rows_data)
        if duplicates:
            self.stack.set_visible_child_name("log")
            self._log(
                f"Nom de point en double : {', '.join(duplicates)} -- "
                f"capture annulee (un nom distinct par point de capture)."
            )
            logger.debug("MainWindow._begin_live_capture: si duplicates -> retour")
            return

        # snapshot des reglages sur le thread principal (widgets GTK non
        # thread-safe) -- reutilise tel quel par _join_live_and_analyze,
        # qui tourne dans un thread d'arriere-plan et ne doit plus y toucher
        auto_topology = self.auto_topology_check.get_active()
        self._live_bucket_ms = self.bucket_spin.get_value()
        self._live_rtp_rate = int(self.rtp_spin.get_value())
        self._live_nat_tolerant = self.nat_check.get_active()
        self._live_triage = self.triage_check.get_active()
        self._live_triage_topn = int(self.triage_topn_spin.get_value())
        self._live_points_order = None if auto_topology else [label for label, _, _ in rows_data]
        self._live_detect_duplicates = (
            self.detect_duplicates_check.get_active() or self.exclude_duplicates_check.get_active()
        )
        self._live_exclude_duplicates = self.exclude_duplicates_check.get_active()
        self._live_nat_window_ms, self._live_idle_timeout_seconds = self._fine_settings()
        self._live_duplicate_threshold_ms = self.duplicate_threshold_spin.get_value()
        self._live_forensic_index = self.forensic_index_check.get_active()  # issue #675
        if self.expertise_settings().active:  # issue #673 : sections relues sur les fichiers
            self._log("Sections d'expertise : analyse de fichiers uniquement, ignorees en capture en direct.")

        # Issue #676 : comparaison avec un courant capture en direct
        # (--live-current) -- baseline et reglages releves ici, thread
        # principal ; None = capture en direct simple.
        self._live_diff = None
        self._live_diff_history = self.history_settings()  # issue #874 : releve ici, thread principal
        if self.diff_check.get_active():
            baseline_captures = self.baseline_panel.captures()
            if len(baseline_captures) < 2:
                self.stack.set_visible_child_name("log")
                self._log("Comparaison : 2 captures de reference minimum -- capture annulee.")
                logger.debug("MainWindow._begin_live_capture: baseline insuffisant -> retour")
                return
            from netcross_gtk4.diff_pipeline import DiffOptions

            self._live_diff = (
                baseline_captures,
                [label for label, _, _ in rows_data],
                DiffOptions(
                    bucket_ms=self._live_bucket_ms,
                    rtp_rate=self._live_rtp_rate,
                    nat_tolerant=self._live_nat_tolerant,
                    nat_window_ms=self._live_nat_window_ms,
                    idle_timeout_seconds=self._live_idle_timeout_seconds,
                    parallel=self.parallel_check.get_active(),
                    auto_topology=auto_topology,
                    loss_min_pp=self.loss_threshold_spin.get_value(),
                    latency_min_ms=self.latency_threshold_spin.get_value(),
                    redact=self.redact_check.get_active(),
                    triage=self.diff_triage_check.get_active(),
                    triage_topn=int(self.diff_triage_topn_spin.get_value()),
                ),
            )

        # Issue #676 : rotation de capture -- un enregistreur tshark par point,
        # lance AVANT les threads d'analyse ; refus d'un point -> rien ne demarre.
        self._live_ring_recorders = {}
        ring_messages = []
        if self.ring_buffer_box.get_visible() and self.ring_buffer_check.get_active():
            try:
                self._live_ring_recorders, ring_messages = start_ring_recorders(
                    rows_data,
                    int(self.ring_max_files_spin.get_value()),
                    self.ring_max_duration_spin.get_value(),
                )
            except RingRecorderError as e:
                logger.warning("MainWindow._begin_live_capture: rotation de capture refusee ({})", e)
                self.stack.set_visible_child_name("log")
                self._log(f"Rotation de capture impossible -- capture annulee : {e}")
                return

        # Issue #676 : rapport HTML en continu, demarre avant les threads de
        # capture ; un refus (port pris, repertoire) annule toute la capture.
        self._live_report_session = None
        if self.live_report_box.get_visible() and self.live_report_check.get_active():
            try:
                self._live_report_session, report_messages = start_live_report(
                    [label for label, _iface, _bpf in rows_data],
                    self.live_report_dir_entry.get_text().strip() or None,
                    self.live_report_interval_spin.get_value(),
                    int(self.live_report_port_spin.get_value()) if self.live_report_serve_check.get_active() else None,
                )
            except LiveReportError as e:
                logger.warning("MainWindow._begin_live_capture: rapport en continu refuse ({})", e)
                if self._live_ring_recorders:
                    stop_ring_recorders(self._live_ring_recorders)
                    self._live_ring_recorders = {}
                self.stack.set_visible_child_name("log")
                self._log(f"Rapport en continu impossible -- capture annulee : {e}")
                return
            ring_messages = [*ring_messages, *report_messages]

        self._live_capturing = True
        self._live_stop_event = threading.Event()
        self._live_packets = []
        self._live_lock = threading.Lock()
        self._live_threads = []

        self.live_panel.set_sensitive(False)
        self.live_extra_box.set_sensitive(False)
        self.ring_buffer_box.set_sensitive(False)
        self.live_report_box.set_sensitive(False)
        self.run_btn.set_label("Arreter et analyser")
        self.pdf_btn.set_sensitive(False)
        self.csv_btn.set_sensitive(False)
        self.md_btn.set_sensitive(False)
        self.log_view.get_buffer().set_text("")
        # Apres la remise a zero du journal, sinon ces messages seraient effaces.
        for message in ring_messages:
            self._log(message)
        self.work_status_label.set_text(
            'Capture en direct en cours -- cliquez sur "Arreter et analyser" quand vous avez assez de trafic capture.'
        )
        self.work_stop_btn.set_visible(True)
        self.spinner.start()
        self.stack.set_visible_child_name("log")

        for label, interface, bpf_filter in rows_data:
            t = threading.Thread(
                target=self._live_capture_worker,
                args=(label, interface, bpf_filter),
                daemon=True,
            )
            self._live_threads.append(t)
            t.start()

        self._live_session_id += 1
        duration = self.live_duration_spin.get_value()
        if duration > 0:
            GLib.timeout_add_seconds(int(duration), self._on_live_duration_elapsed, self._live_session_id)
        logger.debug("MainWindow._begin_live_capture: fin")

    def _on_live_duration_elapsed(self, session_id):
        if self._live_capturing and session_id == self._live_session_id:
            logger.debug("_on_live_duration_elapsed: durée maximale atteinte, session={}", session_id)
            self._log("Duree maximale atteinte -- arret automatique de la capture.")
            self._end_live_capture()
        logger.debug("MainWindow._on_live_duration_elapsed: retour False")
        return False  # ne pas repeter le timeout (GLib.timeout_add_seconds)

    def _live_capture_worker(self, label, interface, bpf_filter):
        logger.debug("_live_capture_worker: label={} interface={}", label, interface)
        GLib.idle_add(
            self._log,
            f"[{label}] capture demarree sur {interface}"
            + (f" (filtre BPF: {bpf_filter})" if bpf_filter else "")
            + "...",
        )
        count = 0
        last_log = time.time()
        report_session = self._live_report_session
        error = None
        try:
            for pkt in parse_live(
                label,
                interface,
                bpf_filter=bpf_filter,
                stop_event=self._live_stop_event,
            ):
                with self._live_lock:
                    self._live_packets.append(pkt)
                if report_session is not None:
                    report_session.add(pkt)
                count += 1
                now = time.time()
                if now - last_log >= 1.0:
                    GLib.idle_add(self._log, f"  [{label}] {count} paquets...")
                    last_log = now
        except Exception as e:  # noqa: BLE001 -- thread de fond : toute erreur
            # (tshark, interface, permission...) doit remonter au journal GUI
            # plutot que de tuer le thread silencieusement.
            logger.exception(f"échec dans _live_capture_worker: {e}")
            GLib.idle_add(self._log, f"[{label}] ERREUR : {e}")
            error = str(e)
        if report_session is not None:
            report_session.point_stopped(label, error)
        GLib.idle_add(self._log, f"[{label}] capture arretee -- {count} paquet(s) au total.")
        logger.debug("MainWindow._live_capture_worker: fin")

    def _end_live_capture(self):
        if not self._live_capturing or self._live_stop_event.is_set():
            logger.debug(
                "MainWindow._end_live_capture: si not self._live_capturing or self._live_stop_event.is_set() -> retour"
            )
            return  # deja arrete/en cours d'arret -- evite un double-clic
            # (bouton config + bouton page Travail) qui lancerait
            # deux threads d'analyse en parallele sur les memes paquets
        logger.debug("_end_live_capture: arrêt de {} thread(s) de capture", len(self._live_threads))
        self.run_btn.set_sensitive(False)
        self.work_stop_btn.set_sensitive(False)
        self.run_btn.set_label("Arret de la capture...")
        self.work_status_label.set_text("Arret de la capture en cours (peut prendre quelques secondes)...")
        self._live_stop_event.set()
        threading.Thread(target=self._join_live_and_analyze, daemon=True).start()
        logger.debug("MainWindow._end_live_capture: fin")

    def _join_live_and_analyze(self):
        for t in self._live_threads:
            t.join()
        # Issue #676 : arret des enregistreurs en ring buffer (fichiers conserves).
        recorders = getattr(self, "_live_ring_recorders", None)
        if recorders:
            for message in stop_ring_recorders(recorders):
                GLib.idle_add(self._log, message)
            self._live_ring_recorders = {}
        # Issue #676 : derniere publication du rapport en continu.
        report_session = getattr(self, "_live_report_session", None)
        if report_session is not None:
            for message in report_session.stop():
                GLib.idle_add(self._log, message)
            self._live_report_session = None
        with self._live_lock:
            all_packets = list(self._live_packets)
        logger.debug("_join_live_and_analyze: {} paquet(s) capturé(s)", len(all_packets))
        if getattr(self, "_live_diff", None) is not None:
            GLib.idle_add(self._log, f"Capture terminee -- {len(all_packets)} paquet(s). Comparaison...")
            self._analyze_live_diff(all_packets)
            logger.debug("MainWindow._join_live_and_analyze: comparaison avec le courant en direct -> retour")
            return
        GLib.idle_add(
            self._log,
            f"Capture terminee -- {len(all_packets)} paquet(s) au total. Analyse...",
        )
        try:
            duplicate_counts = None
            if self._live_detect_duplicates:
                GLib.idle_add(
                    self._log,
                    f"Détection des doublons inter-captures (seuil {self._live_duplicate_threshold_ms:.1f} ms)...",
                )
                duplicate_counts = detect_cross_capture_duplicates(all_packets, self._live_duplicate_threshold_ms)
                GLib.idle_add(self._log, f"  -> {sum(duplicate_counts.values())} paquet(s) dupliqué(s) détecté(s)")

            GLib.idle_add(self._log, "Correlation des flux entre points de capture...")
            flows = correlate(
                all_packets,
                self._live_nat_tolerant,
                getattr(self, "_live_nat_window_ms", 200.0),
                self._live_exclude_duplicates,
            )
            GLib.idle_add(self._log, f"  -> {len(flows)} flux identifies")

            GLib.idle_add(
                self._log,
                "Analyse (pertes, latence, TTL, QoS, fragmentation, debit, TCP, VLAN, RTP, DHCP, SIP...)...",
            )
            report = analyse(
                flows,
                self._live_points_order,
                all_packets,
                self._live_bucket_ms / 1000.0,
                self._live_nat_tolerant,
                self._live_rtp_rate,
                idle_timeout_seconds=getattr(self, "_live_idle_timeout_seconds", None),
                exclude_duplicates=self._live_exclude_duplicates,
                duplicate_counts=duplicate_counts,
            )

            GLib.idle_add(self._log, "Mise en forme du rapport...")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                print_report(report)

            findings = None
            if self._live_triage:
                GLib.idle_add(self._log, "Triage des segments...")
                from netcross_report import (
                    build_findings,
                    format_health_line,
                    health_score,
                    print_triage,
                    rank_segments,
                )

                findings = build_findings(report)
                ranked = rank_segments(findings)
                with contextlib.redirect_stdout(buf):
                    print("\n" + "=" * 70)
                    print("TRIAGE -- PAR OU COMMENCER")
                    print("=" * 70)
                    print_triage(ranked, self._live_triage_topn)
                    print(format_health_line(health_score(ranked)))

            text = buf.getvalue()

            search_index = None
            if getattr(self, "_live_forensic_index", False):
                # Issue #675 : meme index que l'analyse de fichiers
                from netcross_core.forensic_search import ForensicSearchIndex

                GLib.idle_add(self._log, "Index de recherche forensic...")
                search_index = ForensicSearchIndex(all_packets, flows=flows)
                GLib.idle_add(self._log, f"  -> {len(search_index)} element(s) indexe(s)")
        except Exception as e:  # noqa: BLE001 -- thread de fond (analyse live) : toute erreur doit remonter au journal GUI.
            logger.exception(f"échec dans _join_live_and_analyze: {e}")
            GLib.idle_add(self._log, f"ERREUR : {e}")
            GLib.idle_add(self._on_analysis_error, str(e))
            GLib.idle_add(self._reset_live_ui)
            logger.debug("MainWindow._join_live_and_analyze: except Exception -> retour")
            return
        GLib.idle_add(self._log, "Analyse terminee.")
        GLib.idle_add(
            self._on_analysis_done,
            "single",
            report,
            flows,
            findings,
            text,
            None,
            None,
            build_wireshark_expert_events(all_packets),
            None,  # pas de rapport de securite en capture en direct
            search_index,  # positionnel : GLib.idle_add ne transmet pas d'argument nomme
        )
        GLib.idle_add(self._reset_live_ui)
        logger.debug("MainWindow._join_live_and_analyze: fin")

    def _analyze_live_diff(self, current_packets):
        """Issue #676 : comparaison du baseline enregistre avec le courant
        capture en direct (thread d'arriere-plan), meme fin que
        `_run_diff_thread`."""
        from netcross_gtk4.diff_pipeline import run_diff_pipeline

        baseline_captures, current_points, options = self._live_diff
        logger.debug(
            "_analyze_live_diff: {} capture(s) de reference, {} paquet(s) courant",
            len(baseline_captures),
            len(current_packets),
        )
        try:
            result = run_diff_pipeline(
                baseline_captures,
                [],
                options,
                on_progress=lambda msg: GLib.idle_add(self._log, msg),
                current_packets=current_packets,
                current_points=current_points,
            )
        except Exception as e:  # noqa: BLE001 -- thread de fond : toute erreur remonte au journal GUI
            logger.exception(f"échec dans _analyze_live_diff: {e}")
            GLib.idle_add(self._log, f"ERREUR : {e}")
            GLib.idle_add(self._on_analysis_error, str(e))
            GLib.idle_add(self._reset_live_ui)
            logger.debug("MainWindow._analyze_live_diff: except Exception -> retour")
            return
        history = getattr(self, "_live_diff_history", None)
        if history is not None and history.db_path:
            self._record_diff_history(result, history, options.redact)
        GLib.idle_add(
            self._on_diff_done,
            result.findings,
            result.baseline_report,
            result.current_report,
            result.text,
            None,
            None,
            None,
            None,
            result.redaction_map,
        )
        GLib.idle_add(self._reset_live_ui)
        logger.debug("MainWindow._analyze_live_diff: fin")

    def _reset_live_ui(self):
        logger.debug("_reset_live_ui: réinitialisation de l'interface de capture en direct")
        self._live_capturing = False
        self.live_panel.set_sensitive(True)
        self.live_extra_box.set_sensitive(True)
        self.ring_buffer_box.set_sensitive(True)
        self.live_report_box.set_sensitive(True)
        self.work_stop_btn.set_visible(False)
        self.work_stop_btn.set_sensitive(True)
        self._update_run_button_label()
        self._update_run_sensitivity()
        logger.debug("MainWindow._reset_live_ui: retour False")
        return False

    def _load_packets(self, captures, parallel):
        """Commun aux deux modes : lecture sequentielle ou parallele, avec
        journalisation -- equivalent de _load_packets() des deux CLIs."""
        logger.debug("_load_packets: {} capture(s), parallel={}", len(captures), parallel)
        all_packets = []
        if parallel:
            all_packets, per_file_stats = parse_captures_parallel(captures)
            for s in per_file_stats:
                if s["error"]:
                    GLib.idle_add(
                        self._log,
                        f"  [{s['label']}] ECHEC sur {s['path']} : {s['error']}",
                    )
                else:
                    GLib.idle_add(
                        self._log,
                        f"  [{s['label']}] {s['count']} paquets charges depuis {s['path']} ({s['seconds']:.2f}s)",
                    )
        else:
            for label, path in captures:
                GLib.idle_add(self._log, f"Lecture de {os.path.basename(path)} ({label})...")
                pkts = parse_capture(label, path)
                all_packets.extend(pkts)
                GLib.idle_add(self._log, f"  -> {len(pkts)} paquets charges")
        logger.debug("MainWindow._load_packets: retour all_packets={}", summarize(all_packets, "all_packets"))
        return all_packets

    def _run_analysis_thread(
        self,
        captures,
        bucket_ms,
        rtp_rate,
        nat_tolerant,
        parallel,
        auto_topology,
        triage,
        triage_topn,
        tls,
        quic,
        security,
        redact,
        topn,
        detect_duplicates,
        exclude_duplicates,
        duplicate_threshold_ms,
        nat_window_ms=200.0,
        idle_timeout_seconds=None,
        split_interfaces=False,
        forensic_index=False,
        client_groups=None,
        client_reference=None,
        notify=None,
        expertise=None,
        advanced=None,
        history=None,
    ):
        logger.debug(
            "_run_analysis_thread: {} capture(s), triage={} tls={} quic={} security={}",
            len(captures),
            triage,
            tls,
            quic,
            security,
        )
        from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline

        options = AnalysisOptions(
            bucket_ms=bucket_ms,
            rtp_rate=rtp_rate,
            nat_tolerant=nat_tolerant,
            parallel=parallel,
            auto_topology=auto_topology,
            triage=triage,
            triage_topn=triage_topn,
            tls=tls,
            quic=quic,
            security=security,
            redact=redact,
            topn=topn,
            detect_duplicates=detect_duplicates,
            exclude_duplicates=exclude_duplicates,
            duplicate_threshold_ms=duplicate_threshold_ms,
            nat_window_ms=nat_window_ms,
            idle_timeout_seconds=idle_timeout_seconds,
            split_interfaces=split_interfaces,
            forensic_index=forensic_index,
            client_groups=client_groups,
            client_reference=client_reference,
            notify=notify,
            expertise=expertise,
            advanced=advanced,
            history=history,
        )

        def _on_progress(msg):
            GLib.idle_add(self._log, msg)
            logger.debug("MainWindow._run_analysis_thread._on_progress: fin")

        try:
            result = run_analysis_pipeline(captures, options, on_progress=_on_progress)
        except Exception as e:  # noqa: BLE001 -- thread de fond
            logger.exception(f"échec du pipeline d'analyse dans _run_analysis_thread: {e}")
            GLib.idle_add(self._log, f"ERREUR : {e}")
            GLib.idle_add(self._on_analysis_error, str(e))
            logger.debug("MainWindow._run_analysis_thread: except Exception -> retour")
            return

        GLib.idle_add(
            self._on_analysis_done,
            result.mode,
            result.report,
            result.flows,
            result.findings,
            result.text,
            result.tls_findings,
            result.quic_findings,
            result.wireshark_expert_events,
            result.security_report,
            # positionnel : GLib.idle_add ne transmet pas d'argument nomme
            result.search_index,
            result.client_comparison,
            result.expertise,
            result.report_context,
        )
        logger.debug("MainWindow._run_analysis_thread: fin")

    def _run_diff_thread(
        self,
        baseline_captures,
        current_captures,
        bucket_ms,
        rtp_rate,
        nat_tolerant,
        parallel,
        auto_topology,
        loss_min_pp,
        latency_min_ms,
        redact,
        tls,
        quic,
        nat_window_ms=200.0,
        idle_timeout_seconds=None,
        triage=False,
        triage_topn=5,
        history=None,
    ):
        logger.debug(
            "_run_diff_thread: {} capture(s) baseline, {} capture(s) courant",
            len(baseline_captures),
            len(current_captures),
        )
        from netcross_gtk4.diff_pipeline import DiffOptions, run_diff_pipeline

        options = DiffOptions(
            bucket_ms=bucket_ms,
            rtp_rate=rtp_rate,
            nat_tolerant=nat_tolerant,
            parallel=parallel,
            auto_topology=auto_topology,
            loss_min_pp=loss_min_pp,
            latency_min_ms=latency_min_ms,
            redact=redact,
            tls=tls,
            quic=quic,
            nat_window_ms=nat_window_ms,
            idle_timeout_seconds=idle_timeout_seconds,
            triage=triage,
            triage_topn=triage_topn,
        )

        def _on_progress(msg):
            GLib.idle_add(self._log, msg)
            logger.debug("MainWindow._run_diff_thread._on_progress: fin")

        try:
            result = run_diff_pipeline(baseline_captures, current_captures, options, on_progress=_on_progress)
        except Exception as e:  # noqa: BLE001 -- thread de fond
            logger.exception(f"échec du pipeline de comparaison dans _run_diff_thread: {e}")
            GLib.idle_add(self._log, f"ERREUR : {e}")
            GLib.idle_add(self._on_analysis_error, str(e))
            logger.debug("MainWindow._run_diff_thread: except Exception -> retour")
            return

        if history is not None and history.db_path:
            self._record_diff_history(result, history, redact)
        GLib.idle_add(
            self._on_diff_done,
            result.findings,
            result.baseline_report,
            result.current_report,
            result.text,
            result.tls_findings_baseline,
            result.tls_findings_current,
            result.quic_findings_baseline,
            result.quic_findings_current,
            result.redaction_map,
        )
        logger.debug("MainWindow._run_diff_thread: fin")

    def _record_diff_history(self, result, history, redact):
        """Issue #874 : ``--history-db`` de la comparaison ; une base
        illisible n'annule pas la comparaison (message dans le journal)."""
        from netcross_gtk4.report_exports import record_diff_history
        from netcross_report import HistoryDatabaseError

        try:
            message = record_diff_history(
                result.findings, result.baseline_report, result.current_report, history, redact=redact
            )
        except HistoryDatabaseError as exc:
            logger.warning("_record_diff_history: {}", exc)
            message = f"Historique non enregistre : {exc}"
        GLib.idle_add(self._log, message)
        return message

    def _on_analysis_error(self, message):
        logger.debug("_on_analysis_error: {}", message)
        self.spinner.stop()
        self.work_status_label.set_text(f"Erreur : {message}")
        self.run_btn.set_sensitive(True)
        logger.debug("MainWindow._on_analysis_error: retour False")
        return False

    def _appliquer_outcome(self, outcome):
        """Recopie un RunOutcome dans la fenetre (issue #285, lot 2).

        Les quinze champs d'etat sont recopies EN BOUCLE depuis
        `outcome.etat()`, pas un par un : un champ ajoute a `RunOutcome`
        arrive ainsi automatiquement dans les deux modes. C'est le point de
        l'extraction -- avant, analyse et comparaison reecrivaient chacune
        sa liste, et un oubli d'un seul cote faisait afficher au run
        suivant des donnees restees du precedent, sans aucun message.
        """
        logger.debug("_appliquer_outcome: {}", outcome.status)
        for nom, valeur in outcome.etat().items():
            setattr(self, nom, valeur)
        self.duplicate_indicator.set_text(outcome.duplicate_indicator)
        self.spinner.stop()
        self.work_status_label.set_text(outcome.work_status)
        self.result_view.get_buffer().set_text(outcome.result_text)
        self.status_label.set_text(outcome.status)
        logger.debug("MainWindow._appliquer_outcome: fin")

    def _on_analysis_done(
        self,
        mode,
        report,
        flows,
        findings,
        text,
        tls_findings=None,
        quic_findings=None,
        wireshark_expert_events=None,
        security_report=None,
        search_index=None,
        client_comparison=None,
        expertise=None,
        report_context=None,
    ):
        self.expertise_panel.set_exports(expertise)  # issue #673
        # Issue #674 : None en capture en direct (ni fichiers ni historique)
        self.report_exports_panel.set_context(report, security_report, report_context)
        # Issue #675 : nouvel index (ou None : analyse sans index, capture en direct)
        self.forensic_panel.set_index(search_index, self._annotation_captures)
        self.client_compare_panel.set_comparison(client_comparison)
        logger.debug(
            "_on_analysis_done: mode={} flux={} findings={} tls={} quic={} tshark={} securite={}",
            mode,
            len(flows or []),
            len(findings or []),
            len(tls_findings or []),
            len(quic_findings or []),
            len(wireshark_expert_events or []),
            bool(security_report),
        )
        # Signaux tshark bruts : calcules dans le thread d'analyse, ou les
        # paquets sont encore disponibles (issue #14). On garde le RESULTAT
        # plutot que les paquets : conserver `all_packets` dans la fenetre
        # pour un export JSON eventuel immobiliserait la capture entiere en
        # memoire jusqu'a l'analyse suivante.
        self._appliquer_outcome(
            analysis_outcome(
                mode,
                report,
                flows,
                findings,
                text,
                tls_findings=tls_findings,
                quic_findings=quic_findings,
                wireshark_expert_events=wireshark_expert_events,
                security_report=security_report,
                rule_engine=getattr(expertise, "rule_engine", None),  # issue #864
            )
        )
        self.run_btn.set_sensitive(True)
        self.pdf_btn.set_sensitive(True)
        self.csv_btn.set_sensitive(True)
        self.json_btn.set_sensitive(True)
        self.md_btn.set_sensitive(mode == "single")
        self._reset_comm_map_filters()
        # dashboard analytique (issue #18) : reinitialise le contexte de
        # selection partage et peuple les six vues depuis le meme run
        # (desactive en mode diff, ou last_flows est None).
        self.dashboard_selection = DashboardSelection()
        self._refresh_dashboard()
        # exploration statistique (issue #22) : peuple la vue stats
        # depuis les memes flows/report que le dashboard.
        self._refresh_stats()
        # Issue #363 : annotations des captures analysees (sidecars JSON)
        if self._annotation_captures:
            self.annotations_panel.load(self._annotation_captures)
        else:
            self.annotations_panel.clear()
        # Issue #675 : extraction des contenus -- fichiers de l'analyse simple
        self.extraction_panel.set_source(self._annotation_captures, getattr(self, "_extraction_redacted", False))
        # Issue #357 : section Securite -- meme rendu que --security-report
        self._show_security_report()
        self.stack.set_visible_child_name("results")
        logger.debug("MainWindow._on_analysis_done: retour False")
        return False

    def history_settings(self) -> HistorySettings:
        """Historique SQLite de la configuration (issue #674)."""
        label = self.history_label_entry.get_text().strip()
        return HistorySettings(db_path=self.history_option.path, label=label or None)

    def advanced_settings(self) -> AdvancedSettings:
        """Options avancees de la configuration (issue #672)."""
        return settings_from_values(
            self.max_packets_spin.get_value(),
            self.sample_spin.get_value(),
            self.parallel_workers_spin.get_value(),
            test_net_external=self.test_net_external_check.get_active(),
            known_destinations=self.known_destinations_option.path,
            known_hosts=self.known_hosts_option.path,
            cve_db=self.cve_db_option.path,
        )

    def expertise_settings(self) -> ExpertiseSettings:
        """Cases « Expertise » de la configuration (issue #673)."""
        return ExpertiseSettings(
            rule_engine=self.rule_engine_check.get_active(),
            expert_section=self.expert_section_check.get_active(),
            media_quality=self.media_quality_check.get_active(),
            tshark_stats=self.tshark_stats_check.get_active(),
            flow_timeline=self.flow_timeline_check.get_active(),
            flow_timeline_window=self.flow_timeline_window_spin.get_value(),
        )

    def _annotate_from_search(self, point, frame_number) -> None:
        """Issue #675 : « Annoter la trame » d'un resultat de recherche --
        pre-remplit et deplie le panneau d'annotations."""
        logger.debug("MainWindow._annotate_from_search: point={} trame={}", point, frame_number)
        self.annotations_expander.set_expanded(True)
        self.annotations_panel.prefill(point, frame_number)

    def _on_diff_done(
        self,
        findings,
        baseline_report,
        current_report,
        text,
        tls_findings_baseline=None,
        tls_findings_current=None,
        quic_findings_baseline=None,
        quic_findings_current=None,
        redaction_map=(),
    ):
        logger.debug(
            "_on_diff_done: findings={} tls_base={} tls_courant={} quic_base={} quic_courant={}",
            len(findings or []),
            len(tls_findings_baseline or []),
            len(tls_findings_current or []),
            len(quic_findings_baseline or []),
            len(quic_findings_current or []),
        )
        self.forensic_panel.set_index(None)  # issue #675 : pas d'index en comparaison
        self.extraction_panel.set_source(None, False)  # ni d'extraction
        self.client_compare_panel.set_comparison(None)  # ni de comparaison de postes
        self.expertise_panel.set_exports(None)  # ni d'exports d'expertise (issue #673)
        self.report_exports_panel.set_context(None, None, None)  # ni SIEM/ticket/historique (issue #674)
        self.report_exports_panel.set_redaction_map(redaction_map)  # sauf la table d'anonymisation (#876)
        self._appliquer_outcome(
            diff_outcome(
                findings,
                baseline_report,
                current_report,
                text,
                tls_findings_baseline=tls_findings_baseline,
                tls_findings_current=tls_findings_current,
                quic_findings_baseline=quic_findings_baseline,
                quic_findings_current=quic_findings_current,
            )
        )
        self.run_btn.set_sensitive(True)
        self.pdf_btn.set_sensitive(True)
        self.csv_btn.set_sensitive(True)
        self.json_btn.set_sensitive(True)
        self.md_btn.set_sensitive(False)  # pas de Markdown en comparaison (CLI : idem)
        self._reset_comm_map_filters()
        # dashboard analytique (issue #18) : reinitialise le contexte de
        # selection partage et peuple les six vues depuis le meme run
        # (desactive en mode diff, ou last_flows est None).
        self.dashboard_selection = DashboardSelection()
        self._refresh_dashboard()
        self._refresh_stats()
        self.annotations_panel.clear()  # issue #363 : pas de sidecar en mode diff
        self._show_security_report()  # issue #357 : None apres un diff (RunOutcome)
        self.stack.set_visible_child_name("results")
        logger.debug("MainWindow._on_diff_done: retour False")
        return False

    # ================= export CSV =================

    def on_export_csv(self, _btn):
        if self.last_mode is None:
            logger.debug("MainWindow.on_export_csv: si self.last_mode is None -> retour")
            return
        logger.debug("on_export_csv: mode={}", self.last_mode)
        dialog = Gtk.FileDialog()
        dialog.set_initial_name("details_flux.csv" if self.last_mode == "single" else "ecarts.csv")
        dialog.save(self, None, self._on_csv_path_chosen)
        logger.debug("MainWindow.on_export_csv: fin")

    def _on_csv_path_chosen(self, dialog, result):
        try:
            gfile = dialog.save_finish(result)
        except GLib.Error:
            logger.exception("échec dans _on_csv_path_chosen")
            logger.debug("MainWindow._on_csv_path_chosen: except GLib.Error -> retour")
            return
        path = gfile.get_path()
        logger.debug("_on_csv_path_chosen: mode={} path={}", self.last_mode, path)
        try:
            if self.last_mode == "single":
                write_detail_csv(path, self.last_flows, self.last_report.points, names=self.names_table)
            else:
                write_diff_csv(self.last_diff_findings, path)
        except Exception as e:  # noqa: BLE001 -- callback GUI (export CSV) : erreur affichee dans la barre de statut plutot que de faire planter l'appli.
            logger.exception(f"échec dans _on_csv_path_chosen: {e}")
            self.status_label.set_text(f"Erreur CSV : {e}")
            logger.debug("MainWindow._on_csv_path_chosen: except Exception -> retour")
            return
        logger.debug("_on_csv_path_chosen: CSV écrit {}", path)
        self.status_label.set_text(f"CSV ecrit : {path}")
        logger.debug("MainWindow._on_csv_path_chosen: fin")

    # ================= export PDF =================

    def on_export_pdf(self, _btn):
        if self.last_mode is None:
            logger.debug("MainWindow.on_export_pdf: si self.last_mode is None -> retour")
            return
        logger.debug("on_export_pdf: mode={}", self.last_mode)
        dialog = Gtk.FileDialog()
        dialog.set_initial_name("rapport_analyse.pdf" if self.last_mode == "single" else "rapport_comparaison.pdf")
        dialog.save(self, None, self._on_pdf_path_chosen)
        logger.debug("MainWindow.on_export_pdf: fin")

    def _on_pdf_path_chosen(self, dialog, result):
        try:
            gfile = dialog.save_finish(result)
        except GLib.Error:
            logger.exception("échec dans _on_pdf_path_chosen")
            logger.debug("MainWindow._on_pdf_path_chosen: except GLib.Error -> retour")
            return
        path = gfile.get_path()
        logger.debug("_on_pdf_path_chosen: chemin choisi {}", path)
        self.export_pdf_to(path)
        logger.debug("MainWindow._on_pdf_path_chosen: fin")

    def export_pdf_to(self, path):
        """Separe de la callback du dialogue pour pouvoir etre pilote directement (tests)."""
        logger.debug("export_pdf_to: {}", path)
        self.status_label.set_text("Generation du PDF...")
        threading.Thread(target=self._generate_pdf_thread, args=(path,), daemon=True).start()
        logger.debug("MainWindow.export_pdf_to: fin")

    # ================= exploration statistique (issue #22, section 6.8) =================

    def _stats_group_value(self) -> str:
        """Lit la valeur de group_by selectionnee dans le DropDown."""
        opts = group_options()
        idx = self.stats_group_drop.get_selected()
        if 0 <= idx < len(opts):
            logger.debug("MainWindow._stats_group_value: si 0 <= idx < len(opts) -> retour opts[idx][0]")
            return opts[idx][0]
        logger.debug("MainWindow._stats_group_value: retour 'endpoint'")
        return "endpoint"

    def _stats_sort_value(self) -> str:
        """Lit la valeur de sort_by selectionnee dans le DropDown."""
        opts = sort_options()
        idx = self.stats_sort_drop.get_selected()
        if 0 <= idx < len(opts):
            logger.debug("MainWindow._stats_sort_value: si 0 <= idx < len(opts) -> retour opts[idx][0]")
            return opts[idx][0]
        logger.debug("MainWindow._stats_sort_value: retour 'bytes'")
        return "bytes"

    def _refresh_stats(self):
        """Reconstruit la liste des statistiques depuis les memes objets
        que le rapport. Desactive si pas de flows (mode diff ou analyse
        non lancee)."""
        # Issue #453 : les StatRow se construisent depuis des Flow
        # (.endpoints, .packet_count...), pas depuis le dict brut de
        # correlate() -- comme le dashboard ci-dessous.
        flows = self.last_flow_objects
        self.stats_expander.set_sensitive(bool(flows))
        self.stats_csv_btn.set_sensitive(False)
        self.stats_json_btn.set_sensitive(False)
        if not flows:
            logger.debug("_refresh_stats: aucun flux, vue désactivée")
            self._stats_clear_list()
            logger.debug("MainWindow._refresh_stats: si not flows -> retour")
            return
        group_by = self._stats_group_value()
        sort_by = self._stats_sort_value()
        top_n = int(self.stats_topn_spin.get_value())
        query = build_query(
            group_by=group_by,
            sort_by=sort_by,
            top_n=top_n,
        )
        events_by_seg = build_events_by_segment(self.last_findings, flows)
        rows = run_stats(flows, self.last_report, query, events_by_seg)
        logger.debug(
            "_refresh_stats: {} flux, group_by={} sort_by={} top_n={} -> {} ligne(s)",
            len(flows),
            group_by,
            sort_by,
            top_n,
            len(rows),
        )
        self.last_stats_rows = rows
        self._stats_repopulate(rows, flows)
        self.stats_csv_btn.set_sensitive(bool(rows))
        self.stats_json_btn.set_sensitive(bool(rows))
        logger.debug("MainWindow._refresh_stats: fin")

    def _stats_clear_list(self):
        """Vide la ListBox des statistiques."""
        logger.debug("_stats_clear_list: vidage de la liste des statistiques")
        box = self.stats_list_box
        child = box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            box.remove(child)
            child = nxt
        box.append(Gtk.Label(label="(vide)", halign=Gtk.Align.START))
        logger.debug("MainWindow._stats_clear_list: fin")

    def _stats_repopulate(self, rows, flows):
        """Repeuple la ListBox avec une ligne par StatRow.
        Chaque ligne est un bouton cliquable qui declenche le drill-down."""
        logger.debug("_stats_repopulate: {} ligne(s)", len(rows))
        self._stats_clear_list()
        box = self.stats_list_box
        if not rows:
            logger.debug("MainWindow._stats_repopulate: si not rows -> retour")
            return
        for row in rows:
            btn = Gtk.Button(label=format_row(row), halign=Gtk.Align.START)
            btn.connect(
                "clicked",
                lambda _b, r=row: self._stats_select(r, flows),
            )
            box.append(btn)
        logger.debug("MainWindow._stats_repopulate: fin")

    def _stats_select(self, row, flows):
        """Drill-down : affiche les flux d'une ligne statistique.
        Remplace temporairement le contenu de la ListBox par la liste
        des flux, avec un bouton de retour."""
        logger.debug("_stats_select: {} ({} flux)", row.label, len(row.flow_keys))
        self._stats_clear_list()
        box = self.stats_list_box

        back_btn = Gtk.Button(label="<-- Retour aux statistiques", halign=Gtk.Align.START)
        back_btn.connect("clicked", lambda _b: self._refresh_stats())
        box.append(back_btn)

        box.append(
            Gtk.Label(
                label=f"{row.label} ({len(row.flow_keys)} flux)",
                halign=Gtk.Align.START,
                css_classes=["heading"],
            )
        )

        detail_flows = flows_for_row(row, flows)
        if not detail_flows:
            box.append(Gtk.Label(label="(aucun flux)", halign=Gtk.Align.START))
            logger.debug("MainWindow._stats_select: si not detail_flows -> retour")
            return
        for f in detail_flows:
            label = Gtk.Label(label=format_flow_summary(f), halign=Gtk.Align.START)
            label.set_selectable(True)
            box.append(label)
        logger.debug("MainWindow._stats_select: fin")

    def _on_stats_export_csv(self, _btn):
        """Exporte les statistiques courantes en CSV."""
        rows = getattr(self, "last_stats_rows", None)
        if not rows:
            logger.debug("MainWindow._on_stats_export_csv: si not rows -> retour")
            return
        logger.debug("_on_stats_export_csv: {} ligne(s)", len(rows))
        dialog = Gtk.FileDialog()
        dialog.set_title("Exporter les statistiques en CSV")
        dialog.set_initial_name("netcross_stats.csv")
        filter_obj = Gtk.FileFilter()
        filter_obj.set_name("CSV")
        filter_obj.add_pattern("*.csv")
        dialog.set_default_filter(filter_obj)
        dialog.save(self, None, self._on_stats_csv_saved)
        logger.debug("MainWindow._on_stats_export_csv: fin")

    def _on_stats_csv_saved(self, dialog, result):
        try:
            file_obj = dialog.save_finish(result)
        except Exception:
            logger.exception("échec dans _on_stats_csv_saved")
            logger.debug("MainWindow._on_stats_csv_saved: except Exception -> retour")
            return
        if file_obj is None:
            logger.debug("MainWindow._on_stats_csv_saved: si file_obj is None -> retour")
            return
        from netcross_core.stats import export_csv

        rows = getattr(self, "last_stats_rows", None)
        if not rows:
            logger.debug("MainWindow._on_stats_csv_saved: si not rows -> retour")
            return
        path = file_obj.get_path()
        logger.debug("_on_stats_csv_saved: {} ligne(s) vers {}", len(rows), path)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(export_csv(rows))
            self.status_label.set_text(f"Statistiques exportees : {path}")
        except OSError as exc:
            logger.exception(f"échec dans _on_stats_csv_saved: {exc}")
            self.status_label.set_text(f"Erreur export CSV : {exc}")
        logger.debug("MainWindow._on_stats_csv_saved: fin")

    def _on_stats_export_json(self, _btn):
        """Exporte les statistiques courantes en JSON."""
        rows = getattr(self, "last_stats_rows", None)
        if rows:
            logger.debug("_on_stats_export_json: {} ligne(s)", len(rows))
        dialog = Gtk.FileDialog()
        dialog.set_title("Exporter les statistiques en JSON")
        dialog.set_initial_name("netcross_stats.json")
        filter_obj = Gtk.FileFilter()
        filter_obj.set_name("JSON")
        filter_obj.add_pattern("*.json")
        dialog.set_default_filter(filter_obj)
        dialog.save(self, None, self._on_stats_json_saved)
        logger.debug("MainWindow._on_stats_export_json: fin")

    def _on_stats_json_saved(self, dialog, result):
        try:
            file_obj = dialog.save_finish(result)
        except Exception:
            logger.exception("échec dans _on_stats_json_saved")
            logger.debug("MainWindow._on_stats_json_saved: except Exception -> retour")
            return
        if file_obj is None:
            logger.debug("MainWindow._on_stats_json_saved: si file_obj is None -> retour")
            return
        import json

        from netcross_core.stats import export_json

        rows = getattr(self, "last_stats_rows", None)
        if not rows:
            logger.debug("MainWindow._on_stats_json_saved: si not rows -> retour")
            return
        path = file_obj.get_path()
        logger.debug("_on_stats_json_saved: {} ligne(s) vers {}", len(rows), path)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(export_json(rows), fh, indent=2, ensure_ascii=False)
            self.status_label.set_text(f"Statistiques exportees : {path}")
        except OSError as exc:
            logger.exception(f"échec dans _on_stats_json_saved: {exc}")
            self.status_label.set_text(f"Erreur export JSON : {exc}")
        logger.debug("MainWindow._on_stats_json_saved: fin")

    # ================= cartographie des communications (issue #15) =================

    def _reset_comm_map_filters(self):
        """Reinitialise la liste des protocoles apres une analyse, puis
        redessine. Appelee aussi apres une comparaison, ou `last_flows` est
        None : la vue se desactive alors d'elle-meme plutot que d'afficher
        la carte de l'analyse precedente, qui ne correspondrait plus au
        rapport affiche."""
        flows = self.last_flows
        protocoles = available_protocols(flows) if flows else []
        logger.debug("_reset_comm_map_filters: {} protocole(s)", len(protocoles))
        self.comm_proto_drop.set_model(Gtk.StringList.new(["Tous", *protocoles]))
        self.comm_proto_drop.set_selected(0)
        self.comm_map_expander.set_sensitive(bool(flows))
        self._refresh_comm_map()
        logger.debug("MainWindow._reset_comm_map_filters: retour False")
        return False

    # ================= dashboard analytique (issue #18, §6.17) =================

    def _dashboard_clear(self):
        """Reinitialise le contexte de selection partage et rafraichit les
        six vues. Cablage GTK de netcross_gtk4.dashboard_context."""
        logger.debug("_dashboard_clear: réinitialisation du contexte de sélection")
        self.dashboard_selection = DashboardSelection()
        self._refresh_dashboard()
        logger.debug("MainWindow._dashboard_clear: fin")

    def _dashboard_select(self, kind: str, key):
        """Applique une selection sur une des six vues et propage les champs
        lies via le contexte partage, puis rafraichit. ``kind`` distingue
        la vue d'origine (timeline/segment/flow/endpoint/protocol/event).
        """
        # Un `kind` inconnu leve desormais UnknownViewTypeError au lieu de
        # traverser une cascade de elif sans rien faire : avant, un type mal
        # orthographie rendait les clics d'une vue entiere inoperants, sans
        # message ni trace (issue #285, lot 3).
        logger.debug("_dashboard_select: kind={} key={}", kind, key)
        self.dashboard_selection = apply_dashboard_selection(
            kind,
            self.dashboard_selection,
            key,
            flow_par_cle=self._flow_by_key,
            evenements=self._dashboard_events(),
        )
        self._refresh_dashboard()
        logger.debug("MainWindow._dashboard_select: fin")

    def _flow_by_key(self, key):
        # Issue #453 : parcourt les Flow (.key), pas les cles du dict brut
        # -- des tuples sans attribut .key.
        for f in self.last_flow_objects or []:
            if f.key == key:
                logger.debug("MainWindow._flow_by_key: si f.key == key -> retour f={}", summarize(f, "f"))
                return f
        logger.debug("_flow_by_key: clé introuvable {}", key)
        return None

    def _dashboard_events(self):
        """Liste fusionnee des evenements (findings + TLS/QUIC + signaux
        tshark), meme ordre que build_dashboard_snapshot."""
        events = list(self.last_findings or [])
        events.extend(self.last_tls_findings or [])
        events.extend(self.last_quic_findings or [])
        events.extend(self.last_wireshark_expert_events or [])
        logger.debug("_dashboard_events: {} événement(s)", len(events))
        return events

    def _refresh_dashboard(self):
        """Reconstruit le snapshot depuis les memes objets que le rapport et
        repeuple les six vues. Aucune exception ne remonte a l'interface : un
        snapshot vide (analyse pas encore lancee) desactive simplement
        l'expander, comme la cartographie."""
        # Issue #453 : build_dashboard_snapshot attend une liste de Flow
        # (avec .endpoints), pas le dict brut de correlate() -- lui-meme et
        # les vues qu'il alimentait plantaient en silence sur
        # AttributeError: 'tuple' object has no attribute 'endpoints'.
        flows = self.last_flow_objects
        self.dashboard_expander.set_sensitive(bool(flows))
        if not flows:
            logger.debug("_refresh_dashboard: aucun flux, dashboard désactivé")
            # vide aussi les sections : sans cette purge, un run single suivi
            # d'un diff laisserait l'ancien dashboard dans l'arbre GTK (expander
            # desactive mais contenu non nettoye).
            self._dashboard_clear_sections()
            self.dashboard_context_label.set_text("Contexte selectionne : aucun")
            logger.debug("MainWindow._refresh_dashboard: si not flows -> retour")
            return
        snap = build_dashboard_snapshot(
            self.last_report,
            self.last_flow_objects,
            findings=self.last_findings,
            tls_findings=self.last_tls_findings,
            quic_findings=self.last_quic_findings,
            wireshark_expert_events=self.last_wireshark_expert_events,
            selection=self.dashboard_selection,
        )
        self.dashboard_context_label.set_text(f"Contexte selectionne : {snap.selection_summary}")
        logger.debug("_refresh_dashboard: {} flux, contexte={}", len(flows), snap.selection_summary)
        self._dashboard_repopulate(snap)
        logger.debug("MainWindow._refresh_dashboard: fin")

    def _dashboard_clear_sections(self):
        """Retire toutes les sections du dashboard de l'arbre GTK. Utilise
        aussi bien avant un repeuplage qu'a la desactivation (mode sans
        flows) pour ne pas laisser de contenu stale."""
        logger.debug("_dashboard_clear_sections: purge des sections du dashboard")
        box = self.dashboard_sections_box
        child = box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            box.remove(child)
            child = nxt
        logger.debug("MainWindow._dashboard_clear_sections: fin")

    def _dashboard_repopulate(self, snap):
        """Vide la boite des sections et la repeuple avec une section par vue.
        Chaque ligne est un bouton cliquable qui appelle _dashboard_select."""
        logger.debug(
            "_dashboard_repopulate: timeline={} segments={} flows={} endpoints={} protocoles={} evenements={}",
            len(snap.timeline_rows),
            len(snap.segment_rows),
            len(snap.flow_rows),
            len(snap.endpoint_rows),
            len(snap.protocol_rows),
            len(snap.event_rows),
        )
        self._dashboard_clear_sections()
        box = self.dashboard_sections_box
        sections = [
            ("Timeline", snap.timeline_rows, "bucket", row_labels.timeline_row_label, row_labels.timeline_row_key),
            ("Segments", snap.segment_rows, "point", row_labels.segment_row_label, row_labels.segment_row_key),
            ("Flows", snap.flow_rows, "flow", row_labels.flow_row_label, row_labels.flow_row_key),
            ("Endpoints", snap.endpoint_rows, "endpoint", row_labels.endpoint_row_label, row_labels.endpoint_row_key),
            ("Protocoles", snap.protocol_rows, "protocol", row_labels.proto_row_label, row_labels.proto_row_key),
            ("Evenements", snap.event_rows, "event", row_labels.event_row_label, row_labels.event_row_key),
        ]
        for title, rows, kind, label_fn, key_fn in sections:
            frame = Gtk.Frame(label=f"{title} ({len(rows)})")
            lst = Gtk.ListBox()
            lst.set_selection_mode(Gtk.SelectionMode.NONE)
            if not rows:
                lst.append(Gtk.Label(label="(vide)", halign=Gtk.Align.START))
            for row in rows:
                row_key = key_fn(row)
                btn = Gtk.Button(label=label_fn(row), halign=Gtk.Align.START)
                btn.connect(
                    "clicked",
                    lambda _b, k=kind, rk=row_key: self._dashboard_select(k, rk),
                )
                lst.append(btn)
            frame.set_child(lst)
            box.append(frame)
        logger.debug("MainWindow._dashboard_repopulate: fin")

    def _comm_map_filters(self):
        """Filtres actifs, lus depuis les widgets. Extrait pour que la
        logique de lecture reste verifiable sans piloter l'interface."""
        model = self.comm_proto_drop.get_model()
        protocole = None
        if model is not None:
            protocole = selected_protocol(
                self.comm_proto_drop.get_selected(),
                model.get_n_items(),
                model.get_string,
            )
        filtres = comm_map_filters(
            protocole,
            self.comm_topn_spin.get_value(),
            self.comm_anomalies_check.get_active(),
        )
        logger.debug("_comm_map_filters: {}", filtres)
        return filtres

    def _refresh_comm_map(self):
        """Reconstruit la carte et son rendu PNG a partir des filtres
        courants.

        Le graphe est redessine a chaque changement de filtre plutot que
        pre-calcule pour toutes les combinaisons : le cout est un rendu
        matplotlib de quelques dizaines de millisecondes, la ou un cache
        indexe par filtre serait du code a maintenir pour un gain
        imperceptible a l'echelle d'un clic.

        Aucune exception ne remonte a l'interface : matplotlib et networkx
        sont des dependances optionnelles du projet (voir --pdf-report), et
        une vue exploratoire absente ne doit jamais empecher de lire le
        rapport ni d'exporter.
        """
        if not self.last_flows:
            logger.debug("_refresh_comm_map: aucun flux, carte désactivée")
            self.comm_map_picture.set_filename(None)
            self.comm_map_label.set_text("Cartographie disponible apres une analyse simple.")
            logger.debug("MainWindow._refresh_comm_map: si not self.last_flows -> retour False")
            return False
        try:
            from netcross_report.charts import chart_comm_map

            cmap = build_comm_map(self.last_flows, **self._comm_map_filters())
            logger.debug("_refresh_comm_map: {} flux dans la carte", len(self.last_flows))
            if self._comm_map_png is None:
                fd, self._comm_map_png = tempfile.mkstemp(prefix="netcross_comm_map_", suffix=".png")
                os.close(fd)
            rendu = chart_comm_map(cmap, self._comm_map_png)
            self.comm_map_picture.set_filename(rendu)
            self.comm_map_label.set_text(format_comm_map(cmap))
        except Exception as e:  # noqa: BLE001 -- dependances de rendu optionnelles, voir docstring
            logger.exception(f"échec dans _refresh_comm_map: {e}")
            self.comm_map_picture.set_filename(None)
            self.comm_map_label.set_text(f"Cartographie indisponible : {e}")
        logger.debug("MainWindow._refresh_comm_map: retour False")
        return False

    def _session_objects(self):
        """Objets enrichis du dernier run single (issue #14) : memes objets
        que ceux de la CLI, construits par le meme point de passage
        (netcross_report.session_objects) pour que le JSON et le PDF de la
        GUI portent exactement les memes cles et sections.

        `findings` est recalcule ici quand l'utilisateur n'a pas coche le
        triage : ils sont la matiere premiere des ExpertEvent/Diagnosis, et
        `generate_json_report()`/`generate_pdf()` les recalculent de toute
        facon dans ce cas -- autant les calculer une fois et les partager.
        Les signaux tshark, eux, ne sont jamais recalcules : ils viennent du
        thread d'analyse (les paquets bruts ne sont plus disponibles ici).
        """
        logger.debug("_session_objects: construction des objets de session")
        from netcross_report import build_findings, build_session_objects

        findings = self.last_findings if self.last_findings is not None else build_findings(self.last_report)
        logger.debug("MainWindow._session_objects: retour build_session_objects(…)")
        return build_session_objects(
            self.last_report,
            findings,
            flows=self.last_flows,
            wireshark_expert_events=self.last_wireshark_expert_events,
        )

    def _generate_pdf_thread(self, path):
        logger.debug("_generate_pdf_thread: mode={} path={}", self.last_mode, path)
        try:
            if self.last_mode == "single":
                from netcross_report import generate_pdf

                if generate_pdf is None:
                    logger.debug("MainWindow._generate_pdf_thread: si generate_pdf is None -> levée ImportError")
                    raise ImportError("reportlab/matplotlib/networkx requis pour l'export PDF")
                session_objects = self._session_objects()
                generate_pdf(
                    self.last_report,
                    path,
                    findings=self.last_findings,
                    tls_findings=self.last_tls_findings,
                    quic_findings=self.last_quic_findings,
                    session_objects=session_objects,
                    security_report=self.last_security_report,
                    # Issue #674 : --sequence-diagram N
                    sequence_views=sequence_views(
                        self.last_flows,
                        int(self.sequence_diagram_spin.get_value()),
                        flow_objects=getattr(session_objects, "flows", None),
                    ),
                )
            else:
                from netcross_report import generate_diff_pdf

                if generate_diff_pdf is None:
                    logger.debug("MainWindow._generate_pdf_thread: si generate_diff_pdf is None -> levée ImportError")
                    raise ImportError("reportlab/matplotlib/networkx requis pour l'export PDF")
                generate_diff_pdf(
                    self.last_diff_findings,
                    self.last_baseline_report,
                    self.last_current_report,
                    path,
                    tls_findings_baseline=self.last_diff_tls_findings_baseline,
                    tls_findings_current=self.last_diff_tls_findings_current,
                    quic_findings_baseline=self.last_diff_quic_findings_baseline,
                    quic_findings_current=self.last_diff_quic_findings_current,
                )
        except Exception as e:  # noqa: BLE001 -- thread de fond (export PDF) : idem, erreur affichee via GLib.idle_add.
            logger.exception(f"échec dans _generate_pdf_thread: {e}")
            GLib.idle_add(self._on_pdf_error, str(e))
            logger.debug("MainWindow._generate_pdf_thread: except Exception -> retour")
            return
        GLib.idle_add(self._on_pdf_done, path)
        logger.debug("MainWindow._generate_pdf_thread: fin")

    def _on_pdf_error(self, message):
        logger.debug("_on_pdf_error: {}", message)
        self.status_label.set_text(f"Erreur PDF : {message}")
        logger.debug("MainWindow._on_pdf_error: retour False")
        return False

    def _on_pdf_done(self, path):
        logger.debug("_on_pdf_done: {}", path)
        self.status_label.set_text(f"PDF ecrit : {path}")
        logger.debug("MainWindow._on_pdf_done: retour False")
        return False

    # ================= export JSON =================
    # Pendant de on_export_pdf/on_export_csv (Session 37 -- jusque-la
    # absent de la GUI, voir FEATURES.md). netcross_report.json_report est
    # du pur Python (aucune dependance externe, contrairement a
    # generate_pdf) -- pas besoin de garde ImportError equivalente.

    def on_export_json(self, _btn):
        if self.last_mode is None:
            logger.debug("MainWindow.on_export_json: si self.last_mode is None -> retour")
            return
        logger.debug("on_export_json: mode={}", self.last_mode)
        dialog = Gtk.FileDialog()
        dialog.set_initial_name("rapport_analyse.json" if self.last_mode == "single" else "rapport_comparaison.json")
        dialog.save(self, None, self._on_json_path_chosen)
        logger.debug("MainWindow.on_export_json: fin")

    def _on_json_path_chosen(self, dialog, result):
        try:
            gfile = dialog.save_finish(result)
        except GLib.Error:
            logger.exception("échec dans _on_json_path_chosen")
            logger.debug("MainWindow._on_json_path_chosen: except GLib.Error -> retour")
            return
        path = gfile.get_path()
        logger.debug("_on_json_path_chosen: chemin choisi {}", path)
        self.export_json_to(path)
        logger.debug("MainWindow._on_json_path_chosen: fin")

    def on_export_markdown(self, _btn):
        if self.last_mode != "single":
            logger.debug("MainWindow.on_export_markdown: pas d'analyse simple -> retour")
            return
        dialog = Gtk.FileDialog()
        dialog.set_initial_name("rapport_analyse.md")
        dialog.save(self, None, self._on_markdown_path_chosen)

    def _on_markdown_path_chosen(self, dialog, result):
        try:
            gfile = dialog.save_finish(result)
        except GLib.Error:
            logger.exception("échec dans _on_markdown_path_chosen")
            return
        self.export_markdown_to(gfile.get_path())

    def export_markdown_to(self, path):
        """Issue #864 : meme document que --md-report (rapport, constats,
        TLS/QUIC, securite, objets de session, moteur de regles, noms)."""
        from netcross_report import generate_markdown_report

        logger.debug("export_markdown_to: {}", path)
        try:
            generate_markdown_report(
                self.last_report,
                path,
                findings=self.last_findings,
                tls_findings=self.last_tls_findings,
                quic_findings=self.last_quic_findings,
                session_objects=self._session_objects(),
                security_report=self.last_security_report,
                rule_engine_findings=self.last_rule_engine,
                names=self.names_table,
            )
        except OSError as e:
            logger.exception(f"échec dans export_markdown_to: {e}")
            self.status_label.set_text(f"Erreur Markdown : {e}")
            return None
        self.status_label.set_text(f"Rapport Markdown ecrit dans {path}")
        return path

    def export_json_to(self, path):
        """Separe de la callback du dialogue pour pouvoir etre pilote directement (tests)."""
        logger.debug("export_json_to: {}", path)
        self.status_label.set_text("Generation du JSON...")
        threading.Thread(target=self._generate_json_thread, args=(path,), daemon=True).start()
        logger.debug("MainWindow.export_json_to: fin")

    def _generate_json_thread(self, path):
        logger.debug("_generate_json_thread: mode={} path={}", self.last_mode, path)
        try:
            if self.last_mode == "single":
                from netcross_report import generate_json_report

                generate_json_report(
                    self.last_report,
                    path,
                    findings=self.last_findings,
                    tls_findings=self.last_tls_findings,
                    quic_findings=self.last_quic_findings,
                    security_report=self.last_security_report,
                    names=self.names_table,
                    **self._session_objects().json_kwargs(),
                )
            else:
                from netcross_report import generate_json_diff

                generate_json_diff(
                    self.last_diff_findings,
                    self.last_baseline_report,
                    self.last_current_report,
                    path,
                    tls_findings_baseline=self.last_diff_tls_findings_baseline,
                    tls_findings_current=self.last_diff_tls_findings_current,
                    quic_findings_baseline=self.last_diff_quic_findings_baseline,
                    quic_findings_current=self.last_diff_quic_findings_current,
                )
        except Exception as e:  # noqa: BLE001 -- thread de fond (export JSON) : idem, erreur affichee via GLib.idle_add.
            logger.exception(f"échec dans _generate_json_thread: {e}")
            GLib.idle_add(self._on_json_error, str(e))
            logger.debug("MainWindow._generate_json_thread: except Exception -> retour")
            return
        GLib.idle_add(self._on_json_done, path)
        logger.debug("MainWindow._generate_json_thread: fin")

    def _on_json_error(self, message):
        logger.debug("_on_json_error: {}", message)
        self.status_label.set_text(f"Erreur JSON : {message}")
        logger.debug("MainWindow._on_json_error: retour False")
        return False

    def _on_json_done(self, path):
        logger.debug("_on_json_done: {}", path)
        self.status_label.set_text(f"JSON ecrit : {path}")
        logger.debug("MainWindow._on_json_done: retour False")
        return False

    # ================= securite (issue #357) =================

    def _show_security_report(self):
        """Section Securite : rendu de --security-report, exports actifs
        seulement quand un rapport existe (analyse simple, case cochee).
        `last_security_report` vient du RunOutcome (None apres un diff)."""
        security_report = self.last_security_report
        logger.debug("_show_security_report: rapport={}", bool(security_report))
        buf = Gtk.TextBuffer()
        buf.set_text(security_view_text(security_report))
        self.security_view.set_buffer(buf)
        self.security_expander.set_sensitive(security_report is not None)
        self.security_expander.set_expanded(
            security_report is not None
            and bool(security_report.exploits or security_report.anomalies or security_report.cves)
        )
        self.security_html_btn.set_sensitive(security_report is not None)
        self.security_json_btn.set_sensitive(security_report is not None)
        logger.debug("MainWindow._show_security_report: fin")

    def on_export_security(self, suffix):
        if self.last_security_report is None:
            logger.debug("MainWindow.on_export_security: si self.last_security_report is None -> retour")
            return
        logger.debug("on_export_security: format={}", suffix)
        dialog = Gtk.FileDialog()
        dialog.set_initial_name(f"rapport_securite{suffix}")
        dialog.save(self, None, lambda d, r: self._on_security_path_chosen(d, r))
        logger.debug("MainWindow.on_export_security: fin")

    def _on_security_path_chosen(self, dialog, result):
        try:
            gfile = dialog.save_finish(result)
        except GLib.Error:
            logger.exception("échec dans _on_security_path_chosen")
            logger.debug("MainWindow._on_security_path_chosen: except GLib.Error -> retour")
            return
        path = gfile.get_path()
        logger.debug("_on_security_path_chosen: chemin choisi {}", path)
        self.export_security_to(path)
        logger.debug("MainWindow._on_security_path_chosen: fin")

    def export_security_to(self, path):
        """Separe du dialogue pour etre pilote directement (tests). Synchrone :
        le rendu part d'un SecurityReport deja calcule, sans relire de fichier."""
        logger.debug("export_security_to: {}", path)
        try:
            written = export_security_report(self.last_security_report, path)
        except (OSError, ValueError) as e:
            logger.exception(f"échec dans export_security_to: {e}")
            self.status_label.set_text(f"Erreur rapport de securite : {e}")
            logger.debug("MainWindow.export_security_to: except (OSError, ValueError) -> retour None")
            return None
        self.status_label.set_text(f"Rapport de securite ecrit : {written}")
        logger.debug("MainWindow.export_security_to: retour written={}", summarize(written, "written"))
        return written


class NetcrossApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.netcross.analyzer")
        self.main_window = None
        logger.debug("NetcrossApp: application_id={}", self.get_application_id())

    def do_activate(self):
        logger.debug("do_activate: fenêtre existante={}", self.main_window is not None)
        if not self.main_window:
            self.main_window = MainWindow(self)
        self.main_window.present()
        logger.debug("NetcrossApp.do_activate: fin")


def display_available() -> bool:
    """Un affichage GTK4 est-il reellement accessible ?

    ``Gtk.init_check()`` seul ne suffit pas (GTK 4.22 renvoie ``True`` sans
    DISPLAY ni WAYLAND_DISPLAY, cf. tests/gtk4_display.py) : le critere fiable
    est l'existence d'un ``Gdk.Display`` par defaut.
    """
    logger.debug("display_available()")
    return bool(Gtk.init_check()) and Gdk.Display.get_default() is not None


def display_unavailable_message(environ=None, euid=None) -> str:
    """Message affiche quand GTK4 ne peut pas ouvrir d'affichage (#468) :
    cause probable et alternatives, plutot qu'une trace Gtk-CRITICAL."""
    logger.debug(
        "display_unavailable_message: environ={} euid={}",
        summarize(environ, "environ"),
        summarize(euid, "euid"),
    )
    env = os.environ if environ is None else environ
    if euid is None:
        euid = os.geteuid() if hasattr(os, "geteuid") else -1
    lines = ["Netcross : impossible d'ouvrir l'interface graphique (aucun affichage accessible)."]
    if not env.get("DISPLAY") and not env.get("WAYLAND_DISPLAY"):
        lines.append("  Cause : ni DISPLAY ni WAYLAND_DISPLAY ne sont definis (session SSH, console, service...).")
    if euid == 0:
        lines.append(
            "  Cause probable : lancement en root (sudo/su). La session graphique appartient a votre "
            "utilisateur : relancez Netcross sans sudo."
        )
    lines += [
        "  Les captures n'ont pas besoin de root : les droits de lecture du fichier suffisent.",
        "  Sans affichage, utilisez la ligne de commande : netcross --help "
        "(depuis les sources : python3 src/cross_capture_analyzer_cli.py --help)",
    ]
    logger.debug("display_unavailable_message: retour '\\n'.join(…)")
    return "\n".join(lines)


def main():
    # --debug est propre a Netcross : retire avant Gtk.Application.run, qui
    # refuserait une option inconnue.
    argv = list(sys.argv)
    if DEBUG_FLAG in argv:
        argv = [a for a in argv if a != DEBUG_FLAG]
        enable_debug()
    logger.debug("main: démarrage de la GUI GTK4, argv={} debug={}", argv[1:], is_debug_enabled())
    if not display_available():
        logger.error("main: GTK4 ne peut pas s'initialiser, aucun affichage accessible")
        print(display_unavailable_message(), file=sys.stderr)
        logger.debug("main: si not display_available() -> retour 2")
        return 2
    app = NetcrossApp()
    logger.debug("main: retour app.run(…)")
    return app.run(argv)


if __name__ == "__main__":
    sys.exit(main())
