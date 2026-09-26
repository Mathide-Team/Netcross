"""Couverture GTK4 de app.py, lot 8 (issue #429, sous-issue de #421).

Portee : export JSON des statistiques (_on_stats_export_json,
_on_stats_json_saved), reinitialisation des filtres de la carte de
communication (_reset_comm_map_filters) et cablage widget du tableau de
bord analytique (_dashboard_clear, _dashboard_select, _flow_by_key,
_dashboard_events, _refresh_dashboard, _dashboard_clear_sections,
_dashboard_repopulate).

Meme garde que tests/test_gui_security_window.py : ignore proprement si
GTK4/pygobject ou un affichage manquent (CI sans libgtk-4) -- aucun test
de ce fichier ne doit exiger GTK4 en CI.

La logique de calcul du tableau de bord (filtrage, propagation de
selection, construction du snapshot) est deja testee sans GTK dans
tests/test_dashboard_context.py et tests/test_panel_state.py : ce fichier
ne verifie que le cablage de MainWindow sur les vrais widgets (la fenetre
repercute-t-elle bien le snapshot ? un clic declenche-t-il bien la bonne
selection ?), pas le calcul lui-meme.
"""

from __future__ import annotations

import json

import pytest
from conftest import make_pkt

gi = pytest.importorskip("gi", reason="pygobject absent")
try:
    gi.require_version("Gtk", "4.0")
    from gi.repository import GLib, Gtk
except (ValueError, ImportError):
    pytest.skip("GTK4 absent", allow_module_level=True)
if not Gtk.init_check():
    pytest.skip("pas d'affichage pour GTK4", allow_module_level=True)

from netcross_core.analysis import analyse  # noqa: E402
from netcross_core.correlate import build_flows, correlate  # noqa: E402
from netcross_core.stats import StatRow, export_json  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402
from netcross_gtk4.dashboard_context import (  # noqa: E402
    DashboardSelection,
    build_dashboard_snapshot,
    select_protocol,
)
from netcross_gtk4.panel_state import UnknownViewTypeError  # noqa: E402
from netcross_gtk4.run_outcome import analysis_outcome  # noqa: E402
from netcross_report.comm_map import DEFAULT_TOP_N as COMM_MAP_DEFAULT_TOP_N  # noqa: E402


@pytest.fixture(scope="module")
def window():
    app = Gtk.Application(application_id="org.netcross.test429")
    app.register(None)
    return MainWindow(app)


def _scenario_brut():
    """Deux points A/B, un flux TCP 10.0.0.1:1234 -> 10.0.0.2:80 vu aux deux
    points, plus un flux UDP -- meme scenario que test_dashboard_context.py.
    Retourne (report, dict brut de correlate())."""
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=1234,
            dport=80,
            ts=0.0,
            length=100,
            payload_hash="h1",
        ),
        make_pkt(
            point="B",
            proto="TCP",
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=1234,
            dport=80,
            ts=0.05,
            length=100,
            payload_hash="h1",
        ),
        make_pkt(
            point="A",
            proto="TCP",
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=1234,
            dport=80,
            ts=1.0,
            length=100,
            payload_hash="h2",
        ),
        make_pkt(
            point="B",
            proto="TCP",
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=1234,
            dport=80,
            ts=1.05,
            length=100,
            payload_hash="h2",
        ),
        make_pkt(
            point="A",
            proto="UDP",
            src="10.0.0.3",
            dst="10.0.0.4",
            sport=5000,
            dport=5353,
            ts=0.2,
            length=80,
            payload_hash="h3",
        ),
    ]
    flows_dict = correlate(pkts)
    report = analyse(flows_dict, points_order=["A", "B"], all_packets=pkts)
    return report, flows_dict


def _scenario():
    """(report, list[Flow]) du scenario de `_scenario_brut`, pour les tests
    qui appellent directement des fonctions prenant des Flow."""
    report, flows_dict = _scenario_brut()
    return report, build_flows(flows_dict)


def _poser_run(window):
    """Pose l'etat du dernier run exactement comme `_on_analysis_done` :
    `analysis_outcome(...)` puis recopie de `etat()` (voir
    `MainWindow._appliquer_outcome`). `last_flows` recoit donc le dict brut
    de correlate() et `last_flow_objects` la liste de Flow (issue #453) --
    injecter une liste de Flow dans `last_flows` decrirait un etat que
    l'application ne produit jamais. Retourne (report, list[Flow])."""
    report, flows_dict = _scenario_brut()
    outcome = analysis_outcome("single", report, flows_dict, None, "")
    for nom, valeur in outcome.etat().items():
        setattr(window, nom, valeur)
    return report, outcome.flow_objects


def _flow_proto(flow):
    key = flow.key
    if key and key[0] == "NAT" and len(key) >= 2:
        return key[1]
    return key[0] if key else None


def _collect_frames(box):
    frames = []
    child = box.get_first_child()
    while child is not None:
        frames.append(child)
        child = child.get_next_sibling()
    return frames


class _FakeGFile:
    def __init__(self, path):
        self._path = path

    def get_path(self):
        return self._path


def _clear_run_state(window):
    """Remet a plat les attributs `last_*` consommes par ce lot, pour que
    chaque test parte d'un etat connu (fixture `window` partagee)."""
    window.last_report = None
    window.last_flows = None
    window.last_flow_objects = None
    window.last_stats_rows = None
    window.last_findings = None
    window.last_tls_findings = None
    window.last_quic_findings = None
    window.last_wireshark_expert_events = None
    window.dashboard_selection = DashboardSelection()


# ================= export JSON des statistiques =================


def test_on_stats_export_json_ouvre_un_file_dialog(monkeypatch, window):
    _clear_run_state(window)
    appels = []

    def _fake_save(dialog_self, parent, cancellable, callback):
        appels.append((dialog_self, parent, cancellable, callback))

    monkeypatch.setattr(Gtk.FileDialog, "save", _fake_save)

    window._on_stats_export_json(None)

    assert len(appels) == 1
    dialog, parent, cancellable, callback = appels[0]
    assert isinstance(dialog, Gtk.FileDialog)
    assert parent is window
    assert cancellable is None
    assert callback == window._on_stats_json_saved
    assert dialog.get_title() == "Exporter les statistiques en JSON"
    assert dialog.get_initial_name() == "netcross_stats.json"
    assert dialog.get_default_filter().get_name() == "JSON"


def test_on_stats_export_json_avec_lignes_ouvre_aussi_le_dialogue(monkeypatch, window):
    _clear_run_state(window)
    window.last_stats_rows = [StatRow(label="TCP", group_by="protocol", packets=3)]
    appels = []
    monkeypatch.setattr(
        Gtk.FileDialog,
        "save",
        lambda dialog_self, parent, cancellable, callback: appels.append(dialog_self),
    )

    window._on_stats_export_json(None)

    assert len(appels) == 1


def test_on_stats_json_saved_ecrit_le_fichier(window, tmp_path, monkeypatch):
    _clear_run_state(window)
    rows = [
        StatRow(
            label="TCP 10.0.0.1:1234 -> 10.0.0.2:80",
            group_by="flow",
            packets=10,
            bytes=2000,
            duration_ms=500.0,
            throughput_bps=32000.0,
            latency_ms=12.5,
            events=1,
            flow_keys=[("TCP", "10.0.0.1", 1234, "10.0.0.2", 80, 1)],
        ),
    ]
    window.last_stats_rows = rows
    dest = tmp_path / "stats.json"
    dialog = Gtk.FileDialog()
    monkeypatch.setattr(dialog, "save_finish", lambda result: _FakeGFile(str(dest)))

    window._on_stats_json_saved(dialog, None)

    data = json.loads(dest.read_text(encoding="utf-8"))
    assert data == export_json(rows)
    assert window.status_label.get_text() == f"Statistiques exportees : {dest}"


def test_on_stats_json_saved_annulation_ne_leve_pas_et_n_ecrit_rien(window, monkeypatch):
    _clear_run_state(window)
    window.last_stats_rows = [StatRow(label="UDP", group_by="protocol")]
    dialog = Gtk.FileDialog()

    def _raise(result):
        raise GLib.Error("Dismissed by user")

    monkeypatch.setattr(dialog, "save_finish", _raise)
    window.status_label.set_text("")

    window._on_stats_json_saved(dialog, None)  # ne doit pas lever

    assert window.status_label.get_text() == ""


def test_on_stats_json_saved_file_obj_none_n_ecrit_rien(window, monkeypatch):
    _clear_run_state(window)
    window.last_stats_rows = [StatRow(label="TCP", group_by="protocol")]
    dialog = Gtk.FileDialog()
    monkeypatch.setattr(dialog, "save_finish", lambda result: None)
    window.status_label.set_text("")

    window._on_stats_json_saved(dialog, None)

    assert window.status_label.get_text() == ""


def test_on_stats_json_saved_sans_lignes_n_ecrit_rien(window, tmp_path, monkeypatch):
    _clear_run_state(window)
    window.last_stats_rows = None
    dest = tmp_path / "stats.json"
    dialog = Gtk.FileDialog()
    monkeypatch.setattr(dialog, "save_finish", lambda result: _FakeGFile(str(dest)))

    window._on_stats_json_saved(dialog, None)

    assert not dest.exists()


def test_on_stats_json_saved_erreur_ecriture_affiche_le_statut(window, tmp_path, monkeypatch):
    _clear_run_state(window)
    window.last_stats_rows = [StatRow(label="TCP", group_by="protocol")]
    dialog = Gtk.FileDialog()
    bogus = tmp_path / "dossier_absent" / "stats.json"
    monkeypatch.setattr(dialog, "save_finish", lambda result: _FakeGFile(str(bogus)))

    window._on_stats_json_saved(dialog, None)

    assert "Erreur export JSON" in window.status_label.get_text()


# ================= _reset_comm_map_filters =================


def test_reset_comm_map_filters_sans_flows(window):
    _clear_run_state(window)
    window.last_flows = None

    window._reset_comm_map_filters()

    model = window.comm_proto_drop.get_model()
    assert model.get_n_items() == 1
    assert model.get_string(0) == "Tous"
    assert window.comm_proto_drop.get_selected() == 0
    assert window.comm_map_expander.get_sensitive() is False


def test_reset_comm_map_filters_avec_flows_liste_les_protocoles(window):
    _clear_run_state(window)
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.1", dst="10.0.0.2", sport=1111, dport=80),
        make_pkt(point="A", proto="UDP", src="10.0.0.3", dst="10.0.0.4", sport=5000, dport=53),
    ]
    # _reset_comm_map_filters/available_protocols consomment le dict brut de
    # correlate() (cle -> {point: [Pkt]}), pas la liste de Flow -- forme
    # differente de celle utilisee par le tableau de bord ci-dessous.
    window.last_flows = correlate(pkts)

    window._reset_comm_map_filters()

    model = window.comm_proto_drop.get_model()
    protocoles = [model.get_string(i) for i in range(model.get_n_items())]
    assert protocoles == ["Tous", "TCP", "UDP"]
    assert window.comm_proto_drop.get_selected() == 0
    assert window.comm_map_expander.get_sensitive() is True
    # Top-N par defaut (netcross_report.comm_map.DEFAULT_TOP_N), non touche
    # par cette methode -- reste a la valeur posee a la construction.
    assert window.comm_topn_spin.get_value() == COMM_MAP_DEFAULT_TOP_N


# ================= _flow_by_key =================


def test_flow_by_key_retrouve_le_flux(window):
    _clear_run_state(window)
    _, flows = _poser_run(window)
    cible = flows[0]

    assert window._flow_by_key(cible.key) is cible


def test_flow_by_key_cle_introuvable_retourne_none(window):
    _clear_run_state(window)
    _, _ = _poser_run(window)

    assert window._flow_by_key(("TCP", "0.0.0.0", 0, "0.0.0.0", 0, 0)) is None


def test_flow_by_key_sans_flux_retourne_none(window):
    _clear_run_state(window)  # last_flows et last_flow_objects a None

    assert window._flow_by_key(("peu importe",)) is None


# ================= _dashboard_events =================


def test_dashboard_events_fusionne_findings_tls_quic_tshark(window):
    _clear_run_state(window)
    window.last_findings = ["finding"]
    window.last_tls_findings = ["tls"]
    window.last_quic_findings = ["quic"]
    window.last_wireshark_expert_events = ["tshark"]

    assert window._dashboard_events() == ["finding", "tls", "quic", "tshark"]


def test_dashboard_events_vide_si_aucune_source(window):
    _clear_run_state(window)

    assert window._dashboard_events() == []


# ================= _dashboard_select =================


def test_dashboard_select_protocol_filtre_et_rafraichit(window):
    _clear_run_state(window)
    _poser_run(window)

    window._dashboard_select("protocol", "UDP")

    assert window.dashboard_selection.protocol == "UDP"
    assert "proto=UDP" in window.dashboard_context_label.get_text()
    frames = _collect_frames(window.dashboard_sections_box)
    flows_frame = next(f for f in frames if f.get_label().startswith("Flows"))
    assert flows_frame.get_label() == "Flows (1)"  # seul le flux UDP passe le filtre


def test_dashboard_select_flow_resout_la_cle_via_flow_by_key(window):
    _clear_run_state(window)
    _, flows = _poser_run(window)
    tcp_flow = next(f for f in flows if _flow_proto(f) == "TCP")

    window._dashboard_select("flow", tcp_flow.key)

    assert window.dashboard_selection.flow_key == tcp_flow.key
    assert window.dashboard_selection.protocol == "TCP"
    assert window.dashboard_selection.pair == ("A", "B")
    assert "flow=selectionne" in window.dashboard_context_label.get_text()


def test_dashboard_select_flow_cle_introuvable_laisse_la_selection_inchangee(window):
    _clear_run_state(window)
    _poser_run(window)

    window._dashboard_select("flow", ("TCP", "0.0.0.0", 0, "0.0.0.0", 0, 0))

    assert window.dashboard_selection == DashboardSelection()


def test_dashboard_select_event_propage_point_et_protocole(window):
    _clear_run_state(window)
    _poser_run(window)

    class FakeEvent:
        protocol = "TCP"
        segment = "A"
        category = "test"
        severity = "info"
        message = "evenement de test"
        source = "tshark"

    window.last_findings = [FakeEvent()]

    window._dashboard_select("event", 0)

    assert window.dashboard_selection.event_id == 0
    assert window.dashboard_selection.protocol == "TCP"
    assert window.dashboard_selection.point == "A"


def test_dashboard_select_type_inconnu_leve_unknown_view_type_error(window):
    _clear_run_state(window)

    with pytest.raises(UnknownViewTypeError):
        window._dashboard_select("type-invalide", "x")


# ================= _dashboard_clear / _dashboard_clear_sections =================


def test_dashboard_clear_sections_vide_la_boite(window):
    _clear_run_state(window)
    report, flows = _scenario()
    snap = build_dashboard_snapshot(report, flows)
    window._dashboard_repopulate(snap)
    assert window.dashboard_sections_box.get_first_child() is not None

    window._dashboard_clear_sections()

    assert window.dashboard_sections_box.get_first_child() is None


def test_dashboard_clear_reinitialise_la_selection_et_rafraichit(window):
    _clear_run_state(window)
    _poser_run(window)
    window.dashboard_selection = select_protocol(DashboardSelection(), "TCP")
    window._refresh_dashboard()
    assert window.dashboard_selection.protocol == "TCP"

    window._dashboard_clear()

    assert window.dashboard_selection == DashboardSelection()
    assert window.dashboard_context_label.get_text() == "Contexte selectionne : aucune selection active"
    # aucune selection active -> tous les flux (TCP + UDP) redeviennent visibles
    frames = _collect_frames(window.dashboard_sections_box)
    flows_frame = next(f for f in frames if f.get_label().startswith("Flows"))
    assert flows_frame.get_label() == "Flows (2)"


# ================= _refresh_dashboard =================


def test_refresh_dashboard_sans_flux_desactive_et_vide_les_sections(window):
    _clear_run_state(window)
    # peuple d'abord, pour verifier que le passage a vide purge bien le residu
    _poser_run(window)
    window._refresh_dashboard()
    assert window.dashboard_sections_box.get_first_child() is not None

    window.last_flows = None
    window.last_flow_objects = None
    window._refresh_dashboard()

    assert window.dashboard_expander.get_sensitive() is False
    assert window.dashboard_sections_box.get_first_child() is None
    assert window.dashboard_context_label.get_text() == "Contexte selectionne : aucun"


def test_refresh_dashboard_avec_flux_peuple_les_six_vues(window):
    _clear_run_state(window)
    _poser_run(window)

    window._refresh_dashboard()

    assert window.dashboard_expander.get_sensitive() is True
    assert window.dashboard_context_label.get_text() == "Contexte selectionne : aucune selection active"
    frames = _collect_frames(window.dashboard_sections_box)
    assert len(frames) == 6
    titres = {f.get_label() for f in frames}
    assert "Flows (2)" in titres  # flux TCP + UDP
    assert "Segments (1)" in titres  # paire (A, B)


# ================= _dashboard_repopulate =================


def test_dashboard_repopulate_cree_une_section_par_vue_dans_l_ordre(window):
    _clear_run_state(window)
    report, flows = _scenario()
    snap = build_dashboard_snapshot(report, flows)

    window._dashboard_repopulate(snap)

    frames = _collect_frames(window.dashboard_sections_box)
    assert [f.get_label() for f in frames] == [
        f"Timeline ({len(snap.timeline_rows)})",
        f"Segments ({len(snap.segment_rows)})",
        f"Flows ({len(snap.flow_rows)})",
        f"Endpoints ({len(snap.endpoint_rows)})",
        f"Protocoles ({len(snap.protocol_rows)})",
        f"Evenements ({len(snap.event_rows)})",
    ]


def test_dashboard_repopulate_section_vide_affiche_un_placeholder(window):
    _clear_run_state(window)
    snap = build_dashboard_snapshot(None, [])  # snapshot vide -> six vues sans lignes

    window._dashboard_repopulate(snap)

    frames = _collect_frames(window.dashboard_sections_box)
    for frame in frames:
        listbox = frame.get_child()
        first_row = listbox.get_row_at_index(0)
        assert first_row.get_child().get_label() == "(vide)"


def test_dashboard_repopulate_bouton_declenche_dashboard_select(window, monkeypatch):
    _clear_run_state(window)
    report, flows = _scenario()
    snap = build_dashboard_snapshot(report, flows)
    window._dashboard_repopulate(snap)

    appels = []
    monkeypatch.setattr(window, "_dashboard_select", lambda kind, key: appels.append((kind, key)))

    frames = _collect_frames(window.dashboard_sections_box)
    flows_frame = next(f for f in frames if f.get_label().startswith("Flows"))
    listbox = flows_frame.get_child()
    premier_bouton = listbox.get_row_at_index(0).get_child()

    premier_bouton.emit("clicked")

    assert len(appels) == 1
    kind, key = appels[0]
    assert kind == "flow"
    assert key in {f.key for f in flows}
