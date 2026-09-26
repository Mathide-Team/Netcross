"""Couverture GTK4 de app.py, lot 7 (issue #428, sous-issue de #421).

Portee : export PDF (_on_pdf_path_chosen, export_pdf_to) et panneau
Statistiques (_stats_group_value, _stats_sort_value, _refresh_stats,
_stats_clear_list, _stats_repopulate, _stats_select,
_on_stats_export_csv, _on_stats_csv_saved).
Meme garde que tests/test_gui_security_window.py : ignore proprement si
GTK4/pygobject ou un affichage manquent (CI sans libgtk-4) -- aucun test
de ce fichier ne doit exiger GTK4 en CI.
"""

import itertools

from gtk4_display import exiger_gtk4_avec_affichage

Gtk = exiger_gtk4_avec_affichage()
from conftest import make_pkt  # noqa: E402
from gi.repository import GLib  # noqa: E402

import netcross_report  # noqa: E402
from netcross_core.analysis import analyse  # noqa: E402
from netcross_core.correlate import build_flows, correlate  # noqa: E402
from netcross_core.stats import StatRow, export_csv  # noqa: E402
from netcross_gtk4 import app as app_module  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402
from netcross_gtk4.run_outcome import analysis_outcome  # noqa: E402
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

_IDS_APPLICATION = itertools.count(1)


def _make_window():
    """MainWindow fraîche pour chaque test, avec un identifiant d'application
    UNIQUE (même approche que le lot 5, tests/test_app_gtk4_lot5.py).

    Quand un bus D-Bus de session existe (runner GitHub, poste de bureau),
    ``register()`` exporte l'application sur ``/org/netcross/test428`` : une
    seconde inscription avec le même identifiant dans le même processus
    échoue avec « An object is already exported for the interface
    org.gtk.Application ». Sans bus (bac à sable), rien n'est exporté et le
    défaut restait invisible."""
    app = Gtk.Application(application_id=f"org.netcross.test428.n{next(_IDS_APPLICATION)}")
    app.register(None)
    return MainWindow(app)


def _scenario_brut():
    """Deux flux : un TCP 10.0.0.1:1234 -> 10.0.0.2:80 (2 paquets, vu aux
    points A et B), un UDP 10.0.0.3:5000 -> 10.0.0.4:53 (1 paquet, point
    A). Retourne (report, dict brut de correlate()) construits via le meme chemin que
    la production (correlate -> analyse)."""
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
            proto="UDP",
            src="10.0.0.3",
            dst="10.0.0.4",
            sport=5000,
            dport=53,
            ts=1.0,
            length=64,
            payload_hash="h2",
        ),
    ]
    flows_dict = correlate(pkts)
    report = analyse(flows_dict, ["A", "B"], pkts)
    return report, flows_dict


def _scenario():
    """(report, list[Flow]) du scenario de `_scenario_brut`, pour les tests
    qui appellent directement les methodes prenant des Flow."""
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


def _liste_labels(list_box):
    """Extrait le texte affiche de chaque ligne d'un Gtk.ListBox (chaque
    enfant ajoute via append() est enveloppe dans un Gtk.ListBoxRow).

    Note : _stats_clear_list() ajoute TOUJOURS un placeholder "(vide)"
    avant tout repeuplement (_stats_repopulate/_stats_select l'appellent
    en premier sans le retirer ensuite) -- il apparait donc en tete de
    liste meme quand des lignes suivent. Comportement reel du fichier,
    reproduit tel quel ici (voir la remarque de PR)."""
    labels = []
    row = list_box.get_first_child()
    while row is not None:
        labels.append(row.get_child().get_label())
        row = row.get_next_sibling()
    return labels


class _FakeGFile:
    def __init__(self, path):
        self._path = path

    def get_path(self):
        return self._path


# ================= _on_pdf_path_chosen / export_pdf_to =================


def test_on_pdf_path_chosen_annulation_n_appelle_pas_export_pdf_to(monkeypatch):
    window = _make_window()
    appels = []
    monkeypatch.setattr(window, "export_pdf_to", lambda path: appels.append(path))
    dialog = Gtk.FileDialog()

    def _raise(result):
        raise GLib.Error("Dismissed by user")

    monkeypatch.setattr(dialog, "save_finish", _raise)

    window._on_pdf_path_chosen(dialog, None)  # ne doit pas lever

    assert appels == []


def test_on_pdf_path_chosen_succes_appelle_export_pdf_to_avec_le_chemin(monkeypatch):
    window = _make_window()
    appels = []
    monkeypatch.setattr(window, "export_pdf_to", lambda path: appels.append(path))
    dialog = Gtk.FileDialog()
    monkeypatch.setattr(dialog, "save_finish", lambda result: _FakeGFile("/tmp/rapport.pdf"))

    window._on_pdf_path_chosen(dialog, None)

    assert appels == ["/tmp/rapport.pdf"]


class _ImmediateThread:
    """Remplace threading.Thread : execute la cible immediatement et de
    maniere synchrone (deterministe en test, pas de vrai thread)."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        self._target(*self._args, **self._kwargs)


def test_export_pdf_to_lance_le_pipeline_netcross_report_avec_le_bon_chemin(monkeypatch):
    window = _make_window()
    window.last_mode = "single"
    monkeypatch.setattr(window, "_session_objects", lambda: None)
    monkeypatch.setattr(app_module.threading, "Thread", _ImmediateThread)

    appels = []

    def _fake_generate_pdf(report, path, **kwargs):
        appels.append((report, path, kwargs))

    monkeypatch.setattr(netcross_report, "generate_pdf", _fake_generate_pdf)

    window.export_pdf_to("/tmp/rapport-single.pdf")

    assert window.status_label.get_text() == "Generation du PDF..."
    assert len(appels) == 1
    _report, path, _kwargs = appels[0]
    assert path == "/tmp/rapport-single.pdf"


# ================= _stats_group_value / _stats_sort_value =================


def test_stats_group_value_correspond_a_chaque_position_du_dropdown():
    window = _make_window()
    opts = group_options()
    assert window.stats_group_drop.get_model().get_n_items() == len(opts)
    for idx, (valeur, _label) in enumerate(opts):
        window.stats_group_drop.set_selected(idx)
        assert window._stats_group_value() == valeur


def test_stats_group_value_repli_si_hors_plage():
    window = _make_window()
    window.stats_group_drop.set_selected(Gtk.INVALID_LIST_POSITION)
    assert window._stats_group_value() == "endpoint"


def test_stats_sort_value_correspond_a_chaque_position_du_dropdown():
    window = _make_window()
    opts = sort_options()
    assert window.stats_sort_drop.get_model().get_n_items() == len(opts)
    for idx, (valeur, _label) in enumerate(opts):
        window.stats_sort_drop.set_selected(idx)
        assert window._stats_sort_value() == valeur


def test_stats_sort_value_repli_si_hors_plage():
    """Gtk.DropDown ignore set_selected(INVALID_LIST_POSITION) et garde sa
    position : seul un modele vide rend get_selected() hors plage, ce qui
    exerce reellement la branche de repli ("bytes")."""
    window = _make_window()
    window.stats_sort_drop.set_model(Gtk.StringList())
    assert window.stats_sort_drop.get_selected() == Gtk.INVALID_LIST_POSITION
    assert window._stats_sort_value() == "bytes"


# ================= _refresh_stats =================


def test_refresh_stats_sans_flux_desactive_la_vue():
    window = _make_window()
    window.last_flows = None
    window.last_flow_objects = None
    window.last_report = None

    window._refresh_stats()

    assert window.stats_expander.get_sensitive() is False
    assert window.stats_csv_btn.get_sensitive() is False
    assert window.stats_json_btn.get_sensitive() is False
    assert _liste_labels(window.stats_list_box) == ["(vide)"]


def test_refresh_stats_peuple_la_liste_conformement_a_run_stats():
    window = _make_window()
    report, flows = _poser_run(window)
    window.last_findings = None
    window.stats_group_drop.set_selected(0)  # "endpoint"
    window.stats_sort_drop.set_selected(0)  # "packets"
    window.stats_topn_spin.set_value(10)

    window._refresh_stats()

    attendu = run_stats(
        flows,
        report,
        build_query(group_by="endpoint", sort_by="packets", top_n=10),
        build_events_by_segment(None, flows),
    )
    assert attendu  # le scenario doit produire au moins une ligne
    assert window.last_stats_rows == attendu
    assert _liste_labels(window.stats_list_box) == ["(vide)"] + [format_row(r) for r in attendu]
    assert window.stats_expander.get_sensitive() is True
    assert window.stats_csv_btn.get_sensitive() is True
    assert window.stats_json_btn.get_sensitive() is True


# ================= _stats_clear_list / _stats_repopulate =================


def test_stats_repopulate_affiche_un_bouton_par_ligne():
    window = _make_window()
    _report, flows = _scenario()
    rows = [
        StatRow(label="10.0.0.1 <-> 10.0.0.2", group_by="endpoint", packets=2, bytes=200, flow_keys=[flows[0].key]),
        StatRow(label="10.0.0.3 <-> 10.0.0.4", group_by="endpoint", packets=1, bytes=64, flow_keys=[flows[1].key]),
    ]

    window._stats_repopulate(rows, flows)

    assert _liste_labels(window.stats_list_box) == ["(vide)"] + [format_row(r) for r in rows]


def test_stats_repopulate_liste_vide_affiche_le_placeholder():
    window = _make_window()

    window._stats_repopulate([], [])

    assert _liste_labels(window.stats_list_box) == ["(vide)"]


def test_stats_repopulate_le_clic_sur_une_ligne_declenche_le_drill_down():
    window = _make_window()
    _report, flows = _scenario()
    row = StatRow(label="Groupe A", group_by="endpoint", packets=2, bytes=200, flow_keys=[flows[0].key])

    window._stats_repopulate([row], flows)
    placeholder_vide = window.stats_list_box.get_first_child()  # "(vide)", voir _liste_labels
    ligne_bouton = placeholder_vide.get_next_sibling()
    ligne_bouton.get_child().emit("clicked")

    detail = flows_for_row(row, flows)
    labels_attendus = ["(vide)", "<-- Retour aux statistiques", f"{row.label} (1 flux)"]
    labels_attendus += [format_flow_summary(f) for f in detail]
    assert _liste_labels(window.stats_list_box) == labels_attendus


def test_stats_clear_list_vide_puis_affiche_le_placeholder():
    window = _make_window()
    _report, flows = _scenario()
    rows = [StatRow(label="TCP", group_by="protocol", packets=2, bytes=200, flow_keys=[flows[0].key])]
    window._stats_repopulate(rows, flows)
    assert len(_liste_labels(window.stats_list_box)) == 2  # "(vide)" + 1 ligne, voir _liste_labels

    window._stats_clear_list()

    assert _liste_labels(window.stats_list_box) == ["(vide)"]


# ================= _stats_select =================


def test_stats_select_affiche_le_retour_le_titre_et_les_flux_puis_le_retour_reaffiche_les_stats():
    window = _make_window()
    report, flows = _poser_run(window)
    row = StatRow(
        label="10.0.0.1 <-> 10.0.0.2",
        group_by="endpoint",
        packets=2,
        bytes=200,
        flow_keys=[flows[0].key],
    )

    window._stats_select(row, flows)

    detail = flows_for_row(row, flows)
    labels_attendus = ["(vide)", "<-- Retour aux statistiques", f"{row.label} (1 flux)"]
    labels_attendus += [format_flow_summary(f) for f in detail]
    assert _liste_labels(window.stats_list_box) == labels_attendus

    # Le bouton de retour re-declenche _refresh_stats (memes objets last_*).
    placeholder_vide = window.stats_list_box.get_first_child()  # "(vide)", voir _liste_labels
    back_row = placeholder_vide.get_next_sibling()
    back_row.get_child().emit("clicked")

    attendu = run_stats(
        flows,
        report,
        build_query(
            group_by=window._stats_group_value(),
            sort_by=window._stats_sort_value(),
            top_n=int(window.stats_topn_spin.get_value()),
        ),
        build_events_by_segment(None, flows),
    )
    assert _liste_labels(window.stats_list_box) == ["(vide)"] + [format_row(r) for r in attendu]


def test_stats_select_sans_flux_correspondants_affiche_aucun_flux():
    window = _make_window()
    row = StatRow(
        label="fantome",
        group_by="endpoint",
        packets=0,
        bytes=0,
        flow_keys=[("TCP", "9.9.9.9", 1, "9.9.9.8", 2, 0)],
    )

    window._stats_select(row, [])

    assert _liste_labels(window.stats_list_box) == [
        "(vide)",
        "<-- Retour aux statistiques",
        f"{row.label} (1 flux)",
        "(aucun flux)",
    ]


# ================= _on_stats_export_csv / _on_stats_csv_saved =================


def test_on_stats_export_csv_sans_lignes_n_ouvre_pas_de_dialogue(monkeypatch):
    window = _make_window()
    window.last_stats_rows = None
    appels = []

    def _fake_save(dialog_self, parent, cancellable, callback):
        appels.append((dialog_self, parent, cancellable, callback))

    monkeypatch.setattr(Gtk.FileDialog, "save", _fake_save)

    window._on_stats_export_csv(None)

    assert appels == []


def test_on_stats_export_csv_ouvre_un_file_dialog_csv(monkeypatch):
    window = _make_window()
    _poser_run(window)
    window._refresh_stats()
    assert window.last_stats_rows

    appels = []

    def _fake_save(dialog_self, parent, cancellable, callback):
        appels.append((dialog_self, parent, cancellable, callback))

    monkeypatch.setattr(Gtk.FileDialog, "save", _fake_save)

    window._on_stats_export_csv(None)

    assert len(appels) == 1
    dialog, parent, cancellable, callback = appels[0]
    assert isinstance(dialog, Gtk.FileDialog)
    assert parent is window
    assert cancellable is None
    assert callback == window._on_stats_csv_saved
    assert dialog.get_title() == "Exporter les statistiques en CSV"
    assert dialog.get_initial_name() == "netcross_stats.csv"
    assert dialog.get_default_filter().get_name() == "CSV"


def test_on_stats_csv_saved_annulation_n_ecrit_rien(monkeypatch, tmp_path):
    window = _make_window()
    _poser_run(window)
    window._refresh_stats()
    dialog = Gtk.FileDialog()

    def _raise(result):
        raise GLib.Error("Dismissed by user")

    monkeypatch.setattr(dialog, "save_finish", _raise)

    window._on_stats_csv_saved(dialog, None)  # ne doit pas lever

    assert list(tmp_path.iterdir()) == []
    assert window.status_label.get_text() == ""


def test_on_stats_csv_saved_fichier_none_n_ecrit_rien(monkeypatch, tmp_path):
    window = _make_window()
    _poser_run(window)
    window._refresh_stats()
    dialog = Gtk.FileDialog()
    monkeypatch.setattr(dialog, "save_finish", lambda result: None)

    window._on_stats_csv_saved(dialog, None)

    assert list(tmp_path.iterdir()) == []


def test_on_stats_csv_saved_sans_lignes_n_ecrit_rien(monkeypatch, tmp_path):
    window = _make_window()
    window.last_stats_rows = None
    dest = tmp_path / "stats.csv"
    dialog = Gtk.FileDialog()
    monkeypatch.setattr(dialog, "save_finish", lambda result: _FakeGFile(str(dest)))

    window._on_stats_csv_saved(dialog, None)

    assert not dest.exists()


def test_on_stats_csv_saved_succes_ecrit_le_csv_et_met_a_jour_le_statut(monkeypatch, tmp_path):
    window = _make_window()
    _poser_run(window)
    window._refresh_stats()
    rows = window.last_stats_rows
    dest = tmp_path / "stats.csv"
    dialog = Gtk.FileDialog()
    monkeypatch.setattr(dialog, "save_finish", lambda result: _FakeGFile(str(dest)))

    window._on_stats_csv_saved(dialog, None)

    # newline="" : le module csv ecrit des fins de ligne \r\n (RFC 4180) ;
    # sans cela, la lecture texte par defaut les normaliserait en \n et
    # casserait la comparaison octet a octet avec export_csv(rows).
    with open(dest, encoding="utf-8", newline="") as fh:
        contenu = fh.read()
    assert contenu == export_csv(rows)
    assert window.status_label.get_text() == f"Statistiques exportees : {dest}"


def test_on_stats_csv_saved_erreur_ecriture_affiche_le_statut_d_erreur(monkeypatch):
    window = _make_window()
    _poser_run(window)
    window._refresh_stats()
    dialog = Gtk.FileDialog()
    # Repertoire inexistant -> OSError a l'ouverture en ecriture.
    chemin_invalide = "/chemin/inexistant/stats.csv"
    monkeypatch.setattr(dialog, "save_finish", lambda result: _FakeGFile(chemin_invalide))

    window._on_stats_csv_saved(dialog, None)

    assert window.status_label.get_text().startswith("Erreur export CSV :")
