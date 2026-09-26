"""Tests app.py -- lot 3/10 (issue #424, sous-issue de #421) : listes de
captures + bascules de MainWindow (lignes 479-1073).

Meme garde-fou que le lot precedent (`test_gui_security_window.py`, issue
#357) : sautable en CI sans GTK4/pygobject ni affichage.

A partir de ce lot, `MainWindow` est instanciee (fixture "window", scope
module) : `_run_button_state`/`_sync_panel_visibility` lisent et ecrivent de
vrais widgets, pas seulement la logique pure deja couverte par
`test_panel_state.py`. La fenetre etant partagee entre les tests, une fixture
autouse la remet dans un etat neutre (cases decochees, listes vides) avant ET
apres chaque test -- l'ordre des tests ne doit jamais compter.
"""

import json

import pytest

gi = pytest.importorskip("gi", reason="pygobject absent")
try:
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk
except (ValueError, ImportError):
    pytest.skip("GTK4 absent", allow_module_level=True)
if not Gtk.init_check():
    pytest.skip("pas d'affichage pour GTK4", allow_module_level=True)

from netcross_core.bpf_filters import PREDEFINED_BPF_FILTERS  # noqa: E402
from netcross_core.models import BPFFilter  # noqa: E402
from netcross_gtk4.app import CaptureListPanel, LiveCaptureListPanel, MainWindow  # noqa: E402
from netcross_gtk4.panel_state import LABEL_DEMARRER_CAPTURE, LABEL_LANCER_ANALYSE  # noqa: E402


@pytest.fixture(scope="module")
def window():
    app = Gtk.Application(application_id="org.netcross.test424")
    app.register(None)
    return MainWindow(app)


def _clear_listbox(listbox):
    """Vide un Gtk.ListBox -- meme technique que _dashboard_clear_sections/
    _stats_clear_list dans app.py."""
    child = listbox.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        listbox.remove(child)
        child = nxt


def _reset_window(window):
    """Etat neutre : aucune case cochee, aucune ligne dans les panneaux.
    Necessaire car `window` (scope module) est partagee entre les tests."""
    for check in (
        window.diff_check,
        window.live_check,
        window.detect_duplicates_check,
        window.exclude_duplicates_check,
        window.ring_buffer_check,
        window.tls_check,
    ):
        if check.get_active():
            check.set_active(False)
    for panel in (window.single_panel, window.baseline_panel, window.current_panel, window.live_panel):
        _clear_listbox(panel.listbox)
    window._live_capturing = False
    window.run_btn.set_label(LABEL_LANCER_ANALYSE)
    window._update_run_sensitivity()
    window._update_run_button_label()


@pytest.fixture(autouse=True)
def _etat_neutre(window):
    _reset_window(window)
    yield
    _reset_window(window)


# ========================================================================
# CaptureListPanel : add_row / rows / captures
# ========================================================================


def test_capture_list_panel_add_row_sans_selecteur_de_fichiers():
    """`add_row` doit fonctionner sans passer par le Gtk.FileDialog (voir
    _on_files_chosen) -- c'est ce qui rend le panneau pilotable en test."""
    panel = CaptureListPanel("Points de capture")
    row = panel.add_row("/tmp/lan-a.pcapng")
    assert row.label == "LAN-A"
    assert row.path == "/tmp/lan-a.pcapng"


def test_capture_list_panel_add_row_avec_label_explicite():
    panel = CaptureListPanel("Points de capture")
    row = panel.add_row("/tmp/quelconque.pcap", default_label="WAN")
    assert row.label == "WAN"


def test_capture_list_panel_add_row_declenche_on_change():
    appels = []
    panel = CaptureListPanel("Points de capture", on_change=lambda: appels.append(True))
    panel.add_row("/tmp/a.pcap")
    assert appels == [True]


def test_capture_list_panel_rows_et_captures_dans_l_ordre_visuel():
    panel = CaptureListPanel("Points de capture")
    panel.add_row("/tmp/lan.pcap", default_label="LAN")
    panel.add_row("/tmp/wan.pcap", default_label="WAN")
    rows = panel.rows()
    assert [r.label for r in rows] == ["LAN", "WAN"]
    assert panel.captures() == [("LAN", "/tmp/lan.pcap"), ("WAN", "/tmp/wan.pcap")]


# ========================================================================
# LiveCaptureListPanel : add_row / rows / captures
# ========================================================================


def test_live_capture_list_panel_add_row_nom_par_defaut(tmp_path):
    panel = LiveCaptureListPanel("Points en direct", filters_path=tmp_path / "filtres.json")
    assert panel.add_row().label == "POINT1"
    assert panel.add_row().label == "POINT2"


def test_live_capture_list_panel_add_row_avec_valeurs_explicites(tmp_path):
    panel = LiveCaptureListPanel("Points en direct", filters_path=tmp_path / "filtres.json")
    row = panel.add_row("LAN", interface="eth0", bpf_filter="tcp port 80")
    assert row.label == "LAN"
    assert row.interface == "eth0"
    assert row.bpf_filter == "tcp port 80"


def test_live_capture_list_panel_add_row_declenche_on_change(tmp_path):
    appels = []
    panel = LiveCaptureListPanel(
        "Points en direct",
        on_change=lambda: appels.append(True),
        filters_path=tmp_path / "filtres.json",
    )
    panel.add_row()
    assert appels == [True]


def test_live_capture_list_panel_rows_et_captures_dans_l_ordre_visuel(tmp_path):
    panel = LiveCaptureListPanel("Points en direct", filters_path=tmp_path / "filtres.json")
    panel.add_row("LAN", interface="eth0")
    panel.add_row("WAN", interface="eth1", bpf_filter="tcp port 443")
    assert [r.label for r in panel.rows()] == ["LAN", "WAN"]
    assert panel.captures() == [("LAN", "eth0", None), ("WAN", "eth1", "tcp port 443")]


# ========================================================================
# _initial_filters / _save_filter -- fichier isole via tmp_path, jamais
# ~/.netcross/bpf_filters.json du systeme
# ========================================================================


def test_initial_filters_fichier_absent_donne_le_catalogue_predefini_seul(tmp_path):
    panel = LiveCaptureListPanel("Points en direct", filters_path=tmp_path / "absent.json")
    assert panel._filters == list(PREDEFINED_BPF_FILTERS)


def test_initial_filters_fichier_present_ajoute_les_filtres_sauvegardes(tmp_path):
    chemin = tmp_path / "filtres.json"
    chemin.write_text(
        json.dumps({"version": 1, "filters": [{"name": "Web interne", "expression": "net 10.0.0.0/8"}]}),
        encoding="utf-8",
    )
    panel = LiveCaptureListPanel("Points en direct", filters_path=chemin)
    noms = [f.name for f in panel._filters]
    assert noms[: len(PREDEFINED_BPF_FILTERS)] == [f.name for f in PREDEFINED_BPF_FILTERS]
    assert "Web interne" in noms


def test_initial_filters_fichier_illisible_replie_sur_le_catalogue(tmp_path):
    """Un fichier sidecar corrompu (JSON invalide) ne doit pas empecher la
    construction du panneau : le catalogue predefini reste utilisable et le
    fichier n'est pas touche (voir docstring de `_initial_filters`)."""
    chemin = tmp_path / "corrompu.json"
    chemin.write_text("{ceci n'est pas du JSON", encoding="utf-8")

    panel = LiveCaptureListPanel("Points en direct", filters_path=chemin)

    assert panel._filters == list(PREDEFINED_BPF_FILTERS)
    assert chemin.read_text(encoding="utf-8") == "{ceci n'est pas du JSON"  # fichier non touche


def test_save_filter_persiste_et_rafraichit_les_lignes_existantes(tmp_path):
    chemin = tmp_path / "filtres.json"
    panel = LiveCaptureListPanel("Points en direct", filters_path=chemin)
    row = panel.add_row()
    assert not any(f.name == "Interne" for f in row._filters)

    panel._save_filter(BPFFilter("Interne", "net 10.0.0.0/8", "reseau interne"))

    assert any(f.name == "Interne" for f in panel._filters)
    assert any(f.name == "Interne" for f in row._filters), "menu de la ligne deja existante rafraichi"

    # persistance effective : relecture directe du fichier ecrit par upsert_bpf_filter
    relu = json.loads(chemin.read_text(encoding="utf-8"))
    assert any(f["name"] == "Interne" for f in relu["filters"])


# ========================================================================
# Bascules de MainWindow -- effet sur les VRAIS widgets (la logique pure
# est deja couverte par test_panel_state.py)
# ========================================================================


def test_on_diff_toggled_affiche_les_panneaux_de_comparaison(window):
    window.diff_check.set_active(True)
    assert window.diff_panels_box.get_visible() is True
    assert window.single_panel.get_visible() is False
    assert window.single_options_box.get_visible() is False
    assert window.diff_options_box.get_visible() is True
    assert window.live_check.get_sensitive() is False


def test_on_diff_toggled_desactive_le_live_actif(window):
    window.live_check.set_active(True)
    assert window.live_panel.get_visible() is True

    window.diff_check.set_active(True)  # doit declencher _on_live_toggled(False) en cascade

    assert window.live_check.get_active() is False
    assert window.live_panel.get_visible() is False
    assert window.diff_panels_box.get_visible() is True


def test_on_duplicate_detection_toggled_active_le_seuil_et_l_exclusion(window):
    window.detect_duplicates_check.set_active(True)
    assert window.duplicate_threshold_spin.get_sensitive() is True
    assert window.exclude_duplicates_check.get_sensitive() is True


def test_on_duplicate_detection_toggled_desactive_decoche_l_exclusion(window):
    window.detect_duplicates_check.set_active(True)
    window.exclude_duplicates_check.set_active(True)

    window.detect_duplicates_check.set_active(False)

    assert window.exclude_duplicates_check.get_active() is False
    assert window.duplicate_threshold_spin.get_sensitive() is False
    assert window.exclude_duplicates_check.get_sensitive() is False


def test_on_duplicate_exclusion_toggled_active_automatiquement_la_detection(window):
    assert window.detect_duplicates_check.get_active() is False
    window.exclude_duplicates_check.set_active(True)
    assert window.detect_duplicates_check.get_active() is True


def test_on_live_toggled_affiche_le_panneau_live(window):
    window.live_check.set_active(True)
    assert window.live_panel.get_visible() is True
    assert window.live_extra_box.get_visible() is True
    assert window.single_panel.get_visible() is False
    assert window.diff_check.get_sensitive() is False


def test_on_live_toggled_desactive_le_diff_actif(window):
    window.diff_check.set_active(True)
    assert window.diff_panels_box.get_visible() is True

    window.live_check.set_active(True)  # doit declencher _on_diff_toggled(False) en cascade

    assert window.diff_check.get_active() is False
    assert window.diff_panels_box.get_visible() is False
    assert window.live_panel.get_visible() is True


def test_on_ring_buffer_toggled_active_les_spinbuttons_de_configuration(window):
    assert window.ring_max_files_spin.get_sensitive() is False
    assert window.ring_max_duration_spin.get_sensitive() is False

    window.ring_buffer_check.set_active(True)
    assert window.ring_max_files_spin.get_sensitive() is True
    assert window.ring_max_duration_spin.get_sensitive() is True

    window.ring_buffer_check.set_active(False)
    assert window.ring_max_files_spin.get_sensitive() is False
    assert window.ring_max_duration_spin.get_sensitive() is False


def test_sync_panel_visibility_force_tls_off_en_capture_live(window):
    """TLS/QUIC relisent des fichiers ; une capture live n'en produit pas
    (voir panel_state.force_tls_off) -- verifie ici sur le vrai Gtk.CheckButton,
    pas seulement sur PanelVisibility."""
    window.tls_check.set_active(True)

    window.live_check.set_active(True)  # -> _sync_panel_visibility()

    assert window.tls_check.get_active() is False
    assert window.tls_check.get_sensitive() is False


def test_sync_panel_visibility_le_live_ne_force_pas_la_detection_de_doublons(window):
    """Contrairement a TLS/QUIC, la detection de doublons reste pertinente
    en capture live (elle ne relit pas de fichier) : seul le mode
    comparaison la desactive (voir test_panel_state.py)."""
    window.detect_duplicates_check.set_active(True)

    window.live_check.set_active(True)

    assert window.detect_duplicates_check.get_active() is True
    assert window.detect_duplicates_check.get_sensitive() is True


# ========================================================================
# _run_button_state / _update_run_button_label / _update_run_sensitivity
# ========================================================================


def test_run_button_devient_sensible_avec_deux_captures_simples(window):
    window.single_panel.add_row("/tmp/a.pcap", default_label="A")
    window.single_panel.add_row("/tmp/b.pcap", default_label="B")

    window._update_run_sensitivity()
    window._update_run_button_label()

    assert window.run_btn.get_sensitive() is True
    assert window.run_btn.get_label() == LABEL_LANCER_ANALYSE
    assert window.run_btn.get_tooltip_text() is None


def test_run_button_reste_insensible_avec_une_seule_capture_simple(window):
    window.single_panel.add_row("/tmp/a.pcap", default_label="A")

    window._update_run_sensitivity()
    window._update_run_button_label()

    assert window.run_btn.get_sensitive() is False
    assert window.run_btn.get_label() == LABEL_LANCER_ANALYSE
    assert window.run_btn.get_tooltip_text()  # raison du refus affichee en infobulle


def test_run_button_libelle_et_sensibilite_en_mode_live(window):
    window.live_check.set_active(True)
    window.live_panel.add_row("LAN", interface="eth0")
    window.live_panel.add_row("WAN", interface="eth1")

    window._update_run_sensitivity()
    window._update_run_button_label()

    assert window.run_btn.get_label() == LABEL_DEMARRER_CAPTURE
    assert window.run_btn.get_sensitive() is True


def test_run_button_insensible_en_mode_live_sous_le_minimum(window):
    window.live_check.set_active(True)
    window.live_panel.add_row("LAN", interface="eth0")  # un seul point : POINTS_MINIMUM = 2

    window._update_run_sensitivity()
    window._update_run_button_label()

    assert window.run_btn.get_label() == LABEL_DEMARRER_CAPTURE
    assert window.run_btn.get_sensitive() is False
    assert window.run_btn.get_tooltip_text()


def test_run_button_ignore_les_mises_a_jour_pendant_une_capture_en_cours(window):
    """Pendant une capture live, le bouton sert a l'arreter : le recalculer
    sur les compteurs le griserait ou le renommerait (voir docstring de
    _update_run_button_label/_update_run_sensitivity dans app.py)."""
    window._live_capturing = True
    window.run_btn.set_sensitive(True)
    window.run_btn.set_label("Arreter et analyser")

    window._update_run_sensitivity()
    window._update_run_button_label()

    assert window.run_btn.get_sensitive() is True
    assert window.run_btn.get_label() == "Arreter et analyser"


def test_run_button_state_mode_diff_reflete_les_compteurs_des_deux_panneaux(window):
    window.diff_check.set_active(True)
    window.baseline_panel.add_row("/tmp/base1.pcap")
    window.baseline_panel.add_row("/tmp/base2.pcap")
    window.current_panel.add_row("/tmp/cur1.pcap")

    etat = window._run_button_state()

    assert etat.enabled is False
    assert "courant : 1" in etat.raison

    window.current_panel.add_row("/tmp/cur2.pcap")
    etat = window._run_button_state()
    assert etat.enabled is True
    assert etat.raison is None
