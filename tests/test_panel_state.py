"""
Tests des decisions de panneaux de la GUI (`netcross_gtk4/panel_state.py`).

Troisieme lot de l'issue #285. Ces regles decidaient, depuis
`MainWindow`, quels panneaux sont visibles, quelles options sont
utilisables et ce que produit un clic dans le tableau de bord. Une erreur
ici ne leve rien : l'interface a simplement l'air cassee -- un panneau
dans le mauvais mode, une case cochee mais inoperante, un bouton grise
sans raison, un clic sans effet.
"""

import dataclasses
import itertools

import pytest

from netcross_gtk4.dashboard_context import DashboardSelection
from netcross_gtk4.panel_state import (
    LABEL_DEMARRER_CAPTURE,
    LABEL_LANCER_ANALYSE,
    POINTS_MINIMUM,
    TYPES_DE_VUE,
    PanelVisibility,
    UnknownViewTypeError,
    apply_dashboard_selection,
    comm_map_filters,
    panel_visibility,
    run_button_state,
    selected_protocol,
)

MODES = list(itertools.product([False, True], repeat=2))


# --------------------------------------------------------------------------
# Visibilite des panneaux
# --------------------------------------------------------------------------


def test_le_panneau_simple_n_apparait_que_hors_diff_et_hors_live():
    assert panel_visibility(False, False, False).single_panel is True
    assert panel_visibility(True, False, False).single_panel is False
    assert panel_visibility(False, True, False).single_panel is False
    assert panel_visibility(True, True, False).single_panel is False


def test_chaque_cote_a_un_seul_panneau_de_saisie():
    """Deux panneaux de saisie pour un meme cote laisseraient l'utilisateur
    remplir celui qui ne sera pas lu : le courant vient soit des fichiers
    (panneau « Courant »), soit de la capture en direct, jamais des deux."""
    for diff_mode, live_mode in MODES:
        vue = panel_visibility(diff_mode, live_mode, False)
        assert not (vue.current_panel and vue.live_panel), (diff_mode, live_mode)
        assert not (vue.single_panel and (vue.live_panel or vue.diff_panels)), (diff_mode, live_mode)


def test_comparaison_avec_un_courant_capture_en_direct():
    """Issue #676 (equivalent de --live-current) : baseline enregistre +
    courant capture en direct. Le panneau live remplace le panneau
    « Courant » des fichiers ; le tampon circulaire, propre a la capture
    simple, est masque ; TLS/QUIC et la lecture parallele sont indisponibles,
    comme dans la CLI."""
    vue = panel_visibility(True, True, False)
    assert vue.diff_panels is True  # contient le baseline
    assert vue.current_panel is False
    assert vue.live_panel is True
    assert vue.live_extra is True  # duree de capture
    assert vue.ring_buffer is False
    assert vue.single_panel is False
    assert vue.diff_options is True
    assert vue.single_options is False
    assert vue.force_tls_off and vue.force_quic_off
    assert vue.parallel_sensitive is False


def test_le_panneau_courant_et_le_tampon_circulaire_hors_combinaison():
    assert panel_visibility(True, False, False).current_panel is True
    assert panel_visibility(False, True, False).ring_buffer is True
    assert panel_visibility(False, False, False).ring_buffer is False


def test_au_moins_un_panneau_de_saisie_reste_visible():
    """Une page de configuration sans aucun panneau serait un cul-de-sac :
    aucune capture ne pourrait etre ajoutee et rien ne l'expliquerait."""
    for diff_mode, live_mode in MODES:
        vue = panel_visibility(diff_mode, live_mode, False)
        assert vue.single_panel or vue.live_panel or vue.diff_panels, (diff_mode, live_mode)


def test_les_options_simples_et_diff_sont_exclusives():
    for diff_mode, live_mode in MODES:
        vue = panel_visibility(diff_mode, live_mode, False)
        assert vue.single_options != vue.diff_options


def test_le_triage_reste_disponible_en_capture_live():
    """Contrairement a TLS/QUIC, le triage ne relit pas les fichiers de
    capture : il reste pertinent en live. `single_options` ne depend donc que
    de `diff_mode`. Cette distinction etait un commentaire dans app.py ; elle
    est maintenant verifiee."""
    assert panel_visibility(False, True, False).single_options is True


def test_tls_et_quic_restent_visibles_mais_insensibles_en_live():
    """Ces diagnostics relisent les fichiers passes a --capture, et une
    capture live n'en produit pas. Les masquer laisserait croire que l'outil
    n'en est pas capable ; les griser dit « pas dans ce mode »."""
    vue = panel_visibility(False, True, False)
    assert vue.tls_sensitive is False
    assert vue.quic_sensitive is False
    assert vue.single_options is True  # la boite qui les contient reste visible


def test_tls_et_quic_sont_forces_a_inactif_en_live():
    """Une case cochee mais grisee serait un mensonge : l'utilisateur
    croirait l'option active alors qu'elle sera ignoree."""
    vue = panel_visibility(False, True, False)
    assert vue.force_tls_off is True
    assert vue.force_quic_off is True


def test_tls_et_quic_ne_sont_pas_forces_hors_live():
    """Symetrie indispensable : forcer hors live decocherait un choix
    delibere de l'utilisateur a chaque rafraichissement de l'interface."""
    for diff_mode in (False, True):
        vue = panel_visibility(diff_mode, False, False)
        assert vue.force_tls_off is False
        assert vue.force_quic_off is False


def test_la_lecture_parallele_est_insensible_en_live():
    assert panel_visibility(False, True, False).parallel_sensitive is False
    assert panel_visibility(False, False, False).parallel_sensitive is True


def test_les_seuils_de_doublons_suivent_la_detection():
    """Un seuil reglable alors que rien ne le consomme invite a perdre du
    temps sur une valeur sans effet."""
    actif = panel_visibility(False, False, True)
    assert actif.duplicate_threshold_sensitive is True
    assert actif.duplicate_exclude_sensitive is True

    inactif = panel_visibility(False, False, False)
    assert inactif.duplicate_detect_sensitive is True
    assert inactif.duplicate_threshold_sensitive is False
    assert inactif.duplicate_exclude_sensitive is False


def test_les_doublons_sont_indisponibles_et_forces_en_mode_comparaison():
    """La detection compare deux points d'une meme capture ; elle n'a pas de
    sens entre une reference et un courant."""
    vue = panel_visibility(True, False, True)
    assert vue.duplicate_detect_sensitive is False
    assert vue.duplicate_threshold_sensitive is False
    assert vue.duplicate_exclude_sensitive is False
    assert vue.force_duplicate_detect_off is True
    assert vue.force_duplicate_exclude_off is True


def test_un_controle_force_a_inactif_est_toujours_insensible():
    """Invariant transverse : forcer une case a inactif tout en la laissant
    utilisable produirait un aller-retour visible -- l'utilisateur coche,
    l'interface decoche."""
    for diff_mode, live_mode in MODES:
        for detecte in (False, True):
            vue = panel_visibility(diff_mode, live_mode, detecte)
            if vue.force_tls_off:
                assert not vue.tls_sensitive
            if vue.force_quic_off:
                assert not vue.quic_sensitive
            if vue.force_duplicate_detect_off:
                assert not vue.duplicate_detect_sensitive


def test_la_decision_de_visibilite_est_gelee():
    with pytest.raises(dataclasses.FrozenInstanceError):
        panel_visibility(False, False, False).single_panel = True  # type: ignore[misc]


def test_tous_les_champs_de_visibilite_sont_booleens():
    """Un `None` glisse dans un de ces champs serait lu comme « faux » par
    GTK, masquant un panneau au lieu de signaler l'incoherence."""
    vue = panel_visibility(True, False, True)
    for champ in PanelVisibility.__dataclass_fields__:
        assert isinstance(getattr(vue, champ), bool), champ


# --------------------------------------------------------------------------
# Bouton Lancer
# --------------------------------------------------------------------------


def _bouton(**surcharges):
    args = {
        "live_capturing": False,
        "diff_mode": False,
        "live_mode": False,
        "single_rows": 0,
        "baseline_rows": 0,
        "current_rows": 0,
        "live_points": 0,
        "label_actuel": LABEL_LANCER_ANALYSE,
    }
    args.update(surcharges)
    return run_button_state(**args)


def test_l_analyse_simple_exige_deux_captures():
    assert _bouton(single_rows=1).enabled is False
    assert _bouton(single_rows=POINTS_MINIMUM).enabled is True


def test_la_comparaison_exige_deux_captures_de_chaque_cote():
    """Un seul cote suffisant produirait une comparaison entre une analyse
    croisee et un point isole, ce qui n'a pas de sens."""
    assert _bouton(diff_mode=True, baseline_rows=2, current_rows=1).enabled is False
    assert _bouton(diff_mode=True, baseline_rows=1, current_rows=2).enabled is False
    assert _bouton(diff_mode=True, baseline_rows=2, current_rows=2).enabled is True


def test_comparaison_avec_courant_en_direct_compte_baseline_et_points_live():
    """Issue #676 : le courant vient de la capture en direct ; le panneau
    « Courant » des fichiers (masque) n'est pas compte."""
    assert _bouton(diff_mode=True, live_mode=True, baseline_rows=2, live_points=1).enabled is False
    assert _bouton(diff_mode=True, live_mode=True, baseline_rows=1, live_points=2).enabled is False
    etat = _bouton(diff_mode=True, live_mode=True, baseline_rows=2, current_rows=0, live_points=2)
    assert etat.enabled is True
    assert etat.label == LABEL_DEMARRER_CAPTURE
    refus = _bouton(diff_mode=True, live_mode=True, baseline_rows=2, current_rows=5, live_points=1)
    assert "points de capture : 1" in refus.raison


def test_la_capture_live_compte_les_points_apres_eclatement():
    """Une seule ligne « eth0, eth1 » donne deux points (Job 48). Compter les
    lignes refuserait a tort une configuration valide sur une machine a deux
    interfaces -- et l'utilisateur ne verrait qu'un bouton grise."""
    assert _bouton(live_mode=True, live_points=1).enabled is False
    assert _bouton(live_mode=True, live_points=2).enabled is True


def test_le_mode_ignore_les_compteurs_des_autres_modes():
    """Sans cette separation, remplir le panneau simple activerait le bouton
    en mode comparaison, et l'analyse partirait sur des captures vides."""
    assert _bouton(diff_mode=True, single_rows=9, baseline_rows=0, current_rows=0).enabled is False
    assert _bouton(live_mode=True, single_rows=9, live_points=0).enabled is False
    assert _bouton(single_rows=2, baseline_rows=0, current_rows=0, live_points=0).enabled is True


def test_le_refus_est_toujours_motive():
    """C'est l'apport de ce lot : la raison est connue au moment de la
    decision, donc la taire serait un choix. Un bouton grise sans
    explication oblige l'utilisateur a deviner combien de captures il
    manque."""
    for etat in (
        _bouton(single_rows=1),
        _bouton(diff_mode=True, baseline_rows=1, current_rows=5),
        _bouton(live_mode=True, live_points=0),
    ):
        assert etat.enabled is False
        assert etat.raison
        assert str(POINTS_MINIMUM) in etat.raison


def test_la_raison_cite_les_compteurs_reels():
    """Dire « 2 minimum » sans dire « vous en avez 1 » laisse l'utilisateur
    recompter lui-meme."""
    etat = _bouton(diff_mode=True, baseline_rows=1, current_rows=3)
    assert "reference : 1" in etat.raison
    assert "courant : 3" in etat.raison

    live = _bouton(live_mode=True, live_points=1)
    assert "apres eclatement" in live.raison
    assert "1 pour l'instant" in live.raison


def test_aucune_raison_quand_le_bouton_est_actif():
    """Une explication affichee alors que tout va bien serait du bruit et
    finirait par etre ignoree, y compris quand elle compte."""
    assert _bouton(single_rows=2).raison is None
    assert _bouton(diff_mode=True, baseline_rows=2, current_rows=2).raison is None
    assert _bouton(live_mode=True, live_points=2).raison is None


def test_le_libelle_suit_le_mode():
    assert _bouton(single_rows=2).label == LABEL_LANCER_ANALYSE
    assert _bouton(diff_mode=True, baseline_rows=2, current_rows=2).label == LABEL_LANCER_ANALYSE
    assert _bouton(live_mode=True, live_points=2).label == LABEL_DEMARRER_CAPTURE


def test_une_capture_en_cours_n_est_jamais_desactivee_ni_renommee():
    """Pendant une capture, le bouton sert a l'arreter : le recalculer sur
    les compteurs le griserait ou le renommerait au premier changement de
    case, rendant l'arret impossible. La raison le dit au lieu de retourner
    un etat muet."""
    etat = _bouton(live_capturing=True, live_points=0, label_actuel="Arreter la capture")
    assert etat.enabled is True
    assert etat.label == "Arreter la capture"
    assert "capture en cours" in etat.raison


# --------------------------------------------------------------------------
# Filtres de la cartographie
# --------------------------------------------------------------------------


def test_l_entree_tous_les_protocoles_ne_filtre_pas():
    """L'index 0 est l'entree « tous » : renvoyer son libelle filtrerait sur
    un protocole nomme « Tous » et donnerait une carte vide."""
    assert selected_protocol(0, 4, lambda i: ["Tous", "TCP", "UDP", "TLS"][i]) is None


def test_un_protocole_choisi_est_renvoye():
    assert selected_protocol(2, 4, lambda i: ["Tous", "TCP", "UDP", "TLS"][i]) == "UDP"


def test_un_index_hors_bornes_ne_filtre_pas():
    """GTK renvoie `Gtk.INVALID_LIST_POSITION` (un tres grand entier) quand
    rien n'est selectionne : une lecture directe leverait au milieu d'un
    rafraichissement d'interface."""
    appels = []

    def lire(i):
        appels.append(i)
        return "jamais"

    assert selected_protocol(4294967295, 4, lire) is None
    assert selected_protocol(-1, 4, lire) is None
    assert selected_protocol(4, 4, lire) is None
    assert appels == [], "aucune lecture ne doit etre tentee hors bornes"


def test_une_liste_vide_ne_filtre_pas():
    assert selected_protocol(0, 0, lambda i: "jamais") is None


def test_les_filtres_absents_valent_none_et_non_liste_vide():
    """En aval, `None` signifie « pas de filtre » tandis qu'une liste vide
    signifierait « filtrer sur aucun protocole », c'est-a-dire un ecran blanc
    sans message."""
    filtres = comm_map_filters(None, 20, False)
    assert filtres["protocols"] is None
    assert filtres["top_n"] == 20
    assert filtres["only_anomalies"] is False


def test_les_filtres_enveloppent_le_protocole_dans_une_liste():
    assert comm_map_filters("TLS", 5, True)["protocols"] == ["TLS"]


def test_les_filtres_normalisent_les_types_venus_des_widgets():
    """`get_value()` d'un SpinButton renvoie un flottant et `get_active()` un
    entier selon les liaisons : le rendu en aval indexe avec `top_n`."""
    filtres = comm_map_filters("TCP", 12.0, 1)
    assert filtres["top_n"] == 12
    assert isinstance(filtres["top_n"], int)
    assert filtres["only_anomalies"] is True


# --------------------------------------------------------------------------
# Selection au tableau de bord
# --------------------------------------------------------------------------


def test_chaque_type_de_vue_produit_une_selection():
    """Le parcours couvre TYPES_DE_VUE plutot qu'une liste recopiee : un type
    ajoute au module sans branche correspondante fait echouer ce test."""
    for kind in TYPES_DE_VUE:
        selection = apply_dashboard_selection(
            kind,
            DashboardSelection(),
            1 if kind in ("bucket", "event") else "valeur",
            flow_par_cle=lambda _cle: None,
            evenements=[],
        )
        assert selection is not None, kind


def test_un_type_de_vue_inconnu_leve_au_lieu_de_ne_rien_faire():
    """L'ancien code enchainait des `elif` sans branche finale : un type mal
    orthographie traversait la cascade, la selection repartait inchangee et
    l'interface se rafraichissait a l'identique. Les clics d'une vue entiere
    devenaient inoperants, sans message ni trace, et aucun test ne pouvait
    l'attraper."""
    with pytest.raises(UnknownViewTypeError) as erreur:
        apply_dashboard_selection("segment", DashboardSelection(), "A")
    assert "segment" in str(erreur.value)
    assert "bucket" in str(erreur.value), "le message doit lister les types attendus"


def test_le_type_point_est_bien_celui_des_segments():
    """La vue « Segments » utilise le type `point` et non `segment` : la
    selection porte sur un point de capture. C'est volontaire, et c'est
    exactement l'ecart qui justifie de valider le type plutot que de
    l'ignorer."""
    selection = apply_dashboard_selection("point", DashboardSelection(), "POINT_A")
    assert selection.point == "POINT_A"
    assert "segment" not in TYPES_DE_VUE


def test_une_cle_de_flux_introuvable_laisse_la_selection_inchangee():
    """Comportement d'origine conserve : le flux a pu disparaitre entre
    l'affichage de la liste et le clic. Lever ici transformerait une course
    benigne en erreur visible."""
    depart = DashboardSelection(endpoint="10.0.0.1")
    arrivee = apply_dashboard_selection("flow", depart, "cle-absente", flow_par_cle=lambda _cle: None)
    assert arrivee == depart


def test_un_flux_trouve_propage_endpoint_protocole_et_paire():
    """Le chemin nominal : `select_flow` derive l'endpoint, le protocole et
    -- seulement si le flux a ete vu sur exactement deux points -- la paire de
    segment. Ne tester que le cas « flux introuvable » laissait ce chemin
    sans verification alors que c'est celui qu'un clic emprunte."""

    class _Flux:
        key = ("TCP", "10.0.0.1:443", "10.0.0.2:51000")
        endpoints = ("10.0.0.1", "10.0.0.2")
        points = ("POINT_A", "POINT_B")

    selection = apply_dashboard_selection(
        "flow", DashboardSelection(), "peu-importe", flow_par_cle=lambda _cle: _Flux()
    )
    assert selection.flow_key == _Flux.key
    assert selection.endpoint == "10.0.0.1"
    assert selection.protocol == "TCP"
    assert selection.pair == ("POINT_A", "POINT_B")


def test_un_flux_vu_sur_un_seul_point_ne_definit_pas_de_paire():
    """Un flux vu sur un seul point (ou sur trois et plus) ne designe pas un
    segment A -> B : inventer une paire ferait filtrer le tableau de bord sur
    un segment qui n'existe pas."""

    class _FluxUnPoint:
        key = ("UDP", "a", "b")
        endpoints = ("10.0.0.1", "10.0.0.2")
        points = ("POINT_A",)

    selection = apply_dashboard_selection("flow", DashboardSelection(), "k", flow_par_cle=lambda _cle: _FluxUnPoint())
    assert selection.pair is None
    assert selection.flow_key == _FluxUnPoint.key


def test_une_selection_de_flux_sans_resolveur_est_refusee():
    """Appeler sans `flow_par_cle` est une erreur de programmation, pas une
    donnee douteuse : mieux vaut lever que selectionner silencieusement
    rien."""
    with pytest.raises(UnknownViewTypeError):
        apply_dashboard_selection("flow", DashboardSelection(), "cle")


def test_la_selection_d_origine_n_est_jamais_modifiee():
    """`DashboardSelection` est immuable et les `select_*` renvoient une
    copie : une mutation sur place ferait diverger l'etat partage du tableau
    de bord de ce qui est affiche."""
    depart = DashboardSelection()
    apply_dashboard_selection("endpoint", depart, "10.0.0.2")
    assert depart.endpoint is None


def test_la_selection_d_evenement_accepte_une_liste_absente():
    """`_dashboard_events()` peut renvoyer `None` quand aucune analyse n'a
    tourne : le clic ne doit pas faire tomber l'interface."""
    assert apply_dashboard_selection("event", DashboardSelection(), 1, evenements=None) is not None
