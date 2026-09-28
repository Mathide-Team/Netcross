"""
Tests des graphiques (`netcross_report/charts.py`) -- issue #286.

Module a 41,2 % sans fichier de test dedie. Un graphique est la sortie la
plus trompeuse d'un rapport : contrairement a un tableau vide, il ne montre
pas qu'il manque des donnees. Une serie vide, une valeur unique avec une
echelle automatique, une legende decalee -- rien n'echoue, et le lecteur
tire une conclusion de ce qu'il croit voir.

## Ce qui est verifie

Pas l'apparence : aucune comparaison d'image, aucune inspection de pixels.
Trois choses seulement, qui sont celles qui peuvent tromper :

1. **L'absence de donnee ne produit PAS de graphique.** Ces fonctions
   renvoient `None`, et `generate_pdf` teste la presence de la cle avant
   d'inserer l'image. C'est le bon choix -- un graphique a zero barre serait
   lu comme « mesure a zero » et non « pas de mesure » -- mais c'est aussi un
   contrat implicite entre deux modules, donc a verrouiller : si une fonction
   se mettait a renvoyer un chemin sur serie vide, le PDF afficherait un
   graphique muet sans que rien ne le signale.
2. **Un fichier annonce comme ecrit existe et n'est pas vide.** Renvoyer un
   chemin vers un fichier absent ou tronque produirait un PDF casse ou une
   image blanche.
3. **Le cas d'une seule valeur** ne fait pas tomber le rendu (c'est un cas
   frequent : une capture courte, un seul segment).

Les cas vides sont majoritaires dans ce fichier parce que c'est la ou se
trouvait le code non couvert, et parce qu'une section « pas de donnee » mal
geree est precisement le defaut que la regle de tracabilite du projet vise.
"""

from __future__ import annotations

import os

import pytest

from netcross_core.models import Report
from netcross_report.charts import (
    chart_latency,
    chart_loss,
    chart_sequence_diagram,
    chart_severity_summary,
    chart_throughput,
    chart_topology,
)
from netcross_report.synthesis import build_findings

pytest.importorskip("matplotlib", reason="matplotlib absent : graphiques non verifiables")


def _rapport(**mesures) -> Report:
    r = Report(points=["AMONT", "AVAL"], pairs=[("AMONT", "AVAL")])
    for champ, valeurs in mesures.items():
        cible = getattr(r, champ)
        for cle, valeur in valeurs.items():
            cible[cle] = valeur
    return r


def _fichier_utilisable(chemin) -> bool:
    """Un chemin renvoye doit designer un fichier PNG reellement ecrit.

    La verification porte sur la signature PNG et non sur la seule existence :
    un fichier cree puis non ecrit (figure fermee trop tot, erreur avalee)
    passerait un simple `exists()` et donnerait une image blanche dans le PDF.
    """
    return chemin.exists() and chemin.stat().st_size > 0 and chemin.read_bytes().startswith(b"\x89PNG")


# --------------------------------------------------------------------------
# Serie vide : aucun graphique, pas un graphique vide
# --------------------------------------------------------------------------


def test_aucun_graphique_de_debit_sans_mesure_de_debit(tmp_path):
    """`None` et non un graphique a zero barre : une barre absente se lit
    « mesure a zero », pas « pas de mesure ». Les deux appellent des
    conclusions opposees."""
    chemin = tmp_path / "debit.png"
    assert chart_throughput(_rapport(), str(chemin)) is None
    assert not chemin.exists(), "un fichier a ete ecrit pour un graphique non produit"


def test_aucun_graphique_de_latence_sans_mesure_de_latence(tmp_path):
    chemin = tmp_path / "latence.png"
    assert chart_latency(_rapport(), str(chemin)) is None
    assert not chemin.exists()


def test_aucun_graphique_de_pertes_sans_perte(tmp_path):
    """Le cas le plus frequent : une capture saine. Le rapport doit dire par
    ecrit qu'il n'y a pas de perte (c'est le role des tables), pas afficher un
    graphique vide qu'on pourrait croire mal genere."""
    chemin = tmp_path / "pertes.png"
    assert chart_loss(_rapport(), str(chemin)) is None
    assert not chemin.exists()


def test_une_perte_a_zero_ne_compte_pas_comme_une_perte(tmp_path):
    """`loss_count` a 0 est une mesure faite qui a donne zero, pas une
    absence. Le filtre est `> 0` : un point a zero perte n'a pas de barre a
    dessiner, sinon le graphique serait rempli de barres nulles qui noieraient
    les vraies."""
    chemin = tmp_path / "pertes.png"
    r = _rapport(loss_count={"AMONT": 0, "AVAL": 0})
    assert chart_loss(r, str(chemin)) is None


def test_aucun_graphique_de_gravite_sans_constat(tmp_path):
    chemin = tmp_path / "gravite.png"
    assert chart_severity_summary([], str(chemin)) is None
    assert not chemin.exists()


# --------------------------------------------------------------------------
# Donnees presentes : le fichier annonce existe vraiment
# --------------------------------------------------------------------------


def test_le_graphique_de_pertes_ecrit_un_png_utilisable(tmp_path):
    chemin = tmp_path / "pertes.png"
    r = _rapport(loss_count={"AVAL": 42})
    assert chart_loss(r, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_le_graphique_de_latence_ecrit_un_png_utilisable(tmp_path):
    chemin = tmp_path / "latence.png"
    r = _rapport(latency={("AMONT", "AVAL"): [0.01, 0.02, 0.03]})
    assert chart_latency(r, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_le_graphique_de_gravite_ecrit_un_png_utilisable(tmp_path):
    chemin = tmp_path / "gravite.png"
    r = _rapport(loss_count={"AVAL": 500}, seen_count={"AMONT": 1000, "AVAL": 500})
    findings = build_findings(r)
    assert findings, "le scenario ne produit aucun constat : test sans objet"
    assert chart_severity_summary(findings, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


# --------------------------------------------------------------------------
# Une seule valeur : le cas ou l'echelle automatique peut mentir
# --------------------------------------------------------------------------


def test_une_seule_mesure_de_latence_ne_fait_pas_tomber_le_rendu(tmp_path):
    """Une capture courte ne donne qu'un point. La gigue vaut alors 0 par
    convention (`pstdev` exige au moins deux valeurs) : le graphique doit etre
    produit avec une barre d'erreur nulle, pas echouer."""
    chemin = tmp_path / "latence.png"
    r = _rapport(latency={("AMONT", "AVAL"): [0.015]})
    assert chart_latency(r, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_un_seul_segment_garde_une_echelle_lisible(tmp_path):
    """Avec une seule barre, matplotlib centre l'axe sur elle et la barre
    occupe toute la largeur. `chart_latency` fixe explicitement
    `set_xlim(-0.6, n - 0.4)` pour l'eviter -- un detail qui se perdrait
    facilement lors d'une refonte, d'ou ce test."""
    chemin = tmp_path / "latence.png"
    r = _rapport(latency={("AMONT", "AVAL"): [0.02, 0.03]})
    assert chart_latency(r, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_des_valeurs_extremes_ne_font_pas_tomber_le_rendu(tmp_path):
    """Latences de l'ordre de la microseconde et de la dizaine de secondes
    dans la meme serie : un ecart de sept ordres de grandeur. Le graphique
    sera peu lisible -- c'est inevitable et honnete -- mais il ne doit pas
    lever, sinon tout le rapport est perdu a cause d'une valeur aberrante."""
    chemin = tmp_path / "latence.png"
    r = _rapport(latency={("AMONT", "AVAL"): [0.000001, 15.0, 0.0000005]})
    assert chart_latency(r, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_le_graphique_de_pertes_supporte_un_compte_tres_eleve(tmp_path):
    chemin = tmp_path / "pertes.png"
    r = _rapport(loss_count={"AVAL": 10_000_000})
    assert chart_loss(r, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


# --------------------------------------------------------------------------
# Invariant transverse
# --------------------------------------------------------------------------


@pytest.mark.parametrize("fabrique", [chart_throughput, chart_latency, chart_loss])
def test_aucun_graphique_n_ecrit_de_fichier_quand_il_renvoie_none(fabrique, tmp_path):
    """Invariant a verrouiller pour les trois a la fois : un fichier ecrit
    alors que `None` est renvoye resterait sur le disque sans etre reference,
    et un appelant qui se fierait a l'existence du fichier plutot qu'a la
    valeur de retour insererait une image vide dans le PDF."""
    chemin = tmp_path / f"{fabrique.__name__}.png"
    assert fabrique(_rapport(), str(chemin)) is None
    assert not chemin.exists()


# --------------------------------------------------------------------------
# Cartographie des communications et topologie -- graphes networkx
# --------------------------------------------------------------------------
#
# `networkx` est une dependance declaree du projet (pyproject.toml), mais il
# etait absent de l'environnement local : les six tests « sautes » de la suite
# venaient de la. Les sauts sont conserves ici plutot que supprimes -- un test
# qui echoue faute de dependance accuse a tort le code teste.


def _carte(aretes, *, total_edges=None, total_hosts=None):
    """CommMap minimale a partir d'une liste de (src, dst, octets, anomalies)."""
    from netcross_report.comm_map import CommEdge, CommMap, CommNode

    hotes = {h for src, dst, *_ in aretes for h in (src, dst)}
    return CommMap(
        nodes=[CommNode(host=h, packets=10, bytes=1000) for h in sorted(hotes)],
        edges=[
            CommEdge(src=src, dst=dst, packets=max(1, octets // 100), bytes=octets, anomalies=anomalies)
            for src, dst, octets, anomalies in aretes
        ],
        protocols=["TCP"],
        total_edges=total_edges if total_edges is not None else len(aretes),
        total_hosts=total_hosts if total_hosts is not None else len(hotes),
    )


def test_aucune_cartographie_sans_arete(tmp_path):
    """Une carte sans arete n'est pas une carte : la produire donnerait une
    image vide que le lecteur prendrait pour un defaut d'affichage plutot que
    pour une absence de communication."""
    from netcross_report.charts import chart_comm_map

    chemin = tmp_path / "carte.png"
    assert chart_comm_map(_carte([]), str(chemin)) is None
    assert chart_comm_map(None, str(chemin)) is None
    assert not chemin.exists()


def test_la_cartographie_ecrit_un_png_utilisable(tmp_path):
    pytest.importorskip("networkx", reason="networkx absent : graphe non verifiable")
    from netcross_report.charts import chart_comm_map

    chemin = tmp_path / "carte.png"
    carte = _carte([("10.0.0.1", "10.0.0.2", 50_000, 0), ("10.0.0.2", "10.0.0.3", 12_000, 0)])
    assert chart_comm_map(carte, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_la_cartographie_est_reproductible(tmp_path):
    """La disposition en ressort est aleatoire par defaut ; le module fixe la
    graine. Sans cela, deux executions sur la meme capture donneraient deux
    dessins differents, et un rapport relu apres coup ne correspondrait plus a
    celui qui a ete discute -- inacceptable pour une piece illustrant un
    incident. C'est exactement le genre de garantie qu'une refonte perd sans
    que rien n'echoue."""
    pytest.importorskip("networkx", reason="networkx absent : graphe non verifiable")
    from netcross_report.charts import chart_comm_map

    carte = _carte([("10.0.0.1", "10.0.0.2", 50_000, 0), ("10.0.0.2", "10.0.0.3", 12_000, 3)])
    a, b = tmp_path / "a.png", tmp_path / "b.png"
    chart_comm_map(carte, str(a))
    chart_comm_map(carte, str(b))
    assert a.read_bytes() == b.read_bytes(), "deux rendus de la meme carte diffèrent : graine non fixee"


def test_la_cartographie_supporte_une_arete_avec_anomalies(tmp_path):
    """Une arete porteuse de signaux d'expertise est tracee en rouge : c'est
    une branche de code distincte, et c'est la seule qui interesse vraiment le
    lecteur."""
    pytest.importorskip("networkx", reason="networkx absent : graphe non verifiable")
    from netcross_report.charts import chart_comm_map

    chemin = tmp_path / "carte.png"
    carte = _carte([("10.0.0.1", "10.0.0.2", 50_000, 17)])
    assert chart_comm_map(carte, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_la_cartographie_supporte_une_arete_unique(tmp_path):
    """Deux hotes, un sens : le graphe le plus petit qui ait un sens. Une
    disposition en ressort sur deux noeuds est un cas limite classique."""
    pytest.importorskip("networkx", reason="networkx absent : graphe non verifiable")
    from netcross_report.charts import chart_comm_map

    chemin = tmp_path / "carte.png"
    assert chart_comm_map(_carte([("a", "b", 500, 0)]), str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_la_cartographie_supporte_les_deux_sens_entre_deux_hotes(tmp_path):
    """Aller et retour entre les memes hotes : deux aretes distinctes dans un
    DiGraph, qui se superposeraient si le dessin ne les courbait pas."""
    pytest.importorskip("networkx", reason="networkx absent : graphe non verifiable")
    from netcross_report.charts import chart_comm_map

    chemin = tmp_path / "carte.png"
    carte = _carte([("a", "b", 9000, 0), ("b", "a", 400, 2)])
    assert chart_comm_map(carte, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_aucune_topologie_sans_arete_deduite(tmp_path):
    """La topologie est deduite des deltas TTL : sans arete, elle n'a rien a
    montrer. Un diagramme a un seul noeud isole laisserait croire que l'outil
    n'a vu qu'un point de capture."""
    from netcross_report.charts import chart_topology

    chemin = tmp_path / "topo.png"
    assert chart_topology(_rapport(), str(chemin)) is None
    assert not chemin.exists()


def test_la_topologie_ecrit_un_png_utilisable(tmp_path):
    pytest.importorskip("networkx", reason="networkx absent : graphe non verifiable")
    from netcross_report.charts import chart_topology

    chemin = tmp_path / "topo.png"
    r = _rapport()
    # Liste de triplets (amont, aval, info) et non un dictionnaire : forme
    # produite par netcross_core.analysis, verifiee dans report_text.py.
    r.topology_edges = [("AMONT", "AVAL", {"confidence": 0.92, "hops": 2})]
    assert chart_topology(r, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_la_topologie_supporte_un_point_isole(tmp_path):
    """Un point sans arete reste un noeud du graphe : le module le distingue
    par une couleur. L'omettre laisserait croire que la capture n'a pas eu
    lieu sur ce point, alors qu'elle a eu lieu sans permettre de le relier."""
    pytest.importorskip("networkx", reason="networkx absent : graphe non verifiable")
    from netcross_report.charts import chart_topology

    chemin = tmp_path / "topo.png"
    r = Report(points=["AMONT", "AVAL", "ISOLE"], pairs=[("AMONT", "AVAL")])
    r.topology_edges = [("AMONT", "AVAL", {"confidence": 0.8, "hops": 1})]
    assert chart_topology(r, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


# --------------------------------------------------------------------------
# Debit et orchestration
# --------------------------------------------------------------------------


def test_le_graphique_de_debit_ecrit_un_png_utilisable(tmp_path):
    chemin = tmp_path / "debit.png"
    r = _rapport(throughput={"AMONT": {0: 12_000, 1: 15_000}, "AVAL": {0: 11_000, 1: 14_500}})
    assert chart_throughput(r, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_un_point_sans_debit_est_exclu_du_graphique_de_debit(tmp_path):
    """Un point sans mesure ne doit pas apparaitre avec une barre a zero :
    il n'a pas ete mesure, ce qui ne veut pas dire qu'il n'a rien transporte.
    La distinction est la meme que pour les pertes ci-dessus."""
    chemin = tmp_path / "debit.png"
    r = _rapport(throughput={"AMONT": {0: 12_000}})
    assert chart_throughput(r, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_generate_all_charts_ne_renvoie_que_les_graphiques_reellement_produits(tmp_path):
    """C'est le contrat dont depend `generate_pdf` (`if key in charts`) :
    l'absence de cle signifie « pas de graphique ». Une cle pointant vers un
    fichier inexistant ferait echouer le rendu du PDF entier, bien plus loin
    dans l'execution et sans rapport apparent avec la cause."""
    from netcross_report.charts import generate_all_charts

    r = _rapport(loss_count={"AVAL": 9}, latency={("AMONT", "AVAL"): [0.01, 0.02]})
    charts = generate_all_charts(r, build_findings(r), str(tmp_path))
    assert charts, "aucun graphique produit alors que des mesures existent"
    for cle, chemin in charts.items():
        import pathlib

        assert _fichier_utilisable(pathlib.Path(chemin)), f"{cle} pointe vers un fichier inutilisable"


def test_un_rapport_sans_mesure_ne_produit_que_le_graphique_de_chemin(tmp_path):
    """Un premier jet attendait un dictionnaire vide. La realite est plus
    interessante : `path_quality` est produit, parce qu'un couple de points
    declare definit un segment meme sans mesure -- et le graphique **annote
    ce segment « non mesure »** au lieu de dessiner une barre a zero qui se
    lirait « delai nul, aucune perte », soit l'inverse de la verite.

    C'est le comportement voulu, aligne sur le tableau du PDF ou un tiret
    signale une metrique non mesurable et non une valeur nulle. Le test fige
    donc ce resultat plutot que de le corriger : c'est la garde contre le
    graphique trompeur que l'issue #286 demandait de verifier.
    """
    from netcross_report.charts import generate_all_charts

    r = _rapport()
    charts = generate_all_charts(r, [], str(tmp_path))
    assert set(charts) == {"path_quality"}, (
        "un graphique est produit sans mesure correspondante, ou l'annotation « non mesure » du chemin a disparu"
    )


def test_le_graphique_de_chemin_annote_les_segments_non_mesures(tmp_path):
    """Verification directe de l'annotation, sans passer par l'orchestrateur.

    Elle ne peut pas etre lue dans le PNG sans comparaison d'image -- ce que
    ces tests s'interdisent -- donc la figure matplotlib est inspectee avant
    ecriture : les textes annotes sont des objets, pas des pixels.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    from netcross_report.charts import chart_path_quality
    from netcross_report.path_metrics import build_path_metrics

    metrics = build_path_metrics(_rapport())
    assert metrics, "aucun segment : le scenario de test est faux"
    assert all(seg.delay_p95_ms is None and seg.loss_pct is None for seg in metrics)

    chemin = tmp_path / "chemin.png"
    assert chart_path_quality(metrics, str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)

    figures_avant = plt.get_fignums()
    assert not figures_avant, "une figure matplotlib reste ouverte : fuite de memoire sur gros rapport"


def test_le_graphique_de_chemin_est_produit_avec_des_mesures(tmp_path):
    from netcross_report.charts import chart_path_quality
    from netcross_report.path_metrics import build_path_metrics

    r = _rapport(
        seen_count={"AMONT": 1000, "AVAL": 950},
        loss_count={"AVAL": 50},
        latency={("AMONT", "AVAL"): [0.01, 0.02, 0.03]},
    )
    chemin = tmp_path / "chemin.png"
    assert chart_path_quality(build_path_metrics(r), str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_aucun_graphique_de_chemin_sans_segment(tmp_path):
    from netcross_report.charts import chart_path_quality

    chemin = tmp_path / "chemin.png"
    assert chart_path_quality([], str(chemin)) is None
    assert not chemin.exists()


# --------------------------------------------------------------------------
# Series temporelles top-N
# --------------------------------------------------------------------------


def _rapport_topn(by_cat, dimension="protocol", point="AMONT"):
    r = _rapport()
    r.topn_timeseries = {dimension: {point: by_cat}}
    return r


def test_aucune_serie_topn_sans_donnee_pour_ce_point(tmp_path):
    """Une dimension presente mais un point absent : `None`, pas un graphique
    vide. La distinction compte parce que les categories dominantes sont
    calculees point par point -- un point peut n'avoir aucune serie alors que
    son voisin en a."""
    from netcross_report.charts import chart_topn_timeseries

    chemin = tmp_path / "topn.png"
    r = _rapport_topn({})
    assert chart_topn_timeseries(r, "AMONT", "protocol", str(chemin)) is None
    assert chart_topn_timeseries(r, "POINT_INCONNU", "protocol", str(chemin)) is None
    assert chart_topn_timeseries(r, "AMONT", "dimension_inconnue", str(chemin)) is None
    assert not chemin.exists()


def test_aucune_serie_topn_si_les_categories_sont_vides(tmp_path):
    """Categories presentes mais sans aucun bucket : le graphique n'aurait
    aucun axe temporel a tracer. Branche distincte de la precedente, et la
    seule qui protege d'un `all_buckets` vide."""
    from netcross_report.charts import chart_topn_timeseries

    chemin = tmp_path / "topn.png"
    r = _rapport_topn({"TCP": {}, "UDP": {}})
    assert chart_topn_timeseries(r, "AMONT", "protocol", str(chemin)) is None


def test_la_serie_topn_ecrit_un_png_utilisable(tmp_path):
    from netcross_report.charts import chart_topn_timeseries

    chemin = tmp_path / "topn.png"
    r = _rapport_topn({"TCP": {0: 12_000, 1: 9_000, 2: 15_000}, "UDP": {0: 400, 2: 800}})
    assert chart_topn_timeseries(r, "AMONT", "protocol", str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_la_categorie_autres_est_tracee_en_dernier(tmp_path):
    """« autres » est l'agregat de la longue traine : le confondre avec une
    vraie categorie ferait croire a un protocole dominant qui n'existe pas. Le
    module le place en dernier et en gris ; la verification porte sur l'ordre
    des labels de la figure, pas sur les couleurs des pixels.
    """
    import matplotlib

    matplotlib.use("Agg")
    from netcross_core.correlate import TOPN_OTHER_LABEL
    from netcross_report.charts import chart_topn_timeseries

    chemin = tmp_path / "topn.png"
    r = _rapport_topn(
        {
            TOPN_OTHER_LABEL: {0: 100, 1: 200},
            "TCP": {0: 12_000, 1: 9_000},
            "UDP": {0: 3_000, 1: 3_500},
        }
    )
    assert chart_topn_timeseries(r, "AMONT", "protocol", str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_une_seule_categorie_et_un_seul_bucket_ne_font_pas_tomber_le_rendu(tmp_path):
    """Capture d'une seconde, un seul protocole : une aire empilee sur un
    point unique. Cas limite frequent sur les captures de diagnostic courtes."""
    from netcross_report.charts import chart_topn_timeseries

    chemin = tmp_path / "topn.png"
    r = _rapport_topn({"TCP": {0: 5_000}})
    assert chart_topn_timeseries(r, "AMONT", "protocol", str(chemin)) == str(chemin)
    assert _fichier_utilisable(chemin)


def test_generate_topn_charts_sans_serie_ne_renvoie_rien(tmp_path):
    from netcross_report.charts import generate_topn_charts

    assert generate_topn_charts(_rapport(), str(tmp_path)) == {}


def test_generate_topn_charts_prefixe_ses_cles_par_dimension(tmp_path):
    """Les cles retournees alimentent le meme dictionnaire que les graphiques
    generaux : sans prefixe, « protocol » entrerait en collision avec une cle
    existante et un graphique en ecraserait un autre silencieusement."""
    from netcross_report.charts import generate_topn_charts

    r = _rapport_topn({"TCP": {0: 12_000, 1: 9_000}})
    charts = generate_topn_charts(r, str(tmp_path))
    assert charts, "aucun graphique alors qu'une serie existe"
    import pathlib

    for dimension, chemin in charts.items():
        assert dimension == "protocol"
        assert _fichier_utilisable(pathlib.Path(chemin))


# -- Issue #725 : couverture de chart_sequence_diagram et topology ------------


def test_chart_sequence_diagram_vide_retourne_none(tmp_path):
    """Lignes 424-426 : chart_sequence_diagram retourne None si la vue
    est vide ou a moins de 2 hotes."""
    from netcross_report.sequence_view import SequenceView

    path = str(tmp_path / "seq.png")
    # Vue vide
    result = chart_sequence_diagram(SequenceView(title="empty"), path)
    assert result is None


def test_chart_sequence_diagram_avec_steps(tmp_path):
    """Lignes 427-487 : chart_sequence_diagram produit un PNG avec des
    steps et au moins 2 hotes."""
    from netcross_report.sequence_view import SequenceStep, SequenceView

    steps = [
        SequenceStep(
            ts=1.0,
            rel_ms=0.0,
            delta_ms=0.0,
            src="10.0.0.1",
            dst="10.0.0.2",
            point="A",
            length=60,
            proto="TCP",
            sport=50000,
            dport=443,
            flags="SYN",
            frame_number=1,
        ),
        SequenceStep(
            ts=2.0,
            rel_ms=1000.0,
            delta_ms=1000.0,
            src="10.0.0.2",
            dst="10.0.0.1",
            point="A",
            length=60,
            proto="TCP",
            sport=443,
            dport=50000,
            flags="SYN-ACK",
            frame_number=2,
        ),
    ]
    view = SequenceView(
        title="Test flow",
        steps=steps,
        hosts=["10.0.0.1", "10.0.0.2"],
        points=["A"],
    )
    path = str(tmp_path / "seq.png")
    result = chart_sequence_diagram(view, path)
    assert result == path
    assert os.path.exists(path)


def test_chart_sequence_diagram_src_dst_identique(tmp_path):
    """Ligne 443 : src et dst du meme cote -> marqueur au lieu de fleche."""
    from netcross_report.sequence_view import SequenceStep, SequenceView

    steps = [
        SequenceStep(
            ts=1.0,
            rel_ms=0.0,
            delta_ms=0.0,
            src="10.0.0.1",
            dst="10.0.0.1",
            point="A",
            length=60,
            proto="ARP",
            sport=None,
            dport=None,
            flags="",
            frame_number=1,
        ),
    ]
    view = SequenceView(
        title="Broadcast",
        steps=steps,
        hosts=["10.0.0.1", "10.0.0.2"],
        points=["A"],
    )
    path = str(tmp_path / "seq_broadcast.png")
    result = chart_sequence_diagram(view, path)
    assert result == path
    assert os.path.exists(path)


def test_chart_sequence_diagram_step_sans_frame_number(tmp_path):
    """Ligne 464 : trame = '' quand frame_number est None."""
    from netcross_report.sequence_view import SequenceStep, SequenceView

    steps = [
        SequenceStep(
            ts=1.0,
            rel_ms=0.0,
            delta_ms=0.0,
            src="10.0.0.1",
            dst="10.0.0.2",
            point="A",
            length=60,
            proto="UDP",
            sport=53,
            dport=5353,
            flags="",
            frame_number=None,
        ),
    ]
    view = SequenceView(
        title="DNS",
        steps=steps,
        hosts=["10.0.0.1", "10.0.0.2"],
        points=["A"],
    )
    path = str(tmp_path / "seq_no_frame.png")
    result = chart_sequence_diagram(view, path)
    assert result == path
    assert os.path.exists(path)


def test_chart_topology_avec_branch_merge_isole(tmp_path):
    """Lignes 50-63 : chart_topology colore les noeuds branch/merge/isole."""
    from netcross_core.models import Report

    r = Report(points=["10.0.0.1", "10.0.0.2", "10.0.0.3"])
    r.topology_branch_points.append("10.0.0.1")
    r.topology_merge_points.append("10.0.0.2")
    r.topology_isolated.append("10.0.0.3")
    r.topology_edges.append(("10.0.0.1", "10.0.0.2", {"label": "A->B", "confidence": 0.95}))
    r.topology_edges.append(("10.0.0.2", "10.0.0.3", {"label": "B->C", "confidence": 0.88}))
    path = str(tmp_path / "topology.png")
    result = chart_topology(r, path)
    assert result == path
    assert os.path.exists(path)


def test_chart_sequence_diagram_truncated(tmp_path):
    """Ligne 487 : chart_sequence_diagram avec truncated > 0."""
    from netcross_report.sequence_view import SequenceStep, SequenceView

    steps = [
        SequenceStep(
            ts=1.0,
            rel_ms=0.0,
            delta_ms=0.0,
            src="10.0.0.1",
            dst="10.0.0.2",
            point="A",
            length=60,
            proto="TCP",
            sport=50000,
            dport=443,
            flags="SYN",
            frame_number=1,
        ),
    ]
    view = SequenceView(
        title="Truncated flow",
        steps=steps,
        hosts=["10.0.0.1", "10.0.0.2"],
        points=["A"],
        truncated=50,
        total_steps=51,
    )
    path = str(tmp_path / "seq_trunc.png")
    result = chart_sequence_diagram(view, path)
    assert result == path
    assert os.path.exists(path)
