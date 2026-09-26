"""
Tests de regression de l'issue #453 : les flux d'un run existent sous deux
formes dans la GUI, et chaque vue consomme celle qu'elle attend.

## Le defaut

Les deux threads d'analyse (fichier via `run_analysis_pipeline`, capture
en direct via `_join_live_and_analyze`) transmettent a
`_on_analysis_done` le dict brut retourne par `correlate()`
(`{cle: {point: [Pkt, ...]}}`). Ce dict est stocke tel quel dans
`last_flows` -- voulu : le detail CSV (`write_detail_csv`), la
cartographie (`build_comm_map`) et les objets de session
(`build_session_objects`) lisent les paquets qu'il porte, paquets que la
fenetre ne conserve sous aucune autre forme. Mais le dashboard analytique
(`build_dashboard_snapshot`), l'exploration statistique (`run_stats`) et
la recherche de flux par cle (`_flow_by_key`) attendent une `list[Flow]`
avec `.endpoints`, `.points`, `.packet_count`. Resultat : des qu'au moins
un flux existe, `_refresh_dashboard` levait `AttributeError: 'tuple'
object has no attribute 'endpoints'` dans un callback `GLib.idle_add` --
silencieux pour l'application, le tableau de bord ne se mettait jamais a
jour. La vue statistiques, appelee juste apres, etait pareillement
touchee, masquee par la premiere exception.

## Le correctif verifie ici

`analysis_outcome()` derive la `list[Flow]` du dict brut (fonction
`build_flow_objects`), au seul endroit par lequel les DEUX chemins
passent. Les tests verifient que :

- la conversion produit des Flow coherents avec le dict (endpoints,
  points, compteurs) ;
- le dashboard et les statistiques se construisent depuis ces Flow sans
  lever, alors que le dict brut y leve toujours l'AttributeError
  originel (le symptome de l'issue, garde comme temoin) ;
- le dict brut continue d'alimenter les consommateurs orientes Pkt --
  corriger une moitie ne doit pas casser l'autre ;
- le cablage de `app.py` lit bien `last_flow_objects` (et non le dict)
  dans les trois vues orientees objets. `app.py` n'est pas importable
  sans serveur graphique, le fichier est donc relu comme texte, comme le
  fait deja `test_run_outcome.py` pour les champs `last_*`.

La capture est synthetique (deux points, un flux TCP traverse) : le
chemin complet correlate -> analyse -> analysis_outcome -> vues est
celui de la GUI, sans tshark ni GTK.
"""

import ast
import pathlib
import types

import pytest
from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.expert_model import Flow
from netcross_gtk4.dashboard_context import DashboardSelection, build_dashboard_snapshot
from netcross_gtk4.run_outcome import analysis_outcome, build_flow_objects
from netcross_gtk4.stats_view import build_query, flows_for_row, run_stats

# --------------------------------------------------------------------------
# Le run de reference : un flux TCP vu sur deux points de capture
# --------------------------------------------------------------------------


def _run_reel():
    """Un run 'single' complet, meme materiel que les threads de la GUI :
    paquets synthetiques -> correlate() -> analyse() -> analysis_outcome()."""
    pkts_a = [make_pkt(point="A", ts=1.0), make_pkt(point="A", ts=1.1)]
    pkts_b = [make_pkt(point="B", ts=1.05), make_pkt(point="B", ts=1.15)]
    all_packets = pkts_a + pkts_b
    # dict brut, exactement ce que transmettent les deux threads
    flows = correlate(all_packets, False, 200, False)
    report = analyse(flows, ["A", "B"], all_packets, 1.0, False, 8000, 25)
    outcome = analysis_outcome("single", report, flows, None, "texte du rapport")
    return flows, report, outcome


def test_le_run_de_reference_produit_un_flux_deux_points():
    """Garde sur l'outil de test lui-meme : sans flux vu sur deux points,
    les assertions qui suivent ne prouveraient rien."""
    flows, _, outcome = _run_reel()
    assert len(flows) == 1
    assert _etat(outcome)["last_flow_objects"]


def _etat(outcome):
    return outcome.etat()


# --------------------------------------------------------------------------
# analysis_outcome construit la liste de Flow (le correctif, #453)
# --------------------------------------------------------------------------


def test_analysis_outcome_expose_les_flux_comme_liste_de_flow():
    """Le coeur du correctif : `last_flow_objects` porte des Flow, pas les
    cles du dict brut -- c'est ce que `last_flows` n'a jamais fait."""
    flows, _, outcome = _run_reel()
    etat = _etat(outcome)
    assert set(etat) >= {"last_flows", "last_flow_objects"}
    objets = etat["last_flow_objects"]
    assert isinstance(objets, list)
    assert all(isinstance(f, Flow) for f in objets)
    assert len(objets) == len(flows)


def test_les_flow_objects_sont_coherents_avec_le_dict_brut():
    """La conversion ne recalcule rien : chaque Flow porte les points,
    endpoints et compteurs du dict d'origine, paquet par paquet."""
    flows, _, outcome = _run_reel()
    (objet,) = _etat(outcome)["last_flow_objects"]
    ((cle, per_point),) = flows.items()
    assert objet.key == cle
    assert objet.points == list(per_point)
    assert objet.packet_count == {pt: len(pkts) for pt, pkts in per_point.items()}
    assert objet.byte_count == {pt: sum(pk.length for pk in pkts) for pt, pkts in per_point.items()}
    assert objet.first_ts == {pt: min(pk.ts for pk in pkts) for pt, pkts in per_point.items()}
    assert objet.last_ts == {pt: max(pk.ts for pk in pkts) for pt, pkts in per_point.items()}
    assert objet.endpoints == ("10.0.0.1", "10.0.0.2")


def test_build_flow_objects_tolere_les_autres_formes():
    """None reste None (pas de run), une liste de Flow passe telle quelle
    (deja convertie, notamment par les tests), seule la forme dict est
    convertie -- la fonction ne devine pas, elle respecte son entree."""
    assert build_flow_objects(None) is None
    passes = [Flow(key=("TCP",))]
    assert build_flow_objects(passes) is passes
    assert build_flow_objects({}) == []


def test_le_dict_brut_reste_disponible_pour_ses_consommateurs():
    """L'autre moitie du contrat : le dict brut survit au correctif --
    detail CSV, cartographie et objets de session lisent les Pkt qu'il
    porte. `last_flows` reste donc le dict de correlate()."""
    flows, _, outcome = _run_reel()
    assert _etat(outcome)["last_flows"] is flows


# --------------------------------------------------------------------------
# Le symptome de l'issue, et sa disparition
# --------------------------------------------------------------------------


def test_le_dict_brut_faisait_planter_le_dashboard():
    """Temoin du symptome documente dans l'issue : donner le dict brut a
    `build_dashboard_snapshot` leve l'AttributeError sur `.endpoints` (les
    cles du dict sont des tuples). Ce test ne verifie pas le code corrigé,
    il verifie que le defaut etait bien celui decrit -- sans lui, un
    futur refacteur pourrait croire la conversion superflue."""
    _, report, _ = _run_reel()
    dict_brut = correlate([make_pkt(point="A", ts=1.0), make_pkt(point="B", ts=1.05)], False, 200, False)
    with pytest.raises(AttributeError, match="endpoints"):
        build_dashboard_snapshot(report, dict_brut, selection=DashboardSelection())


def test_le_dashboard_se_construit_depuis_les_flow_objects():
    """La regression : le snapshot se construit sans lever, et les six vues
    portent le flux du run."""
    _, report, outcome = _run_reel()
    snap = build_dashboard_snapshot(
        report,
        _etat(outcome)["last_flow_objects"],
        selection=DashboardSelection(),
    )
    assert len(snap.flow_rows) == 1
    assert snap.flow_rows[0]["endpoints"] == ["10.0.0.1", "10.0.0.2"]
    assert snap.flow_rows[0]["packets"] == 4


def test_les_statistiques_se_construisent_depuis_les_flow_objects():
    """La vue statistiques etait pareillement touchee (appelee juste apres
    le dashboard dans `_on_analysis_done`, donc masquee par la premiere
    exception) : `run_stats` itere des `.endpoints` aussi."""
    _, report, outcome = _run_reel()
    rows = run_stats(
        _etat(outcome)["last_flow_objects"],
        report,
        build_query(group_by="endpoint", sort_by="bytes", top_n=10),
    )
    assert rows, "aucune ligne statistique depuis un run a un flux"


def test_le_drill_down_statistique_retrouve_les_flux():
    """Selectionner une ligne statistique affiche ses flux : `flows_for_row`
    lit `.key` sur des Flow, la recherche doit aboutir."""
    _, report, outcome = _run_reel()
    objets = _etat(outcome)["last_flow_objects"]
    rows = run_stats(objets, report, build_query(group_by="flow", sort_by="packets", top_n=10))
    detail = flows_for_row(rows[0], objets)
    assert detail, "le drill-down ne retrouve aucun flux"


# --------------------------------------------------------------------------
# Cablage de app.py (relu comme texte, cf. test_run_outcome)
# --------------------------------------------------------------------------


def _methodes_app_py():
    """{nom de methode: arbre AST} pour les methodes de MainWindow."""
    source = pathlib.Path(__file__).resolve().parents[1] / "src" / "netcross_gtk4" / "app.py"
    arbre = ast.parse(source.read_text(encoding="utf-8"))
    methodes = {}
    for noeud in ast.walk(arbre):
        if isinstance(noeud, ast.FunctionDef) and noeud.name in (
            "_refresh_dashboard",
            "_refresh_stats",
            "_flow_by_key",
        ):
            methodes[noeud.name] = noeud
    assert len(methodes) == 3, "méthodes introuvables dans app.py : l'analyse a échoué, pas le code"
    return methodes


def _attributs_self(noeud):
    """Noms des attributs `self.x` lus dans un sous-arbre."""
    return {
        n.attr
        for n in ast.walk(noeud)
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "self"
    }


@pytest.mark.parametrize("methode", ["_refresh_dashboard", "_refresh_stats", "_flow_by_key"])
def test_les_vues_orientees_objets_lisent_last_flow_objects(methode):
    """Le cablage du correctif : les trois vues qui attendent des Flow
    lisent `last_flow_objects`. Verifie par relecture du source (app.py
    fait `import gi`, absent de la CI) -- meme approche que le garde-fou
    `test_champs_etat_couvre_tous_les_last_de_app_py`."""
    assert "last_flow_objects" in _attributs_self(_methodes_app_py()[methode])


@pytest.mark.parametrize("methode", ["_refresh_dashboard", "_refresh_stats", "_flow_by_key"])
def test_les_vues_orientees_objets_ne_lisent_plus_le_dict_brut(methode):
    """Reciproque : si l'une de ces vues relit `last_flows` (le dict), le
    defaut #453 revient -- l'AttributeError est silencieux, il faut le
    declarer fautif par texte plutot que d'attendre un plantage."""
    assert "last_flows" not in _attributs_self(_methodes_app_py()[methode])


# --------------------------------------------------------------------------
# _flow_by_key : comportement reel, sans instancier MainWindow
# --------------------------------------------------------------------------


@pytest.fixture
def main_window():
    gi = pytest.importorskip("gi", reason="pygobject absent")
    try:
        gi.require_version("Gtk", "4.0")
    except ValueError:
        pytest.skip("GTK 4 absent de cette plateforme")
    from netcross_gtk4.app import MainWindow as _MainWindow

    return _MainWindow


def test_flow_by_key_retrouve_le_flow_de_sa_cle(main_window):
    """`_flow_by_key` ne touche aucun widget : appele sur un simple
    namespace portant `last_flow_objects`, il doit retrouver le Flow de la
    cle selectionnee dans le dashboard -- avant #453, il iterait les cles
    du dict brut et levait sur `.key` d'un tuple."""
    _, _, outcome = _run_reel()
    objets = _etat(outcome)["last_flow_objects"]
    fenetre = types.SimpleNamespace(last_flow_objects=objets)
    for attendu in objets:
        trouve = main_window._flow_by_key(fenetre, attendu.key)
        assert trouve is attendu
    assert main_window._flow_by_key(fenetre, ("cle", "absente")) is None
