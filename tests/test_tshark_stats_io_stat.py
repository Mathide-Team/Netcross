"""
netcross_core.tshark_stats.io_stat -- tests de couverture (issue #710, suite #665).

Complete ``tests/test_tshark_stats.py`` (fixture nominale, intervalle ouvert,
texte sans intervalle) par les chemins rares de ``parse_io_stat`` :

- ligne d'intervalle sans separateur ``|`` (decoupage par tokens) ;
- valeurs plus nombreuses que les colonnes d'en-tete (cles ``value_N``) ;
- tokens/champs non numeriques ignores ;
- bornes de l'intervalle retirees des valeurs.

Ces tests ne dependent pas de tshark : ``parse_io_stat`` est une fonction pure
sur du texte.
"""

from __future__ import annotations

import pytest

from netcross_core.tshark_stats import parse_io_stat


def test_ligne_sans_pipe_decoupee_par_tokens_sans_en_tete():
    series = parse_io_stat("000.000-001.000  100  6400\n")
    assert len(series.points) == 1
    p = series.points[0]
    assert p.start == pytest.approx(0.0)
    assert p.end == pytest.approx(1.0)
    assert p.values == {"value_0": 100.0, "value_1": 6400.0}


def test_ligne_sans_pipe_utilise_les_en_tetes_reconstruits():
    text = "| Time |frames |bytes |\n000.000-001.000 100 6400\n"
    series = parse_io_stat(text)
    assert len(series.points) == 1
    assert series.points[0].values == {"frames": 100.0, "bytes": 6400.0}


def test_ligne_sans_pipe_ignore_les_tokens_non_numeriques():
    series = parse_io_stat("000.000-001.000 abc 12 --\n")
    assert len(series.points) == 1
    assert series.points[0].values == {"value_0": 12.0}


def test_valeurs_plus_nombreuses_que_les_en_tetes_prennent_des_cles_value_n():
    text = "| Time |frames |\n| 000.000-001.000 | 1 | 2 | 3 |\n"
    series = parse_io_stat(text)
    assert series.points[0].values == {"frames": 1.0, "value_1": 2.0, "value_2": 3.0}


def test_valeur_egale_a_une_borne_est_retiree_des_valeurs():
    # "000.000" est aussi la borne de debut : il est ecarte, pas compte comme colonne.
    text = "| Time |frames |\n| 000.000-001.000 | 000.000 | 5 |\n"
    series = parse_io_stat(text)
    assert series.points[0].values == {"frames": 5.0}


def test_intervalle_ouvert_sans_pipe_n_a_pas_de_valeurs_propres():
    # Sans "|", le token "000.000-" n'est pas un nombre et "7" est lu comme borne de fin
    # par _INTERVAL_RE (comportement historique, fige ici).
    series = parse_io_stat("000.000- 7\n")
    assert len(series.points) == 1
    assert series.points[0].start == pytest.approx(0.0)
    assert series.points[0].end == pytest.approx(7.0)
    assert series.points[0].values == {}


def test_lignes_separateur_et_filtre_sont_ignorees():
    text = "==========\nFilter:tcp\n| Time |frames |\n| 000.000-001.000 | 4 |\n----------\n"
    series = parse_io_stat(text)
    assert len(series.points) == 1
    assert series.points[0].values == {"frames": 4.0}
