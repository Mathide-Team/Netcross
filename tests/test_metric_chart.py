"""
tests/test_metric_chart -- tests du generateur de graphes generique
(Job 20, §6.18). Les tests ne verifient pas les pixels : ils
controlent qu'un PNG est cree (chemin retourne, fichier non vide),
que les cas vides retournent None, et que les incoherences de
dimensions levent ValueError.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from netcross_report.metric_charts import (
    ComplianceZone,
    MetricSeries,
    Threshold,
    render_area,
    render_bars,
    render_histogram,
    render_line,
    render_metric_chart,
    render_scatter,
)


def _series(**overrides) -> MetricSeries:
    """MetricSeries avec des valeurs par defaut neutres."""
    defaults: dict = {
        "name": "Debit",
        "values": [10.0, 20.0, 30.0, 40.0, 50.0],
        "unit": "kbps",
        "source": "test",
    }
    defaults.update(overrides)
    return MetricSeries(**defaults)


def _tmp_png(tmp_path: Path, name: str = "chart.png") -> str:
    return str(tmp_path / name)


# --- Rendus de base : chaque type produit un PNG non vide -------------------


@pytest.mark.parametrize("renderer", [render_line, render_area, render_bars, render_scatter])
def test_rendu_produit_png_non_vide(tmp_path, renderer):
    s = _series()
    path = _tmp_png(tmp_path, f"{renderer.__name__}.png")
    result = renderer(s, path)
    assert result == path
    assert os.path.exists(path)
    assert os.path.getsize(path) > 0


def test_histogram_produit_png_non_vide(tmp_path):
    s = _series(values=[1.0, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0, 5.5, 6.0, 7.0] * 3)
    path = _tmp_png(tmp_path, "hist.png")
    result = render_histogram(s, path)
    assert result == path
    assert os.path.exists(path)
    assert os.path.getsize(path) > 0


def test_histogram_sans_unite_ne_definit_pas_xlabel(tmp_path):
    """unit="" : l'axe des x n'est pas etiquete, le rendu aboutit (#750)."""
    s = _series(unit="", values=[1.0, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0, 5.5, 6.0, 7.0] * 3)
    path = _tmp_png(tmp_path, "hist_sans_unite.png")
    assert render_histogram(s, path) == path
    assert os.path.getsize(path) > 0


# --- Cas vide : retourne None -----------------------------------------------


def test_rendu_vide_retourne_none(tmp_path):
    s = _series(values=[])
    path = _tmp_png(tmp_path)
    for renderer in [render_line, render_area, render_bars, render_histogram, render_scatter]:
        assert renderer(s, path) is None


# --- Validation des dimensions ----------------------------------------------


def test_timestamps_longueur_incoherente_leve_value_error(tmp_path):
    s = _series(timestamps=[0.0, 1.0, 2.0])  # 3 vs 5 valeurs
    with pytest.raises(ValueError, match="timestamps"):
        render_line(s, _tmp_png(tmp_path))


def test_labels_longueur_incoherente_leve_value_error(tmp_path):
    s = _series(labels=["A", "B"])  # 2 vs 5 valeurs
    with pytest.raises(ValueError, match="labels"):
        render_bars(s, _tmp_png(tmp_path))


def test_validate_serie_vide_leve_value_error():
    """Les rendus court-circuitent les series vides (retour None) avant
    d'appeler validate() : le chemin d'erreur de validate() n'est donc
    atteignable que par un appel direct (#750)."""
    s = _series(values=[])
    with pytest.raises(ValueError, match="vide"):
        s.validate()


# --- Seuils et zones de conformite ------------------------------------------


def test_seuil_et_zone_ne_cassent_pas_le_rendu(tmp_path):
    s = _series(
        thresholds=[Threshold(value=35.0, label="seuil critique")],
        zones=[ComplianceZone(y_min=0.0, y_max=25.0, label="zone OK")],
    )
    path = _tmp_png(tmp_path)
    result = render_line(s, path)
    assert result == path
    assert os.path.getsize(path) > 0


def test_seuil_sans_etiquette_trace_la_ligne_sans_texte(tmp_path):
    """Un Threshold au label vide trace la ligne mais n'ajoute aucun
    texte ; le seuil suivant est quand meme traite (#750)."""
    s = _series(thresholds=[Threshold(value=35.0), Threshold(value=45.0, label="seuil")])
    path = _tmp_png(tmp_path)
    assert render_line(s, path) == path
    assert os.path.getsize(path) > 0


def test_zone_sans_bornes_utilise_limites_axe(tmp_path):
    """Zone avec y_min=None et y_max=None ne doit pas planter."""
    s = _series(
        zones=[ComplianceZone(y_min=None, y_max=None, label="tout OK")],
    )
    path = _tmp_png(tmp_path)
    result = render_area(s, path)
    assert result == path
    assert os.path.getsize(path) > 0


# --- Dispatcher -------------------------------------------------------------


def test_dispatcher_repartit_vers_bons_rendus(tmp_path):
    s = _series()
    for kind, _expected_name in [
        ("line", "line"),
        ("area", "area"),
        ("bars", "bars"),
        ("histogram", "histogram"),
        ("scatter", "scatter"),
    ]:
        path = _tmp_png(tmp_path, f"disp_{kind}.png")
        result = render_metric_chart(s, path, kind=kind)  # type: ignore[arg-type]
        assert result == path
        assert os.path.exists(path)


def test_dispatcher_rejette_type_inconnu(tmp_path):
    s = _series()
    with pytest.raises(ValueError, match="inconnu"):
        render_metric_chart(s, _tmp_png(tmp_path), kind="radar")  # type: ignore[arg-type]


def test_dispatcher_serie_vide_retourne_none(tmp_path):
    s = _series(values=[])
    assert render_metric_chart(s, _tmp_png(tmp_path), kind="line") is None


# --- Mode categoriel (labels) vs temporel (timestamps) -----------------------


def test_bars_utilise_labels_pour_xticks(tmp_path):
    s = _series(
        values=[5.0, 10.0, 15.0],
        labels=["Point A", "Point B", "Point C"],
    )
    path = _tmp_png(tmp_path)
    result = render_bars(s, path)
    assert result == path
    assert os.path.getsize(path) > 0


def test_line_utilise_timestamps_pour_abscisses(tmp_path):
    s = _series(
        values=[1.0, 3.0, 2.0, 4.0],
        timestamps=[0.5, 1.0, 1.5, 2.0],
    )
    path = _tmp_png(tmp_path)
    result = render_line(s, path)
    assert result == path
    assert os.path.getsize(path) > 0


def test_scatter_sans_timestamps_utilise_index(tmp_path):
    s = _series(values=[10.0, 20.0, 30.0])
    path = _tmp_png(tmp_path)
    result = render_scatter(s, path)
    assert result == path
    assert os.path.getsize(path) > 0


# --- Contexte et titre ------------------------------------------------------


def test_context_apparait_dans_le_titre(tmp_path):
    s = _series(context={"point": "A", "seuil": 100})
    path = _tmp_png(tmp_path)
    result = render_line(s, path)
    assert result == path
    assert os.path.getsize(path) > 0
