"""
netcross_report.metric_charts -- API generique de graphiques : tout
module d'analyse peut produire un graphique a partir d'une MetricSeries
sans reimplementer son propre code matplotlib.

La couche de rendu supporte cinq types : ligne, aire, barres,
histogramme (distribution) et scatter. Chaque rendu peut afficher des
seuils (lignes horizontales de reference) et des zones de conformite
(bandes horizontales colorees).

La discipline de couches import-linter (netcross_report > netcross_core
> pcap_parser) est respectee : ce module n'importe que matplotlib (une
dependance deja declaree dans pyproject.toml) et stdlib -- aucun import
inter-packages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

# --- Modeles de donnees -----------------------------------------------------


@dataclass(slots=True)
class Threshold:
    """Ligne horizontale de reference tracee sur un graphique.

    Utilise pour marquer un seuil d'alerte (ex. delai P95 > 200 ms)
    ou une valeur cible.
    """

    value: float
    label: str = ""
    color: str = "#ef4444"
    linestyle: str = "--"
    linewidth: float = 1.2


@dataclass(slots=True)
class ComplianceZone:
    """Bande horizontale coloree representant une plage de valeurs
    acceptable ou inacceptable.

    y_min / y_max peuvent etre None pour signifier « sans limite »
    (vers le bas ou vers le haut de l'axe Y).
    """

    y_min: float | None
    y_max: float | None
    label: str = ""
    color: str = "#22c55e"
    alpha: float = 0.1


@dataclass(slots=True)
class MetricSeries:
    """Une serie de donnees numeriques, prête a etre tracee par la
    couche de rendu.

    Deux modes d'abscisse :
    - Temporel : ``timestamps`` fourni (longueur == valeurs), utilise
      pour les rendus ligne, aire et scatter.
    - Categoriel : ``labels`` fourni (longueur == valeurs), utilise
      pour les rendus barres et scatter.
    - Aucun : index numeriques (0, 1, 2, ...) utilises par defaut.

    Pour l'histogramme, ``timestamps`` et ``labels`` sont ignores : la
    distribution des ``values`` est tracee directement.
    """

    name: str
    values: list[float]
    unit: str = ""
    timestamps: list[float] | None = None
    labels: list[str] | None = None
    source: str = ""
    context: dict[str, object] = field(default_factory=dict)
    thresholds: list[Threshold] = field(default_factory=list)
    zones: list[ComplianceZone] = field(default_factory=list)

    def validate(self) -> None:
        """Verifie la coherence des dimensions. Leve ValueError si
        les longueurs de timestamps/labels ne correspondent pas a
        values."""
        if not self.values:
            logger.trace("MetricSeries.validate: refus, ValueError")
            logger.debug("MetricSeries.validate: si not self.values -> levée ValueError")
            raise ValueError("MetricSeries.values ne doit pas etre vide")
        n = len(self.values)
        if self.timestamps is not None and len(self.timestamps) != n:
            logger.trace("MetricSeries.validate: refus, ValueError")
            logger.debug(
                "MetricSeries.validate: si self.timestamps is not None and len(self.timestamps) != n -> levée ValueEr…"
            )
            raise ValueError(f"timestamps ({len(self.timestamps)}) et values ({n}) doivent avoir la meme longueur")
        if self.labels is not None and len(self.labels) != n:
            logger.trace("MetricSeries.validate: refus, ValueError")
            logger.debug(
                "MetricSeries.validate: si self.labels is not None and len(self.labels) != n -> levée ValueError"
            )
            raise ValueError(f"labels ({len(self.labels)}) et values ({n}) doivent avoir la meme longueur")
        logger.debug("MetricSeries.validate: fin")


# --- Couche de rendu --------------------------------------------------------

ChartKind = Literal["line", "area", "bars", "histogram", "scatter"]


def _x_values(series: MetricSeries) -> list[float]:
    """Abscisses pour les rendus ligne/aire/scatter : timestamps
    si fournis, sinon index numeriques."""
    if series.timestamps is not None:
        logger.debug("_x_values: si series.timestamps is not None -> retour list(…)")
        return list(series.timestamps)
    logger.debug("_x_values: retour liste")
    return [float(i) for i in range(len(series.values))]


def _decorate(ax, series: MetricSeries) -> None:
    """Applique seuils et zones de conformite sur un axe deja trace."""
    # Zones d'abord (sous les donnees visuellement)
    for zone in series.zones:
        y_min = zone.y_min if zone.y_min is not None else ax.get_ylim()[0]
        y_max = zone.y_max if zone.y_max is not None else ax.get_ylim()[1]
        ax.axhspan(y_min, y_max, alpha=zone.alpha, color=zone.color, zorder=1)
    # Seuils par-dessus
    for th in series.thresholds:
        ax.axhline(
            y=th.value,
            color=th.color,
            linestyle=th.linestyle,
            linewidth=th.linewidth,
            zorder=4,
        )
        if th.label:
            ax.text(
                0.99,
                th.value,
                f" {th.label}",
                transform=ax.get_yaxis_transform(),
                ha="right",
                va="bottom",
                fontsize=7,
                color=th.color,
            )
    logger.debug("_decorate: fin")


def _title(series: MetricSeries) -> str:
    parts = [series.name]
    if series.context:
        ctx = ", ".join(f"{k}={v}" for k, v in series.context.items())
        parts.append(ctx)
    logger.debug("_title: retour ' -- '.join(…)")
    return " -- ".join(parts)


def _ylabel(series: MetricSeries) -> str:
    logger.debug("_ylabel: retour series.unit if series.unit else ''")
    return series.unit if series.unit else ""


def _save(fig, path: str) -> str:
    logger.debug("_save: fig={} path={}", summarize(fig, "fig"), summarize(path, "path"))
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.debug("_save: retour path={}", summarize(path, "path"))
    return path


def render_line(series: MetricSeries, path: str) -> str | None:
    """Trace une courbe lineaire. Retourne le chemin PNG ou None si
    la serie est vide."""
    logger.debug("render_line: series={} path={}", summarize(series, "series"), summarize(path, "path"))
    if not series.values:
        logger.debug("render_line: si not series.values -> retour None")
        return None
    series.validate()
    x = _x_values(series)
    y = series.values
    fig, ax = plt.subplots(figsize=(9, 3.2))
    ax.plot(x, y, color="#3b82f6", linewidth=1.6, marker="o", markersize=3, zorder=3)
    ax.set_title(_title(series))
    ax.set_ylabel(_ylabel(series))
    ax.grid(axis="y", linestyle=":", alpha=0.4)
    _decorate(ax, series)
    logger.debug("render_line: retour _save(…)")
    return _save(fig, path)


def render_area(series: MetricSeries, path: str) -> str | None:
    """Trace une aire remplie sous la courbe. Retourne le chemin PNG
    ou None si la serie est vide."""
    logger.debug("render_area: series={} path={}", summarize(series, "series"), summarize(path, "path"))
    if not series.values:
        logger.debug("render_area: si not series.values -> retour None")
        return None
    series.validate()
    x = _x_values(series)
    y = series.values
    fig, ax = plt.subplots(figsize=(9, 3.2))
    ax.fill_between(x, y, alpha=0.3, color="#3b82f6", zorder=2)
    ax.plot(x, y, color="#3b82f6", linewidth=1.2, zorder=3)
    ax.set_title(_title(series))
    ax.set_ylabel(_ylabel(series))
    ax.grid(axis="y", linestyle=":", alpha=0.4)
    _decorate(ax, series)
    logger.debug("render_area: retour _save(…)")
    return _save(fig, path)


def render_bars(series: MetricSeries, path: str) -> str | None:
    """Trace un diagramme en barres. Utilise labels si fournis, sinon
    des index. Retourne le chemin PNG ou None si la serie est vide."""
    logger.debug("render_bars: series={} path={}", summarize(series, "series"), summarize(path, "path"))
    if not series.values:
        logger.debug("render_bars: si not series.values -> retour None")
        return None
    series.validate()
    x = list(range(len(series.values)))
    bar_labels = series.labels if series.labels is not None else [str(i) for i in x]
    fig, ax = plt.subplots(figsize=(9, 3.2))
    ax.bar(x, series.values, color="#3b82f6", width=0.6, zorder=3)
    ax.set_xticks(x)
    ax.set_xticklabels(bar_labels, rotation=30, ha="right", fontsize=8)
    ax.set_title(_title(series))
    ax.set_ylabel(_ylabel(series))
    ax.grid(axis="y", linestyle=":", alpha=0.4)
    _decorate(ax, series)
    logger.debug("render_bars: retour _save(…)")
    return _save(fig, path)


def render_histogram(series: MetricSeries, path: str) -> str | None:
    """Trace un histogramme (distribution) des valeurs. Ignore
    timestamps et labels. Retourne le chemin PNG ou None si la serie
    est vide ou contient moins de 2 valeurs distinctes."""
    logger.debug("render_histogram: series={} path={}", summarize(series, "series"), summarize(path, "path"))
    if not series.values:
        logger.debug("render_histogram: si not series.values -> retour None")
        return None
    series.validate()
    fig, ax = plt.subplots(figsize=(9, 3.2))
    n_bins = min(30, max(5, len(series.values) // 3))
    ax.hist(series.values, bins=n_bins, color="#8b5cf6", edgecolor="white", zorder=3)
    ax.set_title(_title(series))
    ax.set_ylabel("compte")
    if series.unit:
        ax.set_xlabel(series.unit)
    ax.grid(axis="y", linestyle=":", alpha=0.4)
    _decorate(ax, series)
    logger.debug("render_histogram: retour _save(…)")
    return _save(fig, path)


def render_scatter(series: MetricSeries, path: str) -> str | None:
    """Trace un nuage de points. Utilise timestamps si fournis, sinon
    des index. Retourne le chemin PNG ou None si la serie est vide."""
    logger.debug("render_scatter: series={} path={}", summarize(series, "series"), summarize(path, "path"))
    if not series.values:
        logger.debug("render_scatter: si not series.values -> retour None")
        return None
    series.validate()
    x = _x_values(series)
    y = series.values
    fig, ax = plt.subplots(figsize=(9, 3.2))
    ax.scatter(x, y, color="#10b981", s=20, zorder=3)
    ax.set_title(_title(series))
    ax.set_ylabel(_ylabel(series))
    ax.grid(axis="y", linestyle=":", alpha=0.4)
    _decorate(ax, series)
    logger.debug("render_scatter: retour _save(…)")
    return _save(fig, path)


_RENDERERS = {
    "line": render_line,
    "area": render_area,
    "bars": render_bars,
    "histogram": render_histogram,
    "scatter": render_scatter,
}


def render_metric_chart(
    series: MetricSeries,
    path: str,
    kind: ChartKind = "line",
) -> str | None:
    """Point d'entree generique : trace un graphique de type ``kind``
    a partir de ``series``. Retourne le chemin PNG ou None si la serie
    est vide.

    Leve ValueError si ``kind`` n'est pas un type de graphique reconnu.
    """
    logger.debug(
        "render_metric_chart: series={} path={} kind={}",
        summarize(series, "series"),
        summarize(path, "path"),
        summarize(kind, "kind"),
    )
    renderer = _RENDERERS.get(kind)
    if renderer is None:
        logger.debug("render_metric_chart: refus, ValueError")
        raise ValueError(f"Type de graphique inconnu : {kind!r}. Types reconnus : {', '.join(sorted(_RENDERERS))}")
    logger.debug("render_metric_chart: retour renderer(…)")
    return renderer(series, path)
