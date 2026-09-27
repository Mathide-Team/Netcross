"""
netcross_core.baseline_profile -- profil de reference dynamique construit
a partir de l'historique SQLite (Job 12/issue #9, section 8.5 de
FEATURES.md).

Transforme la comparaison baseline/courant en source de reference
generale : au lieu de comparer deux runs isoles, on agrege l'historique
complet en une distribution de reference (mediane, percentiles, variance).

L'historique est stocke dans SQLite par ``netcross_report.history`` -- ce
module le lit directement via ``sqlite3`` (stdlib), sans importer
``netcross_report`` (respect du contrat d'architecture : netcross_core
ne depend jamais de netcross_report).

Schema SQLite utilise (table ``runs``) :
- ``health_score`` (INTEGER) : score de sante global
- ``total_findings`` (INTEGER) : nombre total de constats
- ``finding_counts`` (TEXT, JSON) : compteurs par severite

Metriques extraites :
- ``health_score`` : distribution des scores de sante
- ``total_findings`` : distribution du nombre de constats
- ``finding_count:<severity>`` : distribution par severite
"""

from __future__ import annotations

import json
import sqlite3
import statistics
from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class BaselineProfile:
    """Distribution de reference pour une metrique, construite a partir
    de l'historique SQLite.

    ``metric`` : nom de la metrique (ex: ``health_score``,
    ``total_findings``, ``finding_count:anomalie``).

    ``count`` : nombre de runs historiques utilises.

    ``percentiles`` : dictionnaire des percentiles calcules
    (``P50`` = mediane, ``P95``, ``P99``).

    ``mean``, ``variance``, ``std`` : statistiques de dispersion.

    ``min``, ``max`` : extremes observes.

    ``values`` : liste triee des valeurs brutes (pour inspection ou
    comparaison manuelle).
    """

    metric: str
    count: int = 0
    mean: float = 0.0
    median: float = 0.0
    percentiles: dict[str, float] = field(default_factory=dict)
    variance: float = 0.0
    std: float = 0.0
    min: float = 0.0
    max: float = 0.0
    values: list[float] = field(default_factory=list)


def _percentile(sorted_values: list[float], p: float) -> float:
    """Calcule le p-eme percentile (0-100) d'une liste triee.

    Methode d'interpolation lineaire (meme convention que numpy/Excel).
    """
    if not sorted_values:
        logger.debug("_percentile: retour 0.0")
        return 0.0
    if len(sorted_values) == 1:
        logger.debug("_percentile: retour element")
        return sorted_values[0]
    k = (len(sorted_values) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    logger.debug("_percentile: retour calcul")
    return sorted_values[f] + (sorted_values[c] - sorted_values[f]) * (k - f)


def build_baseline_profile(metric: str, values: list[float]) -> BaselineProfile:
    """Construit un ``BaselineProfile`` a partir d'une liste de valeurs
    brutes. Pure fonction de calcul, sans I/O.

    Si la liste est vide, retourne un profil avec count=0 et toutes les
    statistiques a zero.
    """
    if not values:
        logger.debug("build_baseline_profile: retour BaselineProfile(...)")
        return BaselineProfile(metric=metric, count=0)

    sorted_vals = sorted(values)
    n = len(sorted_vals)
    mean = statistics.mean(sorted_vals)
    var = statistics.variance(sorted_vals) if n > 1 else 0.0
    std = statistics.stdev(sorted_vals) if n > 1 else 0.0

    logger.debug("build_baseline_profile: retour BaselineProfile(...)")
    return BaselineProfile(
        metric=metric,
        count=n,
        mean=mean,
        median=statistics.median(sorted_vals),
        percentiles={
            "P50": _percentile(sorted_vals, 50),
            "P95": _percentile(sorted_vals, 95),
            "P99": _percentile(sorted_vals, 99),
        },
        variance=var,
        std=std,
        min=sorted_vals[0],
        max=sorted_vals[-1],
        values=sorted_vals,
    )


def _extract_metrics_from_row(row: sqlite3.Row) -> dict[str, float]:
    """Extrait les metriques d'une ligne de la table ``runs``.

    Retourne un dict ``{metric_name: value}`` pour chaque metrique
    disponible dans cette ligne.
    """
    metrics: dict[str, float] = {}
    metrics["health_score"] = float(row["health_score"])
    metrics["total_findings"] = float(row["total_findings"])

    # finding_counts est un JSON : {"anomalie": 3, "a_surveiller": 5, ...}
    try:
        counts = json.loads(row["finding_counts"])
        if isinstance(counts, dict):
            for sev, count in counts.items():
                metrics[f"finding_count:{sev}"] = float(count)
    except (json.JSONDecodeError, TypeError):
        logger.exception("échec dans _extract_metrics_from_row")
        pass

    logger.debug("_extract_metrics_from_row: retour metrics")
    return metrics


def load_baseline_from_db(
    db_path: str,
    metric: str = "health_score",
    label: str | None = None,
    limit: int | None = None,
) -> BaselineProfile | None:
    """Charge l'historique SQLite et construit un ``BaselineProfile``
    pour la metrique donnee.

    ``metric`` : nom de la metrique (``health_score``,
    ``total_findings``, ``finding_count:<severity>``).

    ``label`` : filtre optionnel par label de run.

    ``limit`` : nombre maximum de runs a considerer (les plus recents).

    Retourne ``None`` si la base n'existe pas ou ne contient aucun run.
    """
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error:
        logger.exception("échec dans load_baseline_from_db")
        logger.debug("load_baseline_from_db: except sqlite3.Error -> retour None")
        return None

    try:
        query = "SELECT * FROM runs"
        params: list = []
        conditions: list[str] = []
        if label is not None:
            conditions.append("label = ?")
            params.append(label)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY id DESC"
        if limit is not None:
            query += f" LIMIT {int(limit)}"

        rows = conn.execute(query, params).fetchall()
    except sqlite3.Error:
        logger.exception("échec dans load_baseline_from_db")
        conn.close()
        logger.debug("load_baseline_from_db: retour None")
        return None
    finally:
        conn.close()

    if not rows:
        logger.debug("load_baseline_from_db: retour None")
        return None

    values: list[float] = []
    for row in rows:
        metrics = _extract_metrics_from_row(row)
        if metric in metrics:
            values.append(metrics[metric])

    if not values:
        logger.debug("load_baseline_from_db: retour None")
        return None

    logger.debug("load_baseline_from_db: retour build_baseline_profile(...)")
    return build_baseline_profile(metric, values)


def load_all_baselines(
    db_path: str,
    label: str | None = None,
    limit: int | None = None,
) -> list[BaselineProfile]:
    """Charge toutes les metriques disponibles depuis l'historique et
    construit un ``BaselineProfile`` pour chacune.

    Retourne une liste vide si la base n'existe pas ou est vide.
    """
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error:
        logger.exception("échec dans load_all_baselines")
        logger.debug("load_all_baselines: except sqlite3.Error -> retour liste vide")
        return []

    try:
        query = "SELECT * FROM runs"
        params: list = []
        conditions: list[str] = []
        if label is not None:
            conditions.append("label = ?")
            params.append(label)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY id DESC"
        if limit is not None:
            query += f" LIMIT {int(limit)}"

        rows = conn.execute(query, params).fetchall()
    except sqlite3.Error:
        logger.exception("échec dans load_all_baselines")
        conn.close()
        logger.debug("load_all_baselines: retour liste")
        return []
    finally:
        conn.close()

    if not rows:
        logger.debug("load_all_baselines: retour liste")
        return []

    # Collecter toutes les metriques disponibles
    all_metrics: dict[str, list[float]] = {}
    for row in rows:
        metrics = _extract_metrics_from_row(row)
        for metric_name, value in metrics.items():
            all_metrics.setdefault(metric_name, []).append(value)

    logger.debug("load_all_baselines: retour liste")
    return [build_baseline_profile(m, vals) for m, vals in all_metrics.items() if vals]
