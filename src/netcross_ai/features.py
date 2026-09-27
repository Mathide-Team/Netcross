"""Vecteur de caracteristiques d'un flux, calcule a partir des statistiques
FLOW-4 (``Report.flow_anomalies`` / ``security.flow_stats``) : taille,
SPLT, entropie, ratio montant/descendant, regularite temporelle.

Pur Python : aucune dependance, utilisable sans le module ML (export d'un
jeu d'entrainement, explication des ecarts)."""

from __future__ import annotations

import math
from statistics import mean, pstdev

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

FEATURE_NAMES: tuple[str, ...] = (
    "log_paquets",
    "log_octets",
    "entropie_tailles",
    "taille_mediane",
    "ratio_montant",
    "cv_intervalles",
    "splt_taille_moyenne",
    "splt_taille_ecart_type",
    "log_intervalle_moyen_ms",
    "part_petits_paquets",
    "part_gros_paquets",
)

_SMALL, _LARGE = 100, 500


def _splt_sizes(flow: dict) -> list[float]:
    sizes = []
    for item in flow.get("splt") or []:
        # SPLT : (taille, delta_t) -- tolere aussi une taille seule
        value = item[0] if isinstance(item, (list, tuple)) else item
        if isinstance(value, (int, float)):
            sizes.append(abs(float(value)))
    logger.debug("_splt_sizes: retour sizes")
    return sizes


def _size_counts(flow: dict) -> dict[float, int]:
    counts: dict[float, int] = {}
    for size, n in (flow.get("size_distribution") or {}).items():
        try:
            counts[float(size)] = int(n)
        except (TypeError, ValueError):  # noqa: PERF203 -- entree JSON externe, rare
            logger.exception("échec dans _size_counts")
            continue
    logger.debug("_size_counts: retour counts")
    return counts


def flow_features(flow: dict) -> list[float]:
    """Vecteur de ``len(FEATURE_NAMES)`` reels, sans NaN ni infini."""
    sizes = _splt_sizes(flow)
    counts = _size_counts(flow)
    total = sum(counts.values())
    inter = [float(x) for x in flow.get("inter_arrivals") or [] if isinstance(x, (int, float))]
    vector = [
        math.log1p(max(0, flow.get("packet_count", 0) or 0)),
        math.log1p(max(0, flow.get("byte_count", 0) or 0)),
        float(flow.get("entropy", 0.0) or 0.0),
        float(flow.get("median_size", 0.0) or 0.0),
        float(flow.get("upload_ratio", 0.0) or 0.0),
        float(flow.get("regularity_cv", 0.0) or 0.0),
        mean(sizes) if sizes else 0.0,
        pstdev(sizes) if len(sizes) > 1 else 0.0,
        math.log1p(mean(inter) * 1000) if inter else 0.0,
        sum(n for s, n in counts.items() if s < _SMALL) / total if total else 0.0,
        sum(n for s, n in counts.items() if s > _LARGE) / total if total else 0.0,
    ]
    logger.debug("flow_features: retour liste")
    return [v if math.isfinite(v) else 0.0 for v in vector]


def flow_key(flow: dict) -> str:
    logger.debug("flow_key: retour valeur")
    return f"{flow.get('src', '?')} -> {flow.get('dst', '?')}"
