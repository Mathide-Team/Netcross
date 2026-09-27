"""Detection d'anomalies de flux par rapport a une baseline (Isolation Forest).

La baseline est un fichier JSON de **caracteristiques** (jamais un modele
serialise par pickle : un fichier de baseline recu ne peut pas executer de
code). Le modele est reentraine a chaque chargement, avec une graine fixe :
meme baseline -> memes resultats.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev

from netcross_ai.features import FEATURE_NAMES, flow_features, flow_key
from netcross_ai.flow_classifier import is_feature_vector
from netcross_ai.optional import require_ml
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)
BASELINE_SCHEMA = "netcross.ai.baseline/1"
MIN_BASELINE_FLOWS = 20
_Z_EXPLAIN = 3.0


class BaselineError(ValueError):
    """Fichier de baseline invalide ou trop petit."""


@dataclass
class Baseline:
    vectors: list[list[float]]
    label: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @classmethod
    def from_flows(cls, flows: list[dict], label: str = "") -> Baseline:
        logger.debug("from_flows: retour cls(...)")
        return cls([flow_features(f) for f in flows], label)

    def merge(self, other: Baseline) -> Baseline:
        logger.debug("merge: retour Baseline(...)")
        return Baseline(self.vectors + other.vectors, self.label or other.label)

    def to_dict(self) -> dict:
        logger.debug("to_dict: retour dict")
        return {
            "schema": BASELINE_SCHEMA,
            "features": list(FEATURE_NAMES),
            "label": self.label,
            "created_at": self.created_at,
            "vectors": self.vectors,
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), ensure_ascii=False), encoding="utf-8")
        logger.debug("Baseline.save: fin")

    @classmethod
    def from_dict(cls, data: object, source: str = "baseline") -> Baseline:
        """Valide un document ``netcross.ai.baseline/1`` deja decode."""
        if not isinstance(data, dict) or data.get("schema") != BASELINE_SCHEMA:
            logger.trace("Baseline.from_dict: refus, BaselineError")
            logger.debug(
                "Baseline.from_dict: si not isinstance(data, dict) or data.get('schema') != BASELIN… -> levée Baselin…"
            )
            raise BaselineError(f"{source} n'est pas une baseline {BASELINE_SCHEMA}.")
        if data.get("features") != list(FEATURE_NAMES):
            logger.trace("Baseline.from_dict: refus, BaselineError")
            logger.debug("Baseline.from_dict: si data.get('features') != list(FEATURE_NAMES) -> levée BaselineError")
            raise BaselineError(f"{source} : caracteristiques differentes de cette version, regenerer la baseline.")
        vectors = data.get("vectors")
        if not isinstance(vectors, list) or not all(is_feature_vector(v) for v in vectors):
            logger.trace("Baseline.from_dict: refus, BaselineError")
            logger.debug(
                "Baseline.from_dict: si not isinstance(vectors, list) or not all((is_feature_vector… -> levée Baselin…"
            )
            raise BaselineError(f"{source} : vecteurs invalides.")
        logger.debug("from_dict: retour cls(...)")
        return cls(
            [[float(x) for x in v] for v in vectors], str(data.get("label", "")), str(data.get("created_at", ""))
        )

    @classmethod
    def load(cls, path: str | Path) -> Baseline:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.exception(f"échec dans load: {exc}")
            raise BaselineError(f"baseline illisible ({path}) : {exc}") from exc
        logger.debug("load: retour from_dict(...)")
        return cls.from_dict(data, str(path))


@dataclass
class FlowAnomaly:
    flow: str
    score: float  # 0 (typique) .. 1 (tres atypique)
    is_anomaly: bool
    classification: str
    reasons: list[str]

    def to_dict(self) -> dict:
        logger.debug("to_dict: retour dict")
        return {
            "flow": self.flow,
            "score": self.score,
            "is_anomaly": self.is_anomaly,
            "classification": self.classification,
            "reasons": self.reasons,
        }


def _explain(vector: list[float], means: list[float], stds: list[float]) -> list[str]:
    out = []
    for name, value, m, s in zip(FEATURE_NAMES, vector, means, stds):
        z = (value - m) / s if s > 1e-9 else (0.0 if abs(value - m) < 1e-9 else float("inf"))
        if abs(z) >= _Z_EXPLAIN:
            out.append(f"{name} = {value:.3g} (baseline {m:.3g} +/- {s:.2g})")
    logger.debug("_explain: retour out")
    return out


def detect_anomalies(baseline: Baseline, flows: list[dict], contamination: float | str = "auto") -> list[FlowAnomaly]:
    """Score chaque flux ; les plus atypiques en premier."""
    require_ml("La detection d'anomalies")
    if len(baseline.vectors) < MIN_BASELINE_FLOWS:
        logger.trace("detect_anomalies: refus, BaselineError")
        logger.debug("detect_anomalies: si len(baseline.vectors) < MIN_BASELINE_FLOWS -> levée BaselineError")
        raise BaselineError(
            f"baseline trop petite ({len(baseline.vectors)} flux, {MIN_BASELINE_FLOWS} minimum) : "
            "l'enrichir avec d'autres captures de trafic normal."
        )
    if not flows:
        logger.debug("detect_anomalies: retour liste")
        return []
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=0)
    model.fit(baseline.vectors)
    vectors = [flow_features(f) for f in flows]
    raw = [-s for s in model.score_samples(vectors)]  # plus grand = plus atypique
    flags = model.predict(vectors)
    columns = list(zip(*baseline.vectors))
    means = [mean(c) for c in columns]
    stds = [pstdev(c) for c in columns]
    # score_samples est dans ]0, 1] en valeur absolue (0.5 ~ typique)
    results = [
        FlowAnomaly(
            flow=flow_key(f),
            score=round(min(1.0, max(0.0, r)), 3),
            is_anomaly=bool(flag == -1),
            classification=str(f.get("classification", "")),
            reasons=_explain(v, means, stds),
        )
        for f, v, r, flag in zip(flows, vectors, raw, flags)
    ]
    logger.debug("detect_anomalies: retour sorted(...)")
    return sorted(results, key=lambda a: a.score, reverse=True)
