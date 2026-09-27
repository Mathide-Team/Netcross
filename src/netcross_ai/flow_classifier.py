"""Classification de flux avec score de confiance (foret aleatoire).

Jeu d'entrainement : JSON ``netcross.ai.training/1`` -- une liste
d'exemples ``{"flow": {...stats FLOW-4...}, "label": "tunnel"}``, ou
``{"features": [...], "label": "tunnel"}`` (vecteur de caracteristiques deja
calcule, sans aucun identifiant : forme des paquets de modeles partages,
issue #271). Il se
constitue avec ``--ai-training-export`` (flux de la capture pre-etiquetes par
les regles FLOW-4), que l'analyste corrige et complete (tunnel, c2,
exfiltration...). Comme la baseline, aucun modele pickle : reentraine a
chaque chargement, graine fixe.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from netcross_ai.features import FEATURE_NAMES, flow_features, flow_key
from netcross_ai.optional import require_ml
from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)
TRAINING_SCHEMA = "netcross.ai.training/1"
MIN_SAMPLES = 10
SUGGESTED_LABELS = ("normal", "interactif", "transfert", "obfusque", "tunnel", "c2", "exfiltration")


class TrainingSetError(ValueError):
    """Jeu d'entrainement invalide."""


def export_training_set(flows: list[dict], path: str | Path) -> int:
    """Ecrit les flux pre-etiquetes (classification FLOW-4) a relire/corriger."""
    logger.debug("export_training_set: flows={} path={}", summarize(flows, "flows"), summarize(path, "path"))
    samples = [{"flow": f, "label": f.get("classification") or "normal"} for f in flows]
    data = {"schema": TRAINING_SCHEMA, "labels_suggeres": list(SUGGESTED_LABELS), "samples": samples}
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    logger.debug("export_training_set: retour len(...)")
    return len(samples)


def load_training_set(path: str | Path) -> list[tuple[dict | list[float], str]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.exception(f"échec dans load_training_set: {exc}")
        raise TrainingSetError(f"jeu d'entrainement illisible ({path}) : {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != TRAINING_SCHEMA:
        logger.debug(
            "load_training_set: si not isinstance(data, dict) or data.get('schema') != TRAININ… -> levée TrainingSetE…"
        )
        raise TrainingSetError(f"{path} n'est pas un jeu {TRAINING_SCHEMA}.")
    samples: list[tuple[dict | list[float], str]] = []
    for i, item in enumerate(data.get("samples") or []):
        if isinstance(item, dict) and item.get("label") and isinstance(item.get("flow"), dict):
            samples.append((item["flow"], str(item["label"])))
        elif isinstance(item, dict) and item.get("label") and is_feature_vector(item.get("features")):
            samples.append(([float(x) for x in item["features"]], str(item["label"])))
        else:
            logger.debug(
                "load_training_set: sinon (isinstance(item, dict) and item.get('la…) -> levée TrainingSetError"
            )
            raise TrainingSetError(
                f"{path} : exemple {i} invalide (attendu {{'flow': {{...}}, 'label': '...'}} "
                f"ou {{'features': [{len(FEATURE_NAMES)} nombres], 'label': '...'}})."
            )
    logger.debug("load_training_set: retour samples")
    return samples


def is_feature_vector(value: object) -> bool:
    """Vrai pour une liste de len(FEATURE_NAMES) nombres finis (bool exclus)."""
    logger.debug("is_feature_vector: retour booleen")
    return (
        isinstance(value, list)
        and len(value) == len(FEATURE_NAMES)
        and all(
            isinstance(x, (int, float)) and not isinstance(x, bool) and x == x and abs(x) != float("inf") for x in value
        )
    )


def sample_vector(sample: dict | list[float]) -> list[float]:
    """Vecteur de caracteristiques d'un exemple (flux FLOW-4 ou vecteur deja calcule)."""
    logger.debug("sample_vector: retour conditionnel")
    return list(sample) if isinstance(sample, list) else flow_features(sample)


@dataclass
class FlowPrediction:
    flow: str
    label: str
    confidence: float
    rule_classification: str

    def to_dict(self) -> dict:
        logger.debug("to_dict: retour dict")
        return {
            "flow": self.flow,
            "label": self.label,
            "confidence": self.confidence,
            "rule_classification": self.rule_classification,
        }


class FlowClassifier:
    def __init__(self, samples: list[tuple[dict | list[float], str]]):
        logger.debug("FlowClassifier.__init__: samples={}", summarize(samples, "samples"))
        require_ml("La classification de flux")
        labels = Counter(label for _f, label in samples)
        if len(samples) < MIN_SAMPLES or len(labels) < 2:
            logger.debug("FlowClassifier.__init__: refus, TrainingSetError")
            raise TrainingSetError(
                f"jeu d'entrainement insuffisant : {len(samples)} exemple(s), {len(labels)} classe(s) "
                f"({MIN_SAMPLES} exemples et 2 classes minimum)."
            )
        from sklearn.ensemble import RandomForestClassifier

        self.labels = dict(labels)
        self._model = RandomForestClassifier(n_estimators=200, random_state=0, class_weight="balanced")
        self._model.fit([sample_vector(f) for f, _l in samples], [label for _f, label in samples])
        logger.debug("FlowClassifier.__init__: fin")

    def predict(self, flows: list[dict]) -> list[FlowPrediction]:
        if not flows:
            logger.debug("predict: retour liste")
            return []
        probas = self._model.predict_proba([flow_features(f) for f in flows])
        classes = list(self._model.classes_)
        out = []
        for flow, row in zip(flows, probas):
            best = max(range(len(classes)), key=lambda i: row[i])
            out.append(
                FlowPrediction(
                    flow=flow_key(flow),
                    label=str(classes[best]),
                    confidence=round(float(row[best]), 3),
                    rule_classification=str(flow.get("classification", "")),
                )
            )
        logger.debug("predict: retour out")
        return out
