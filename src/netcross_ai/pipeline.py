"""Orchestration des trois usages pour la CLI (``--ai-*``) et mise en forme."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from netcross_ai.anomaly import Baseline, detect_anomalies
from netcross_ai.flow_classifier import FlowClassifier, export_training_set, load_training_set
from netcross_ai.report_writer import write_summary
from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

AI_SCHEMA = "netcross.ai/1"


@dataclass
class AIOptions:
    baseline_path: str | None = None
    baseline_save: str | None = None
    baseline_label: str = ""
    training_path: str | None = None
    training_export: str | None = None
    summary_engine: str | None = None
    endpoint: str | None = None


def run_ai(report: Any, flows: list[dict], options: AIOptions) -> dict:
    """Execute les usages demandes ; leve AIUnavailableError, BaselineError,
    TrainingSetError ou WriterConfigError sur une demande impossible."""
    logger.debug(
        "run_ai: report={} flows={} options={}",
        summarize(report, "report"),
        summarize(flows, "flows"),
        summarize(options, "options"),
    )
    result: dict = {"schema": AI_SCHEMA, "flows": len(flows)}
    if options.baseline_save:
        new = Baseline.from_flows(flows, options.baseline_label)
        if os.path.exists(options.baseline_save):
            # enrichissement : une baseline se construit sur plusieurs captures
            new = Baseline.load(options.baseline_save).merge(new)
        new.save(options.baseline_save)
        result["baseline_saved"] = {"path": options.baseline_save, "flows": len(new.vectors)}
    if options.baseline_path:
        baseline = Baseline.load(options.baseline_path)
        result["anomalies"] = [a.to_dict() for a in detect_anomalies(baseline, flows)]
        result["baseline"] = {"path": options.baseline_path, "flows": len(baseline.vectors), "label": baseline.label}
    if options.training_export:
        result["training_exported"] = {
            "path": options.training_export,
            "samples": export_training_set(flows, options.training_export),
        }
    if options.training_path:
        classifier = FlowClassifier(load_training_set(options.training_path))
        result["classification"] = [p.to_dict() for p in classifier.predict(flows)]
        result["training"] = {"path": options.training_path, "labels": classifier.labels}
    if options.summary_engine:
        result["summary"] = write_summary(report, result, options.summary_engine, options.endpoint).to_dict()
    logger.debug("run_ai: retour result")
    return result


def format_ai(result: dict, top: int = 10) -> str:
    logger.debug("format_ai: result={} top={}", summarize(result, "result"), summarize(top, "top"))
    lines = ["", "=" * 70, "MODULE IA LOCAL (issue #146)", "=" * 70]
    if "baseline_saved" in result:
        b = result["baseline_saved"]
        lines.append(f"Baseline enregistree : {b['path']} ({b['flows']} flux au total).")
    if "anomalies" in result:
        flagged = [a for a in result["anomalies"] if a["is_anomaly"]]
        b = result["baseline"]
        lines.append(f"\nAnomalies vs baseline ({b['flows']} flux de reference) : {len(flagged)} flux atypique(s)")
        for a in flagged[:top]:
            lines.append(f"  [{a['score']:.2f}] {a['flow']} ({a['classification'] or '-'})")
            lines.extend(f"      - {r}" for r in a["reasons"][:4])
    if "training_exported" in result:
        t = result["training_exported"]
        lines.append(f"\nJeu d'entrainement exporte : {t['path']} ({t['samples']} flux pre-etiquetes a corriger).")
    if "classification" in result:
        lines.append(f"\nClassification ({', '.join(sorted(result['training']['labels']))}) :")
        preds = sorted(result["classification"], key=lambda p: (p["label"] == "normal", -p["confidence"]))
        lines.extend(
            f"  {p['label']:<13} {p['confidence']:>5.0%}  {p['flow']} (regles : {p['rule_classification']})"
            for p in preds[:top]
        )
    if "summary" in result:
        s = result["summary"]
        lines.append(f"\nResume executif ({s['engine']}) :")
        if s["fallback_reason"]:
            lines.append(f"  ({s['fallback_reason']})")
        lines.append(s["text"])
        if s["correlations"]:
            lines.append("\nCorrelations :")
            lines.extend(f"  - {c}" for c in s["correlations"])
        if s["recommendations"]:
            lines.append("\nRecommandations :")
            lines.extend(f"  {i}. {r}" for i, r in enumerate(s["recommendations"], 1))
    logger.debug("format_ai: retour join(...)")
    return "\n".join(lines)
