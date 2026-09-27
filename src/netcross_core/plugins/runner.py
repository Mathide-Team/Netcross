"""
netcross_core.plugins.runner -- execution isolee des plugins (issue #284).

Regle de tracabilite : un detecteur muet parce que plante doit se
distinguer d'un detecteur qui n'a rien trouve. Chaque plugin execute (ou
refuse) produit UNE ligne dans `Report.plugin_runs` :

    detecteur site_smb : ok, 2 constat(s)
    detecteur maison : ok, aucun constat
    detecteur fragile : erreur, constats absents -- ValueError: boom
    detecteur bavard : partiel, 3 constat(s), 1 invalide(s) ignore(s) -- ...

Une exception d'un plugin n'interrompt jamais l'analyse. Les constats du
coeur sont photographies avant chaque detecteur et restaures s'ils ont
change (defense en profondeur, en plus des vues en lecture seule).
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from netcross_core.logging_config import get_logger, summarize
from netcross_core.plugins.api import (
    Detector,
    DetectorContext,
    Exporter,
    InvalidFindingError,
    ReadOnlyView,
    validate_finding,
)

logger = get_logger(__name__)

_KIND_LABEL = {"detector": "detecteur", "exporter": "exporteur", "plugin": "plugin"}


def _run(plugin: str, kind: str, status: str, reason: str | None = None, **extra: Any) -> dict[str, Any]:
    run: dict[str, Any] = {"plugin": plugin, "kind": kind, "status": status, "reason": reason, **extra}
    run["line"] = run_line(run)
    logger.debug("_run: retour run={}", summarize(run, "run"))
    return run


def run_line(run: dict[str, Any]) -> str:
    label = f"{_KIND_LABEL.get(run['kind'], run['kind'])} {run['plugin']}"
    status = run["status"]
    reason = run.get("reason")
    if run["kind"] == "detector" and status in {"ok", "partiel"}:
        n = run.get("findings", 0)
        text = f"{label} : {status}, " + (f"{n} constat(s)" if n else "aucun constat")
        if run.get("invalid"):
            text += f", {run['invalid']} invalide(s) ignore(s)"
    elif run["kind"] == "detector" and status == "erreur":
        text = f"{label} : erreur, constats absents"
    elif run["kind"] == "exporter" and status == "ok":
        text = f"{label} : ok, ecrit dans {run.get('path')}"
    else:
        text = f"{label} : {status}"
    logger.debug("run_line: retour f'(text) -- (reason)' if reason else text")
    return f"{text} -- {reason}" if reason else text


def _error(exc: BaseException) -> str:
    logger.debug("_error: retour f'(exc.__class__.__name__): (exc)'[:300]")
    return f"{exc.__class__.__name__}: {exc}"[:300]


def load_error_runs(errors: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Lignes de tracabilite pour les plugins demandes mais non charges."""
    logger.debug("load_error_runs: retour liste")
    return [_run(e["plugin"], "plugin", "refuse", e["reason"]) for e in errors]


def run_detectors(detectors: list[Detector], packets: list[Any], report: Any) -> list[dict[str, Any]]:
    """Execute chaque detecteur et ajoute ses constats valides a
    `report.security_findings` (cle `plugin` = nom du detecteur)."""
    runs = []
    if report.security_findings is None:
        report.security_findings = []
    for det in detectors:
        name = det.name
        snapshot = copy.deepcopy(report.security_findings)
        try:
            raw = det.analyse(DetectorContext.build(packets, report))
        except Exception as exc:  # noqa: BLE001 -- un plugin ne fait jamais echouer l'analyse
            logger.warning("detecteur {} : erreur, constats absents -- {}", name, _error(exc))
            runs.append(_run(name, "detector", "erreur", _error(exc), findings=0, invalid=0))
            continue
        finally:
            if report.security_findings != snapshot:
                logger.warning("detecteur {} : modification des constats du coeur annulee", name)
                report.security_findings[:] = snapshot
        if raw is None:
            raw = []
        if not isinstance(raw, list | tuple):
            reason = f"renvoie {type(raw).__name__}, liste de constats attendue"
            logger.warning("detecteur {} : erreur, constats absents -- {}", name, reason)
            runs.append(_run(name, "detector", "erreur", reason, findings=0, invalid=0))
            continue
        valid, problems = [], []
        for item in raw:
            try:
                finding = validate_finding(item)
            except InvalidFindingError as exc:
                logger.exception(f"échec dans run_detectors: {exc}")
                problems.append(str(exc))
                continue
            finding["plugin"] = name
            valid.append(finding)
        report.security_findings.extend(valid)
        status = "partiel" if problems else "ok"
        reason = f"premier motif : {problems[0]}" if problems else None
        if problems:
            logger.warning("detecteur {} : {} constat(s) invalide(s) ignore(s) -- {}", name, len(problems), problems[0])
        runs.append(_run(name, "detector", status, reason, findings=len(valid), invalid=len(problems)))
    logger.debug("run_detectors: retour runs={}", summarize(runs, "runs"))
    return runs


def run_exporters(exporters: dict[str, Exporter], targets: list[tuple[str, str]], report: Any) -> list[dict[str, Any]]:
    """`targets` : couples (nom d'exporteur, chemin). Un exporteur non
    charge (non autorise, introuvable) donne une ligne `absent`."""
    runs = []
    view = ReadOnlyView(report)
    for name, path in targets:
        exporter = exporters.get(name)
        if exporter is None:
            runs.append(_run(name, "exporter", "absent", "non charge (absent de --plugins ou refuse)"))
            continue
        try:
            exporter.export(view, Path(path))
        except Exception as exc:  # noqa: BLE001
            logger.warning("exporteur {} : erreur -- {}", name, _error(exc))
            runs.append(_run(name, "exporter", "erreur", _error(exc), path=path))
            continue
        runs.append(_run(name, "exporter", "ok", path=path))
    logger.debug("run_exporters: retour runs={}", summarize(runs, "runs"))
    return runs
