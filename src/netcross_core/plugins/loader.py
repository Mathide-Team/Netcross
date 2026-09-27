"""
netcross_core.plugins.loader -- decouverte et chargement EXPLICITE des
plugins (issue #284).

Deux sources :

- `entry_points` des groupes `netcross.detectors` / `netcross.exporters`
  (mecanisme standard, installable par pip). La decouverte ne lit que les
  METADONNEES : aucun code de plugin n'est importe tant que son nom n'est
  pas dans `--plugins`. Un plugin installe n'est pas un plugin autorise.
- `--plugin-path FICHIER.py` : un script local que personne n'empaquettera.
  Donner le chemin vaut consentement a importer le fichier ; ses detecteurs
  et exporteurs ne s'executent pourtant que s'ils sont nommes dans
  `--plugins`. Le module declare `DETECTORS = [...]` et/ou
  `EXPORTERS = [...]` (instances ou classes sans argument).

Contrat d'import : un plugin n'importe que `netcross_core` -- jamais
`netcross_report` ni `netcross_gtk4`. Verifie AVANT execution par lecture
de l'AST du fichier source ; un plugin en infraction est refuse.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any

from netcross_core.logging_config import get_logger
from netcross_core.plugins.api import Detector, Exporter

logger = get_logger(__name__)

GROUPS = {"detector": "netcross.detectors", "exporter": "netcross.exporters"}
FORBIDDEN_IMPORTS = ("netcross_report", "netcross_gtk4")


class PluginLoadError(Exception):
    """Plugin introuvable, refuse ou invalide ; motif lisible."""


@dataclass(frozen=True, slots=True)
class PluginInfo:
    """Plugin DECOUVERT (pas forcement charge ni autorise)."""

    name: str
    kind: str  # "detector" | "exporter"
    origin: str  # "entry_point:<distribution>" | "fichier:<chemin>"
    target: str  # "module:attr" pour un entry point, chemin pour un fichier


@dataclass(slots=True)
class LoadedPlugins:
    detectors: list[Detector] = field(default_factory=list)
    exporters: dict[str, Exporter] = field(default_factory=dict)
    # une ligne par plugin demande qui n'a pas pu etre charge
    errors: list[dict[str, str]] = field(default_factory=list)


def forbidden_imports(source: str) -> list[str]:
    """Modules interdits importes par `source` (import et from ... import)."""
    found = []
    for node in ast.walk(ast.parse(source)):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        found += [n for n in names if n.split(".")[0] in FORBIDDEN_IMPORTS]
    return sorted(set(found))


def _check_source(path: str | None, label: str) -> None:
    if not path or not path.endswith(".py"):
        return
    try:
        source = Path(path).read_text(encoding="utf-8")
    except OSError:
        logger.exception("erreur: OSError")
        return
    try:
        bad = forbidden_imports(source)
    except SyntaxError as exc:
        logger.exception(f"échec dans _check_source: {exc}")
        raise PluginLoadError(f"{label} : erreur de syntaxe ({exc.msg}, ligne {exc.lineno})") from exc
    if bad:
        raise PluginLoadError(
            f"{label} importe {', '.join(bad)} : un plugin ne doit importer que netcross_core "
            "(il recoit le Report, pas le moteur de rendu)"
        )


def _entry_points(group: str) -> list[metadata.EntryPoint]:
    return sorted(metadata.entry_points(group=group), key=lambda ep: ep.name)


def discover_installed() -> list[PluginInfo]:
    """Plugins installes (metadonnees seulement, AUCUN import)."""
    logger.debug("discover_installed()")
    infos = []
    for kind, group in GROUPS.items():
        for ep in _entry_points(group):
            dist = getattr(ep.dist, "name", None) or "?"
            infos.append(PluginInfo(ep.name, kind, f"entry_point:{dist}", ep.value))
    return infos


def _instantiate(obj: Any) -> Any:
    return obj() if isinstance(obj, type) else obj


def _check_kind(obj: Any, kind: str, label: str) -> Any:
    proto = Detector if kind == "detector" else Exporter
    method = "analyse" if kind == "detector" else "export"
    if not isinstance(getattr(obj, "name", None), str) or not callable(getattr(obj, method, None)):
        logger.trace("_check_kind: refus, PluginLoadError")
        raise PluginLoadError(f"{label} : ne respecte pas le protocole {proto.__name__} (name + {method}())")
    return obj


def load_path_module(path: str) -> dict[str, list[Any]]:
    """Importe un fichier plugin apres verification de ses imports."""
    file = Path(path)
    if not file.is_file():
        raise PluginLoadError(f"--plugin-path {path} : fichier introuvable")
    _check_source(str(file), f"--plugin-path {path}")
    mod_name = f"netcross_plugin_{file.stem}_{abs(hash(str(file.resolve()))):x}"
    spec = importlib.util.spec_from_file_location(mod_name, file)
    if spec is None or spec.loader is None:
        raise PluginLoadError(f"--plugin-path {path} : module Python non chargeable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        logger.exception(f"échec dans load_path_module: {exc}")
        sys.modules.pop(mod_name, None)
        raise PluginLoadError(f"--plugin-path {path} : import en erreur ({exc.__class__.__name__}: {exc})") from exc
    out: dict[str, list[Any]] = {"detector": [], "exporter": []}
    for kind, attr in (("detector", "DETECTORS"), ("exporter", "EXPORTERS")):
        for obj in getattr(module, attr, None) or []:
            label = f"{path}:{attr}"
            out[kind].append(_check_kind(_instantiate(obj), kind, label))
    if not out["detector"] and not out["exporter"]:
        raise PluginLoadError(f"--plugin-path {path} : ni DETECTORS ni EXPORTERS declares")
    return out


def _load_entry_point(ep: metadata.EntryPoint, kind: str) -> Any:
    label = f"plugin {ep.name}"
    module_name = ep.value.split(":")[0].strip()
    try:
        spec = importlib.util.find_spec(module_name)
    except (ImportError, ValueError) as exc:
        logger.exception(f"échec dans _load_entry_point: {exc}")
        raise PluginLoadError(f"{label} : module {module_name} introuvable ({exc})") from exc
    _check_source(spec.origin if spec else None, label)
    try:
        obj = ep.load()
    except Exception as exc:
        logger.exception(f"échec dans _load_entry_point: {exc}")
        raise PluginLoadError(f"{label} : import en erreur ({exc.__class__.__name__}: {exc})") from exc
    return _check_kind(_instantiate(obj), kind, label)


def load_plugins(authorized: list[str], plugin_paths: list[str] | None = None) -> LoadedPlugins:
    """Charge UNIQUEMENT les plugins nommes dans `authorized`.

    Un nom demande mais introuvable, ou un plugin refuse, donne une ligne
    d'erreur (jamais une exception) : l'analyse continue sans lui."""
    loaded = LoadedPlugins()
    wanted = list(dict.fromkeys(authorized))
    found: set[str] = set()

    for path in plugin_paths or []:
        try:
            objs = load_path_module(path)
        except PluginLoadError as exc:
            logger.exception(f"échec dans load_plugins: {exc}")
            loaded.errors.append({"plugin": path, "reason": str(exc)})
            continue
        for det in objs["detector"]:
            if det.name in wanted and det.name not in found:
                loaded.detectors.append(det)
                found.add(det.name)
        for exp in objs["exporter"]:
            if exp.name in wanted and exp.name not in found:
                loaded.exporters[exp.name] = exp
                found.add(exp.name)

    for kind, group in GROUPS.items():
        for ep in _entry_points(group):
            if ep.name not in wanted or ep.name in found:
                continue  # installe mais non autorise : jamais importe
            found.add(ep.name)
            try:
                obj = _load_entry_point(ep, kind)
            except PluginLoadError as exc:
                logger.exception(f"échec dans load_plugins: {exc}")
                loaded.errors.append({"plugin": ep.name, "reason": str(exc)})
                continue
            if kind == "detector":
                loaded.detectors.append(obj)
            else:
                loaded.exporters[obj.name] = obj

    for name in wanted:
        if name not in found and not any(e["plugin"] == name for e in loaded.errors):
            loaded.errors.append({"plugin": name, "reason": "introuvable (ni installe ni dans --plugin-path)"})
    return loaded


def list_plugins(authorized: list[str], plugin_paths: list[str] | None = None) -> list[dict[str, Any]]:
    """Pour `--list-plugins` : installes ET locaux, autorises ou non.

    Les fichiers `--plugin-path` sont importes (le chemin vaut consentement) ;
    les entry points ne le sont pas."""
    rows = [
        {"name": i.name, "kind": i.kind, "origin": i.origin, "authorized": i.name in authorized, "error": None}
        for i in discover_installed()
    ]
    for path in plugin_paths or []:
        try:
            objs = load_path_module(path)
        except PluginLoadError as exc:
            logger.exception(f"échec dans list_plugins: {exc}")
            origin = f"fichier:{path}"
            rows.append({"name": path, "kind": "?", "origin": origin, "authorized": False, "error": str(exc)})
            continue
        for kind, items in objs.items():
            rows += [
                {
                    "name": o.name,
                    "kind": kind,
                    "origin": f"fichier:{path}",
                    "authorized": o.name in authorized,
                    "error": None,
                }
                for o in items
            ]
    return rows
