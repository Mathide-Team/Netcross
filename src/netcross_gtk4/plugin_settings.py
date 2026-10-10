"""netcross_gtk4.plugin_settings -- plugins tiers dans la GUI (issue #867).

Equivalent GUI de ``--plugins``, ``--plugin-path``, ``--plugin-export`` et
``--list-plugins`` de la CLI, avec les memes regles :

- chargement EXPLICITE : un plugin installe ou present dans un fichier
  n'est execute que s'il est nomme dans « Plugins » ;
- les detecteurs ajoutent leurs constats au rapport de securite, qui doit
  donc etre demande (meme refus que la CLI, avant l'analyse) ;
- les exporteurs ecrivent ``NOM=FICHIER`` apres l'analyse ;
- un plugin introuvable ou en erreur donne une ligne de trace, jamais un
  echec de l'analyse (``Report.plugin_runs``, section « Plugins » du
  rapport de securite).

Module sans GTK (aucun import de gi).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

__all__ = [
    "PluginSettings",
    "PluginSettingsError",
    "PreparedPlugins",
    "detector_runs",
    "exporter_runs",
    "format_plugin_list",
    "prepare_plugins",
    "settings_from_widgets",
]

_SEPARATORS = re.compile(r"[;\n]")


class PluginSettingsError(ValueError):
    """Reglage de plugin mal forme (export sans ``NOM=FICHIER``)."""


@dataclass(frozen=True)
class PluginSettings:
    names: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    exports: tuple[tuple[str, str], ...] = ()

    @property
    def active(self) -> bool:
        return bool(self.names)


@dataclass
class PreparedPlugins:
    """Plugins charges avant l'analyse, transmis au pipeline."""

    loaded: Any
    exports: list[tuple[str, str]] = field(default_factory=list)


def _names(text: str) -> tuple[str, ...]:
    seen: list[str] = []
    for part in text.split(","):
        name = part.strip()
        if name and name not in seen:
            seen.append(name)
    return tuple(seen)


def _items(text: str) -> tuple[str, ...]:
    return tuple(p.strip() for p in _SEPARATORS.split(text) if p.strip())


def settings_from_widgets(names_text: str, paths_text: str, exports_text: str) -> PluginSettings:
    """Reglages depuis les champs : noms separes par des virgules (comme
    ``--plugins``), fichiers et exports separes par « ; » (options
    repetables de la CLI). Leve PluginSettingsError sur un export mal forme."""
    logger.debug(
        "settings_from_widgets: names={} paths={} exports={}",
        summarize(names_text, "names"),
        summarize(paths_text, "paths"),
        summarize(exports_text, "exports"),
    )
    exports = []
    for spec in _items(exports_text):
        name, sep, path = spec.partition("=")
        if not sep or not name.strip() or not path.strip():
            logger.debug("settings_from_widgets: refus, export mal forme {!r}", spec)
            raise PluginSettingsError(f"--plugin-export : format attendu NOM=FICHIER, recu {spec!r}.")
        exports.append((name.strip(), os.path.expanduser(path.strip())))
    settings = PluginSettings(
        names=_names(names_text),
        paths=tuple(os.path.expanduser(p) for p in _items(paths_text)),
        exports=tuple(exports),
    )
    logger.debug("settings_from_widgets: retour {}", summarize(settings, "settings"))
    return settings


def prepare_plugins(settings: PluginSettings, security: bool) -> tuple[PreparedPlugins | None, list[str]]:
    """Validation et chargement AVANT l'analyse, comme la CLI : renvoie
    (plugins prets ou None, erreurs bloquantes)."""
    logger.debug("prepare_plugins: settings={} security={}", summarize(settings, "settings"), security)
    errors: list[str] = []
    if settings.paths and not settings.names:
        errors.append("--plugin-path sans --plugins : aucun plugin autorise, rien ne s'executerait.")
    errors += [
        f"--plugin-export {name} : exporteur absent de --plugins."
        for name, _path in settings.exports
        if name not in settings.names
    ]
    if errors or not settings.names:
        logger.debug("prepare_plugins: retour sans chargement ({} erreur(s))", len(errors))
        return None, errors
    from netcross_core.plugins import load_plugins

    loaded = load_plugins(list(settings.names), list(settings.paths))
    if loaded.detectors and not security:
        names = ", ".join(d.name for d in loaded.detectors)
        logger.debug("prepare_plugins: refus, detecteurs sans rapport de securite")
        return None, [f"detecteur(s) de plugin {names} : « Rapport de securite » requis (--security-report)."]
    logger.debug(
        "prepare_plugins: retour {} detecteur(s), {} exporteur(s)", len(loaded.detectors), len(loaded.exporters)
    )
    return PreparedPlugins(loaded=loaded, exports=list(settings.exports)), []


def detector_runs(prepared: PreparedPlugins, packets: list, report: Any) -> list[dict]:
    """Detecteurs autorises + plugins non charges : lignes de trace, comme
    la CLI quand ``--security-report`` est demande."""
    from netcross_core.plugins import load_error_runs, run_detectors

    runs = load_error_runs(prepared.loaded.errors) + run_detectors(prepared.loaded.detectors, packets, report)
    logger.debug("detector_runs: retour {} ligne(s)", len(runs))
    return runs


def exporter_runs(prepared: PreparedPlugins, report: Any) -> list[dict]:
    """Exporteurs demandes (``NOM=FICHIER``), apres l'analyse."""
    from netcross_core.plugins import run_exporters

    runs = run_exporters(prepared.loaded.exporters, prepared.exports, report)
    logger.debug("exporter_runs: retour {} ligne(s)", len(runs))
    return runs


def format_plugin_list(settings: PluginSettings) -> str:
    """Texte de « Lister les plugins », identique a ``--list-plugins``."""
    logger.debug("format_plugin_list: settings={}", summarize(settings, "settings"))
    from netcross_core.plugins import list_plugins

    rows = list_plugins(list(settings.names), list(settings.paths))
    if not rows:
        logger.debug("format_plugin_list: aucun plugin")
        return "Aucun plugin installe (entry points netcross.detectors / netcross.exporters) ni --plugin-path."
    lines = [f"{'NOM':<24} {'TYPE':<10} {'AUTORISE':<9} ORIGINE"]
    for row in rows:
        allowed = "oui" if row["authorized"] else "non"
        lines.append(f"{row['name']:<24} {row['kind']:<10} {allowed:<9} {row['origin']}")
        if row["error"]:
            lines.append(f"  !! {row['error']}")
    unknown = [n for n in settings.names if n not in {r["name"] for r in rows}]
    if unknown:
        lines.append(f"Demande(s) dans --plugins mais introuvable(s) : {', '.join(unknown)}")
    logger.debug("format_plugin_list: retour {} ligne(s)", len(lines))
    return "\n".join(lines)
