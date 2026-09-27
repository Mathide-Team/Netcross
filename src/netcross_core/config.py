"""
netcross_core.config -- chargement de configuration depuis .netcross.toml
(issue #170).

Permet de ne plus tout passer par arguments CLI : un fichier de
configuration TOML à la racine du projet (ou spécifié via --config)
définit les valeurs par défaut.

Sections supportées :

    [analysis]
    points_order = ["LAN", "WAN"]
    bucket_seconds = 1.0
    rtp_clock_rate = 8000

    [output]
    format = "text"          # text | json | pdf | csv
    output_path = ""
    json_report = ""
    security_report = ""

    [security]
    enable = true

    [parallel]
    workers = 0              # 0 = auto (os.cpu_count())

    [notify]                 # issue #280 -- secrets ICI ou en variables
    webhook = ""             # d'environnement, jamais en ligne de commande
    slack_webhook = ""       # (NETCROSS_SLACK_WEBHOOK)
    email_to = ""            # destinataires separes par des virgules
    smtp_host = ""           # NETCROSS_SMTP_HOST
    smtp_port = 587          # NETCROSS_SMTP_PORT
    smtp_user = ""           # NETCROSS_SMTP_USER
    smtp_password = ""       # NETCROSS_SMTP_PASSWORD
    smtp_from = ""           # NETCROSS_SMTP_FROM
    smtp_starttls = true
    silence_hours = 24.0     # fenetre anti-repetition
    state_path = ""          # defaut : ~/.cache/netcross/notify-state.json

Usage :

    from netcross_core.config import load_config, NetcrossConfig

    cfg = load_config()                     # cherche .netcross.toml
    cfg = load_config("/path/to/cfg.toml")  # fichier explicite
    print(cfg.analysis.points_order)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# tomllib est dans la stdlib depuis Python 3.11.
# Pour 3.9-3.10, tomli est un fallback optionnel.
from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    logger.exception("erreur: ModuleNotFoundError")
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        logger.exception("erreur: ModuleNotFoundError")
        tomllib = None  # type: ignore[assignment]


@dataclass
class AnalysisConfig:
    """Configuration de l'analyse."""

    points_order: list[str] = field(default_factory=list)
    bucket_seconds: float = 1.0
    rtp_clock_rate: int = 8000


@dataclass
class OutputConfig:
    """Configuration de la sortie."""

    format: str = "text"
    output_path: str = ""
    json_report: str = ""
    security_report: str = ""


@dataclass
class SecurityConfig:
    """Configuration de la sécurité."""

    enable: bool = True


@dataclass
class ParallelConfig:
    """Configuration de la parallélisation."""

    workers: int = 0  # 0 = auto


@dataclass
class NotifyConfig:
    """Canaux de notification (issue #280). Aucun seuil ici : le seuil
    reste un choix explicite de la ligne de commande (`--notify-on`)."""

    webhook: str = ""
    slack_webhook: str = ""
    email_to: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = field(default="", repr=False)
    smtp_from: str = ""
    smtp_starttls: bool = True
    silence_hours: float = 24.0
    state_path: str = ""


@dataclass
class NetcrossConfig:
    """Configuration globale de Netcross chargée depuis .netcross.toml."""

    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    parallel: ParallelConfig = field(default_factory=ParallelConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)

    # Métadonnées
    source_path: str | None = None


def _parse_bool(val: object) -> bool:
    logger.debug("_parse_bool: val={}", summarize(val, "val"))
    if isinstance(val, bool):
        logger.debug("_parse_bool: retour val")
        return val
    if isinstance(val, str):
        logger.debug("_parse_bool: retour booleen")
        return val.lower() in ("true", "yes", "1", "on")
    logger.debug("_parse_bool: retour bool(...)")
    return bool(val)


def load_config(config_path: str | Path | None = None) -> NetcrossConfig:
    """Charge la configuration depuis un fichier .netcross.toml.

    Si ``config_path`` est None, cherche dans l'ordre :
    1. Variable d'environnement ``NETCROSS_CONFIG``
    2. ``.netcross.toml`` dans le répertoire courant
    3. ``~/.netcross.toml`` (config utilisateur)

    Retourne une ``NetcrossConfig`` avec les valeurs par défaut si aucun
    fichier n'est trouvé (pas d'erreur).
    """
    logger.debug("load_config: config_path={}", summarize(config_path, "config_path"))
    if tomllib is None:
        logger.debug("load_config: retour NetcrossConfig(...)")
        return NetcrossConfig()

    path = _find_config(config_path)
    if path is None or not path.exists():
        logger.debug("load_config: retour NetcrossConfig(...)")
        return NetcrossConfig()

    with path.open("rb") as f:
        data = tomllib.load(f)

    cfg = NetcrossConfig(source_path=str(path))

    # [analysis]
    analysis = data.get("analysis", {})
    cfg.analysis.points_order = list(analysis.get("points_order", []))
    cfg.analysis.bucket_seconds = float(analysis.get("bucket_seconds", 1.0))
    cfg.analysis.rtp_clock_rate = int(analysis.get("rtp_clock_rate", 8000))

    # [output]
    output = data.get("output", {})
    cfg.output.format = str(output.get("format", "text"))
    cfg.output.output_path = str(output.get("output_path", ""))
    cfg.output.json_report = str(output.get("json_report", ""))
    cfg.output.security_report = str(output.get("security_report", ""))

    # [security]
    security = data.get("security", {})
    cfg.security.enable = _parse_bool(security.get("enable", True))

    # [parallel]
    parallel = data.get("parallel", {})
    cfg.parallel.workers = int(parallel.get("workers", 0))

    # [notify]
    notify = data.get("notify", {})
    for key in ("webhook", "slack_webhook", "email_to", "smtp_host", "smtp_user", "smtp_password", "smtp_from"):
        setattr(cfg.notify, key, str(notify.get(key, "")))
    cfg.notify.smtp_port = int(notify.get("smtp_port", 587))
    cfg.notify.smtp_starttls = _parse_bool(notify.get("smtp_starttls", True))
    cfg.notify.silence_hours = float(notify.get("silence_hours", 24.0))
    cfg.notify.state_path = str(notify.get("state_path", ""))

    logger.debug("load_config: retour cfg")
    return cfg


def _find_config(config_path: str | Path | None) -> Path | None:
    """Trouve le fichier de configuration à charger."""
    logger.debug("_find_config: config_path={}", summarize(config_path, "config_path"))
    if config_path is not None:
        logger.debug("_find_config: retour Path(...)")
        return Path(config_path)

    # 1. Variable d'environnement
    env_path = os.environ.get("NETCROSS_CONFIG")
    if env_path:
        logger.debug("_find_config: retour Path(...)")
        return Path(env_path)

    # 2. .netcross.toml dans le répertoire courant
    cwd_path = Path.cwd() / ".netcross.toml"
    if cwd_path.exists():
        logger.debug("_find_config: retour cwd_path")
        return cwd_path

    # 3. ~/.netcross.toml
    home_path = Path.home() / ".netcross.toml"
    if home_path.exists():
        logger.debug("_find_config: retour home_path")
        return home_path

    logger.debug("_find_config: retour None")
    return None
