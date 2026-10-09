"""netcross_gtk4.advanced_options -- options d'analyse avancees de la GUI
(issue #672), sans GTK.

Equivalents de ``--max-packets``, ``--sample 1/N``, ``--parallel-workers``,
``--test-net-external``, ``--known-destinations``, ``--known-hosts`` et
``--cve-db``, avec les memes refus que la CLI : les fichiers de securite
exigent le rapport de securite, doivent exister et contenir au moins une IP
(une baseline vide ferait passer tous les hotes pour nouveaux), et une base
CVE absente n'est jamais creee vide.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

# Bornes des reglages numeriques (0 = pas de limite / automatique)
MAX_PACKETS_MAX = 1_000_000_000
SAMPLE_MAX = 1_000_000
WORKERS_MAX = 256


class AdvancedOptionError(ValueError):
    """Option refusee, message pour l'utilisateur."""


@dataclass(frozen=True)
class AdvancedSettings:
    max_packets: int | None = None
    sample_n: int | None = None
    parallel_workers: int | None = None
    test_net_external: bool = False
    known_destinations: str | None = None
    known_hosts: str | None = None
    cve_db: str | None = None

    @property
    def security_files(self) -> bool:
        return bool(self.known_destinations or self.known_hosts or self.cve_db)


def settings_from_values(
    max_packets: float,
    sample: float,
    workers: float,
    test_net_external: bool = False,
    known_destinations: str | None = None,
    known_hosts: str | None = None,
    cve_db: str | None = None,
) -> AdvancedSettings:
    """Valeurs des widgets -> reglages : 0 (et 1 pour l'echantillonnage)
    veut dire « pas de limite » ou « automatique »."""
    return AdvancedSettings(
        max_packets=int(max_packets) or None,
        sample_n=int(sample) if int(sample) > 1 else None,
        parallel_workers=int(workers) or None,
        test_net_external=test_net_external,
        known_destinations=known_destinations or None,
        known_hosts=known_hosts or None,
        cve_db=cve_db or None,
    )


def validate(settings: AdvancedSettings, *, security: bool) -> list[str]:
    """Motifs de refus (liste vide : lancement possible), libelles de la CLI."""
    errors = []
    for option, path in (
        ("--known-destinations", settings.known_destinations),
        ("--known-hosts", settings.known_hosts),
        ("--cve-db", settings.cve_db),
    ):
        if not path:
            continue
        if not security:
            errors.append(f"{option} necessite « Rapport de securite »")
        elif not os.path.isfile(path):
            errors.append(f"{option} : fichier introuvable : {path}")
    if settings.test_net_external and not security:
        errors.append("« Plages TEST-NET externes » necessite « Rapport de securite »")
    return errors


def load_host_set(path: str | None, option: str) -> frozenset[str] | None:
    """Lit une liste d'IP (meme lecteur que la CLI) ; None sans fichier."""
    if not path:
        return None
    from netcross_core.discovery.assets import load_baseline_hosts

    hosts = load_baseline_hosts(path)
    if not hosts:
        raise AdvancedOptionError(f"{option} : aucune IP lue dans {path} (JSON invalide ou liste vide)")
    logger.debug("load_host_set: {} IP dans {}", len(hosts), path)
    return frozenset(hosts)


def workers_note(workers: int | None, cpu_count: int | None) -> str | None:
    """Avertissement de la CLI quand on demande plus de lecteurs que de coeurs."""
    cpus = cpu_count or 1
    if workers and workers > cpus:
        return (
            f"{workers} lecteurs demandes pour {cpus} coeur(s) : au-dela, les processus tshark se disputent le CPU "
            "et la lecture peut ralentir."
        )
    return None
