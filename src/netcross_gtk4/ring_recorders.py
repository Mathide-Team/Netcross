"""netcross_gtk4.ring_recorders -- rotation de capture (ring buffer) de la
GUI en capture en direct (issue #676).

La case « Rotation de capture » existait sans etre cablee. Elle lance
desormais, pour chaque point de capture, un ``tshark`` d'enregistrement en
ring buffer natif (``pcap_parser.capture.start_ring_recorder``), en parallele
de l'analyse en direct : meme comportement que ``--ring-buffer N:SECONDES``
de la CLI.

Module sans GTK (aucun import de gi) : testable sans interface graphique,
meme principe que live_capture_points.py. Les fonctions renvoient des
messages a afficher dans le journal de la GUI au lieu d'imprimer.
"""

from __future__ import annotations

import os
import signal
import tempfile
from collections.abc import Callable, Sequence

from netcross_core.logging_config import get_logger
from pcap_parser.capture import TsharkNotFoundError, start_ring_recorder, stop_ring_recorder
from pcap_parser.remote import CaptureSourceError

logger = get_logger(__name__)


class RingRecorderError(Exception):
    """Un point ne peut pas etre enregistre en ring buffer (source pipe://,
    tshark absent, repertoire impossible a creer). Les enregistreurs deja
    lances ont ete arretes avant la levee."""


def start_ring_recorders(
    points: Sequence[tuple[str, str, str | None]],
    max_files: int,
    max_duration: float,
    *,
    starter: Callable = start_ring_recorder,
    mkdtemp: Callable = tempfile.mkdtemp,
) -> tuple[dict, list[str]]:
    """Lance un enregistreur par point ``(label, interface, filtre_bpf)``.

    Renvoie ``({label: (processus, repertoire)}, messages)``. Leve
    ``RingRecorderError`` si un point est refuse : tout est alors arrete, la
    capture ne doit pas demarrer a moitie enregistree."""
    recorders: dict = {}
    messages: list[str] = []
    for label, interface, bpf_filter in points:
        try:
            directory = mkdtemp(prefix=f"netcross-ring-{label}-")
            proc = starter(
                interface,
                directory,
                max_files=max_files,
                max_duration_per_file=max_duration,
                prefix=label,
                bpf_filter=bpf_filter,
            )
        except (CaptureSourceError, TsharkNotFoundError, OSError) as exc:
            logger.warning("start_ring_recorders: point {} refuse ({})", label, exc)
            stop_ring_recorders(recorders)
            raise RingRecorderError(f"[{label}] {exc}") from exc
        recorders[label] = (proc, directory)
        messages.append(
            f"[{label}] rotation de capture : {max_files} fichier(s) de {max_duration:g} s max dans {directory}"
        )
    logger.debug("start_ring_recorders: {} enregistreur(s)", len(recorders))
    return recorders, messages


def stop_ring_recorders(recorders: dict, *, stopper: Callable = stop_ring_recorder) -> list[str]:
    """Arrete les enregistreurs ; renvoie, par point, le nombre de fichiers
    conserves et l'eventuelle erreur de tshark."""
    messages: list[str] = []
    for label, (proc, directory) in recorders.items():
        err = stopper(proc)
        try:
            files = sorted(f for f in os.listdir(directory) if not f.startswith("."))
        except OSError as exc:
            logger.warning("stop_ring_recorders: repertoire {} illisible ({})", directory, exc)
            files = []
        messages.append(f"[{label}] rotation de capture : {len(files)} fichier(s) conserve(s) dans {directory}")
        if proc.returncode not in (0, -signal.SIGTERM, None) and err:
            messages.append(f"[{label}] enregistreur tshark : {err}")
    logger.debug("stop_ring_recorders: {} message(s)", len(messages))
    return messages
