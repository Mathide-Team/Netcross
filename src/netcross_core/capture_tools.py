"""netcross_core.capture_tools -- manipulation de fichiers de capture
partagee par la CLI, la GUI et l'API (issues #868, #869, #870, #886, #887).

Fusion (``--merge``), decoupage (``--split``), conversion (``--convert``),
export filtre (``--export-pcap``) et recalage temporel
(``--adjust-time-output``) : les fonctions de ``pcap_parser.capture`` font
le travail ; ce module porte la validation et les messages communs, pour
qu'une meme entree soit refusee de la meme facon partout. Aucune analyse
n'est lancee.
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence

from netcross_core.logging_config import get_logger
from pcap_parser.capture import (
    adjust_timestamps,
    convert_capture,
    export_csv,
    export_filtered,
    export_json,
    merge_captures,
    split_capture,
)

logger = get_logger(__name__)

CONVERT_FORMATS = ("pcap", "pcapng", "erf", "csv", "json")
CONVERT_EXTENSIONS = {"pcap": "pcap", "pcapng": "pcapng", "erf": "erf", "csv": "csv", "json": "json"}
SPLIT_MODES = ("time", "count", "size")

_SIZE_RE = re.compile(r"(\d+(?:[.,]\d+)?)\s*([kmg])?[ob]?", re.IGNORECASE)
_SIZE_FACTORS = {None: 1, "k": 10**3, "m": 10**6, "g": 10**9}


def parse_size(text: str) -> int | None:
    """ "100M" -> 100_000_000. Unites DECIMALES (k=10^3, M=10^6, G=10^9),
    comme ``tcpdump -C``. Suffixe optionnel o/b (100Mo, 100MB). None si le
    format n'est pas reconnu (MiB/Mio volontairement refuses)."""
    m = _SIZE_RE.fullmatch(text.strip())
    if not m:
        logger.debug("parse_size: format non reconnu {!r}", text)
        return None
    number, unit = m.groups()
    return int(float(number.replace(",", ".")) * _SIZE_FACTORS[unit.lower() if unit else None])


def parse_split_spec(spec: str) -> tuple[str, float | int]:
    """MODE:VALEUR -> (mode, valeur) pour ``split_capture`` : time:60
    (secondes, decimales admises), count:10000 (paquets), size:100M
    (octets). ValueError avec le message de la CLI."""
    mode, sep, raw = spec.partition(":")
    mode = mode.strip().lower()
    raw = raw.strip()
    err = f"Format invalide pour --split: {spec} (attendu time:SECONDES, count:PAQUETS ou size:TAILLE, ex: size:100M)"
    if not sep or mode not in SPLIT_MODES or not raw:
        raise ValueError(err)
    value: float | int | None
    try:
        if mode == "time":
            value = float(raw.replace(",", "."))
        elif mode == "count":
            value = int(raw)
        else:
            value = parse_size(raw)
    except ValueError:
        logger.exception("échec dans parse_split_spec")
        value = None
    if value is None or value <= 0:
        hint = " (unites decimales k/M/G, ex: 100M ; MiB/Mio non supportes)" if mode == "size" else ""
        raise ValueError(f"{err} -- la valeur doit etre un nombre > 0{hint}")
    return mode, value


def parse_endpoints(text: str | None) -> list[str] | None:
    """``--export-endpoints`` : « IP1,IP2 » -> liste (None si vide)."""
    endpoints = [ip.strip() for ip in (text or "").split(",") if ip.strip()]
    return endpoints or None


def split_label_dir(output_dir: str, label: str) -> str:
    """Sous-repertoire d'un point pour ``--split`` : separateurs de chemin
    neutralises, jamais de « .. »."""
    return os.path.join(output_dir, re.sub(r"[^\w.-]+", "_", label).lstrip(".") or "capture")


def merge(paths: Sequence[str], output_path: str, dedup: bool = False) -> str:
    """``--merge`` : message de la CLI."""
    merge_captures(list(paths), output_path, dedup=dedup)
    return (
        f"{len(paths)} fichier(s) fusionne(s) dans {output_path}"
        + (" (paquets identiques dedupliques)" if dedup else "")
        + "."
    )


def split(path: str, output_dir: str, spec: str) -> list[str]:
    """``--split MODE:VALEUR`` d'un fichier : segments crees, dans l'ordre."""
    mode, value = parse_split_spec(spec)
    return split_capture(path, output_dir, mode, value)


def convert(path_in: str, path_out: str, fmt: str) -> str:
    """``--convert`` : pcap, pcapng, erf, ou export structure csv/json."""
    if fmt not in CONVERT_FORMATS:
        raise ValueError(f"format non supporte : {fmt!r}. Formats reconnus : {', '.join(CONVERT_FORMATS)}.")
    if fmt == "csv":
        export_csv(path_in, path_out)
    elif fmt == "json":
        export_json(path_in, path_out)
    else:
        convert_capture(path_in, path_out, fmt=fmt)
    return f"Converti {path_in} -> {path_out} (format: {fmt})."


def export_subset(
    path_in: str,
    path_out: str,
    bpf_filter: str | None = None,
    time_start: float | None = None,
    time_end: float | None = None,
    endpoints: list[str] | None = None,
) -> str:
    """``--export-pcap`` avec ``--export-bpf``, ``--export-time-start``,
    ``--export-time-end``, ``--export-endpoints``."""
    export_filtered(
        path_in,
        path_out,
        bpf_filter=bpf_filter or None,
        time_start=time_start,
        time_end=time_end,
        endpoints=endpoints,
    )
    return f"{path_out} cree."


def adjust_time(
    path_in: str,
    path_out: str,
    offset: float | None = None,
    normalize: bool = False,
    align_to: str | None = None,
) -> str:
    """``--adjust-time-output`` avec ``--time-offset``, ``--normalize-time``
    ou ``--align-to`` : un seul des trois, comme la CLI."""
    if sum((offset is not None, bool(normalize), bool(align_to))) > 1:
        raise ValueError("--time-offset, --normalize-time et --align-to sont mutuellement exclusifs.")
    adjust_timestamps(
        path_in,
        path_out,
        offset_seconds=offset if offset is not None else 0.0,
        normalize=normalize,
        align_to=align_to or None,
    )
    return f"{path_out} cree."
