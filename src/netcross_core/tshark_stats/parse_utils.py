"""
netcross_core.tshark_stats.parse_utils -- utilitaires de parsing tolerants
pour les sorties texte ``tshark -z``.

Les tableaux ``tshark -z`` sont delimites par des lignes ``====`` et des
champs separees par ``|`` ; les en-tetes sont souvent eclates sur plusieurs
lignes et les formats varient entre versions de tshark. Ce module fournit
les briques communes :

- detection des separateurs / lignes de titre / filtre ;
- decoupage des champs ``|`` ;
- conversions numeriques tolérantes (vide, ``-``, virgules, unites) ;
- normalisation d'en-tete (minuscules, espaces compactes, ``%`` retire).
"""

from __future__ import annotations

import re

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

#: Caracteres consideres comme separateurs de tableau (lignes ``====``).
_SEP_CHARS = frozenset("=-")


def is_separator(line: str) -> bool:
    """Vrai pour une ligne de separateur ``====`` (ou ``----``)."""
    s = line.strip()
    if len(s) < 3:
        return False
    return set(s) <= _SEP_CHARS


def is_filter_line(line: str) -> bool:
    return line.strip().startswith("Filter:")


def is_title_or_section(line: str) -> bool:
    """Lignes de titre / section sans donnees chiffrees."""
    s = line.strip()
    if not s or is_separator(s) or is_filter_line(s):
        return True
    # En-tetes typiques des tableaux conv/endpoints/io,stat.
    upper = s.upper()
    return any(
        kw in upper
        for kw in (
            "ADDRESS",
            "PACKETS",
            "BYTES",
            "PROTOCOL",
            "DURATION",
            "<-",
            "->",
            "INTERVAL",
            "FRAMES",
            "BITS/S",
            "MBIT/S",
        )
    )


def split_fields(line: str) -> list[str]:
    """Decoupe une ligne ``|``-delimitee en champs depouilles.

    Retourne une liste vide si la ligne ne contient pas de ``|``.
    """
    if "|" not in line:
        return []
    parts = line.split("|")
    # Le premier et le dernier champ sont vides (bords du tableau).
    if parts and parts[0].strip() == "":
        parts = parts[1:]
    if parts and parts[-1].strip() == "":
        parts = parts[:-1]
    return [p.strip() for p in parts]


_NUM_RE = re.compile(r"[^\d.\-+eE]")


def parse_int(s: str | None) -> int | None:
    """Conversion entier tolérante : ``""``/``-`` -> None, virgules/espaces
    et unites eventuelles retirees."""
    if s is None:
        return None
    t = s.strip().replace(",", "")
    if t in ("", "-", "--"):
        return None
    m = _NUM_RE.sub("", t)
    if m in ("", "-", "+", "."):
        return None
    try:
        return int(float(m))
    except ValueError:
        logger.exception("échec dans parse_int")
        return None


def parse_float(s: str | None) -> float | None:
    if s is None:
        return None
    t = s.strip().replace(",", "")
    if t in ("", "-", "--"):
        return None
    m = _NUM_RE.sub("", t)
    if m in ("", "-", "+", "."):
        return None
    try:
        return float(m)
    except ValueError:
        logger.exception("échec dans parse_float")
        return None


def normalize_header(s: str) -> str:
    """Normalise un nom de colonne : minuscules, espaces compactes,
    ``%`` retire, unites ``bits/s``/``mbit/s`` ramenees a ``bits_s``."""
    t = s.strip().lower()
    t = t.replace("%", "")
    t = t.replace("<->", " address ")
    t = t.replace("->", " ")
    t = t.replace("<-", " ")
    t = t.replace("bits/s", "bits_s")
    t = t.replace("mbit/s", "bits_s")
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def find_column(headers: list[str], *keywords: str) -> int | None:
    """Retourne l'indice de la premiere colonne dont l'en-tete normalise
    contient tous les mots-cles donnes, ou None."""
    logger.debug("find_column: headers={} keywords={}", summarize(headers, "headers"), summarize(keywords, "keywords"))
    for i, h in enumerate(headers):
        nh = normalize_header(h)
        if all(kw in nh for kw in keywords):
            return i
    return None


def data_rows(text: str) -> list[str]:
    """Extrait les lignes de donnees d'un tableau ``tshark -z`` : lignes
    contenant au moins un ``|`` et au moins un champ numerique, en
    ignorant separateurs, titres, filtre et en-tetes."""
    rows: list[str] = []
    for line in text.splitlines():
        if is_separator(line) or is_filter_line(line):
            continue
        fields = split_fields(line)
        if len(fields) < 2:
            continue
        if is_title_or_section(line):
            continue
        # Une ligne de donnees contient au moins un champ numerique.
        if any(parse_int(f) is not None or parse_float(f) is not None for f in fields):
            rows.append(line)
    return rows


def header_lines(text: str) -> list[str]:
    """Lignes d'en-tete d'un tableau ``tshark -z`` : lignes contenant
    ``|`` mais identifiees comme section/titre (mots-cles Address,
    Packets, Bytes, fleches...). Les en-tetes tshark sont souvent
    eclates sur plusieurs lignes ; voir :func:`reconstruct_headers`."""
    out: list[str] = []
    for line in text.splitlines():
        if is_separator(line) or is_filter_line(line):
            continue
        if "|" not in line:
            continue
        if is_title_or_section(line):
            out.append(line)
    return out


def reconstruct_headers(text: str) -> list[str]:
    """Reconstruit le nom complet de chaque colonne en joignant les
    fragments d'en-tete multi-lignes par indice de colonne.

    tshark eclate souvent un en-tete sur 2 a 4 lignes (ex: conv,tcp) ;
    chaque ligne apporte un fragment par colonne. On aligne les fragments
    par indice de champ (apres :func:`split_fields`) et on les concatene.
    Retourne une liste vide si aucun en-tete n'est trouve.
    """
    lines = header_lines(text)
    if not lines:
        return []
    per_index: dict[int, list[str]] = {}
    max_idx = -1
    for line in lines:
        fields = split_fields(line)
        for i, f in enumerate(fields):
            per_index.setdefault(i, []).append(f)
            max_idx = max(max_idx, i)
    names: list[str] = []
    for i in range(max_idx + 1):
        parts = [p for p in per_index.get(i, []) if p]
        names.append(normalize_header(" ".join(parts)))
    return names


def raw_fields_from(headers: list[str], fields: list[str]) -> dict[str, str]:
    """Construit un dict ``{nom_colonne: valeur}`` pour toutes les colonnes
    d'une ligne de donnees -- absorbe les colonnes non mappees."""
    out: dict[str, str] = {}
    for i, val in enumerate(fields):
        key = headers[i] if i < len(headers) else f"col_{i}"
        out[key] = val
    return out
