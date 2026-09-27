"""
netcross_report.siem_export -- export des constats de securite pour
integration SIEM : CEF (issue #170), LEEF 2.0 et STIX 2.1 (issue #279).

- **CEF** (ArcSight ; lisible par Splunk, ELK, Wazuh) :
  ``CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension``
- **LEEF 2.0** (IBM QRadar) :
  ``LEEF:2.0|Vendor|Product|Version|EventID|x09|cle=valeur<TAB>cle=valeur``
- **STIX 2.1** (MISP, OpenCTI) : graphe d'objets, voir
  :mod:`netcross_report.stix_export`.

CEF et LEEF sont deux projections des MEMES enregistrements :
``_to_siem_records`` fait la selection et la normalisation des champs
(severite numerique, identifiant de signature, horodatage), ``to_cef`` et
``to_leef`` ne font que la mise en forme -- sans quoi les deux formats
deriveraient.

Usage :

    from netcross_report.siem_export import export_cef, export_leef, write_siem

    lines = export_cef(report)                 # list[str]
    write_siem(report, "out.leef", "leef")     # cef / leef / stix
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Constantes CEF
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Report

logger = get_logger(__name__)
_DEVICE_VENDOR = "Netcross"
_DEVICE_PRODUCT = "Netcross"
_DEVICE_VERSION = "1.0"

# Mapping sévérité Netcross → sévérité CEF (entier 0-10)
_SEVERITY_MAP = {
    "critique": 10,
    "elevee": 8,
    "haute": 8,
    "moyenne": 6,
    "modere": 6,
    "faible": 3,
    "info": 1,
    "informationnel": 1,
}

# Catégories Netcross → Signature ID CEF (arbitraire, stable)
_SIGID_MAP = {
    "exploit": 100,
    "anomalie": 200,
    "dns_tunnel": 201,
    "beaconing": 202,
    "protocol_mismatch": 203,
    "cve": 300,
    "lateral_movement": 204,
    "dga": 205,
    "fast_flux": 206,
}


def _cef_severity(severity: str) -> int:
    """Convertit une sévérité texte en entier CEF (0-10)."""
    logger.debug("_cef_severity: retour get(...)")
    return _SEVERITY_MAP.get(severity.lower(), 5)


def _cef_sigid(category: str) -> int:
    """Convertit une catégorie en Signature ID CEF."""
    logger.debug("_cef_sigid: retour get(...)")
    return _SIGID_MAP.get(category, 999)


def _escape_cef_field(value: str) -> str:
    """Échappe les caractères spéciaux CEF (pipe, backslash)."""
    logger.debug("_escape_cef_field: retour replace(...)")
    return value.replace("\\", "\\\\").replace("|", "\\|")


SIEM_FORMATS = ("cef", "leef", "stix")


@dataclass(frozen=True, slots=True)
class SiemRecord:
    """Un constat normalise, commun a CEF et LEEF."""

    sig_id: int
    category: str
    severity: str
    severity_num: int
    detail: str
    point: str | None
    timestamp_ms: int
    finding: Mapping[str, Any] = field(default_factory=dict)


def _to_siem_records(report: Report) -> list[SiemRecord]:
    """Selection et normalisation communes : un enregistrement par constat.

    L'horodatage est l'heure de l'export (les constats ne portent pas celle
    de leur paquet), lue une fois pour tout le lot."""
    logger.debug("_to_siem_records: report={}", summarize(report, "report"))
    now_ms = int(_dt.datetime.now().timestamp() * 1000)
    records = []
    for finding in report.security_findings:
        severity = finding.get("severity", "faible")
        category = finding.get("category", "anomalie")
        records.append(
            SiemRecord(
                sig_id=_cef_sigid(category),
                category=category,
                severity=severity,
                severity_num=_cef_severity(severity),
                detail=finding.get("detail", ""),
                point=finding.get("point"),
                timestamp_ms=now_ms,
                finding=finding,
            )
        )
    logger.debug("_to_siem_records: retour records")
    return records


# -- CEF ----------------------------------------------------------------------


def _format_extension(record: SiemRecord) -> str:
    """Formate la partie extension CEF (sortie figee, voir
    tests/test_siem_cef_golden.py)."""
    ext_parts: list[str] = []
    if record.point:
        ext_parts.append(f"shost={_escape_cef_field(record.point)}")
    ext_parts.append(f"rt={record.timestamp_ms}")
    logger.debug("_format_extension: retour join(...)")
    return " ".join(ext_parts)


def to_cef(records: list[SiemRecord]) -> list[str]:
    """Met en forme des enregistrements en lignes CEF."""
    logger.debug("to_cef: records={}", summarize(records, "records"))
    lines: list[str] = []
    for rec in records:
        name = _escape_cef_field(f"{rec.category}: {rec.detail}"[:255])
        lines.append(
            f"CEF:0|{_DEVICE_VENDOR}|{_DEVICE_PRODUCT}|{_DEVICE_VERSION}|{rec.sig_id}|{name}|"
            f"{rec.severity_num}|{_format_extension(rec)}"
        )
    logger.debug("to_cef: retour lines")
    return lines


def export_cef(report: Report) -> list[str]:
    """Exporte les constats de securite d'un Report en lignes CEF.

    Retourne une liste de chaines, une par constat. Le resultat peut
    etre ecrit ligne par ligne dans un fichier ``.cef`` ou envoye
    directement a un SIEM via syslog.
    """
    logger.debug("export_cef: report={}", summarize(report, "report"))
    return to_cef(_to_siem_records(report))


# -- LEEF 2.0 -----------------------------------------------------------------

# Separateur d'attributs : tabulation, declaree en hexadecimal dans l'en-tete
# (LEEF 2.0 accepte `xHH`) -- c'est le separateur par defaut de QRadar.
LEEF_DELIMITER = "\t"
_LEEF_DELIMITER_HEADER = "x09"
_LEEF_TIME_FORMAT = "MMM dd yyyy HH:mm:ss.SSS z"
_LEEF_MAX_MSG = 1000


def _escape_leef_header(value: str) -> str:
    """En-tete LEEF : `|` separe les champs, `\\` echappe."""
    logger.debug("_escape_leef_header: retour replace(...)")
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _escape_leef_value(value: Any) -> str:
    """Valeur d'attribut LEEF : echappe `\\`, `=`, le separateur et les
    fins de ligne (un evenement tient sur une ligne)."""
    logger.debug("_escape_leef_value: retour replace(...)")
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace(LEEF_DELIMITER, "\\t")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def _leef_time(timestamp_ms: int) -> str:
    when = _dt.datetime.fromtimestamp(timestamp_ms / 1000, tz=_dt.UTC)
    logger.debug("_leef_time: retour calcul")
    return when.strftime("%b %d %Y %H:%M:%S.") + f"{when.microsecond // 1000:03d} UTC"


def to_leef(records: list[SiemRecord]) -> list[str]:
    """Met en forme des enregistrements en lignes LEEF 2.0.

    Attributs standard QRadar : ``cat``, ``sev`` (1-10), ``devTime`` +
    ``devTimeFormat``, ``src``/``dst``/``dstPort`` quand le constat les
    porte ; attributs propres : ``point`` (point de capture), ``cveId``,
    ``msg`` (detail, tronque a 1000 caracteres)."""
    logger.debug("to_leef: records={}", summarize(records, "records"))
    lines: list[str] = []
    for rec in records:
        f = rec.finding
        attrs: list[tuple[str, Any]] = [
            ("cat", rec.category),
            ("sev", max(1, rec.severity_num)),
            ("devTime", _leef_time(rec.timestamp_ms)),
            ("devTimeFormat", _LEEF_TIME_FORMAT),
        ]
        if f.get("src"):
            attrs.append(("src", f["src"]))
        if f.get("host"):
            attrs.append(("dst", f["host"]))
        if isinstance(f.get("port"), int):
            attrs.append(("dstPort", f["port"]))
        if rec.point:
            attrs.append(("point", rec.point))
        if f.get("cve_id"):
            attrs.append(("cveId", f["cve_id"]))
        attrs.append(("msg", rec.detail[:_LEEF_MAX_MSG]))
        header = "|".join(
            _escape_leef_header(v)
            for v in ("LEEF:2.0", _DEVICE_VENDOR, _DEVICE_PRODUCT, _DEVICE_VERSION, str(rec.sig_id))
        )
        body = LEEF_DELIMITER.join(f"{k}={_escape_leef_value(v)}" for k, v in attrs)
        lines.append(f"{header}|{_LEEF_DELIMITER_HEADER}|{body}")
    logger.debug("to_leef: retour lines")
    return lines


def export_leef(report: Report) -> list[str]:
    """Exporte les constats de securite d'un Report en lignes LEEF 2.0."""
    logger.debug("export_leef: retour to_leef(...)")
    return to_leef(_to_siem_records(report))


# -- Ecriture -----------------------------------------------------------------


def _write_lines(lines: list[str], output_path: str | Path) -> str:
    logger.debug(
        "_write_lines: lines={} output_path={}",
        summarize(lines, "lines"),
        summarize(output_path, "output_path"),
    )
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    logger.debug("_write_lines: retour str(...)")
    return str(path.resolve())


def write_cef(report: Report, output_path: str | Path) -> str:
    """Ecrit les constats de securite au format CEF dans un fichier.

    Retourne le chemin absolu du fichier ecrit.
    """
    logger.debug(
        "write_cef: report={} output_path={}",
        summarize(report, "report"),
        summarize(output_path, "output_path"),
    )
    return _write_lines(export_cef(report), output_path)


def write_leef(report: Report, output_path: str | Path) -> str:
    """Ecrit les constats de securite au format LEEF 2.0 ; retourne le
    chemin absolu du fichier ecrit."""
    logger.debug("write_leef: retour _write_lines(...)")
    return _write_lines(export_leef(report), output_path)


def write_siem(
    report: Report,
    output_path: str | Path,
    fmt: str,
    *,
    observed_from: _dt.datetime | None = None,
    observed_until: _dt.datetime | None = None,
) -> str:
    """Ecrit l'export `fmt` (``cef``, ``leef`` ou ``stix``). Les bornes
    temporelles ne servent qu'a STIX (dates deterministes des objets)."""
    logger.debug(
        "write_siem: report={} output_path={} fmt={} observed_from={} observed_until={}",
        summarize(report, "report"),
        summarize(output_path, "output_path"),
        summarize(fmt, "fmt"),
        summarize(observed_from, "observed_from"),
        summarize(observed_until, "observed_until"),
    )
    if fmt == "cef":
        logger.debug("write_siem: retour write_cef(...)")
        return write_cef(report, output_path)
    if fmt == "leef":
        logger.debug("write_siem: retour write_leef(...)")
        return write_leef(report, output_path)
    if fmt == "stix":
        from netcross_report.stix_export import write_stix

        logger.debug("write_siem: retour write_stix(...)")
        return write_stix(report, output_path, observed_from=observed_from, observed_until=observed_until)
    logger.debug("write_siem: refus, ValueError")
    raise ValueError(f"format SIEM inconnu : {fmt!r} (attendu : {', '.join(SIEM_FORMATS)})")
