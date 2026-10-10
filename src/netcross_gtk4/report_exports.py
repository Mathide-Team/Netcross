"""netcross_gtk4.report_exports -- diagramme de sequence, export SIEM,
historique SQLite et ticket de support dans la GUI (issue #674), sans GTK.

Memes fonctions que la CLI (``--sequence-diagram``, ``--siem-export``,
``--history-db``/``--history-label``/``--history-show``,
``--support-ticket``/``--support-consent``, et depuis l'issue #877
``--support-scope``/``--support-marker``/``--support-map``) : un export
GUI et un export CLI de la meme analyse sont identiques.
"""

from __future__ import annotations

import contextlib
import io
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

SEQUENCE_FLOWS_MAX = 20
HISTORY_SHOW_MAX = 1000
SIEM_EXTENSIONS = {"cef": "cef", "leef": "leef", "stix": "json"}


@dataclass(frozen=True)
class HistorySettings:
    """``--history-db`` et ``--history-label`` (None : pas d'historique)."""

    db_path: str | None = None
    label: str | None = None


@dataclass(frozen=True)
class ReportContext:
    """Ce que le panneau garde d'une analyse de fichiers terminee."""

    observed_from: datetime | None = None
    observed_until: datetime | None = None
    captures: int = 0
    redact: bool = False
    history: HistorySettings = HistorySettings()
    history_message: str = ""
    # Issue #876 : table adresse reelle -> pseudonyme (--redact-map)
    redaction_map: tuple[tuple[str, str, str], ...] = ()


def record_history(report, settings: HistorySettings, *, findings=None, tls=None, quic=None, redact=False) -> str:
    """Enregistre le run comme ``--history-db`` ; renvoie le message du
    journal. HistoryDatabaseError remonte (fichier qui n'est pas une base
    netcross : l'appelant l'affiche, l'analyse elle-meme reste valable)."""
    from netcross_report import record_run

    record_run(
        report,
        settings.db_path,
        findings=findings,
        tls_findings=tls,
        quic_findings=quic,
        meta={"Anonymisation": "adresses IP/MAC anonymisees (--redact)"} if redact else None,
        label=settings.label,
    )
    label_txt = f" (etiquette: {settings.label})" if settings.label else ""
    return f"Resume de ce run enregistre dans l'historique {settings.db_path}{label_txt}."


def history_text(db_path: str, limit: int | None, label: str | None) -> str:
    """Texte de ``--history-show N`` (``print_history``)."""
    from netcross_report import list_history, print_history

    entries = list_history(db_path, limit=limit or None, label=label)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_history(entries)
    return buf.getvalue()


def sequence_views(flows, max_flows: int, flow_objects=None) -> list | None:
    """``--sequence-diagram N`` pour l'export PDF ; None si 0."""
    if not max_flows or not flows:
        return None
    from netcross_report.sequence_view import top_flow_views

    return top_flow_views(flows, flow_objects=flow_objects, max_flows=max_flows)


def export_siem(report, path: str, fmt: str, context: ReportContext) -> str:
    """``--siem-export FMT --siem-output PATH``."""
    from netcross_report.siem_export import write_siem

    return write_siem(report, path, fmt, observed_from=context.observed_from, observed_until=context.observed_until)


class SupportTicketError(ValueError):
    """Reglage du ticket refuse (portee, marqueur), meme message que la CLI."""


def parse_support_markers(text: str) -> dict[str, str]:
    """``"trace_id=T-042; ticket=INC-7"`` -> dict (``--support-marker``
    repete ; separateur ``;``). Refuse une entree sans ``=`` ou sans cle."""
    logger.debug("parse_support_markers: text={!r}", text)
    markers: dict[str, str] = {}
    for spec in (part.strip() for part in (text or "").split(";")):
        if not spec:
            continue
        cle, sep, valeur = spec.partition("=")
        if not sep or not cle.strip():
            logger.debug("parse_support_markers: refus de {!r}", spec)
            raise SupportTicketError(f"--support-marker : format attendu CLE=VALEUR, recu {spec!r}.")
        markers[cle.strip()] = valeur.strip()
    logger.debug("parse_support_markers: retour {} marqueur(s)", len(markers))
    return markers


def check_support_scopes(scopes) -> tuple[str, ...]:
    """Portees cochees (``--support-scope``), dans l'ordre de ``SCOPES`` ;
    au moins une, aucune inconnue."""
    from netcross_core.support import SCOPES

    logger.debug("check_support_scopes: scopes={}", scopes)
    demandees = tuple(scopes)
    inconnues = [s for s in demandees if s not in SCOPES]
    if inconnues:
        raise SupportTicketError(
            f"--support-scope : portee(s) inconnue(s) {', '.join(inconnues)} (attendu parmi : {', '.join(SCOPES)})."
        )
    if not demandees:
        raise SupportTicketError("--support-scope : cochez au moins une portee du ticket.")
    retenues = tuple(s for s in SCOPES if s in demandees)
    logger.debug("check_support_scopes: retour {}", retenues)
    return retenues


@dataclass(frozen=True)
class SupportTicketResult:
    path: str
    occurrences: int
    scopes: tuple[str, ...]
    markers: dict[str, str] = field(default_factory=dict)
    # Correspondance reelle <-> pseudonyme du ticket (``--support-map``) :
    # a garder chez l'operateur, jamais avec le ticket.
    scrubber: Any = None


def write_support_ticket(
    path: str,
    context: ReportContext,
    *,
    consent: bool,
    scopes=None,
    markers: dict[str, str] | None = None,
) -> SupportTicketResult:
    """Ticket « diagnostic » de ``--support-ticket`` : portees
    (``--support-scope``, toutes par defaut) et marqueurs
    (``--support-marker``) comme la CLI. Refuse sans consentement."""
    from netcross_core.support import SCOPES, Consent, ConsentRequiredError, TextScrubber, build_ticket, write_ticket

    logger.debug("write_support_ticket: path={} scopes={} markers={}", path, scopes, markers)
    if not consent:
        raise ConsentRequiredError("ticket refuse : cochez d'abord le consentement a la remontee (--support-consent)")
    retenues = SCOPES if scopes is None else check_support_scopes(scopes)
    scrubber = TextScrubber()
    ticket = build_ticket(
        consent=Consent(
            granted=True,
            scopes=retenues,
            granted_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            source="gui",
        ),
        kind="diagnostic",
        markers=dict(markers or {}),
        log_lines=[
            f"captures analysees : {context.captures}",
            "interfaces live : 0",
            f"anonymisation des adresses (--redact) : {'oui' if context.redact else 'non'}",
        ],
        scrubber=scrubber,
    )
    written = write_ticket(ticket, path)
    logger.debug("write_support_ticket: ticket ecrit dans {}", written)
    return SupportTicketResult(
        path=written,
        occurrences=ticket.anonymization["total_occurrences"],
        scopes=retenues,
        markers=dict(markers or {}),
        scrubber=scrubber,
    )


def write_support_map(scrubber, path: str) -> str:
    """Meme CSV que ``--support-map`` (correspondance du dernier ticket)."""
    from netcross_core.support.ticket import write_support_map_csv

    logger.debug("write_support_map: path={}", path)
    if scrubber is None:
        raise ValueError("aucun ticket ecrit : la correspondance suit le ticket de support")
    written = write_support_map_csv(scrubber, path)
    logger.debug("write_support_map: retour {}", written)
    return written
