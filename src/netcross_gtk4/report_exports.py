"""netcross_gtk4.report_exports -- diagramme de sequence, export SIEM,
historique SQLite et ticket de support dans la GUI (issue #674), sans GTK.

Memes fonctions que la CLI (``--sequence-diagram``, ``--siem-export``,
``--history-db``/``--history-label``/``--history-show``,
``--support-ticket``/``--support-consent``) : un export GUI et un export
CLI de la meme analyse sont identiques.
"""

from __future__ import annotations

import contextlib
import io
from dataclasses import dataclass
from datetime import datetime, timezone

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


def write_support_ticket(path: str, context: ReportContext, *, consent: bool) -> tuple[str, int]:
    """Ticket « diagnostic » de ``--support-ticket`` (toutes les portees,
    comme ``--support-consent`` sans ``--support-scope``). Refuse sans
    consentement. Renvoie (chemin, occurrences redigees)."""
    from netcross_core.support import SCOPES, Consent, ConsentRequiredError, TextScrubber, build_ticket, write_ticket

    if not consent:
        raise ConsentRequiredError("ticket refuse : cochez d'abord le consentement a la remontee (--support-consent)")
    ticket = build_ticket(
        consent=Consent(
            granted=True,
            scopes=SCOPES,
            granted_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            source="gui",
        ),
        kind="diagnostic",
        log_lines=[
            f"captures analysees : {context.captures}",
            "interfaces live : 0",
            f"anonymisation des adresses (--redact) : {'oui' if context.redact else 'non'}",
        ],
        scrubber=TextScrubber(),
    )
    written = write_ticket(ticket, path)
    return written, ticket.anonymization["total_occurrences"]
