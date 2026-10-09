"""netcross_report -- synthese, triage, et generation de rapports (PDF,
JSON) a partir d'un Report netcross_core.

synthesis, triage et json_report sont du pur Python (aucune dependance
externe) : toujours disponibles. generate_pdf a besoin de reportlab/
matplotlib/networkx -- si ces paquets ne sont pas installes, generate_pdf
vaut None plutot que de faire planter l'import de tout le package (un
appelant qui ne veut que le triage ou le JSON n'a pas a installer
reportlab)."""

from netcross_core.logging_config import get_logger
from netcross_report.comm_map import (
    CommEdge,
    CommMap,
    CommNode,
    available_protocols,
    build_comm_map,
    format_comm_map,
)
from netcross_report.expert_events import build_diagnoses, build_expert_events
from netcross_report.history import (
    HistoryDatabaseError,
    HistoryEntry,
    list_history,
    print_history,
    record_diff_run,
    record_run,
)
from netcross_report.json_report import build_json_report_document, generate_json_diff, generate_json_report
from netcross_report.markdown_report import build_markdown_report_document, generate_markdown_report
from netcross_report.metric_charts import (
    ComplianceZone,
    MetricSeries,
    Threshold,
    render_area,
    render_bars,
    render_histogram,
    render_line,
    render_metric_chart,
    render_scatter,
)
from netcross_report.path_metrics import (
    SegmentMetrics,
    build_path_metrics,
    degradation_summary,
    rank_path_segments,
)
from netcross_report.rule_engine import available_rule_ids, evaluate, print_rule_engine
from netcross_report.security_report import (
    SecurityDashboard,
    SecurityItem,
    SecurityReport,
    ServiceEntry,
    build_security_report,
    format_security_report,
    print_security_report,
)
from netcross_report.sequence_view import (
    SequenceStep,
    SequenceView,
    build_sequence_view,
    top_flow_views,
)
from netcross_report.session_objects import (
    SessionObjects,
    build_session_objects,
    format_session_objects,
    print_session_objects,
)
from netcross_report.synthesis import Finding, build_findings
from netcross_report.triage import (
    DEFAULT_SEVERITY_WEIGHTS,
    HEALTH_LABELS,
    SegmentScore,
    format_health_line,
    health_label,
    health_score,
    print_triage,
    rank_segments,
)

logger = get_logger(__name__)

try:
    from netcross_report.pdf import generate_diff_pdf, generate_pdf
except ImportError:
    logger.debug("dépendance optionnelle absente: ImportError")
    generate_pdf = None  # type: ignore[assignment]  # reportlab absent -- repli optionnel
    generate_diff_pdf = None  # type: ignore[assignment]

__all__ = [
    "DEFAULT_SEVERITY_WEIGHTS",
    "HEALTH_LABELS",
    "CommEdge",
    "CommMap",
    "CommNode",
    "ComplianceZone",
    "Finding",
    "HistoryDatabaseError",
    "HistoryEntry",
    "MetricSeries",
    "SecurityDashboard",
    "SecurityItem",
    "SecurityReport",
    "SegmentMetrics",
    "SegmentScore",
    "SequenceStep",
    "SequenceView",
    "ServiceEntry",
    "SessionObjects",
    "Threshold",
    "available_protocols",
    "available_rule_ids",
    "build_comm_map",
    "build_diagnoses",
    "build_expert_events",
    "build_findings",
    "build_json_report_document",
    "build_markdown_report_document",
    "build_path_metrics",
    "build_security_report",
    "build_sequence_view",
    "build_session_objects",
    "degradation_summary",
    "evaluate",
    "format_comm_map",
    "format_health_line",
    "format_security_report",
    "format_session_objects",
    "generate_diff_pdf",
    "generate_json_diff",
    "generate_json_report",
    "generate_markdown_report",
    "generate_pdf",
    "health_label",
    "health_score",
    "list_history",
    "print_history",
    "print_rule_engine",
    "print_security_report",
    "print_session_objects",
    "print_triage",
    "rank_path_segments",
    "rank_segments",
    "record_diff_run",
    "record_run",
    "render_area",
    "render_bars",
    "render_histogram",
    "render_line",
    "render_metric_chart",
    "render_scatter",
    "top_flow_views",
]
