"""
netcross_api.models -- modèles Pydantic pour les requêtes/réponses API
(issue #209).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


class HealthResponse(BaseModel):
    """Réponse du health check."""

    status: str = "ok"
    version: str = "1.0.0"


class AnalysisSummary(BaseModel):
    """Résumé d'une analyse (retourné par POST /captures)."""

    analysis_id: str
    status: str = "completed"
    point_count: int = 0
    packet_count: int = 0
    security_finding_count: int = 0
    history_id: int | None = Field(default=None, description="Id du run dans l'historique (history=true, #890)")
    history_error: str | None = Field(
        default=None, description="Enregistrement dans l'historique impossible (l'analyse reste valable)"
    )


class AnalysisAccepted(BaseModel):
    """Réponse 202 des uploads : analyse enregistrée, en tâche de fond (#356)."""

    analysis_id: str
    status: str = "pending"
    status_url: str = Field(description="Route à interroger jusqu'à completed/failed")


class AnalysisStatus(BaseModel):
    """Statut d'une analyse pour GET /analyses/{id}/status (issue #356)."""

    analysis_id: str
    status: str = Field(description="pending, completed ou failed")
    error: str | None = Field(default=None, description="Cause de l'échec (status failed)")
    summary: dict | None = Field(
        default=None, description="Résumé (compteurs, et points/segments en multi-points) une fois completed"
    )


class SecurityFinding(BaseModel):
    """Un constat de sécurité sérialisé."""

    severity: str = ""
    category: str = ""
    detail: str = ""
    point: str | None = None


class SecurityReport(BaseModel):
    """Rapport de sécurité pour GET /analyses/{id}/security."""

    analysis_id: str
    findings: list[SecurityFinding] = Field(default_factory=list)
    service_fingerprints: list[dict] = Field(default_factory=list)
    lateral_movement_events: list[dict] = Field(default_factory=list)
    dga_alerts: list[dict] = Field(default_factory=list)
    fast_flux_alerts: list[dict] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    """Réponse d'erreur standard."""

    detail: str


class SegmentLoss(BaseModel):
    """Pertes et délai d'un segment amont -> aval (issue #354).

    Mêmes grandeurs que le tableau « Qualité par segment » des rapports :
    pertes comptées au point AVAL, taux rapporté aux paquets vus à ce point.
    """

    segment: str = Field(description="Libellé « amont -> aval », identique à celui des constats")
    upstream: str
    downstream: str
    loss_count: int = 0
    loss_pct: float | None = Field(default=None, description="Pertes / paquets vus au point aval (%)")
    seen_downstream: int = 0
    off_path_count: int = Field(default=0, description="Paquets hors chemin au point aval (#352), pas des pertes")
    latency_samples: int = 0
    latency_avg_ms: float | None = None


class MultiAnalysisSummary(BaseModel):
    """Résumé d'une analyse multi-points (issue #354)."""

    analysis_id: str
    status: str = "completed"
    point_count: int = 0
    packet_count: int = 0
    security_finding_count: int = 0
    history_id: int | None = Field(default=None, description="Id du run dans l'historique (history=true, #890)")
    history_error: str | None = Field(
        default=None, description="Enregistrement dans l'historique impossible (l'analyse reste valable)"
    )
    points: list[str] = Field(default_factory=list, description="Points dans l'ordre amont -> aval retenu")
    order_source: str = Field(
        default="auto",
        description="« points_order » si l'ordre a été fourni, « auto » s'il a été déduit",
    )
    segments: list[SegmentLoss] = Field(default_factory=list)
