"""
netcross_core.compliance -- evaluateur de conformite, huitieme et
neuvieme objets de contrat de la Session 0 (FEATURES.md section 13.3) :
`ReferenceProfile`/`ComplianceResult` (netcross_core.expert_model).

Catalogue enrichi (Session 6/Job 10) : RFC 6349 (debit TCP) et RFC 9544
(SLO/SLA latence/gigue) comme sources normatives, plus bonnes pratiques
operationnelles.

Chaque metrique du registre `_METRIC_FUNCS` est une aggregation
EXPLICITE et deja triviale a partir de champs `Report` existants (jamais
un `getattr(report, ref.metric)` direct -- la plupart des champs `Report`
sont des dict par point/segment, pas des scalaires directement
comparables a un seuil).
"""

from __future__ import annotations

import operator as _operator

from netcross_core.expert_model import ComplianceResult, ReferenceProfile
from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)


def _metric_pmtud_blackhole_total(report) -> float:
    """Nombre total de noirs PMTUD detectes, tous segments confondus."""
    return float(sum(report.pmtud_blackhole.values()))


def _metric_loss_rate_pct(report) -> float:
    """Taux de perte global (%), agrege sur tous les points -- somme des
    pertes / somme des paquets vus, pas une moyenne des taux par point
    (qui pondererait a tort un point a faible volume comme un point a fort
    volume)."""
    seen = sum(report.seen_count.values())
    if not seen:
        return 0.0
    return sum(report.loss_count.values()) / seen * 100.0


def _metric_tcp_retransmission_rate_pct(report) -> float:
    """Taux de retransmission TCP global (%) -- RFC 6349 section 4.2 : le
    ratio de retransmissions sur le total de segments envoyes est un
    indicateur de sante du chemin. Agrege sur tous les points."""
    total_segments = sum(report.tcp_total_segments.values()) if hasattr(report, "tcp_total_segments") else 0
    if not total_segments:
        return 0.0
    return sum(report.tcp_retransmissions.values()) / total_segments * 100.0


def _metric_avg_rtt_ms(report) -> float:
    """RTT moyen (ms) -- RFC 6349 section 4.3 : le RTT est un indicateur
    cle de performance. Moyenne sur tous les segments."""
    values = [v for v in report.rtt_ms.values() if v and v > 0] if hasattr(report, "rtt_ms") else []
    if not values:
        return 0.0
    return sum(values) / len(values)


def _metric_throughput_mbps(report) -> float:
    """Debit global (Mbps) -- RFC 6349 section 4.4 : le debit observe est
    compare au debit theorique (BDP). Agrege sur tous les points."""
    total_bytes = sum(report.total_bytes.values()) if hasattr(report, "total_bytes") else 0
    duration = (
        max(report.capture_duration.values()) if hasattr(report, "capture_duration") and report.capture_duration else 0
    )
    if duration <= 0:
        return 0.0
    return total_bytes * 8 / 1_000_000 / duration


def _metric_latency_ms(report) -> float:
    """Latence moyenne (ms) -- RFC 9544 section 5 : la latence de bout en
    bout est une metrique SLO fondamentale. Moyenne sur tous les segments."""
    values = [v for v in report.latency_ms.values() if v and v > 0] if hasattr(report, "latency_ms") else []
    if not values:
        return 0.0
    return sum(values) / len(values)


def _metric_jitter_ms(report) -> float:
    """Gigue moyenne (ms) -- RFC 9544 section 5 : la variation de latence
    est une metrique SLO. Moyenne sur tous les segments."""
    values = [v for v in report.jitter_ms.values() if v and v > 0] if hasattr(report, "jitter_ms") else []
    if not values:
        return 0.0
    return sum(values) / len(values)


# Registre des metriques evaluables -- voir ReferenceProfile.metric.
# Ajouter une metrique = ajouter une entree ici, aucune autre modification
# necessaire (evaluate_compliance() reste generique).
_METRIC_FUNCS = {
    "pmtud_blackhole_total": _metric_pmtud_blackhole_total,
    "loss_rate_pct": _metric_loss_rate_pct,
    "tcp_retransmission_rate_pct": _metric_tcp_retransmission_rate_pct,
    "avg_rtt_ms": _metric_avg_rtt_ms,
    "throughput_mbps": _metric_throughput_mbps,
    "latency_ms": _metric_latency_ms,
    "jitter_ms": _metric_jitter_ms,
}

_OPERATORS = {
    "<=": _operator.le,
    "<": _operator.lt,
    ">=": _operator.ge,
    ">": _operator.gt,
    "==": _operator.eq,
}

# Referentiels par defaut, fournis a titre d'exemple minimal et reel --
# catalogue enrichi (Session 6/Job 10) : RFC 6349 (debit TCP), RFC 9544
# (SLO/SLA latence/gigue), bonnes pratiques operationnelles.
DEFAULT_REFERENCES = [
    # -- RFC 6349 : Framework for Benchmarking TCP Throughput --
    ReferenceProfile(
        id="rfc6349-pmtud-no-blackhole",
        metric="pmtud_blackhole_total",
        operator="<=",
        threshold=0.0,
        unit="occurrence(s)",
        source=(
            "RFC 6349 section 3.3 / RFC 1191 (IPv4) / RFC 8201 (IPv6)"
            " -- un chemin PMTUD sain ne doit jamais rester bloque silencieusement"
        ),
        provenance="normative",
        version="6349",
        confidence="high",
    ),
    ReferenceProfile(
        id="rfc6349-loss-rate-1pct",
        metric="loss_rate_pct",
        operator="<=",
        threshold=1.0,
        unit="%",
        source="RFC 6349 section 4.2 -- un taux de perte > 1% degrade significativement le debit TCP",
        provenance="normative",
        version="6349",
        confidence="high",
        deviation_margin=0.5,
    ),
    ReferenceProfile(
        id="rfc6349-retransmission-rate-2pct",
        metric="tcp_retransmission_rate_pct",
        operator="<=",
        threshold=2.0,
        unit="%",
        source="RFC 6349 section 4.2 -- les retransmissions indiquent une congestion ou un lien degrade",
        provenance="normative",
        version="6349",
        confidence="high",
        deviation_margin=1.0,
    ),
    ReferenceProfile(
        id="rfc6349-rtt-50ms",
        metric="avg_rtt_ms",
        operator="<=",
        threshold=50.0,
        unit="ms",
        source="RFC 6349 section 4.3 -- RTT moyen, indicateur de sante du chemin",
        provenance="normative",
        version="6349",
        confidence="medium",
        deviation_margin=0.2,
    ),
    # -- RFC 9544 : SLO/SLA Framework --
    ReferenceProfile(
        id="rfc9544-latency-100ms",
        metric="latency_ms",
        operator="<=",
        threshold=100.0,
        unit="ms",
        source="RFC 9544 section 5 -- latence de bout en bout, seuil SLO typique",
        provenance="normative",
        version="9544",
        confidence="high",
        deviation_margin=0.1,
    ),
    ReferenceProfile(
        id="rfc9544-jitter-30ms",
        metric="jitter_ms",
        operator="<=",
        threshold=30.0,
        unit="ms",
        source="RFC 9544 section 5 -- variation de latence, seuil SLO typique",
        provenance="normative",
        version="9544",
        confidence="high",
        deviation_margin=0.15,
    ),
    # -- Bonne pratique operationnelle --
    ReferenceProfile(
        id="loss-rate-max-1pct",
        metric="loss_rate_pct",
        operator="<=",
        threshold=1.0,
        unit="%",
        source="Bonne pratique operationnelle courante (pas une RFC) -- seuil de perte tolere pour un lien en bon etat",
        provenance="recommandee",
        confidence="medium",
    ),
]


def _compute_status(observed: float, ref: ReferenceProfile, op) -> str:
    """Determine le statut de conformite : CONFORME, DEVIATION ou
    VIOLATION.

    DEVIATION : la valeur observee depasse le seuil mais reste dans la
    marge de tolerance definie par `ref.deviation_margin` (relative au
    seuil). Ex: seuil=100, margin=0.1 -> DEVIATION entre 100 et 110.

    Sans `deviation_margin` (None), pas de nuance DEVIATION --
    comportement d'origine : CONFORME ou VIOLATION uniquement.
    """
    if op(observed, ref.threshold):
        status = "CONFORME"
    elif ref.deviation_margin is not None and ref.threshold > 0:
        margin_abs = ref.threshold * ref.deviation_margin
        status = "DEVIATION" if observed <= ref.threshold + margin_abs else "VIOLATION"
    else:
        status = "VIOLATION"
    logger.debug(
        "_compute_status: {} {} {} -> {} (observé={})",
        ref.metric,
        ref.operator,
        ref.threshold,
        status,
        round(observed, 3),
    )
    return status


def evaluate_compliance(report, references=None) -> list[ComplianceResult]:
    """Evalue `report` contre `references` (par defaut DEFAULT_REFERENCES
    ci-dessus). Une metrique absente de `_METRIC_FUNCS` produit un
    ComplianceResult a `INDETERMINE` plutot qu'une exception -- un
    referentiel mal configure ne doit jamais faire planter l'analyse.

    Statuts produits : CONFORME, DEVIATION (ecart mineur dans la marge
    de tolerance), VIOLATION, INDETERMINE.
    """
    logger.debug(
        "evaluate_compliance: report={} references={}",
        summarize(report, "report"),
        summarize(references, "references"),
    )
    if references is None:
        references = DEFAULT_REFERENCES
    results = []
    for ref in references:
        func = _METRIC_FUNCS.get(ref.metric)
        op = _OPERATORS.get(ref.operator)
        if func is None or op is None:
            logger.debug("evaluate_compliance: métrique '{}' indéterminée", ref.metric)
            results.append(ComplianceResult(ref, None, "INDETERMINE"))
            continue
        observed = func(report)
        status = _compute_status(observed, ref, op)
        results.append(ComplianceResult(ref, observed, status))
    conforme = sum(1 for r in results if r.status == "CONFORME")
    deviation = sum(1 for r in results if r.status == "DEVIATION")
    violation = sum(1 for r in results if r.status == "VIOLATION")
    indetermine = sum(1 for r in results if r.status == "INDETERMINE")
    logger.debug(
        "evaluate_compliance: {} référence(s) -> {} conforme(s), {} déviation(s), {} violation(s), {} indéterminé(s)",
        len(results),
        conforme,
        deviation,
        violation,
        indetermine,
    )
    return results
