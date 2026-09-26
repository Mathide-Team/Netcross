"""
netcross_core.causality -- moteur de correlation causale (Session 3 de la
section 13.3 de FEATURES.md, Job 4/issue #4).

Fusionne les evenements elementaires (perte + retransmissions + hausse RTT +
anomalie segment) en evenements corroles avec CAUSE PROBABLE et IMPACT,
en remplissant les champs `ExpertEvent.cause` / `ExpertEvent.impact` et
`Diagnosis.cause` / `Diagnosis.impact` qui restent TOUJOURS `None` dans les
passes precedentes (voir `expert_model.ExpertEvent` et
`expert_model.Diagnosis`).

Approche : correlation par SEGMENT (pas par flux -- `ExpertEvent.flow_keys`
reste vide cote source "netcross" aujourd'hui, voir `expert_model` ; la
correlation par flux depend du Job 8/9, hors perimetre ici). Pour chaque
segment, le moteur examine l'ensemble des `rule_id` presents et cherche
des PATTERNS de co-occurrence qui suggerent une cause commune :

1. **Congestion / saturation** : perte de paquets + retransmission TCP +
   bufferbloat ou saturation sur le meme segment -> cause probable
   "congestion", impact "pertes + latence + debit effondre".
2. **PMTUD / MTU insuffisant** : PMTUD black hole + fragmentation ou
   ICMP Fragmentation Needed -> cause probable "MTU insuffisant",
   impact "connexions TCP qui stagnent".
3. **Ralentissement applicatif** : temps de traitement serveur dominant +
   reponse HTTP lente ou timeout -> cause probable "ralentissement
   applicatif cote serveur", impact "lenteur percue par l'utilisateur
   -- pas un probleme reseau".

Chaque pattern ne renseigne `cause`/`impact` que sur les ExpertEvent dont
le `rule_id` participe au pattern (pas sur tous les evenements du segment
-- un `dns_nxdomain` sur un segment congeste ne doit pas heriter de la
cause "congestion"). Les objets existants sont MUTES en place (meme
liste retournee, ordre preserve, `evidence` inchange).

CORRELATION PAR SEGMENT UNIQUEMENT : les ExpertEvent de source "netcross"
ne portent pas `flow_keys` (vide, voir `expert_model`), et `Finding.segment`
n'est pas toujours un nom de point -- `rtp_quality_mos` utilise une
etiquette de flux, `dns_slow_resolution`/`http_slow_response`/`server_
processing_dominant` utilisent "global". Les patterns ci-dessus ne se
declenchent donc que sur des segments PARTAGES par plusieurs symptomes,
ce qui correspond aux cas ou la correlation est structurellement fiable
(pertes + retransmissions + bufferbloat sur le MEME point de capture).
La correlation par flux (quand `flow_keys` sera peuple) est un chantier
futur, explicitement hors perimetre de ce job -- voir Job 8/9.
"""

from __future__ import annotations

from netcross_core.expert_model import Diagnosis, ExpertEvent
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

# -- Patterns de correlation ----------------------------------------------
#
# Chaque pattern est un tuple :
#   (rule_ids_a_matcher, rule_ids_a_enrichir, cause, impact)
#
# - `rule_ids_to_match` : ensemble de rule_id dont la CO-OCCURRENCE
#   (au moins un de chaque) sur un meme segment declenche le pattern.
#   Chaque element de l'ensemble est un sous-ensemble alternatif
#   (ex: {"tcp_retransmission_rto", "tcp_retransmission_fast"} = l'un
#   OU l'autre suffit).
# - `rule_ids_to_enrich` : ensemble des rule_id qui doivent recevoir
#   cause/impact si le pattern declenche (pas tous les evenements du
#   segment -- voir docstring de module).

_CorrelationPattern = tuple[
    list[set[str]],  # groupes de rule_id a matcher (au moins 1 de chaque groupe)
    set[str],  # rule_id a enrichir
    str,  # cause
    str,  # impact
]

_PATTERNS: list[_CorrelationPattern] = [
    # 1. Congestion / saturation
    (
        [
            {"loss_per_segment"},
            {"tcp_retransmission_rto", "tcp_retransmission_fast"},
            {"bufferbloat", "saturation"},
        ],
        {"loss_per_segment", "tcp_retransmission_rto", "tcp_retransmission_fast", "bufferbloat", "saturation"},
        "Congestion probable sur ce segment : pertes + retransmissions TCP + "
        "signaux de saturation/bufferbloat co-occurrent",
        "Degradation de bout en bout : latence elevee, taux de perte, debit effondre",
    ),
    # 2. PMTUD / MTU insuffisant
    (
        [
            {"pmtud_blackhole"},
            {"fragmentation_new", "icmp_fragmentation_needed"},
        ],
        {"pmtud_blackhole", "fragmentation_new", "icmp_fragmentation_needed"},
        "MTU insuffisant sur ce segment : PMTUD black hole + fragmentation/ICMP Fragmentation Needed co-occurrent",
        "Connexions TCP qui stagnent sans progresser (segments retransmis sans reduction de MSS)",
    ),
    # 3. Ralentissement applicatif cote serveur
    (
        [
            {"server_processing_dominant"},
            {"http_slow_response", "http_timeout"},
        ],
        {"server_processing_dominant", "http_slow_response", "http_timeout"},
        "Ralentissement applicatif cote serveur : temps de traitement serveur dominant + reponse HTTP lente/timeout",
        "Lenteur percue par l'utilisateur -- la cause est applicative, pas un probleme de transport reseau",
    ),
]


def _match_pattern(
    pattern: _CorrelationPattern,
    rule_ids_by_segment: set[str],
) -> bool:
    """Verifie si un pattern declenche : au moins un rule_id de CHAQUE
    groupe de `rule_ids_to_match` doit etre present dans
    `rule_ids_by_segment`."""
    groups_to_match, _, _, _ = pattern
    return all(group & rule_ids_by_segment for group in groups_to_match)


def correlate_event_causes(events: list[ExpertEvent]) -> list[ExpertEvent]:
    """Enrichit les `ExpertEvent` passes en argument avec `cause` et
    `impact` en correlant les symptomes co-occurrents sur un meme segment.

    Mute les objets en place (meme liste retournee, ordre preserve,
    `evidence` inchange). Un `ExpertEvent` dont le `rule_id` ne participe
    a aucun pattern declenche garde `cause`/`impact` a `None`.

    See module docstring for the three correlation patterns and the
    segment-only scope (flow-level correlation is future work, Job 8/9).
    """
    # Grouper les rule_id par segment
    rule_ids_by_segment: dict[str, set[str]] = {}
    for ev in events:
        if ev.rule_id:
            rule_ids_by_segment.setdefault(ev.segment, set()).add(ev.rule_id)

    # Pour chaque segment, trouver les patterns qui declenchent
    patterns_by_segment: dict[str, list[_CorrelationPattern]] = {}
    for segment, rule_ids in rule_ids_by_segment.items():
        matched = [p for p in _PATTERNS if _match_pattern(p, rule_ids)]
        if matched:
            patterns_by_segment[segment] = matched

    # Enrichir les ExpertEvent dont le rule_id participe a un pattern
    for ev in events:
        segment_patterns = patterns_by_segment.get(ev.segment)
        if not segment_patterns or not ev.rule_id:
            continue
        for pattern in segment_patterns:
            _, enrich_ids, cause, impact = pattern
            if ev.rule_id in enrich_ids and ev.cause is None:
                ev.cause = cause
                ev.impact = impact
                break  # un seul pattern par evenement (priorite : ordre _PATTERNS)

    logger.debug(
        "correlate_event_causes: {} événement(s), {} segment(s) avec motif, {} cause(s) attribuée(s)",
        len(events),
        len(patterns_by_segment),
        sum(1 for ev in events if ev.cause is not None),
    )
    return events


def correlate_diagnosis_causes(diagnoses: list[Diagnosis]) -> list[Diagnosis]:
    """Derive `Diagnosis.cause` et `Diagnosis.impact` a partir des
    `ExpertEvent` deja enrichis par `correlate_event_causes()`.

    Un `Diagnosis` recoit la cause/impact du PREMIER pattern declenche
    parmi ses evenements (priorite : ordre de `_PATTERNS`). Si aucun
    evenement du diagnostic n'a de cause, le diagnostic garde
    `cause`/`impact` a `None`.
    """
    for diag in diagnoses:
        for ev in diag.events:
            if ev.cause is not None:
                diag.cause = ev.cause
                diag.impact = ev.impact
                break
    logger.debug(
        "correlate_diagnosis_causes: {} diagnostic(s), {} avec cause",
        len(diagnoses),
        sum(1 for d in diagnoses if d.cause is not None),
    )
    return diagnoses
