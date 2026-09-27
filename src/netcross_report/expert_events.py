"""
netcross_report.expert_events -- construit les vues `ExpertEvent`/
`Diagnosis` (Session 36, cinquieme et sixieme objets de contrat de la
Session 0, FEATURES.md section 13.3) a partir d'une liste de `Finding`/
`DiffFinding` deja construite (`build_findings()`/`diff_reports()`).

Ne detecte rien de nouveau : pure conversion/regroupement de donnees deja
calculees -- voir `netcross_core.expert_model` pour ce que `cause`/
`impact` valent ici (toujours `None`, le moteur de correlation causale
qui les alimenterait est la Session 3 de la section 13.3, absente
aujourd'hui). Meme raisonnement pour `confidence`/`first_seen`/
`last_seen` (Session 40) et `layer`/`protocol` (Session 41) : `Finding`
ne porte aucune de ces donnees, et `Finding.category` (regroupement
metier -- "Pertes", "Saturation"...) ne correspond pas de facon fiable a
un protocole/une couche unique pour la deviner -- voir la docstring de
module d'`expert_model.py` pour le detail complet. Tous ces champs
restent donc `None` sur tout `ExpertEvent` construit par ce module ;
seule `netcross_core.wireshark_expert` (source "tshark") les renseigne a
ce jour.

`rule_id` (Session 48) fait exception a l'alinea precedent : c'est le
SEUL champ de cette liste renseigne cote source "netcross" plutot que
cote "tshark" -- voir `netcross_core.expert_model.ExpertEvent` pour le
detail complet (miroir exact de `remediation`, mais dans l'autre sens).
Recopie simple depuis `Finding.rule_id` quand il existe (`getattr`
defensif : `DiffFinding` ne declare pas ce champ), jamais recalcule ici.
"""

from __future__ import annotations

from netcross_core.expert_model import Diagnosis, ExpertEvent
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


def build_expert_events(findings) -> list[ExpertEvent]:
    """Convertit chaque Finding/DiffFinding (duck-type : `severity`/
    `category`/`segment`/`message`/`evidence`) en `ExpertEvent`. Quand
    l'objet source declare un champ `event` (`Finding`, pas `DiffFinding`
    qui ne le declare pas), l'attache egalement en retour (`finding.event
    = ev`) -- c'est le "Finding enrichi" de la Session 0 : depuis un
    `Finding` deja affiche, on peut desormais naviguer vers l'ExpertEvent
    qui le represente, meme s'il ne porte pas encore de cause/impact."""
    events = []
    for f in findings:
        ev = ExpertEvent(
            category=f.category,
            severity=f.severity,
            segment=f.segment,
            message=f.message,
            evidence=list(getattr(f, "evidence", None) or []),
            rule_id=getattr(f, "rule_id", None),
        )
        if hasattr(f, "event"):
            f.event = ev
        events.append(ev)
    logger.debug("build_expert_events: retour events")
    return events


def build_diagnoses(events) -> list[Diagnosis]:
    """Regroupe une liste d'`ExpertEvent` (voir build_expert_events()
    ci-dessus) par segment -- un seul `Diagnosis` par segment distinct,
    dans l'ordre de premiere apparition."""
    by_segment: dict[str, Diagnosis] = {}
    for ev in events:
        diag = by_segment.setdefault(ev.segment, Diagnosis(segment=ev.segment))
        diag.events.append(ev)
    logger.debug("build_diagnoses: retour list(...)")
    return list(by_segment.values())
