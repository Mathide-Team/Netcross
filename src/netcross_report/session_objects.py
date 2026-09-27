"""
netcross_report.session_objects -- construction et rendu CONSOLE des objets
de contrat de la Session 0 (Job 4/issue #13).

Avant cette session, les objets enrichis (Flow, Conversation, ExpertEvent,
Diagnosis, ComplianceResult, plus les ExpertEvent bruts de source "tshark")
n'existaient QUE le long du chemin `--json-report` de
`cross_capture_analyzer_cli.py` : le bloc de construction etait ecrit en
ligne dans la CLI, sous le `if args.json_report:`. Consequences directes de
cette localisation :

  * la console et le PDF n'y avaient aucun acces -- l'operateur qui
    n'exporte pas de JSON ne voit jamais ni cause/impact, ni conformite,
    ni expertise tshark ;
  * la GUI (`netcross_gtk4.app._generate_json_thread`, issue #14) produit
    un JSON AMPUTE de ces memes cles, faute de pouvoir reutiliser le bloc.

Ce module extrait ce bloc SANS le modifier : `build_session_objects()`
enchaine exactement les memes appels, dans le meme ordre, avec les memes
arguments que la CLI -- aucun nouveau calcul, aucune nouvelle lecture de
capture, aucun seuil introduit ici. C'est un point de passage unique,
consommable par les trois sorties (console, PDF, JSON) et par la GUI.

`format_session_objects()` en donne un rendu texte pour la console, dans
le meme esprit que `netcross_core.report_text.print_report()` :
deterministe, sans couleur, plafonne par `top_n` (un flux par ligne sur
une capture de 20 000 flux serait illisible -- meme discipline que le
plafonnement des `*_examples` de `Report`).

Couche : `netcross_report` peut importer `netcross_core` (contrat
`[tool.importlinter]` de pyproject.toml), jamais l'inverse.
"""

from dataclasses import dataclass, field

from netcross_core.causality import correlate_diagnosis_causes, correlate_event_causes
from netcross_core.compliance import evaluate_compliance
from netcross_core.correlate import build_conversations, build_flows
from netcross_core.logging_config import get_logger, summarize
from netcross_core.wireshark_expert import build_wireshark_expert_events
from netcross_report.expert_events import build_diagnoses, build_expert_events

logger = get_logger(__name__)

# Plafond par defaut du rendu console : au-dela, seules les premieres
# entrees sont listees et une ligne "... et N autres" resume le reste.
# Meme ordre de grandeur que le top_n du triage (print_triage) -- la
# console n'est pas le bon support pour un inventaire exhaustif, c'est le
# role de --json-report.
DEFAULT_TOP_N = 10

# Ordre d'affichage des statuts de conformite dans la ligne de synthese :
# du plus grave au moins grave, pour que l'operateur lise d'abord ce qui
# ne passe pas. Les statuts inconnus (referentiel mal configure) sont
# affiches apres, par ordre alphabetique -- jamais ignores silencieusement.
_COMPLIANCE_STATUS_ORDER = ["VIOLATION", "DEVIATION", "CONFORME", "INDETERMINE"]

_SEPARATOR = "=" * 70


@dataclass
class SessionObjects:
    """Les six objets enrichis, groupes tels qu'ils sont consommes par les
    sorties. `wireshark_expert_events` vaut `None` (et non `[]`) quand les
    paquets bruts n'ont pas ete fournis a `build_session_objects()` :
    "non calcule" et "calcule, aucun evenement" doivent rester
    distinguables, c'est exactement la convention d'absence de
    `generate_json_report()` (cle absente vs cle a liste vide)."""

    flows: list = field(default_factory=list)
    conversations: list = field(default_factory=list)
    expert_events: list = field(default_factory=list)
    diagnoses: list = field(default_factory=list)
    compliance: list = field(default_factory=list)
    wireshark_expert_events: list | None = None

    def json_kwargs(self) -> dict:
        """Les memes objets sous la forme attendue par
        `generate_json_report(**kwargs)`. `wireshark_expert_events` est
        omis quand il vaut `None`, pour que la cle JSON reste absente --
        sans ce filtrage, la GUI produirait `"wireshark_expert_events":
        []`, ce qui affirmerait a tort qu'aucun signal tshark n'a ete
        trouve alors qu'aucun n'a ete cherche."""
        kwargs = {
            "flows": self.flows,
            "conversations": self.conversations,
            "expert_events": self.expert_events,
            "diagnoses": self.diagnoses,
            "compliance": self.compliance,
        }
        if self.wireshark_expert_events is not None:
            kwargs["wireshark_expert_events"] = self.wireshark_expert_events
        return kwargs


def build_session_objects(
    report, findings, flows=None, all_packets=None, wireshark_expert_events=None
) -> SessionObjects:
    """Construit les objets enrichis a partir de donnees DEJA calculees.

    report : objet Report (`netcross_core.analysis.analyse()`).
    findings : liste de Finding deja calculee (`build_findings(report)`) --
    jamais recalculee ici, meme convention que `generate_pdf()`/
    `generate_json_report()`.
    flows : dict brut produit par `netcross_core.correlate.correlate()`
    (cle -> {point: [Pkt, ...]}). Absent -> `flows`/`conversations`
    restent des listes vides : les ExpertEvent/Diagnosis/compliance, eux,
    ne dependent que de `findings` et `report` et restent donc calcules.
    all_packets : liste plate de paquets bruts (chaque Pkt porte son
    `point`, comme l'attend `build_wireshark_expert_events()`) pour
    l'expertise tshark. Absent -> `wireshark_expert_events` reste `None` (voir
    SessionObjects).
    wireshark_expert_events : signaux tshark DEJA construits, a utiliser
    tel quel au lieu de les recalculer depuis `all_packets`. Prevu pour un
    appelant de longue duree comme la GUI (issue #14), qui conserve le
    resultat de l'analyse mais PAS les paquets bruts -- les garder en
    memoire pour un export JSON eventuel couterait la taille de la
    capture entiere. Prioritaire sur `all_packets` quand les deux sont
    fournis.

    Sequence identique a celle de la CLI (--json-report) : build_flows ->
    build_conversations -> build_expert_events -> build_diagnoses ->
    correlate_event_causes -> correlate_diagnosis_causes ->
    evaluate_compliance -> build_wireshark_expert_events. L'ordre n'est
    pas cosmetique : `correlate_diagnosis_causes()` derive cause/impact
    des ExpertEvent DEJA enrichis par `correlate_event_causes()`, et
    `build_diagnoses()` doit avoir groupe les evenements avant.
    """
    flow_objs = build_flows(flows) if flows else []
    conversations = build_conversations(flow_objs) if flow_objs else []
    expert_events = build_expert_events(findings)
    diagnoses = build_diagnoses(expert_events)
    correlate_event_causes(expert_events)
    correlate_diagnosis_causes(diagnoses)
    compliance = evaluate_compliance(report)
    if wireshark_expert_events is None and all_packets:
        wireshark_expert_events = build_wireshark_expert_events(all_packets)
    return SessionObjects(
        flows=flow_objs,
        conversations=conversations,
        expert_events=expert_events,
        diagnoses=diagnoses,
        compliance=compliance,
        wireshark_expert_events=wireshark_expert_events,
    )


def _flow_label(flow) -> str:
    """Libelle court d'un Flow pour la console : les endpoints ordonnes
    quand ils sont connus (`build_flows()` les pose systematiquement),
    sinon la cle brute -- un Flow sans endpoints ne doit pas disparaitre
    du rendu."""
    if flow.endpoints:
        return f"{flow.endpoints[0]} <-> {flow.endpoints[1]}"
    return str(flow.key)


def _total(counter: dict) -> int:
    return sum(counter.values())


def _truncated(items, top_n):
    """(premieres entrees, nombre de restantes) -- `top_n` None ou <= 0
    desactive le plafond (utile pour un test ou un export)."""
    if top_n is None or top_n <= 0 or len(items) <= top_n:
        return list(items), 0
    return list(items[:top_n]), len(items) - top_n


def _format_flows(objs, top_n) -> list[str]:
    lines = [f"Flux correles : {len(objs.flows)} ({len(objs.conversations)} conversation(s))"]
    # Tri par volume de paquets decroissant : sur une capture reelle, les
    # flux les plus bavards sont ceux qui portent le trafic a expliquer.
    # A volume egal, le libelle tranche pour garder un ordre stable d'une
    # execution a l'autre (les dicts de Report sont des defaultdict, leur
    # ordre d'insertion depend de l'ordre de lecture des captures).
    ordered = sorted(objs.flows, key=lambda f: (-_total(f.packet_count), _flow_label(f)))
    shown, remaining = _truncated(ordered, top_n)
    for flow in shown:
        points = ", ".join(flow.points)
        lines.append(
            f"  {_flow_label(flow)} -- {_total(flow.packet_count)} paquet(s), "
            f"{_total(flow.byte_count)} octet(s), vu a : {points}"
        )
    if remaining:
        lines.append(f"  ... et {remaining} autre(s) flux (voir --json-report)")
    return lines


def _format_events(events, title, top_n) -> list[str]:
    lines = [f"{title} : {len(events)}"]
    shown, remaining = _truncated(events, top_n)
    for ev in shown:
        lines.append(f"  [{ev.severity}] {ev.category} -- {ev.segment}")
        lines.append(f"      {ev.message}")
        # cause/impact ne sont renseignes que pour les evenements dont le
        # rule_id participe a un pattern de correlation (voir
        # netcross_core.causality) : la majorite des evenements n'en a
        # pas, on n'affiche donc la ligne que si elle porte une valeur.
        if ev.cause:
            lines.append(f"      Cause probable : {ev.cause}")
        if ev.impact:
            lines.append(f"      Impact : {ev.impact}")
    if remaining:
        lines.append(f"  ... et {remaining} autre(s) evenement(s) (voir --json-report)")
    return lines


def _format_diagnoses(diagnoses, top_n) -> list[str]:
    lines = [f"Diagnostics par segment : {len(diagnoses)}"]
    shown, remaining = _truncated(diagnoses, top_n)
    for diag in shown:
        lines.append(f"  {diag.segment} -- {len(diag.events)} evenement(s)")
        if diag.cause:
            lines.append(f"      Cause probable : {diag.cause}")
        if diag.impact:
            lines.append(f"      Impact : {diag.impact}")
    if remaining:
        lines.append(f"  ... et {remaining} autre(s) segment(s) (voir --json-report)")
    return lines


def _compliance_counts(results) -> list[str]:
    counts: dict[str, int] = {}
    for res in results:
        counts[res.status] = counts.get(res.status, 0) + 1
    known = [f"{counts[s]} {s}" for s in _COMPLIANCE_STATUS_ORDER if s in counts]
    unknown = [f"{counts[s]} {s}" for s in sorted(counts) if s not in _COMPLIANCE_STATUS_ORDER]
    return known + unknown


def _format_compliance(results, top_n) -> list[str]:
    summary = ", ".join(_compliance_counts(results))
    lines = [f"Conformite aux referentiels : {len(results)} evaluee(s)" + (f" -- {summary}" if summary else "")]

    # Les ecarts d'abord (VIOLATION puis DEVIATION), le reste ensuite :
    # meme intention que le tri du triage, l'operateur doit voir ce qui
    # ne passe pas sans derouler toute la liste.
    def _rank(res):
        order = _COMPLIANCE_STATUS_ORDER
        return (order.index(res.status) if res.status in order else len(order), res.reference.id)

    shown, remaining = _truncated(sorted(results, key=_rank), top_n)
    for res in shown:
        ref = res.reference
        observed = "non mesure" if res.observed is None else f"{res.observed:g} {ref.unit}"
        lines.append(
            f"  [{res.status}] {ref.id} -- {ref.metric} : observe {observed}, "
            f"seuil {ref.operator} {ref.threshold:g} {ref.unit} ({ref.source})"
        )
    if remaining:
        lines.append(f"  ... et {remaining} autre(s) referentiel(s) (voir --json-report)")
    return lines


def format_session_objects(objs, top_n=DEFAULT_TOP_N) -> list[str]:
    """Rendu console des objets enrichis, une chaine par ligne (jamais de
    `print()` ici : la GUI redirige `stdout` et les tests comparent des
    listes -- meme separation que `netcross_core.report_text`).

    Chaque bloc est omis quand il n'a rien a montrer, sauf les
    evenements d'expertise : "0 evenement" est en soi une information
    (l'analyse a tourne et n'a rien diagnostique), alors qu'une section
    "Flux correles : 0" n'apparait que parce que l'appelant n'a pas
    passe `flows`.
    """
    lines = [_SEPARATOR, "EXPERTISE -- OBJETS ENRICHIS", _SEPARATOR, ""]
    if objs.flows:
        lines += [*_format_flows(objs, top_n), ""]
    lines += [*_format_events(objs.expert_events, "Evenements d'expertise (netcross)", top_n), ""]
    if objs.diagnoses:
        lines += [*_format_diagnoses(objs.diagnoses, top_n), ""]
    if objs.compliance:
        lines += [*_format_compliance(objs.compliance, top_n), ""]
    if objs.wireshark_expert_events:
        lines += [*_format_events(objs.wireshark_expert_events, "Expertise tshark (signaux bruts)", top_n), ""]
    return lines


def print_session_objects(objs, top_n=DEFAULT_TOP_N) -> None:
    """Ecrit `format_session_objects()` sur stdout -- pendant de
    `netcross_core.report_text.print_report()` pour les objets enrichis."""
    logger.debug("print_session_objects: objs={} top_n={}", summarize(objs, "objs"), summarize(top_n, "top_n"))
    for line in format_session_objects(objs, top_n):
        print(line)
