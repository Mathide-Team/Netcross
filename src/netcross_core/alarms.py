"""
netcross_core.alarms -- alarmes et surveillance de seuils en analyse live
(§6.16, Session 11).

Module AWARE mais NON COUPLÉ au moteur de règles : il consomme des
AlarmSignal — tuples (rule_id, segment, severity, value) que l'appelant
construit depuis les Finding produits par netcross_report.rule_engine.
evaluate() ou netcross_report.synthesis.build_findings(). Ce module vit
dans netcross_core (couche la plus basse du contrat
netcross_gtk4 -> netcross_report -> netcross_core -> pcap_parser) :
il NE PEUT PAS importer Finding depuis netcross_report.synthesis —
d'où le type AlarmSignal défini ici, convertible depuis un Finding par
l'appelant (un adaptateur léger vit naturellement côté netcross_report
ou CLI, pas ici).

Pipeline documenté dans docs/features-backlog.md §6.16 :

    capture live → fenêtre glissante → métriques → règles → événements
    → seuil / hystérésis / durée minimale → notification

Ce module implémente les TROIS dernières briques : fenêtre glissante
sur les signaux, hystérésis trigger/clear, durée minimale de
persistance. Les notifications sont accumulées dans une liste
d'AlarmEvent — AUCUNE livraison externe (email, syslog...) dans ce
module : un appelant branché sur `AlarmEngine.events` peut les router
vers le canal de son choix (callback, file, GUI...).

Critère d'acceptation de l'issue #26 : une alarme ne se déclenche PAS
sur une valeur ponctuelle isolée — chaque AlarmConfig exige une
fenêtre glissante, un ratio minimal d'échantillons positifs dans cette
fenêtre, ET une durée minimale de persistance avant de lever
l'AlarmEvent. Un signal isolé au milieu d'une fenêtre calme ne produit
JAMAIS d'alarme (vérifié par test_« signal_isolé_ne_leve_pas_alarme »).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class AlarmSignal:
    """Signal d'entrée pour le moteur d'alarmes — convertible depuis un
    netcross_report.synthesis.Finding par l'appelant (adaptateur léger
    côté netcross_report/CLI, PAS dans ce module — voir docstring de
    module pour la justification du contrat de couches).

    rule_id : id stable de la Rule du catalogue (expert_rules) qui a
    produit ce signal, ou identifiant libre si la source n'est pas le
    catalogue.

    segment : point ou paire de points concerné (ex: "A", "A -> B").

    severity : une des trois valeurs de SEVERITY_ORDER
    (netcross_report.synthesis) — "anomalie", "a_surveiller", "info".

    value : valeur numérique OPTIONNELLE pour les règles à seuil
    (ex: taux de perte 4.2%, latence moyenne 350ms...). Utilisée par
    l'hystérésis trigger/clear quand AlarmConfig.trigger_threshold est
    défini ; ignorée sinon (alarme sur présence/absence pure).
    """

    rule_id: str
    segment: str
    severity: str
    value: float | None = None


@dataclass
class AlarmConfig:
    """Configuration d'UNE surveillance d'alarme — une paire (rule_id,
    segment) donnée, OU un rule_id avec segment=None pour surveiller
    TOUS les segments rencontrés pour cette règle.

    window_seconds : durée de la fenêtre glissante — les signaux plus
    anciens que `timestamp - window_seconds` sont éliminés à chaque
    feed().

    min_persistence_seconds : durée minimale pendant laquelle le signal
    doit être présent (au-dessus du seuil de déclenchement) avant que
    l'alarme ne soit levée. Un signal isolé au milieu d'une fenêtre
    calme ne déclenche JAMAIS.

    min_sample_ratio : fraction minimale d'échantillons positifs dans
    la fenêtre glissante pour considérer la condition comme active
    (entre 0.0 et 1.0). 0.5 = au moins la moitié des évaluations dans
    la fenêtre doivent montrer le signal. Protège contre le bruit
    ponctuel même sans hystérésis numérique.

    trigger_threshold : seuil de DÉCLENCHEMENT pour l'hystérésis
    numérique (la value du AlarmSignal doit être >= trigger pour
    considérer l'échantillon positif). None = hystérésis sur
    présence/absence pure (tout signal reçu est positif).

    clear_threshold : seuil de RETOUR À LA NORMALE pour l'hystérésis
    numérique. Une alarme déjà levée ne se cleared que quand la value
    descend SOUS clear_threshold (qui doit être < trigger_threshold).
    None = retour à la normale dès l'absence de signal.
    """

    rule_id: str
    segment: str | None = None
    window_seconds: float = 60.0
    min_persistence_seconds: float = 10.0
    min_sample_ratio: float = 0.5
    trigger_threshold: float | None = None
    clear_threshold: float | None = None


@dataclass
class AlarmEvent:
    """Une alarme levée ou levée-then-clearée par le moteur.

    state : "raised" quand l'alarme vient d'être déclenchée (le signal
    a persisté au-dessus du seuil pendant min_persistence_seconds),
    "cleared" quand une alarme précédemment levée est retombée sous le
    seuil de clear. Le moteur ne réémet PAS "raised" tant que
    l'alarme n'a pas été clearée entre temps (pas de flapping).

    timestamp : horodatage du feed() qui a déclenché cet événement.

    message : description humaine prête à afficher/notification.
    """

    rule_id: str
    segment: str
    state: str
    timestamp: float
    message: str


@dataclass
class _SegmentState:
    """État interne du moteur pour UNE paire (AlarmConfig, segment)
    surveillée. Pas exposed publiquement — détail d'implémentation.

    samples : liste des (timestamp, is_positive) dans la fenêtre
    glissante, is_positive = True si le signal était au-dessus du
    seuil de trigger (ou simplement présent si pas d'hystérésis
    numérique).

    active_since : timestamp du premier échantillon positif consécutif
    de la série courante, None si le dernier échantillon était négatif.
    Sert au calcul de persistance.

    alarmed : True si une alarme est actuellement levée pour ce
    segment. Empêche le re-déclenchement (flapping) tant que la
    condition n'est pas retombée sous clear_threshold.
    """

    samples: list[tuple[float, bool]] = field(default_factory=list)
    active_since: float | None = None
    alarmed: bool = False


class AlarmEngine:
    """Moteur d'alarmes — alimenté par feed() à chaque cycle d'évaluation
    du moteur de règles. Maintient l'état glissant, applique
    l'hystérésis et la persistance, accumule les AlarmEvent.

    Usage typique (côté CLI/GUI, qui peut importer netcross_report) :

        engine = AlarmEngine([AlarmConfig(rule_id="loss_per_segment", ...)])
        for batch in live_evaluation_batches:
            signals = [AlarmSignal(f.rule_id, f.segment, f.severity) for f in findings]
            engine.feed(timestamp, signals)
            for evt in engine.events:
                notify(evt)

    Le moteur est déterministe et sans effet de bord externe — testable
    avec des listes de AlarmSignal synthétiques, sans capture live.
    """

    def __init__(self, configs: list[AlarmConfig]):
        self._configs = configs
        # État par (config_index, segment) — segment résolu dynamiquement
        # au premier feed() si AlarmConfig.segment est None.
        self._states: dict[tuple[int, str], _SegmentState] = {}
        self._events: list[AlarmEvent] = []

    @property
    def events(self) -> list[AlarmEvent]:
        """Tous les AlarmEvent émis depuis la création du moteur
        (raised ET cleared), dans l'ordre chronologique."""
        return list(self._events)

    @property
    def active_alarms(self) -> list[AlarmEvent]:
        """Uniquement les AlarmEvent "raised" encore actifs (non
        encore cleared). Utile pour un tableau de bord temps réel."""
        raised: dict[tuple[str, str], AlarmEvent] = {}
        for evt in self._events:
            key = (evt.rule_id, evt.segment)
            if evt.state == "raised":
                raised[key] = evt
            else:  # "cleared" — retire l'alarme si elle était active
                raised.pop(key, None)
        return list(raised.values())

    def feed(self, timestamp: float, signals: list[AlarmSignal]) -> list[AlarmEvent]:
        """Traite un lot de signaux issus d'UN cycle d'évaluation du
        moteur de règles à l'instant `timestamp`. Renvvoie les
        AlarmEvent nouvellement émis par ce cycle (sous-ensemble de
        self.events, jamais None).

        Un signal dont le (rule_id, segment) ne correspond à AUCUNE
        AlarmConfig est ignoré silencieusement — le moteur ne surveille
        que ce qu'on lui a demandé de surveiller.
        """
        new_events: list[AlarmEvent] = []

        # Indexer les signaux reçus ce cycle par (rule_id, segment).
        active_keys: set[tuple[str, str]] = set()
        signal_values: dict[tuple[str, str], float | None] = {}
        for sig in signals:
            key = (sig.rule_id, sig.segment)
            active_keys.add(key)
            signal_values[key] = sig.value

        logger.debug("feed: {} signal(s) reçu(s), {} config(s)", len(signals), len(self._configs))

        for ci, cfg in enumerate(self._configs):
            # Déterminer quels segments sont concernés par cette config.
            if cfg.segment is not None:
                segments = [cfg.segment]
            else:
                # segment=None : surveiller TOUS les segments vus ce
                # cycle pour ce rule_id.
                segments = [seg for (rid, seg) in active_keys if rid == cfg.rule_id]

            for seg in segments:
                state_key: tuple[int, str] = (ci, seg)
                state = self._states.get(state_key)
                if state is None:
                    state = _SegmentState()
                    self._states[state_key] = state

                sig_key = (cfg.rule_id, seg)
                sig_present = sig_key in active_keys
                sig_value = signal_values.get(sig_key)

                is_positive = self._is_positive(cfg, sig_present, sig_value)
                is_clear = self._is_cleared(cfg, sig_present, sig_value)

                # Enregistrer l'échantillon.
                state.samples.append((timestamp, is_positive))
                # Élaguer la fenêtre glissante.
                cutoff = timestamp - cfg.window_seconds
                state.samples = [(ts, pos) for ts, pos in state.samples if ts >= cutoff]

                new_evt = self._evaluate(cfg, seg, state, timestamp, is_positive, is_clear)
                if new_evt is not None:
                    new_events.append(new_evt)
                    self._events.append(new_evt)

        return new_events

    def _is_positive(
        self,
        cfg: AlarmConfig,
        signal_present: bool,
        value: float | None,
    ) -> bool:
        """Détermine si un échantillon est positif (au-dessus du seuil
        de trigger) selon la configuration d'hystérésis.

        Sans trigger_threshold (None) : positif = signal présent.

        Avec trigger_threshold : positif = signal présent ET value >=
        trigger_threshold. Si l'alarme est déjà levée, on utilise le
        seuil de clear (clear_threshold) pour la détection de retour à
        la normale — c'est l'hystérésis proprement dite.
        """
        if not signal_present:
            return False
        if cfg.trigger_threshold is None:
            return True
        if value is None:
            # Signal présent mais sans valeur numérique alors qu'un
            # seuil est défini — on ne peut pas conclure, on considère
            # négatif (prudence : ne pas alerter sur donnée incomplète).
            return False
        return value >= cfg.trigger_threshold

    def _is_cleared(
        self,
        cfg: AlarmConfig,
        signal_present: bool,
        value: float | None,
    ) -> bool:
        """Détermine si un échantillon indique un retour à la normale
        pour une alarme DÉJÀ levée. Symétrique de _is_positive mais
        avec le seuil de clear (hystérésis) :
        - sans clear_threshold : cleared = signal absent.
        - avec clear_threshold : cleared = signal absent OU value <
          clear_threshold.
        """
        if not signal_present:
            return True
        if cfg.clear_threshold is None:
            # Pas de seuil de clear défini : le signal présent maintient
            # l'alarme, même sous le seuil de trigger.
            return False
        if value is None:
            return False
        return value < cfg.clear_threshold

    def _evaluate(
        self,
        cfg: AlarmConfig,
        segment: str,
        state: _SegmentState,
        timestamp: float,
        is_positive: bool,
        is_clear: bool,
    ) -> AlarmEvent | None:
        """Évalue l'état d'un segment après enregistrement du dernier
        échantillon. Renvvoie un AlarmEvent si une transition s'est
        produite ce cycle, None sinon.

        Deux transitions possibles :
        - None → "raised" : le signal persiste au-dessus du seuil
          de trigger depuis au moins min_persistence_seconds ET le
          ratio d'échantillons positifs dans la fenêtre >=
          min_sample_ratio.
        - "raised" → "cleared" : le signal est retombé sous le seuil
          de clear (is_clear=True), avec hystérésis : une valeur entre
          clear_threshold et trigger_threshold ne clear PAS.
        """
        if not state.alarmed:
            # Chercher à lever l'alarme.
            if not is_positive:
                state.active_since = None
                return None

            if state.active_since is None:
                state.active_since = timestamp

            # Vérifier le ratio d'échantillons positifs dans la fenêtre.
            if state.samples:
                positive_count = sum(1 for _, pos in state.samples if pos)
                ratio = positive_count / len(state.samples)
            else:
                ratio = 0.0

            if ratio < cfg.min_sample_ratio:
                return None

            # Vérifier la durée de persistance.
            persistence = timestamp - state.active_since
            if persistence < cfg.min_persistence_seconds:
                return None

            state.alarmed = True
            logger.debug(
                "_evaluate: alarme levée {} sur {} (persistance={:.1f}s, ratio={:.0%})",
                cfg.rule_id,
                segment,
                persistence,
                ratio,
            )
            return AlarmEvent(
                rule_id=cfg.rule_id,
                segment=segment,
                state="raised",
                timestamp=timestamp,
                message=(
                    f"Alarme levée : {cfg.rule_id} sur {segment} (persistance {persistence:.1f}s, ratio {ratio:.0%})"
                ),
            )
        else:
            # Alarme déjà levée — chercher un retour à la normale.
            # is_clear utilise clear_threshold (hystérésis) : une valeur
            # entre clear et trigger ne clear PAS.
            if not is_clear:
                return None  # toujours au-dessus du clear, pas de clear.

            state.alarmed = False
            state.active_since = None
            logger.debug("_evaluate: alarme cleared {} sur {}", cfg.rule_id, segment)
            return AlarmEvent(
                rule_id=cfg.rule_id,
                segment=segment,
                state="cleared",
                timestamp=timestamp,
                message=f"Alarme cleared : {cfg.rule_id} sur {segment} retombée sous le seuil",
            )
