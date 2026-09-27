"""Capture en continu + diff en direct (Job 33, issue #33).

Le plus gros chantier des pistes d'origine : capture continue avec diff
en temps reel entre un baseline enregistre et une capture live.

Ce module implemente la boucle de diff live :
1. Charge un baseline (Report serialise) au demarrage.
2. Capture en continu via pcap_parser.capture.iter_live() (une interface,
   LiveDiffEngine.start) ou iter_live_multi() (plusieurs interfaces
   simultanees, un label par interface, LiveDiffEngine.start_multi -- Job 48).
3. Periodiquement (toutes les `eval_interval_seconds`), construit un Report
   partiel sur la fenetre glissante et le compare au baseline via
   netcross_core.baseline_diff.diff_reports().
4. Les DiffFinding resultants sont convertis en AlarmSignal et alimentent
   le AlarmEngine (Job 26 / issue #26).
5. Les AlarmEvent (raised/cleared) sont exposes via callback pour
   notification (email, syslog, etc. -- a brancher par l'appelant).
6. Optionnellement, un CaptureRingBuffer (Job 37, issue #157) est avance
   a chaque paquet -- voir _add_packet() -- pour faire tourner la
   retention disque des fichiers de capture EN MEME TEMPS que le diff
   live, sans jamais interrompre ce dernier (maybe_rotate() ne fait rien
   tant que la duree max par fichier n'est pas atteinte).

Couche : netcross_core -- depend de pcap_parser (iter_live,
iter_live_multi, CaptureRingBuffer), baseline_diff, alarms. Aucune
dependance GUI/CLI.

Limitations :
- Le diff porte sur les metriques du Report (pertes, latence, QoS...), pas
  sur la comparaison paquet par paquet.
- La fenetre glissante est en temps de capture (pk.ts), pas en temps reel.
- Aucune persistance du baseline en interne -- l'appelant fournit le Report.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Callable

from netcross_core.alarms import AlarmEngine, AlarmSignal
from netcross_core.baseline_diff import DiffFinding, diff_reports
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Pkt, Report
from pcap_parser.capture import CaptureRingBuffer

logger = get_logger(__name__)


@dataclass(frozen=True)
class LiveDiffConfig:
    """Configuration de la boucle de diff live.

    - eval_interval_seconds : periode d'evaluation du diff (defaut 5s).
    - window_seconds : fenetre glissante en secondes (defaut 60s).
    - max_packets_per_window : limite de paquets conserves par fenetre
      (defaut 100000, pour limiter la memoire).
    - min_packets_for_diff : nombre minimal de paquets dans la fenetre
      avant de tenter un diff (defaut 100, evite le bruit au demarrage).
    """

    eval_interval_seconds: float = 5.0
    window_seconds: float = 60.0
    max_packets_per_window: int = 100000
    min_packets_for_diff: int = 100


@dataclass
class LiveDiffState:
    """Etat courant de la boucle de diff live.

    - running : True si la boucle tourne.
    - packets_in_window : paquets accumules dans la fenetre courante.
    - last_eval_ts : timestamp de la derniere evaluation.
    - last_diff_count : nombre de DiffFinding lors de la derniere eval.
    - total_evaluations : nombre total d'evaluations effectuees.
    """

    running: bool = False
    packets_in_window: list[Pkt] = field(default_factory=list)
    last_eval_ts: float = 0.0
    last_diff_count: int = 0
    total_evaluations: int = 0


def finding_to_alarm_signal(
    finding: DiffFinding,
    segment: str | None = None,
) -> AlarmSignal:
    """Convertit un DiffFinding en AlarmSignal pour le AlarmEngine.

    DiffFinding porte category (utilise comme rule_id), severity, segment
    et after (nouvelle valeur mesuree). On restructure dans le tuple
    AlarmSignal attendu par le moteur.
    """
    logger.debug("finding_to_alarm_signal(finding={}, segment={})", finding, segment)
    return AlarmSignal(
        rule_id=finding.category,
        segment=segment or finding.segment,
        severity=finding.severity,
        value=finding.after,
    )


class LiveDiffEngine:
    """Boucle de capture continue avec diff en temps reel.

    Utilisation :

        engine = LiveDiffEngine(
            baseline_report=my_baseline,
            on_alarm=my_callback,
        )
        engine.start(interface="eth0")
        # ... plus tard ...
        engine.stop()

    Plusieurs interfaces simultanees (Job 48) : un label par interface, a
    faire correspondre aux noms de points du baseline.

        engine.start_multi([("LAN", "eth0"), ("WAN", "eth1")])

    L'engine tourne dans un thread dedie. La capture live (iter_live, ou
    iter_live_multi qui fusionne ses propres threads de lecture) est
    consommee dans ce thread, et le diff est evalue periodiquement.
    """

    def __init__(
        self,
        baseline_report: Report,
        config: LiveDiffConfig | None = None,
        on_alarm: Callable[[object], None] | None = None,
        alarm_engine: AlarmEngine | None = None,
        ring_buffer: CaptureRingBuffer | None = None,
    ):
        logger.debug(
            "LiveDiffEngine.__init__: baseline_report={} config={} on_alarm={} alarm_engine={} ring_buffer={}",
            summarize(baseline_report, "baseline_report"),
            summarize(config, "config"),
            summarize(on_alarm, "on_alarm"),
            summarize(alarm_engine, "alarm_engine"),
            summarize(ring_buffer, "ring_buffer"),
        )
        self.baseline = baseline_report
        self.config = config or LiveDiffConfig()
        self.on_alarm = on_alarm
        self.alarm_engine = alarm_engine or AlarmEngine([])
        self.ring_buffer = ring_buffer
        self.state = LiveDiffState()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        logger.debug("LiveDiffEngine.__init__: fin")

    def start(self, interface: str, bpf_filter: str | None = None) -> None:
        """Demarre la capture live sur UNE interface et la boucle de diff.

        Le point de capture des paquets porte le nom de l'interface.
        """
        logger.debug("start(interface={}, bpf_filter={})", interface, bpf_filter)
        self._ensure_idle()
        self._stop_event.clear()
        self._launch(self._run, interface, bpf_filter)
        logger.debug("LiveDiffEngine.start: fin")

    def start_multi(self, interfaces: Sequence[tuple[str, str]], bpf_filter: str | None = None) -> None:
        """Demarre la capture live SIMULTANEE sur plusieurs interfaces.

        `interfaces` : sequence de (label, interface), ex.
        [("LAN", "eth0"), ("WAN", "eth1")]. Chaque paquet porte le label de
        son interface comme point de capture -- pour un diff pertinent, ces
        labels doivent correspondre aux noms de points du baseline
        (`baseline_report.points`). `bpf_filter` s'applique a chaque
        interface.

        Une interface en erreur (tshark absent, interface inconnue,
        permission...) interrompt toute la capture : le thread s'arrete
        (`state.running` repasse a False) au lieu de comparer au baseline
        des donnees auxquelles il manque un point.

        Raises:
            RuntimeError: si l'engine tourne deja.
            ValueError: liste vide, label ou interface vide, label en
                double -- levee ici, avant tout demarrage de thread.
        """
        logger.debug("start_multi(interfaces={}, bpf_filter={})", interfaces, bpf_filter)
        from netcross_core.parsing import parse_live_multi

        self._ensure_idle()
        self._stop_event.clear()
        # Cree ici (thread appelant) et non dans le thread de capture : les
        # arguments invalides remontent immediatement a l'appelant, sans
        # laisser l'engine a moitie demarre. Rien n'est lance avant la
        # premiere iteration, faite par _consume dans le thread dedie.
        packets = parse_live_multi(interfaces, stop_event=self._stop_event, bpf_filter=bpf_filter)
        self._launch(self._consume, packets)
        logger.debug("LiveDiffEngine.start_multi: fin")

    def _ensure_idle(self) -> None:
        if self.state.running:
            logger.debug("LiveDiffEngine._ensure_idle: si self.state.running -> levée RuntimeError")
            raise RuntimeError("LiveDiffEngine deja en cours")
        logger.debug("LiveDiffEngine._ensure_idle: fin")

    def _launch(self, target: Callable[..., None], *args: object) -> None:
        self.state.running = True
        self._thread = threading.Thread(target=target, args=args, daemon=True)
        self._thread.start()
        logger.debug("LiveDiffEngine._launch: fin")

    def stop(self, timeout: float = 5.0) -> None:
        """Arrete la capture et attend la fin du thread."""
        logger.debug("stop(timeout={})", timeout)
        self._stop_event.set()
        self.state.running = False
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.debug("LiveDiffEngine.stop: fin")

    def _run(self, interface: str, bpf_filter: str | None) -> None:
        """Capture sur une interface (start) : source de paquets pour _consume."""
        # parse_live (netcross_core.parsing) convertit deja les RawPacket de
        # pcap_parser.capture en Pkt etiquetes -- on n'a pas besoin de gerer
        # la conversion RawPacket -> Pkt manuellement.
        from netcross_core.parsing import parse_live

        self._consume(
            parse_live(
                label=interface,
                interface=interface,
                bpf_filter=bpf_filter,
                stop_event=self._stop_event,
            )
        )
        logger.debug("LiveDiffEngine._run: fin")

    def _consume(self, packets: Iterable[Pkt]) -> None:
        """Boucle principale : consomme les paquets live + evaluation
        periodique du diff. Commune a start (une interface) et start_multi."""
        try:
            for pkt in packets:
                if self._stop_event.is_set():
                    break
                self._add_packet(pkt)
                now = time.time()
                if now - self.state.last_eval_ts >= self.config.eval_interval_seconds:
                    self._evaluate_diff()
                    self.state.last_eval_ts = now
        except Exception:
            logger.exception("échec dans _consume")
            if self.state.running:
                self.state.running = False
            logger.debug("LiveDiffEngine._consume: except Exception -> relance de l'exception en cours")
            raise
        logger.debug("LiveDiffEngine._consume: fin")

    def _add_packet(self, pkt: Pkt) -> None:
        """Ajoute un paquet a la fenetre glissante, en respectant la limite."""
        self.state.packets_in_window.append(pkt)
        # Elagage de la fenetre : retirer les paquets trop anciens
        cutoff = pkt.ts - self.config.window_seconds
        self.state.packets_in_window = [p for p in self.state.packets_in_window if p.ts >= cutoff]
        # Limite de memoire
        if len(self.state.packets_in_window) > self.config.max_packets_per_window:
            self.state.packets_in_window = self.state.packets_in_window[-self.config.max_packets_per_window :]
        # Ring buffer (Job 37) : avance l'horloge de rotation sur le temps de
        # capture (pk.ts, meme convention que la fenetre glissante ci-dessus),
        # sans jamais bloquer ni ralentir le diff live -- maybe_rotate() est un
        # no-op tant que max_duration_per_file n'est pas atteint.
        if self.ring_buffer is not None:
            self.ring_buffer.maybe_rotate(pkt.ts)
        logger.debug("LiveDiffEngine._add_packet: fin")

    def _evaluate_diff(self) -> list[DiffFinding]:
        """Construit un Report partiel et le compare au baseline.

        Retourne les DiffFinding trouves. Nourrit aussi le AlarmEngine.
        """
        self.state.total_evaluations += 1

        pkts = self.state.packets_in_window
        if len(pkts) < self.config.min_packets_for_diff:
            logger.debug(
                "LiveDiffEngine._evaluate_diff: si len(pkts) < self.config.min_packets_for_diff -> retour liste vide"
            )
            return []

        # Construction d'un Report partiel sur la fenetre courante.
        # On reutilise le pipeline d'analyse existant (analyse) sur les
        # paquets accumules. Le baseline_report fournit les points_order.
        from netcross_core.analysis import analyse
        from netcross_core.correlate import correlate

        flows = correlate(pkts)
        points_order = self.baseline.points or list({p.point for p in pkts})
        current = analyse(flows, points_order=points_order, all_packets=pkts)

        # Diff contre le baseline
        findings = diff_reports(self.baseline, current)
        self.state.last_diff_count = len(findings)

        # Conversion en AlarmSignal et alimentation du AlarmEngine
        signals = [finding_to_alarm_signal(f) for f in findings]
        if signals:
            timestamp = pkts[-1].ts if pkts else time.time()
            self.alarm_engine.feed(timestamp, signals)

        # Notification des nouvelles alarmes
        if self.on_alarm is not None:
            for event in self.alarm_engine.events:
                self.on_alarm(event)

        logger.debug("LiveDiffEngine._evaluate_diff: retour findings={}", summarize(findings, "findings"))
        return findings


__all__ = [
    "LiveDiffConfig",
    "LiveDiffEngine",
    "LiveDiffState",
    "finding_to_alarm_signal",
]
