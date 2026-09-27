"""
netcross_core.live_report -- issue #274 : export / rapport temps reel du
mode ``--live``.

Proposition retenue : un **dictionnaire structure** (schema
``netcross.live/1``) tenu a jour pendant la capture, publie sous deux
formes complementaires dans un repertoire :

- ``live.json`` -- **instantane complet**, remplace atomiquement a chaque
  tick (ecriture dans un fichier temporaire puis ``os.replace`` : un lecteur
  ne voit jamais un fichier a moitie ecrit). Lecture **successive** : on
  relit le tout et on remplace l'affichage.
- ``live.jsonl`` -- **journal** en ajout seul, une ligne par tick (deltas
  par point, debits, evenements), numerotee par ``seq``. Lecture
  **completive** : on ne traite que les lignes de ``seq`` superieur au
  dernier vu, l'affichage s'enrichit sans jamais etre remplace.
- ``index.html`` -- page de presentation (rendue par
  ``netcross_report.live_html``) qui sait faire les deux.

Seules des metriques **incrementales** (O(1) par paquet) sont calculees
pendant la capture : relancer l'analyse complete a chaque tick couterait
O(n) sur une capture qui grossit. L'analyse complete reste faite a l'arret,
comme avant.

Couche : netcross_core. Le rendu HTML est injecte (``render_html``) pour ne
pas dependre de netcross_report.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

SCHEMA = "netcross.live/1"
MAX_HOST_EVENTS = 200  # au-dela, un seul evenement de synthese (evite un journal geant sur un scan)
TOP_N = 10
SPIKE_FACTOR = 3.0
SPIKE_MIN_PPS = 50.0
JOURNAL_TAIL = 200  # lignes de journal recopiees dans la page (lecture hors serveur)


def _iso(ts: float) -> str:
    logger.debug("_iso: retour datetime.fromtimestamp(ts, tz=timezone.…(…)")
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


@dataclass
class _Point:
    packets: int = 0
    bytes: int = 0
    retransmissions: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    status: str = "capture"
    error: str | None = None
    # etat du tick precedent
    tick_packets: int = 0
    tick_bytes: int = 0
    ewma_pps: float | None = None
    silent: bool = False


@dataclass
class LiveAggregator:
    """Etat incremental de la capture en cours. Thread-safe."""

    points: dict[str, _Point] = field(default_factory=dict)
    protocols: Counter = field(default_factory=Counter)
    conversations: Counter = field(default_factory=Counter)
    hosts: set = field(default_factory=set)
    started_at: float = field(default_factory=time.time)
    _events: list[dict] = field(default_factory=list)
    _host_overflow: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _seq: int = 0
    _last_tick: float | None = None

    def register(self, label: str) -> None:
        with self._lock:
            self.points.setdefault(label, _Point())
        logger.debug("LiveAggregator.register: fin")

    def add(self, pkt) -> None:
        with self._lock:
            pt = self.points.setdefault(pkt.point, _Point())
            pt.packets += 1
            pt.bytes += pkt.length or 0
            pt.retransmissions += bool(getattr(pkt, "is_retransmission", False))
            pt.first_ts = pkt.ts if pt.first_ts is None else pt.first_ts
            pt.last_ts = pkt.ts
            self.protocols[pkt.proto] += 1
            self.conversations[(pkt.src, pkt.dst, pkt.proto)] += pkt.length or 0
            for host in (pkt.src, pkt.dst):
                if host and host not in self.hosts:
                    self.hosts.add(host)
                    if len(self.hosts) <= MAX_HOST_EVENTS:
                        self._events.append({"type": "nouvel_hote", "point": pkt.point, "host": host})
                    else:
                        self._host_overflow += 1
        logger.debug("LiveAggregator.add: fin")

    def set_status(self, label: str, status: str, error: str | None = None) -> None:
        with self._lock:
            pt = self.points.setdefault(label, _Point())
            pt.status, pt.error = status, error
            self._events.append({"type": "point_" + status, "point": label, **({"detail": error} if error else {})})
        logger.debug("LiveAggregator.set_status: fin")

    def tick(self, now: float | None = None, *, final: bool = False) -> tuple[dict, dict]:
        """(instantane complet, ligne de journal) -- consomme les evenements."""
        logger.debug("tick(now={})", now)
        now = time.time() if now is None else now
        with self._lock:
            self._seq += 1
            span = (now - self._last_tick) if self._last_tick is not None else (now - self.started_at)
            span = max(span, 1e-6)
            self._last_tick = now
            deltas: dict[str, dict] = {}
            events = self._events
            self._events = []
            if self._host_overflow:
                events.append({"type": "nouveaux_hotes_nombreux", "count": self._host_overflow})
                self._host_overflow = 0
            for label, pt in self.points.items():
                dp, db = pt.packets - pt.tick_packets, pt.bytes - pt.tick_bytes
                pt.tick_packets, pt.tick_bytes = pt.packets, pt.bytes
                pps, bps = dp / span, db * 8 / span
                deltas[label] = {"packets": dp, "bytes": db, "pps": round(pps, 1), "bps": round(bps)}
                if pt.status == "capture" and not final:
                    if dp == 0 and pt.packets and not pt.silent:
                        pt.silent = True
                        events.append({"type": "point_silencieux", "point": label})
                    elif dp and pt.silent:
                        pt.silent = False
                        events.append({"type": "point_repris", "point": label})
                    if pt.ewma_pps is not None and pps >= SPIKE_MIN_PPS and pps > SPIKE_FACTOR * pt.ewma_pps:
                        events.append(
                            {
                                "type": "pic_de_debit",
                                "point": label,
                                "pps": round(pps, 1),
                                "moyenne": round(pt.ewma_pps, 1),
                            }
                        )
                pt.ewma_pps = pps if pt.ewma_pps is None else 0.7 * pt.ewma_pps + 0.3 * pps
            for e in events:
                e.setdefault("t", _iso(now))
            journal = {
                "schema": SCHEMA,
                "seq": self._seq,
                "t": _iso(now),
                "elapsed_s": round(now - self.started_at, 1),
                "final": final,
                "points": deltas,
                "events": events,
            }
            snapshot = {
                "schema": SCHEMA,
                "seq": self._seq,
                "generated_at": _iso(now),
                "started_at": _iso(self.started_at),
                "elapsed_s": round(now - self.started_at, 1),
                "final": final,
                "totals": {
                    "packets": sum(p.packets for p in self.points.values()),
                    "bytes": sum(p.bytes for p in self.points.values()),
                    "hosts": len(self.hosts),
                },
                "points": {
                    label: {
                        "status": "arrete" if final and pt.status == "capture" else pt.status,
                        "error": pt.error,
                        "packets": pt.packets,
                        "bytes": pt.bytes,
                        "retransmissions": pt.retransmissions,
                        "pps": deltas[label]["pps"],
                        "bps": deltas[label]["bps"],
                        "first_packet": _iso(pt.first_ts) if pt.first_ts else None,
                        "last_packet": _iso(pt.last_ts) if pt.last_ts else None,
                    }
                    for label, pt in self.points.items()
                },
                "protocols": dict(self.protocols.most_common()),
                "top_conversations": [
                    {"src": s, "dst": d, "proto": p, "bytes": b}
                    for (s, d, p), b in self.conversations.most_common(TOP_N)
                ],
                "last_events": events,
            }
        logger.debug("LiveAggregator.tick: retour tuple de 2")
        return snapshot, journal


def _atomic_write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        logger.exception("erreur: BaseException")
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        logger.debug("_atomic_write: except BaseException -> relance de l'exception en cours")
        raise
    logger.debug("_atomic_write: fin")


class LiveReportWriter:
    """Publie instantane + journal + page dans ``out_dir``."""

    def __init__(
        self,
        out_dir: str | Path,
        render_html: Callable[[dict, list[dict], float], str] | None = None,
        interval: float = 5.0,
    ) -> None:
        logger.debug(
            "LiveReportWriter.__init__: out_dir={} render_html={} interval={}",
            summarize(out_dir, "out_dir"),
            summarize(render_html, "render_html"),
            summarize(interval, "interval"),
        )
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.render_html = render_html
        self.interval = interval
        self.snapshot_path = self.out_dir / "live.json"
        self.journal_path = self.out_dir / "live.jsonl"
        self.html_path = self.out_dir / "index.html"
        self.journal_path.write_text("", encoding="utf-8")  # une session = un journal
        self._tail: list[dict] = []
        logger.debug("LiveReportWriter.__init__: fin")

    def publish(self, snapshot: dict, journal: dict) -> None:
        logger.debug("publish(snapshot={}, journal={})", snapshot, journal)
        line = json.dumps(journal, ensure_ascii=False, separators=(",", ":"))
        with self.journal_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        self._tail = [*self._tail, journal][-JOURNAL_TAIL:]
        _atomic_write(self.snapshot_path, json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n")
        if self.render_html is not None:
            _atomic_write(self.html_path, self.render_html(snapshot, self._tail, self.interval))
        logger.debug("LiveReportWriter.publish: fin")


class LiveReporter:
    """Relie l'agregateur a l'ecrivain : un thread publie toutes les
    ``interval`` secondes, puis une derniere fois (``final``) a l'arret.
    Une erreur d'ecriture (disque plein...) est journalisee sans jamais
    interrompre la capture."""

    def __init__(self, writer: LiveReportWriter, aggregator: LiveAggregator | None = None) -> None:
        logger.debug(
            "LiveReporter.__init__: writer={} aggregator={}",
            summarize(writer, "writer"),
            summarize(aggregator, "aggregator"),
        )
        self.writer = writer
        self.aggregator = aggregator or LiveAggregator()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.failures = 0
        logger.debug("LiveReporter.__init__: fin")

    def add(self, pkt) -> None:
        self.aggregator.add(pkt)
        logger.debug("LiveReporter.add: fin")

    def _publish(self, final: bool = False) -> None:
        snapshot, journal = self.aggregator.tick(final=final)
        try:
            self.writer.publish(snapshot, journal)
        except OSError as exc:
            self.failures += 1
            logger.warning("rapport temps reel : ecriture impossible ({}), capture poursuivie", exc)
        logger.debug("LiveReporter._publish: fin")

    def _loop(self) -> None:
        while not self._stop.wait(self.writer.interval):
            self._publish()
        logger.debug("LiveReporter._loop: fin")

    def start(self) -> None:
        self._publish()
        self._thread = threading.Thread(target=self._loop, name="netcross-live-report", daemon=True)
        self._thread.start()
        logger.debug("LiveReporter.start: fin")

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        self._publish(final=True)
        logger.debug("LiveReporter.stop: fin")
