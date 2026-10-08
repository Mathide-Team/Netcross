"""netcross_gtk4.live_report_session -- rapport HTML rafraichi en continu
pendant une capture en direct de la GUI (issue #676).

Equivalent GUI de ``--live-report REP``, ``--live-report-interval S`` et
``--live-report-serve PORT`` de la CLI : meme moteur
(``netcross_core.live_report.LiveReporter``), memes fichiers (``live.json``,
``live.jsonl``, ``index.html``), meme page (``netcross_report.live_html``).

Module sans GTK (aucun import de gi) : testable sans interface graphique,
meme principe que ring_recorders.py. Les fonctions renvoient des messages a
afficher dans le journal de la GUI au lieu d'imprimer.
"""

from __future__ import annotations

import functools
import tempfile
import threading
from collections.abc import Callable, Sequence
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from netcross_core.live_report import LiveReporter, LiveReportWriter
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

DEFAULT_INTERVAL = 5.0


class LiveReportError(Exception):
    """Le rapport en continu ne peut pas demarrer (repertoire impossible a
    creer, port deja pris). Rien n'est lance : la capture ne doit pas
    demarrer sans le rapport que l'utilisateur a demande."""


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 -- signature imposee par http.server
        pass


def _default_render() -> Callable:
    from netcross_report.live_html import render_live_html

    return render_live_html


class LiveReportSession:
    """Rapport en continu d'une session de capture : ``add`` par paquet,
    ``point_stopped`` a la fin de chaque point, ``stop`` a l'arret."""

    def __init__(self, reporter: LiveReporter, server: ThreadingHTTPServer | None) -> None:
        self.reporter = reporter
        self.server = server

    @property
    def html_path(self) -> Path:
        return self.reporter.writer.html_path

    @property
    def url(self) -> str | None:
        if self.server is None:
            return None
        return f"http://127.0.0.1:{self.server.server_address[1]}/"

    def add(self, pkt) -> None:
        self.reporter.add(pkt)

    def point_stopped(self, label: str, error: str | None = None) -> None:
        """Etat du point dans la page : ``arrete`` ou ``erreur`` (message)."""
        if error is None:
            self.reporter.aggregator.set_status(label, "arrete")
        else:
            self.reporter.aggregator.set_status(label, "erreur", error)

    def stop(self) -> list[str]:
        """Derniere publication (``final``), arret du serveur ; messages pour
        le journal."""
        self.reporter.stop()
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        messages = [f"Rapport en continu : derniere publication dans {self.html_path}"]
        if self.reporter.failures:
            messages.append(
                f"Rapport en continu : {self.reporter.failures} publication(s) impossible(s) (voir le journal debug)"
            )
        logger.debug("LiveReportSession.stop: {}", messages)
        return messages


def start_live_report(
    labels: Sequence[str],
    out_dir: str | None,
    interval: float = DEFAULT_INTERVAL,
    serve_port: int | None = None,
    *,
    render: Callable | None = None,
    mkdtemp: Callable = tempfile.mkdtemp,
    server_factory: Callable = ThreadingHTTPServer,
) -> tuple[LiveReportSession, list[str]]:
    """Demarre le rapport en continu pour les points ``labels``.

    ``out_dir`` vide ou ``None`` : repertoire temporaire. ``serve_port`` :
    ``None`` = page non servie, ``0`` = port libre choisi par le systeme,
    sinon port fixe (127.0.0.1 uniquement). Leve ``LiveReportError`` si le
    repertoire ou le port est inutilisable."""
    if interval < 1:
        raise LiveReportError(f"intervalle de rafraichissement trop court ({interval:g} s, minimum 1 s)")
    if serve_port is not None and not 0 <= serve_port <= 65535:
        raise LiveReportError(f"port invalide : {serve_port}")
    try:
        directory = out_dir or mkdtemp(prefix="netcross-live-report-")
        if Path(directory).exists() and not Path(directory).is_dir():
            raise LiveReportError(f"{directory} n'est pas un repertoire")
        writer = LiveReportWriter(directory, render or _default_render(), interval)
    except OSError as exc:
        logger.warning("start_live_report: repertoire refuse ({})", exc)
        raise LiveReportError(f"repertoire inutilisable : {exc}") from exc
    server = None
    if serve_port is not None:
        handler = functools.partial(_QuietHandler, directory=str(writer.out_dir))
        try:
            server = server_factory(("127.0.0.1", serve_port), handler)
        except OSError as exc:
            logger.warning("start_live_report: port {} refuse ({})", serve_port, exc)
            raise LiveReportError(f"impossible d'ecouter sur le port {serve_port} ({exc})") from exc
        threading.Thread(target=server.serve_forever, name="netcross-gui-live-http", daemon=True).start()
    reporter = LiveReporter(writer)
    for label in labels:
        reporter.aggregator.register(label)
    reporter.start()
    session = LiveReportSession(reporter, server)
    messages = [f"Rapport en continu : {writer.html_path} (rafraichi toutes les {interval:g} s)"]
    if session.url:
        messages.append(f"Rapport en continu servi sur {session.url} (?mode=completive pour le journal)")
    logger.debug("start_live_report: {}", messages)
    return session, messages
