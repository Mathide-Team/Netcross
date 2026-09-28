"""Tests complementaires de netcross_core.notify.transports (#682).

`tests/test_notify.py` couvre les chemins nominaux (serveur HTTP local,
SMTP simule). Ce fichier ajoute ce qui restait non couvert :

- `_reason` : un motif lisible pour chaque famille d'exception ;
- `_post_json` : reponse HTTP hors 2xx qui n'est pas deja une HTTPError ;
- `slack_blocks` : resume sans constat, sans chemin de rapport, non
  anonymise ;
- `EmailNotifier` : construction invalide, envoi sans STARTTLS ni
  identifiants ;
- le corps du protocole `Notifier.send` (un simple stub).
"""

from __future__ import annotations

import errno
import smtplib
import socket
import urllib.error
import urllib.request

import pytest

from netcross_core.notify import EmailNotifier, NotifyError, build_summary
from netcross_core.notify.transports import Notifier, _post_json, _reason, slack_blocks

_FINDINGS = [
    {"severity": "critique", "category": "exploit", "detail": "Log4Shell depuis 10.0.0.42", "point": "LAN"},
]


def _summary(*, findings=_FINDINGS, detail="resume", report_path=None, threshold="elevee"):
    return build_summary(
        findings, score=73, level="critique", threshold=threshold, report_path=report_path, detail=detail
    )


# -- Notifier (protocole) --------------------------------------------------------------------


def test_protocole_notifier_send_est_un_stub():
    """Le corps de `Notifier.send` est `...` : il ne fait rien et renvoie None."""
    assert Notifier.send(object(), _summary()) is None


# -- _reason -----------------------------------------------------------------------------------


def _http_error(code):
    return urllib.error.HTTPError("http://example.test/hook", code, "refuse", {}, None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("exc", "attendu"),
    [
        (_http_error(404), "HTTP 404"),
        (TimeoutError(), "delai depasse"),
        (socket.timeout(), "delai depasse"),
        (urllib.error.URLError(TimeoutError()), "delai depasse"),
        (urllib.error.URLError("nom inconnu"), "injoignable (nom inconnu)"),
        (smtplib.SMTPAuthenticationError(535, b"refuse"), "authentification SMTP refusee"),
        (smtplib.SMTPServerDisconnected("coupe"), "erreur SMTP (SMTPServerDisconnected)"),
        (OSError(errno.ECONNREFUSED, "Connection refused"), "injoignable (Connection refused)"),
        (OSError("sans errno"), "injoignable (sans errno)"),
        (ValueError("mauvaise valeur"), "ValueError: mauvaise valeur"),
    ],
)
def test_reason_motif_lisible(exc, attendu):
    assert _reason(exc) == attendu


# -- _post_json ----------------------------------------------------------------------------------


class _Reponse:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def test_post_json_statut_hors_2xx_leve_notify_error(monkeypatch):
    """urlopen leve deja HTTPError pour 4xx/5xx ; un statut 3xx/1xx qui
    arrive jusqu'a nous doit quand meme etre refuse."""
    monkeypatch.setattr(urllib.request, "urlopen", lambda _request, timeout: _Reponse(302))
    with pytest.raises(NotifyError, match="HTTP 302"):
        _post_json("http://example.test/hook", {"a": 1}, 1.0)


def test_post_json_statut_2xx_accepte(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", lambda _request, timeout: _Reponse(204))
    assert _post_json("http://example.test/hook", {"a": 1}, 1.0) is None


def test_post_json_valueerror_devient_notify_error(monkeypatch):
    def leve(_request, timeout):
        raise ValueError("unknown url type")

    monkeypatch.setattr(urllib.request, "urlopen", leve)
    with pytest.raises(NotifyError, match="ValueError: unknown url type"):
        _post_json("http://example.test/hook", {"a": 1}, 1.0)


# -- slack_blocks -----------------------------------------------------------------------------------


def _textes(blocks):
    return [b["text"]["text"] if "text" in b else b["elements"][0]["text"] for b in blocks]


def test_slack_blocks_sans_constat_ni_chemin_de_rapport_non_anonymise():
    summary = _summary(findings=[], detail="complet")
    assert summary.top == [] and summary.report_path is None and summary.anonymized is False

    blocks = slack_blocks(summary)

    assert [b["type"] for b in blocks] == ["header", "section", "context"]
    contexte = _textes(blocks)[-1]
    assert contexte == f"Seuil : {summary.threshold}"


def test_slack_blocks_anonymise_sans_chemin_de_rapport():
    summary = _summary()
    assert summary.report_path is None and summary.anonymized is True

    contexte = _textes(slack_blocks(summary))[-1]

    assert "Rapport" not in contexte
    assert contexte.endswith("adresses internes anonymisees")


def test_slack_blocks_chemin_de_rapport_non_anonymise():
    summary = _summary(detail="complet", report_path="/tmp/secu.html")

    contexte = _textes(slack_blocks(summary))[-1]

    assert "Rapport : " in contexte
    assert "anonymisees" not in contexte


# -- EmailNotifier ------------------------------------------------------------------------------------


def test_courriel_sans_serveur_leve_valueerror():
    with pytest.raises(ValueError, match="serveur SMTP manquant"):
        EmailNotifier(host="", recipients=("a@b.c",), sender="n@b.c")


def test_courriel_sans_destinataire_leve_valueerror():
    with pytest.raises(ValueError, match="aucun destinataire"):
        EmailNotifier(host="smtp.example", recipients=(), sender="n@b.c")


class _SMTPSimple:
    """SMTP simule qui note ce qui est appele."""

    instances: list = []

    def __init__(self, host, port, timeout):
        self.appels = []
        type(self).instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def starttls(self, context):
        self.appels.append("starttls")

    def login(self, user, password):
        self.appels.append("login")

    def send_message(self, msg):
        self.appels.append("send_message")


def test_courriel_sans_starttls_ni_identifiants(monkeypatch):
    _SMTPSimple.instances = []
    monkeypatch.setattr(smtplib, "SMTP", _SMTPSimple)
    email = EmailNotifier(
        host="smtp.example",
        recipients=("soc@example.org",),
        sender="netcross@example.org",
        starttls=False,
        username=None,
    )

    assert email.send(_summary()) is True

    assert _SMTPSimple.instances[0].appels == ["send_message"]
