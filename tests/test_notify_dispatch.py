"""
netcross_core.notify.dispatch -- chemins d'erreur et cas limites (issue #720,
suite de #665).

`tests/test_notify.py` (issue #280) couvre le parcours nominal de la
repartition des notifications ; `dispatch.py` restait a 93,7 %. Ce fichier
couvre ce qui manquait, sans `# pragma: no cover` :

- `_load_state` : fichier d'etat en JSON valide mais qui n'est pas un objet ;
- `_save_state` : etat impossible a enregistrer -- l'ecriture ne bloque
  jamais l'envoi, la prochaine analyse re-notifie ;
- `_fmt_age` : age d'une heure ou plus, exprime en heures ;
- `run_notifications` : seuil fourni mais aucun canal exploitable.

Aucun reseau, aucun tshark, aucun GTK : des fichiers dans `tmp_path`, une
doublure de canal et des `monkeypatch`.
"""

from __future__ import annotations

import json
import os
import socket

import pytest
from loguru import logger

from netcross_core.config import NotifyConfig
from netcross_core.notify import build_summary, run_notifications, send_notifications
from netcross_core.notify.dispatch import _fmt_age, _load_state, _save_state, is_silenced

FINDINGS = [
    {
        "severity": "critique",
        "category": "exploit",
        "detail": "Log4Shell (LOG4SHELL) depuis 10.0.0.42 vers 10.0.0.5, 12 occurrences",
        "point": "LAN",
        "host": "10.0.0.5",
        "port": 80,
        "src": "10.0.0.42",
        "signature_id": "LOG4SHELL",
    },
]


def _summary():
    return build_summary(FINDINGS, score=73, level="critique", threshold="elevee", report_path=None, detail="resume")


class _Canal:
    """Doublure d'un canal : garde ce qu'on lui envoie, n'echoue jamais."""

    def __init__(self, name: str = "webhook") -> None:
        self.name = name
        self.sent: list = []

    def send(self, summary) -> bool:
        self.sent.append(summary)
        return True


@pytest.fixture
def avertissements():
    """Messages loguru de niveau WARNING et plus emis pendant le test."""
    recus: list[str] = []
    sink = logger.add(lambda m: recus.append(m.record["message"]), level="WARNING")
    yield recus
    logger.remove(sink)


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("appel reseau interdit")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def _resume_interdit(_seuil):
    raise AssertionError("le resume ne doit pas etre construit sans canal exploitable")


# -- _load_state : JSON valide mais pas un objet ----------------------------------------


@pytest.mark.parametrize("contenu", ["[1, 2, 3]", '"texte"', "42", "null"])
def test_etat_json_valide_mais_pas_un_objet_est_traite_comme_vide(tmp_path, contenu):
    state = tmp_path / "state.json"
    state.write_text(contenu, encoding="utf-8")
    assert _load_state(state) == {}
    # consequence pour l'anti-repetition : rien n'est considere comme deja notifie
    assert is_silenced("empreinte", state, silence_seconds=3600, now=1000.0) is None


def test_etat_qui_n_est_pas_un_objet_n_empeche_ni_l_envoi_ni_sa_reecriture(tmp_path):
    state = tmp_path / "state.json"
    state.write_text("[1, 2, 3]", encoding="utf-8")
    canal = _Canal()
    summary = _summary()

    resultats = send_notifications(summary, [canal], state_path=state, silence_seconds=3600, now=1000.0)

    assert [r.status for r in resultats] == ["envoye"]
    assert len(canal.sent) == 1
    # l'etat inutilisable est remplace par un objet valide
    assert json.loads(state.read_text(encoding="utf-8")) == {summary.fingerprint: 1000.0}


# -- _save_state : etat impossible a enregistrer ----------------------------------------


def test_etat_non_enregistrable_ne_bloque_pas_l_envoi_et_la_suivante_re_notifie(tmp_path, avertissements):
    # le « dossier » parent du fichier d'etat est en realite un fichier : mkdir echoue (OSError)
    obstacle = tmp_path / "obstacle"
    obstacle.write_text("je suis un fichier, pas un dossier", encoding="utf-8")
    state = obstacle / "state.json"
    canal = _Canal()
    summary = _summary()

    premiere = send_notifications(summary, [canal], state_path=state, silence_seconds=3600, now=1000.0)
    seconde = send_notifications(summary, [canal], state_path=state, silence_seconds=3600, now=1100.0)

    assert [premiere[0].status, seconde[0].status] == ["envoye", "envoye"]
    # faute d'etat enregistre, pas d'anti-repetition : le meme lot est re-notifie
    assert len(canal.sent) == 2
    assert not state.exists()
    # ... mais l'echec est dit, pas avale
    assert sum("etat anti-repetition non enregistre" in m for m in avertissements) == 2


def test_remplacement_du_fichier_d_etat_en_echec_ne_leve_pas(tmp_path, monkeypatch, avertissements):
    def disque_plein(*_a, **_k):
        raise OSError("disque plein")

    monkeypatch.setattr(os, "replace", disque_plein)
    state = tmp_path / "state.json"

    _save_state(state, {"empreinte": 1000.0})  # ne leve pas

    assert not state.exists()
    assert any("etat anti-repetition non enregistre" in m and "disque plein" in m for m in avertissements)


# -- _fmt_age : heures au-dela de 3600 s ------------------------------------------------


@pytest.mark.parametrize(
    ("secondes", "attendu"),
    [
        (0, "0 min"),
        (59, "0 min"),
        (600, "10 min"),
        (3599, "59 min"),
        (3600, "1.0 h"),
        (5400, "1.5 h"),
        (86400, "24.0 h"),
    ],
)
def test_fmt_age_minutes_sous_l_heure_puis_heures(secondes, attendu):
    assert _fmt_age(secondes) == attendu


def test_raison_du_silence_exprimee_en_heures_au_dela_d_une_heure(tmp_path):
    state = tmp_path / "state.json"
    canal = _Canal()
    summary = _summary()
    send_notifications(summary, [canal], state_path=state, silence_seconds=86400, now=1000.0)

    resultats = send_notifications(summary, [canal], state_path=state, silence_seconds=86400, now=1000.0 + 2 * 3600)

    assert [r.status for r in resultats] == ["silence"]
    assert resultats[0].reason == "meme lot de constats deja notifie il y a 2.0 h"
    assert resultats[0].line() == (
        "notification webhook : non envoyee (anti-repetition), meme lot de constats deja notifie il y a 2.0 h"
    )
    assert len(canal.sent) == 1


# -- run_notifications : seuil fourni, aucun canal exploitable --------------------------


def test_seuil_sans_aucun_canal_configure_rend_les_lignes_non_configure(no_network):
    resultats = run_notifications(_resume_interdit, threshold="elevee", cfg=NotifyConfig(), env={})

    assert [(r.channel, r.status) for r in resultats] == [
        ("webhook", "non_configure"),
        ("slack", "non_configure"),
        ("courriel", "non_configure"),
    ]
    assert [r.line() for r in resultats] == [
        "notification webhook : non configuree",
        "notification slack : non configuree",
        "notification courriel : non configuree",
    ]


def test_seuil_avec_un_canal_mal_configure_rend_l_echec_sans_construire_le_resume(no_network):
    resultats = run_notifications(
        _resume_interdit, threshold="elevee", cfg=NotifyConfig(), webhook="file:///etc/passwd", env={}
    )

    par_canal = {r.channel: r for r in resultats}
    assert par_canal["webhook"].status == "echec"
    assert "configuration invalide" in (par_canal["webhook"].reason or "")
    assert par_canal["slack"].status == "non_configure"
    assert par_canal["courriel"].status == "non_configure"
