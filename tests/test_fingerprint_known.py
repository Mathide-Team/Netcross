"""
netcross_core.fingerprint.known -- chemin d'erreur de
`load_known_fingerprints` (issue #690, suite de #665 : couverture >= 98 %).

Les tests existants (`test_fingerprinting.py`,
`test_fingerprints_reference.py`) ne chargent que la base livree avec le
projet. La branche `except (OSError, json.JSONDecodeError)` -- celle qui
garantit qu'une base absente ou illisible ne fait jamais echouer
l'analyse, seulement priver l'analyste de l'identification lisible de
l'outil -- n'etait exercee par aucun test (lignes 65-68, 87,1 % mesures
sur `known.py`).

Tout est synthetique : fichiers temporaires (`tmp_path`), aucune capture,
aucun tshark.
"""

from __future__ import annotations

import json

import pytest
from loguru import logger

from netcross_core.fingerprint.known import load_known_fingerprints

_BASE_VIDE = {"ja4": {}, "hassh": {}}


@pytest.fixture
def journal():
    logger.enable("netcross_core")
    lignes: list[tuple[str, str]] = []
    sink = logger.add(lambda m: lignes.append((m.record["level"].name, m.record["message"])), level="TRACE")
    yield lignes
    logger.remove(sink)


# -- base absente ou illisible : jamais d'exception ---------------------------


def test_fichier_absent_renvoie_une_base_vide(tmp_path):
    assert load_known_fingerprints(tmp_path / "absent.json") == _BASE_VIDE


def test_chemin_qui_est_un_repertoire_renvoie_une_base_vide(tmp_path):
    # Autre sous-classe d'OSError que FileNotFoundError (IsADirectoryError
    # sous Linux, PermissionError sous Windows) : `except OSError` doit
    # toutes les couvrir, pas seulement le cas « fichier absent ».
    assert load_known_fingerprints(tmp_path) == _BASE_VIDE


@pytest.mark.parametrize(
    "contenu",
    ["", "{ceci n'est pas du JSON", '{"ja4": {"t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb": "curl"'],
    ids=["fichier_vide", "syntaxe_invalide", "json_tronque"],
)
def test_json_illisible_renvoie_une_base_vide(tmp_path, contenu):
    chemin = tmp_path / "corrompue.json"
    chemin.write_text(contenu, encoding="utf-8")
    assert load_known_fingerprints(chemin) == _BASE_VIDE


def test_l_echec_de_chargement_est_journalise_en_erreur(tmp_path, journal):
    # « Jamais d'exception » ne veut pas dire « en silence » : l'analyste
    # doit pouvoir retrouver pourquoi la base d'outils connus est vide.
    load_known_fingerprints(tmp_path / "absent.json")
    assert any(niveau == "ERROR" and "load_known_fingerprints" in message for niveau, message in journal)


# -- base alternative valide : le contraste ----------------------------------


def test_base_alternative_valide_se_charge_depuis_un_str_ou_un_path(tmp_path, journal):
    chemin = tmp_path / "ma_base.json"
    chemin.write_text(json.dumps({"ja4": {"t13d_x": "outil maison 1.0"}}), encoding="utf-8")

    attendu = {"ja4": {"t13d_x": "outil maison 1.0"}, "hassh": {}}  # famille absente du fichier -> {}
    assert load_known_fingerprints(chemin) == attendu
    assert load_known_fingerprints(str(chemin)) == attendu
    assert not any(niveau in ("ERROR", "CRITICAL") for niveau, _message in journal)


def test_un_echec_n_est_pas_memorise_par_le_cache(tmp_path):
    # `_load_cached` est sous `lru_cache` : une exception n'y est jamais
    # memorisee. Corriger le fichier apres un echec doit donc suffire, sans
    # relancer le processus (cas d'un utilisateur qui maintient sa base).
    chemin = tmp_path / "ma_base.json"
    chemin.write_text("{pas encore du JSON", encoding="utf-8")
    assert load_known_fingerprints(chemin) == _BASE_VIDE

    chemin.write_text(json.dumps({"hassh": {"deadbeef": "OpenSSH maison"}}), encoding="utf-8")
    assert load_known_fingerprints(chemin) == {"ja4": {}, "hassh": {"deadbeef": "OpenSSH maison"}}
