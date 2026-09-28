"""Tests en processus de netcross_core.logging_config (#681).

`tests/test_logging_config.py` verifie le comportement de bout en bout dans
des sous-processus (le logging est un etat global) : coverage ne mesure pas
ces sous-processus, d'ou un module a 81 %. Ces tests couvrent les memes
chemins dans le processus de pytest, avec un etat global isole et restaure :

- `stderr` est remplace par un tampon pour lire ce que loguru ecrit ;
- l'environnement NETCROSS_* est vide au depart ;
- a la fin, les handlers poses par le test sont retires et la
  configuration d'origine (niveau, handler stderr) est reposee.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import sys

import pytest
from loguru import logger as _logger

import netcross_core.logging_config as lc


def _fermer_handlers() -> None:
    """Retire (et ferme) les handlers poses par logging_config."""
    for handler_id in list(lc._HANDLER_IDS):
        with contextlib.suppress(ValueError):
            _logger.remove(handler_id)
    lc._HANDLER_IDS.clear()


@pytest.fixture
def logging_isole(monkeypatch):
    """Rend (module, tampon stderr) avec un etat de logging isole."""
    for var in ("NETCROSS_LOG_LEVEL", "NETCROSS_DEBUG", "NETCROSS_LOG_FILE"):
        monkeypatch.delenv(var, raising=False)
    etat_configure, etat_niveau = lc._CONFIGURED, lc._LEVEL
    tampon = io.StringIO()
    monkeypatch.setattr(sys, "stderr", tampon)

    yield lc, tampon

    # stderr/environnement d'origine d'abord : le handler repose ci-dessous
    # doit s'attacher au vrai stderr, pas au tampon du test.
    monkeypatch.undo()
    _fermer_handlers()
    if etat_configure:
        lc._CONFIGURED = True
        lc.configure_logging(etat_niveau, force=True)
    else:
        lc._CONFIGURED = False
        lc._LEVEL = etat_niveau


def test_level_from_env_niveau_explicite(logging_isole, monkeypatch):
    monkeypatch.setenv("NETCROSS_LOG_LEVEL", " warning ")
    monkeypatch.setenv("NETCROSS_DEBUG", "1")  # NETCROSS_LOG_LEVEL est prioritaire
    assert lc.level_from_env() == "WARNING"


@pytest.mark.parametrize("valeur", ["1", "true", "YES", "oui", " On "])
def test_level_from_env_netcross_debug(logging_isole, monkeypatch, valeur):
    monkeypatch.setenv("NETCROSS_DEBUG", valeur)
    assert lc.level_from_env() == "DEBUG"


def test_level_from_env_defaut(logging_isole, monkeypatch):
    monkeypatch.setenv("NETCROSS_DEBUG", "non")
    assert lc.level_from_env() == "INFO"


def test_configure_logging_idempotent_sans_force(logging_isole):
    module, _ = logging_isole
    module.configure_logging("INFO", force=True)
    identifiants = list(module._HANDLER_IDS)

    module.configure_logging("DEBUG")  # deja configure : sans effet

    assert module._LEVEL == "INFO"
    assert module._HANDLER_IDS == identifiants


def test_configure_logging_force_remplace_les_handlers(logging_isole):
    module, tampon = logging_isole
    module.configure_logging("INFO", force=True)
    anciens = list(module._HANDLER_IDS)

    module.configure_logging("DEBUG", force=True)

    assert module._LEVEL == "DEBUG"
    assert len(module._HANDLER_IDS) == 1
    assert module._HANDLER_IDS != anciens
    assert "tracing debug actif : niveau=DEBUG" in tampon.getvalue()


def test_configure_logging_force_sans_handler_connu(logging_isole):
    """Deja configure mais aucun identifiant a retirer : boucle vide."""
    module, _ = logging_isole
    module.configure_logging("INFO", force=True)
    _fermer_handlers()  # _HANDLER_IDS vide, _CONFIGURED reste vrai

    module.configure_logging("WARNING", force=True)

    assert module._LEVEL == "WARNING"
    assert len(module._HANDLER_IDS) == 1


def test_configure_logging_premiere_configuration(logging_isole):
    """Pas encore configure : le handler par defaut de loguru est retire."""
    module, _ = logging_isole
    module._CONFIGURED = False

    module.configure_logging("INFO")

    assert module._CONFIGURED is True
    assert module._LEVEL == "INFO"
    assert len(module._HANDLER_IDS) == 1


def test_configure_logging_niveau_inconnu_repli_sur_info(logging_isole):
    module, tampon = logging_isole

    module.configure_logging("BAVARD", force=True)

    assert module._LEVEL == "INFO"
    assert "niveau de log inconnu 'BAVARD', repli sur INFO" in tampon.getvalue()


def test_configure_logging_copie_dans_un_fichier(logging_isole, tmp_path):
    module, _ = logging_isole
    fichier = tmp_path / "netcross.log"

    module.configure_logging("DEBUG", log_file=str(fichier), force=True)
    assert len(module._HANDLER_IDS) == 2  # stderr + fichier
    _logger.info("message-fichier-temoin")
    _fermer_handlers()

    assert "message-fichier-temoin" in fichier.read_text(encoding="utf-8")


def test_configure_logging_fichier_depuis_l_environnement(logging_isole, monkeypatch, tmp_path):
    module, _ = logging_isole
    fichier = tmp_path / "env.log"
    monkeypatch.setenv("NETCROSS_LOG_FILE", str(fichier))

    module.configure_logging("INFO", force=True)
    assert len(module._HANDLER_IDS) == 2
    _logger.info("message-env-temoin")
    _fermer_handlers()

    assert "message-env-temoin" in fichier.read_text(encoding="utf-8")


def test_enable_debug_bascule_en_debug(logging_isole):
    module, tampon = logging_isole
    module.configure_logging("INFO", force=True)

    module.enable_debug()

    assert module._LEVEL == "DEBUG"
    assert module.is_debug_enabled() is True
    assert "enable_debug: fin" in tampon.getvalue()


def test_current_level_configure_a_la_demande(logging_isole):
    module, _ = logging_isole
    module._CONFIGURED = False

    assert module.current_level() == "INFO"
    assert module._CONFIGURED is True


def test_apply_debug_argument_actif(logging_isole):
    module, _ = logging_isole
    module.configure_logging("INFO", force=True)

    module.apply_debug_argument(argparse.Namespace(debug=True))

    assert module._LEVEL == "DEBUG"


def test_apply_debug_argument_inactif(logging_isole):
    module, _ = logging_isole
    module.configure_logging("INFO", force=True)

    module.apply_debug_argument(argparse.Namespace(debug=False))
    module.apply_debug_argument(argparse.Namespace())  # pas d'attribut debug

    assert module._LEVEL == "INFO"
