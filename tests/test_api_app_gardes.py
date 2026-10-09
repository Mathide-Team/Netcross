"""Issue #736 : gardes de netcross_api/app.py non atteintes par les tests
HTTP (repli ImportError QUIC, erreurs d'analyse, nom de fichier vide)."""

from __future__ import annotations

import asyncio
import importlib
import sys
from types import SimpleNamespace

import pytest
from conftest import make_pkt

try:
    api_module = importlib.import_module("netcross_api.app")
    from fastapi import HTTPException
except ImportError:
    pytest.skip("fastapi non installe (extra [api])", allow_module_level=True)

AnalysisError = api_module.AnalysisError
ApiAnalysisOptions = api_module.ApiAnalysisOptions


def test_quic_sans_cryptography_leve_analysis_error(monkeypatch):
    """Lignes 238-240 : quic demande mais module QUIC inimportable."""
    monkeypatch.setitem(sys.modules, "netcross_core.quic_diagnostics", None)
    options = ApiAnalysisOptions(quic=True)
    with pytest.raises(AnalysisError, match="cryptography"):
        api_module._tls_quic_findings([("A", "/inexistant.pcap")], ["A"], options)


def _captures_parsees(monkeypatch):
    monkeypatch.setattr(api_module, "parse_capture", lambda label, path: [make_pkt(point=label)])


def test_erreur_inattendue_pendant_l_analyse_est_encapsulee(monkeypatch):
    """Lignes 311-313 : une exception quelconque devient AnalysisError."""
    _captures_parsees(monkeypatch)

    def _boom(*args, **kwargs):
        raise RuntimeError("correlation cassee")

    monkeypatch.setattr(api_module, "correlate", _boom)
    with pytest.raises(AnalysisError, match="Erreur d'analyse: correlation cassee"):
        api_module._analyse_captures([("A", "/x.pcap")], None, multi=False)


def test_analysis_error_pendant_l_analyse_est_propagee_telle_quelle(monkeypatch):
    """Lignes 308-310 : une AnalysisError levee dans l'analyse est relancee."""
    _captures_parsees(monkeypatch)

    def _refus(*args, **kwargs):
        raise AnalysisError("refus explicite")

    monkeypatch.setattr(api_module, "correlate", _refus)
    with pytest.raises(AnalysisError, match=r"^refus explicite$"):
        api_module._analyse_captures([("A", "/x.pcap")], None, multi=False)


def _options_formulaire():
    return {
        "nat_tolerant": False,
        "nat_window_ms": 50.0,
        "tls": False,
        "quic": False,
        "redact": False,
        "max_packets": None,
        "sample": None,
        "test_net_external": False,
        "parallel_workers": None,
        "names": None,
        "known_destinations": None,
        "known_hosts": None,
        "wait": False,
        "_auth": None,
    }


def test_upload_capture_nom_de_fichier_vide_400():
    """Lignes 426-427 : fichier sans nom -> 400."""
    with pytest.raises(HTTPException) as exc:
        asyncio.run(api_module.upload_capture(file=SimpleNamespace(filename=""), label="A", **_options_formulaire()))
    assert exc.value.status_code == 400
    assert exc.value.detail == "Nom de fichier manquant"


def test_upload_multi_capture_nom_de_fichier_vide_400():
    """Lignes 564-565 : un des fichiers sans nom -> 400 avec son etiquette."""
    fichiers = [SimpleNamespace(filename=""), SimpleNamespace(filename="dc.pcap")]
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            api_module.upload_multi_capture(files=fichiers, labels="LAN,DC", points_order="", **_options_formulaire())
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == "Nom de fichier manquant pour LAN"
