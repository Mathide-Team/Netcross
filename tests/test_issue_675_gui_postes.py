"""Issue #675 : comparaison de postes dans la GUI (equivalent de
--client-group / --client-reference / --client-diff-csv). Partie sans GTK."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from conftest import make_pkt

import netcross_gtk4.analysis_pipeline as pipeline_mod
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline
from netcross_gtk4.client_compare_view import (
    ClientGroupError,
    comparison_summary,
    parse_client_groups,
    validate_client_settings,
)


def test_groupes_separes_par_point_virgule():
    assert parse_client_groups(" A=10.0.0.5 ; B=10.0.0.12, 10.0.0.13;") == {
        "A": {"10.0.0.5"},
        "B": {"10.0.0.12", "10.0.0.13"},
    }
    assert parse_client_groups("") == {}
    assert parse_client_groups("A=1.1.1.1; A=2.2.2.2") == {"A": {"1.1.1.1", "2.2.2.2"}}


@pytest.mark.parametrize("texte", ["PosteA", "=10.0.0.1", "A=", "A= , "])
def test_groupe_invalide(texte):
    with pytest.raises(ClientGroupError, match="groupe invalide"):
        parse_client_groups(texte)


def test_validations_de_la_cli():
    deux = {"A": {"1.1.1.1"}, "B": {"2.2.2.2"}}
    assert validate_client_settings({}, None, False) == []
    assert validate_client_settings(deux, "B", False) == []
    assert "au moins deux groupes" in validate_client_settings({}, "A", False)[0]
    assert "au moins 2 postes" in validate_client_settings({"A": {"1.1.1.1"}}, None, False)[0]
    assert "absente des groupes" in validate_client_settings(deux, "Z", False)[0]
    assert "anonymisation" in validate_client_settings(deux, None, True)[0]


def test_synthese():
    assert "renseignez au moins deux groupes" in comparison_summary(None)
    comp = SimpleNamespace(reference="A", clients={"A": 1, "B": 2, "C": 3}, diffs={"B": [1, 2], "C": [3]})
    assert comparison_summary(comp).startswith("Reference : A ; compare(s) : B, C ; 3 ecart(s).")


# -- pipeline --


@pytest.fixture
def _paquets(monkeypatch):
    pkts = [
        make_pkt(point="A", src="10.0.0.5", dst="10.0.0.9", sport=1, ts=1000.0),
        make_pkt(point="B", src="10.0.0.5", dst="10.0.0.9", sport=1, ts=1000.001),
        make_pkt(point="A", src="10.0.0.12", dst="10.0.0.9", sport=2, ts=1000.0),
    ]
    monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: [p for p in pkts if p.point == label])


def test_pipeline_compare_les_postes(_paquets):
    journal = []
    result = run_analysis_pipeline(
        [("A", "a.pcap"), ("B", "b.pcap")],
        AnalysisOptions(
            parallel=False,
            client_groups={"OK": {"10.0.0.5"}, "KO": {"10.0.0.12"}},
            client_reference="OK",
        ),
        on_progress=journal.append,
    )
    assert result.client_comparison is not None
    assert result.client_comparison.reference == "OK"
    assert set(result.client_comparison.clients) == {"OK", "KO"}
    assert "COMPARAISON CLIENT VS CLIENT" in result.text
    assert "Comparaison de postes..." in journal


def test_pipeline_sans_groupes(_paquets):
    result = run_analysis_pipeline([("A", "a.pcap"), ("B", "b.pcap")], AnalysisOptions(parallel=False))
    assert result.client_comparison is None
    assert "COMPARAISON CLIENT VS CLIENT" not in result.text


def test_pipeline_refuse_l_anonymisation(_paquets):
    with pytest.raises(ValueError, match="anonymisation"):
        run_analysis_pipeline(
            [("A", "a.pcap")],
            AnalysisOptions(parallel=False, redact=True, client_groups={"A": {"1.1.1.1"}, "B": {"2.2.2.2"}}),
        )
