"""Issue #675 : recherche forensic dans la GUI (equivalent de
--forensic-search / --search-*). Partie sans GTK : saisie, mise en forme,
export JSON et index construit par le pipeline."""

from __future__ import annotations

import json

import pytest
from conftest import make_pkt

import netcross_gtk4.analysis_pipeline as pipeline_mod
from netcross_core.forensic_search import ForensicSearchIndex, ForensicSearchQuery, ForensicSearchResult
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline
from netcross_gtk4.forensic_view import (
    MAX_DISPLAYED,
    SEARCH_FIELDS,
    SearchInputError,
    build_query,
    format_result_row,
    search_payload,
    summary_line,
    write_search_json,
)


def test_memes_champs_que_la_cli():
    import cross_capture_analyzer_cli as cli

    assert SEARCH_FIELDS == cli._SEARCH_FIELDS


def test_requete_depuis_les_widgets():
    q = build_query(text=" login ", address="10.0.0.1", port=" 443 ", field_index=1, value="example")
    assert q == ForensicSearchQuery(text="login", address="10.0.0.1", port=443, field="sni", field_value="example")
    assert build_query(protocol="DNS").protocol == "DNS"
    assert build_query(point="LAN", field_index=0, value="x").field is None


def test_champ_seul_teste_la_presence():
    q = build_query(field_index=SEARCH_FIELDS.index("uri") + 1)
    assert q.field == "uri"
    assert q.field_value is None


@pytest.mark.parametrize("port", ["abc", "-1", "70000"])
def test_port_invalide(port):
    with pytest.raises(SearchInputError, match="port invalide"):
        build_query(port=port)


def test_formulaire_vide_refuse():
    with pytest.raises(SearchInputError, match="au moins un critere"):
        build_query(text="   ", field_index=0)


def test_ligne_de_resultat():
    r = ForensicSearchResult("packet", "LAN", 12, 0.0, ("sni",), "TLS example.org")
    assert format_result_row(r) == "1970-01-01 00:00:00.000 packet [LAN] trame 12 (sni) -- TLS example.org"
    assert format_result_row(ForensicSearchResult("flow", None, None, None)) == "- flow"


def test_resume():
    assert summary_line([]) == "Aucun resultat."
    rs = [ForensicSearchResult("packet", "A", 1, 1.0), ForensicSearchResult("flow", None, None, None)] * 2
    assert summary_line(rs) == "4 resultat(s) : 2 flow, 2 packet."
    beaucoup = [ForensicSearchResult("packet", "A", i, 1.0) for i in range(MAX_DISPLAYED + 1)]
    assert "500 premiers affiches" in summary_line(beaucoup)


def test_export_identique_a_la_cli(tmp_path):
    q = ForensicSearchQuery(text="x", port=53)
    rs = [ForensicSearchResult("packet", "A", 3, 2.0, ("dns_name",), "x.example")]
    payload = search_payload(q, rs)
    assert payload == {
        "version": 1,
        "query": {"text": "x", "port": 53},
        "count": 1,
        "results": [
            {
                "kind": "packet",
                "point": "A",
                "frame_number": 3,
                "ts": 2.0,
                "matched_fields": ("dns_name",),
                "snippet": "x.example",
            }
        ],
    }
    path = write_search_json(tmp_path / "r.json", q, rs)
    relu = json.loads(path.read_text(encoding="utf-8"))
    assert relu["count"] == 1
    assert relu["results"][0]["matched_fields"] == ["dns_name"]


def test_recherche_reelle_sur_un_index():
    pkts = [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", dport=443), make_pkt(point="B", src="10.9.9.9")]
    index = ForensicSearchIndex(pkts)
    resultats = index.search(build_query(address="10.0.0.1"))
    assert resultats
    assert all(r.point == "A" for r in resultats if r.kind == "packet")


# -- pipeline --


@pytest.fixture
def _paquets(monkeypatch):
    pkts = [make_pkt(point="A", sport=1), make_pkt(point="B", sport=1, ts=1000.001)]
    monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: [p for p in pkts if p.point == label])


def test_pipeline_construit_l_index_sur_demande(_paquets):
    journal = []
    result = run_analysis_pipeline(
        [("A", "a.pcap"), ("B", "b.pcap")],
        AnalysisOptions(parallel=False, forensic_index=True),
        on_progress=journal.append,
    )
    assert isinstance(result.search_index, ForensicSearchIndex)
    assert len(result.search_index) >= 2  # deux paquets + le flux
    assert any("element(s) indexe(s)" in ligne for ligne in journal)


def test_pipeline_sans_index_par_defaut(_paquets):
    result = run_analysis_pipeline([("A", "a.pcap"), ("B", "b.pcap")], AnalysisOptions(parallel=False))
    assert result.search_index is None
