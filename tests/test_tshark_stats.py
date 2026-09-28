"""
netcross_core.tshark_stats -- tests des adaptateurs de statistiques tshark -z
(Job 19 / issue #20, section 6.19).

Les parsers sont testes avec des fixtures texte (tests/data/) representant le
format documente par la page de manuel tshark(1) (colonnes en ordre documente).
Le runner est teste par monkeypatch de subprocess (tshark non installe dans
l'environnement de test).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from netcross_core.tshark_stats import (
    ApplicationStat,
    ConversationStat,
    EndpointStat,
    MetricSeries,
    ProtocolHierarchyStat,
    ResponseTimeStat,
    TsharkUnavailableError,
    collect_conversations,
    parse_conversations,
    parse_dns_stat,
    parse_endpoints,
    parse_http_stat,
    parse_io_stat,
    parse_protocol_hierarchy,
    parse_response_time,
    run_tshark_stat,
)

_DATA = Path(__file__).parent / "data"


def _fixture(name: str) -> str:
    return (_DATA / name).read_text(encoding="utf-8")


# -- conversations ----------------------------------------------------------


def test_parse_conversations_extrait_endpoints_et_compteurs():
    convs = parse_conversations(_fixture("tshark_conv_tcp.txt"), protocol="tcp")
    assert len(convs) == 2
    c = convs[0]
    assert isinstance(c, ConversationStat)
    assert c.protocol == "tcp"
    assert c.endpoint_a == "192.168.0.1:5000"
    assert c.endpoint_b == "10.0.0.2:80"
    # Ordre documente : frames A->B, bytes A->B, frames B->A, bytes B->A,
    # total frames, total bytes, rel start, duration, bits/s.
    assert c.packets_ab == 5
    assert c.bytes_ab == 1000
    assert c.packets_ba == 4
    assert c.bytes_ba == 800
    assert c.packets_total == 9
    assert c.bytes_total == 1800
    assert c.rel_start == pytest.approx(0.023)
    assert c.duration == pytest.approx(2.345)
    assert c.bits_per_second == 6144
    # raw_fields preserve toutes les colonnes brutes.
    assert c.raw_fields


def test_parse_conversations_sortie_vide_retourne_liste_vide():
    assert parse_conversations("rien a voir ici") == []


# -- endpoints --------------------------------------------------------------


def test_parse_endpoints_extrait_adresse_et_compteurs():
    eps = parse_endpoints(_fixture("tshark_endpoints_tcp.txt"), protocol="tcp")
    assert len(eps) == 2
    e = eps[0]
    assert isinstance(e, EndpointStat)
    assert e.address == "192.168.0.1:5000"
    assert e.packets_total == 9
    assert e.bytes_total == 1800
    assert e.packets_out == 5
    assert e.bytes_out == 1000
    assert e.packets_in == 4
    assert e.bytes_in == 800
    assert e.bits_per_second == 6144


# -- protocol hierarchy -----------------------------------------------------


def test_parse_protocol_hierarchy_extrait_profondeur_et_compteurs():
    nodes = parse_protocol_hierarchy(_fixture("tshark_io_phs.txt"))
    assert nodes
    by_proto = {n.protocol: n for n in nodes}
    assert isinstance(by_proto["frame"], ProtocolHierarchyStat)
    assert by_proto["frame"].frame_count == 1000
    assert by_proto["frame"].byte_count == 64000
    assert by_proto["frame"].depth == 0
    assert by_proto["eth"].depth == 1
    assert by_proto["http"].depth == 4
    assert by_proto["http"].frame_count == 100
    assert by_proto["dns"].byte_count == 3200


@pytest.mark.parametrize(
    "texte",
    [
        "",  # sortie vide
        "\n   \n",  # lignes blanches uniquement
        "===\nProtocol Hierarchy Statistics\nFilter: \n===\n",  # en-tetes seuls, aucune donnee
        "frame\n",  # un seul jeton : pas de compteur
        "frame eth ip\n",  # deux jetons ou plus mais aucun chiffre
    ],
)
def test_parse_protocol_hierarchy_sans_ligne_de_donnees_donne_liste_vide(texte):
    assert parse_protocol_hierarchy(texte) == []


def test_parse_protocol_hierarchy_ignore_les_lignes_sans_donnees_au_milieu_des_donnees():
    texte = (
        "===\n"
        "Protocol Hierarchy Statistics\n"
        "Filter:\n"
        "\n"
        "frame                      frames:10 bytes:1000\n"
        "  pas de chiffre ici\n"  # deux jetons et plus, sans aucun chiffre : ignoree
        "  isole\n"  # un seul jeton : ignoree
        "  eth                      frames:10 bytes:1000\n"
        "===\n"
    )
    nodes = parse_protocol_hierarchy(texte)
    assert [n.protocol for n in nodes] == ["frame", "eth"]
    assert [n.depth for n in nodes] == [0, 0]  # l'indentation de 2 espaces < _INDENT


# -- io stat ----------------------------------------------------------------


def test_parse_io_stat_construit_une_serie_temporelle():
    series = parse_io_stat(_fixture("tshark_io_stat.txt"))
    assert isinstance(series, MetricSeries)
    assert len(series.points) == 3
    p0 = series.points[0]
    assert p0.start == pytest.approx(0.0)
    assert p0.end == pytest.approx(1.0)
    assert p0.values["frames"] == 100
    assert p0.values["bytes"] == 6400
    assert series.points[1].values["frames"] == 200


def test_parse_io_stat_intervalle_ouvert():
    series = parse_io_stat("| Time |frames |\n| 000.000- |    100 |\n")
    assert len(series.points) == 1
    assert series.points[0].start == pytest.approx(0.0)
    assert series.points[0].end is None
    assert series.points[0].values["frames"] == 100


def test_parse_io_stat_aucun_intervalle_retourne_serie_vide():
    assert parse_io_stat("pas d'intervalle").points == ()


# -- http / dns / response time --------------------------------------------


def test_parse_http_stat_agrege_les_metriques_nommees():
    stats = parse_http_stat(_fixture("tshark_http_stat.txt"))
    assert len(stats) == 1
    s = stats[0]
    assert isinstance(s, ApplicationStat)
    assert s.application == "http"
    assert s.metrics["get"] == 12
    assert s.metrics["post"] == 3
    assert s.metrics["200 ok"] == 10
    assert s.metrics["404 not found"] == 2


def test_parse_dns_stat_agrege_les_metriques_nommees():
    stats = parse_dns_stat(_fixture("tshark_dns_tree.txt"))
    assert len(stats) == 1
    s = stats[0]
    assert isinstance(s, ApplicationStat)
    assert s.application == "dns"
    assert s.metrics["a"] == 20
    assert s.metrics["aaaa"] == 5


def test_parse_response_time_extrait_min_max_mean():
    rt = parse_response_time(_fixture("tshark_http_rtt.txt"), application="http")
    assert isinstance(rt, ResponseTimeStat)
    assert rt.application == "http"
    assert rt.count == 12
    assert rt.min_ms == pytest.approx(0.005)
    assert rt.max_ms == pytest.approx(0.250)
    assert rt.mean_ms == pytest.approx(0.045)


def test_parse_response_time_aucune_metrique_retourne_none():
    assert parse_response_time("rien") is None


# -- runner (monkeypatch) ---------------------------------------------------


class _FakeCompleted:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_run_tshark_stat_invoque_tshark_et_retourne_stdout(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeCompleted(0, "STATS OUTPUT\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    out = run_tshark_stat("capture.pcap", "conv,tcp")
    assert out == "STATS OUTPUT\n"
    assert captured["cmd"][0] == "tshark"
    assert "-q" in captured["cmd"]
    assert "conv,tcp" in captured["cmd"]


def test_run_tshark_stat_tshark_absent_leve_tsharkunavailable(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("no such file")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(TsharkUnavailableError):
        run_tshark_stat("capture.pcap", "conv,tcp")


def test_collect_conversations_chaine_runner_et_parser(monkeypatch):
    text = _fixture("tshark_conv_tcp.txt")
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: _FakeCompleted(0, text))
    convs = collect_conversations("capture.pcap", protocol="tcp")
    assert len(convs) == 2
    assert convs[0].endpoint_a == "192.168.0.1:5000"


# -- Issues #693, #688, #687, #679 : cas limites des parseurs et du runner ---


def test_split_endpoints_champ_sans_separateur():
    """Lignes 38-39 : un champ d'un seul jeton -> (champ, "")."""
    from netcross_core.tshark_stats.conversations import _split_endpoints

    assert _split_endpoints("10.0.0.1") == ("10.0.0.1", "")


def test_parse_http_et_dns_sans_metrique_renvoient_liste_vide():
    """http.py 55-56 et dns.py 49-50 : aucune ligne etiquetee -> []."""
    from netcross_core.tshark_stats.dns import parse_dns_stat
    from netcross_core.tshark_stats.http import parse_http_stat

    assert parse_http_stat("=====\nrien d'exploitable\n") == []
    assert parse_dns_stat("=====\nrien d'exploitable\n") == []


def test_run_tshark_stat_code_non_nul(monkeypatch):
    """Lignes 60-64 : code non nul sans sortie -> CalledProcessError ;
    code non nul avec sortie -> sortie conservee."""
    from netcross_core.tshark_stats import runner

    sorties = iter(["", "tableau partiel\n"])

    def _faux_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 2, next(sorties), "erreur")

    monkeypatch.setattr(runner.subprocess, "run", _faux_run)
    with pytest.raises(subprocess.CalledProcessError):
        runner.run_tshark_stat("x.pcap", "io,stat,1")
    assert runner.run_tshark_stat("x.pcap", "io,stat,1") == "tableau partiel\n"
# -- Issue #718 : mediane et valeurs illisibles du temps de reponse -----------


def test_parse_response_time_mediane_et_valeur_illisible():
    """Ligne 55 : une valeur non convertible est ignoree ; ligne 66 : la
    mediane est reconnue."""
    from netcross_core.tshark_stats.response_time import parse_response_time

    texte = "Count       ...\nMedian      12.5\nMax         40\n"
    stat = parse_response_time(texte)
    assert stat is not None
    assert stat.median_ms == 12.5
    assert stat.count is None
