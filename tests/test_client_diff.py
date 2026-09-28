"""
netcross_core.client_diff -- comparaison "client vs client". On
construit des Pkt synthetiques (make_pkt) avec des src/dst distincts par
client puis on verifie le regroupement, la construction d'un Report par
client et la diff N-way contre une reference -- sans rejouer tshark ni
scapy (meme discipline que test_analysis.py/test_baseline_diff.py).
"""

import csv

import pytest
from conftest import make_pkt

from netcross_core.client_diff import (
    ClientComparisonResult,
    compare_clients,
    group_packets_by_client,
    print_client_comparison,
    write_client_diff_csv,
)


def _client_group():
    return {"PosteA": {"10.0.0.5"}, "PosteB": {"10.0.0.12"}}


def test_group_packets_by_client_matches_src():
    pkts = [
        make_pkt(point="A", src="10.0.0.5", dst="10.0.0.1"),
        make_pkt(point="A", src="10.0.0.12", dst="10.0.0.1"),
    ]
    by_client = group_packets_by_client(pkts, _client_group())
    assert len(by_client["PosteA"]) == 1
    assert len(by_client["PosteB"]) == 1


def test_group_packets_by_client_matches_dst_too():
    # une reponse serveur *vers* le poste doit aussi compter pour lui,
    # pas seulement ce qu'il emet
    pkt = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.5")
    by_client = group_packets_by_client([pkt], _client_group())
    assert by_client["PosteA"] == [pkt]
    assert by_client["PosteB"] == []


def test_group_packets_by_client_ignores_unmatched_ip():
    pkt = make_pkt(point="A", src="10.0.0.99", dst="10.0.0.1")
    by_client = group_packets_by_client([pkt], _client_group())
    assert by_client["PosteA"] == []
    assert by_client["PosteB"] == []


def test_group_packets_by_client_multi_ip_same_client():
    group = {"PosteB": {"10.0.0.12", "10.0.0.13"}, "PosteA": {"10.0.0.5"}}
    pkts = [
        make_pkt(point="A", src="10.0.0.12", dst="10.0.0.1"),
        make_pkt(point="A", src="10.0.0.13", dst="10.0.0.1"),
    ]
    by_client = group_packets_by_client(pkts, group)
    assert len(by_client["PosteB"]) == 2


def test_compare_clients_requires_at_least_two_clients():
    pkts = [make_pkt(point="A", src="10.0.0.5")]
    with pytest.raises(ValueError, match="au moins 2 clients"):
        compare_clients(pkts, {"PosteA": {"10.0.0.5"}})


def test_compare_clients_unknown_reference_raises():
    pkts = [make_pkt(point="A", src="10.0.0.5")]
    with pytest.raises(ValueError, match="reference inconnu"):
        compare_clients(pkts, _client_group(), reference="Inconnu")


def test_compare_clients_default_reference_is_first_client_group():
    pkts = [
        make_pkt(point="A", src="10.0.0.5", dst="10.0.0.1", sport=1),
        make_pkt(point="A", src="10.0.0.12", dst="10.0.0.1", sport=2),
    ]
    result = compare_clients(pkts, _client_group(), points_order=["A", "B"])
    assert result.reference == "PosteA"
    assert set(result.clients) == {"PosteA", "PosteB"}
    assert set(result.diffs) == {"PosteB"}  # la reference n'est jamais diffee contre elle-meme


def test_compare_clients_result_contains_one_report_per_client():
    pkts = [
        make_pkt(point="A", src="10.0.0.5", dst="10.0.0.1", sport=1),
        make_pkt(point="A", src="10.0.0.12", dst="10.0.0.1", sport=2),
    ]
    result = compare_clients(pkts, _client_group(), points_order=["A", "B"])
    assert isinstance(result, ClientComparisonResult)
    assert result.clients["PosteA"].packet_count == 1
    assert result.clients["PosteB"].packet_count == 1
    assert result.clients["PosteA"].ips == ("10.0.0.5",)


def _posteb_ok():
    """Autre echange de PosteB vu aux deux points : le chemin de PosteB passe
    bien par B, l'absence du flux 200 y est donc une perte et non du trafic
    hors chemin (issue #352)."""
    return [make_pkt(point=p, src="10.0.0.12", dst="10.0.0.1", sport=3, key_id=300) for p in ("A", "B")]


def test_compare_clients_detects_regression_on_lossy_client():
    # PosteA (reference) : meme flux vu aux 2 points -> pas de perte
    ref_a = make_pkt(point="A", src="10.0.0.5", dst="10.0.0.1", sport=1, key_id=100)
    ref_b = make_pkt(point="B", src="10.0.0.5", dst="10.0.0.1", sport=1, key_id=100)
    # PosteB : flux vu seulement au point A -> perte detectee au point B
    other_a = make_pkt(point="A", src="10.0.0.12", dst="10.0.0.1", sport=2, key_id=200)

    result = compare_clients(
        [ref_a, ref_b, other_a, *_posteb_ok()],
        _client_group(),
        reference="PosteA",
        points_order=["A", "B"],
    )
    pertes = [f for f in result.diffs["PosteB"] if f.category == "Pertes"]
    assert pertes
    assert pertes[0].severity == "regression"
    assert pertes[0].segment == "B"


def test_no_diff_reported_when_clients_behave_identically():
    ref_a = make_pkt(point="A", src="10.0.0.5", dst="10.0.0.1", sport=1, key_id=100)
    ref_b = make_pkt(point="B", src="10.0.0.5", dst="10.0.0.1", sport=1, key_id=100)
    other_a = make_pkt(point="A", src="10.0.0.12", dst="10.0.0.1", sport=2, key_id=200)
    other_b = make_pkt(point="B", src="10.0.0.12", dst="10.0.0.1", sport=2, key_id=200)

    result = compare_clients(
        [ref_a, ref_b, other_a, other_b],
        _client_group(),
        reference="PosteA",
        points_order=["A", "B"],
    )
    pertes = [f for f in result.diffs["PosteB"] if f.category == "Pertes"]
    assert not pertes


def test_signature_aggregates_dhcp_vendor_class_and_sip_user_agent():
    pkt = make_pkt(
        point="A",
        src="10.0.0.12",
        dst="10.0.0.1",
        dhcp_vendor_class="MSFT 5.0",
        sip_user_agent="Old-SIP-Client/1.0",
    )
    result = compare_clients([pkt, make_pkt(point="A", src="10.0.0.5", dst="10.0.0.1")], _client_group())
    sig = result.clients["PosteB"].signature
    assert sig.dhcp_vendor_classes["MSFT 5.0"] == 1
    assert sig.sip_user_agents["Old-SIP-Client/1.0"] == 1


def test_print_client_comparison_outputs_reference_and_regression(capsys):
    ref_a = make_pkt(point="A", src="10.0.0.5", dst="10.0.0.1", sport=1, key_id=100)
    ref_b = make_pkt(point="B", src="10.0.0.5", dst="10.0.0.1", sport=1, key_id=100)
    other_a = make_pkt(point="A", src="10.0.0.12", dst="10.0.0.1", sport=2, key_id=200)

    result = compare_clients(
        [ref_a, ref_b, other_a, *_posteb_ok()],
        _client_group(),
        reference="PosteA",
        points_order=["A", "B"],
    )
    print_client_comparison(result)
    out = capsys.readouterr().out
    assert "COMPARAISON CLIENT VS CLIENT" in out
    assert "PosteA (reference)" in out
    assert "PosteB (vs PosteA)" in out
    assert "REGRESSION" in out


def test_print_client_comparison_no_gap_message(capsys):
    ref_a = make_pkt(point="A", src="10.0.0.5", dst="10.0.0.1", sport=1, key_id=100)
    ref_b = make_pkt(point="B", src="10.0.0.5", dst="10.0.0.1", sport=1, key_id=100)
    other_a = make_pkt(point="A", src="10.0.0.12", dst="10.0.0.1", sport=2, key_id=200)
    other_b = make_pkt(point="B", src="10.0.0.12", dst="10.0.0.1", sport=2, key_id=200)

    result = compare_clients(
        [ref_a, ref_b, other_a, other_b],
        _client_group(),
        reference="PosteA",
        points_order=["A", "B"],
    )
    print_client_comparison(result)
    out = capsys.readouterr().out
    assert "Aucun ecart significatif" in out


def test_write_client_diff_csv(tmp_path):
    ref_a = make_pkt(point="A", src="10.0.0.5", dst="10.0.0.1", sport=1, key_id=100)
    ref_b = make_pkt(point="B", src="10.0.0.5", dst="10.0.0.1", sport=1, key_id=100)
    other_a = make_pkt(point="A", src="10.0.0.12", dst="10.0.0.1", sport=2, key_id=200)

    result = compare_clients(
        [ref_a, ref_b, other_a, *_posteb_ok()],
        _client_group(),
        reference="PosteA",
        points_order=["A", "B"],
    )
    path = tmp_path / "client_diff.csv"
    write_client_diff_csv(result, str(path))

    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows
    assert all(row["client"] == "PosteB" for row in rows)
    assert all(row["reference"] == "PosteA" for row in rows)
    assert any(row["severite"] == "regression" for row in rows)


# -- Issue #734 : affichage console de la signature DHCP ----------------------


def test_print_signature_affiche_dhcp_vendor_class(capsys):
    """Lignes 243-244 : _print_signature affiche la vendor class DHCP."""
    from collections import Counter
    from types import SimpleNamespace

    from netcross_core.client_diff import _print_signature

    sig = SimpleNamespace(
        dhcp_vendor_classes=Counter({"MSFT 5.0": 3, "android-dhcp-13": 1}),
        sip_user_agents=Counter(),
    )
    _print_signature(sig)
    out = capsys.readouterr().out
    assert "DHCP vendor class" in out
    assert "MSFT 5.0 (3)" in out
