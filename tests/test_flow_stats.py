"""
Tests de netcross_core.security.flow_stats (issue #145, FLOW-4).
Analyse statistique des flux : SPLT, entropie, ratio up/down,
regularite temporelle, classification.
"""

from __future__ import annotations

import gzip
import random

from conftest import make_pkt

from netcross_core.security.flow_stats import (
    CLASSIFICATION_INTERACTIVE,
    CLASSIFICATION_NORMAL,
    CLASSIFICATION_OBFUSCATED,
    CLASSIFICATION_TRANSFER,
    FlowStatsThresholds,
    analyze_flow_stats,
)
from pcap_parser.packet import _byte_entropy

# -- Helpers -------------------------------------------------------------------

CLIENT = "192.168.1.10"
SERVER = "10.0.0.1"


def _make_flows(pkts_spec):
    """Construit des paquets a partir d'une liste de (src, dst, size, ts)."""
    return [make_pkt(src=src, dst=dst, length=size, ts=ts) for src, dst, size, ts in pkts_spec]


# -- Tests: SPLT ---------------------------------------------------------------


def test_splt_captures_first_packets():
    """SPLT contient les N premiers paquets avec (taille, delta_t)."""
    pkts = _make_flows(
        [
            (CLIENT, SERVER, 100, 0.0),
            (CLIENT, SERVER, 200, 1.0),
            (CLIENT, SERVER, 150, 2.5),
        ]
    )
    result = analyze_flow_stats(pkts)

    assert len(result.flows) == 1
    flow = result.flows[0]
    assert len(flow.splt) == 3
    assert flow.splt[0] == (100, 0.0)
    assert flow.splt[1] == (200, 1.0)
    assert flow.splt[2] == (150, 1.5)


def test_splt_capped_at_max():
    """SPLT est limite a splt_max_packets."""
    pkts = _make_flows([(CLIENT, SERVER, 100, float(i)) for i in range(30)])
    result = analyze_flow_stats(pkts, thresholds=FlowStatsThresholds(splt_max_packets=10))
    flow = result.flows[0]
    assert len(flow.splt) == 10


# -- Tests: classification interactif ------------------------------------------


def test_classification_interactive():
    """Petits paquets reguliers -> interactif."""
    pkts = _make_flows([(CLIENT, SERVER, 60, float(i)) for i in range(10)])
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert flow.classification == CLASSIFICATION_INTERACTIVE
    assert flow.median_size < 100


# -- Tests: classification transfert -------------------------------------------


def test_classification_transfer():
    """Gros paquets unidirectionnels -> transfert."""
    pkts = _make_flows([(CLIENT, SERVER, 1400, float(i)) for i in range(10)])
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert flow.classification == CLASSIFICATION_TRANSFER
    assert flow.median_size > 500
    assert flow.upload_ratio > 0.8


# -- Tests: classification obfusque --------------------------------------------


def _payload_pkts(payloads, src=CLIENT, dst=SERVER):
    """Paquets portant l'entropie/longueur de payload calculees comme au
    parsing (pcap_parser.packet._byte_entropy + len)."""
    return [
        make_pkt(
            src=src,
            dst=dst,
            length=len(p) + 54,
            ts=float(i),
            payload_entropy=_byte_entropy(p),
            payload_len=len(p),
        )
        for i, p in enumerate(payloads)
    ]


_HTTP_REQUEST = (
    b"GET /index.html?q=reseau HTTP/1.1\r\nHost: www.example.org\r\n"
    b"User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0\r\n"
    b"Accept: text/html,application/xhtml+xml\r\nAccept-Language: fr-FR,fr;q=0.9\r\n"
    b"Cookie: session=abc123def456\r\n\r\n"
)
_HTML = (
    b"<html><head><title>Accueil</title></head><body><h1>Bienvenue</h1>"
    b"<p>Le serveur de supervision du reseau est disponible. Consultez la "
    b"documentation pour la configuration des points de capture.</p></body></html>\n"
) * 10


def test_classification_obfuscated_encrypted_payload():
    """#351 : flux chiffre (octets uniformes) -> obfusque, meme a tailles
    constantes (entropie des tailles nulle : l'ancien critere le ratait)."""
    rng = random.Random(351)
    payloads = [bytes(rng.randrange(256) for _ in range(1400)) for _ in range(20)]
    flow = analyze_flow_stats(_payload_pkts(payloads)).flows[0]
    assert flow.entropy == 0.0
    assert flow.byte_entropy > 7.8
    assert flow.byte_entropy_ratio > 0.95
    assert flow.payload_bytes == 20 * 1400
    assert flow.classification == CLASSIFICATION_OBFUSCATED


def test_classification_obfuscated_small_encrypted_records():
    """Normalisation par log2(min(n, 256)) : des enregistrements chiffres
    de 160 octets (entropie brute ~6,6 bits) restent detectes."""
    rng = random.Random(7)
    payloads = [bytes(rng.randrange(256) for _ in range(160)) for _ in range(10)]
    flow = analyze_flow_stats(_payload_pkts(payloads)).flows[0]
    assert flow.byte_entropy < 7.5
    assert flow.classification == CLASSIFICATION_OBFUSCATED


def test_http_text_is_normal_despite_varied_sizes():
    """#351 : du HTTP texte aux tailles variees -> normal (l'entropie des
    tailles, > 3 bits ici, ne suffit plus a classer obfusque)."""
    payloads = [_HTTP_REQUEST] + [_HTML[: 150 + 45 * i] for i in range(14)]
    flow = analyze_flow_stats(_payload_pkts(payloads)).flows[0]
    assert flow.entropy > 3.5
    assert flow.byte_entropy_ratio < 0.8
    assert flow.classification == CLASSIFICATION_NORMAL


def test_single_compressed_packet_does_not_flip_text_flow():
    """Moyenne ponderee et non maximum : un paquet gzip isole dans un flux
    texte ne suffit pas a le classer obfusque."""
    payloads = [_HTML[:1400]] * 9 + [gzip.compress(_HTML * 5)[:300]]
    flow = analyze_flow_stats(_payload_pkts(payloads)).flows[0]
    assert flow.classification != CLASSIFICATION_OBFUSCATED


def test_tiny_payloads_are_ignored_for_byte_entropy():
    """En dessous de 128 octets par paquet, l'entropie n'est pas
    significative (texte et alea se confondent) : pas prise en compte."""
    rng = random.Random(1)
    payloads = [bytes(rng.randrange(256) for _ in range(40)) for _ in range(50)]
    flow = analyze_flow_stats(_payload_pkts(payloads)).flows[0]
    assert flow.payload_bytes == 0
    assert flow.byte_entropy == 0.0
    assert flow.classification != CLASSIFICATION_OBFUSCATED


def test_byte_entropy_fields_exported():
    rng = random.Random(3)
    payloads = [bytes(rng.randrange(256) for _ in range(500)) for _ in range(3)]
    d = analyze_flow_stats(_payload_pkts(payloads)).flows[0].to_dict()
    assert d["payload_bytes"] == 1500
    assert 0.9 < d["byte_entropy_ratio"] <= 1.0
    assert d["byte_entropy"] > 7.0


def test_custom_byte_entropy_threshold():
    payloads = [_HTML[:1400]] * 3
    strict = FlowStatsThresholds(high_byte_entropy_ratio=0.3)
    assert analyze_flow_stats(_payload_pkts(payloads), thresholds=strict).flows[0].classification == (
        CLASSIFICATION_OBFUSCATED
    )


# -- Tests: classification normal ----------------------------------------------


def test_classification_normal():
    """Trafic normal (HTTP classique) -> normal."""
    # Melange de petits et gros paquets, entropie moderee
    pkts = _make_flows(
        [
            (CLIENT, SERVER, 400, 0.0),
            (CLIENT, SERVER, 600, 1.0),
            (CLIENT, SERVER, 350, 2.0),
        ]
    )
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert flow.classification == CLASSIFICATION_NORMAL


# -- Tests: ratio up/down ------------------------------------------------------


def test_upload_download_ratio():
    """Ratio up/down calcule correctement."""
    pkts = _make_flows(
        [
            (CLIENT, SERVER, 1000, 0.0),
            (CLIENT, SERVER, 2000, 1.0),
            (SERVER, CLIENT, 500, 2.0),
        ]
    )
    result = analyze_flow_stats(pkts)
    client_to_server = next(f for f in result.flows if f.src == CLIENT and f.dst == SERVER)
    assert client_to_server.upload_bytes == 3000
    assert client_to_server.download_bytes == 500
    assert 0.8 < client_to_server.upload_ratio < 0.9


# -- Tests: regularite temporelle ---------------------------------------------


def test_regularity_cv_calculated():
    """Coefficient de variation des intervalles calcule."""
    # Intervalles reguliers (1.0s entre chaque)
    pkts = _make_flows([(CLIENT, SERVER, 100, float(i)) for i in range(10)])
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert len(flow.inter_arrivals) == 9
    assert flow.regularity_cv < 0.01  # tres regulier


def test_irregular_timing_high_cv():
    """Intervalles irreguliers -> CV eleve."""
    timestamps = [0.0, 0.1, 5.0, 0.2, 10.0, 0.3, 15.0, 0.4, 20.0]
    pkts = _make_flows([(CLIENT, SERVER, 100, ts) for ts in timestamps])
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert flow.regularity_cv > 1.0  # tres irregulier


# -- Tests: entropie -----------------------------------------------------------


def test_entropy_uniform_distribution():
    """Distribution uniforme -> entropie maximale."""
    sizes = [100, 200, 300, 400, 500, 600, 700, 800]
    pkts = _make_flows([(CLIENT, SERVER, sizes[i % len(sizes)], float(i)) for i in range(40)])
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert flow.entropy > 2.5  # 8 valeurs uniformes -> entropie = log2(8) = 3.0


def test_entropy_single_size():
    """Tous les paquets de meme taille -> entropie nulle."""
    pkts = _make_flows([(CLIENT, SERVER, 100, float(i)) for i in range(10)])
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert flow.entropy == 0.0


# -- Tests: plusieurs flux -----------------------------------------------------


def test_multiple_flows_separated():
    """Deux paires differentes -> deux flux separes."""
    pkts = _make_flows(
        [
            (CLIENT, SERVER, 100, 0.0),
            ("10.0.0.2", "10.0.0.3", 200, 1.0),
        ]
    )
    result = analyze_flow_stats(pkts)
    assert len(result.flows) == 2


# -- Tests: vide ---------------------------------------------------------------


def test_empty_input():
    """Aucun paquet -> aucun flux."""
    result = analyze_flow_stats([])
    assert result.flows == []


# -- Tests: serialisation ------------------------------------------------------


def test_flow_to_dict():
    """to_dict produit un dict structure."""
    pkts = _make_flows([(CLIENT, SERVER, 100, 0.0)])
    result = analyze_flow_stats(pkts)
    d = result.to_dict()

    assert "flows" in d
    assert len(d["flows"]) == 1
    assert d["flows"][0]["src"] == CLIENT
    assert d["flows"][0]["dst"] == SERVER


# -- Tests: seuils personnalisables -------------------------------------------


def test_custom_small_packet_threshold():
    """Seuil de petit paquet personnalise."""
    # Avec seuil a 50, des paquets de 60 ne sont plus "interactif"
    pkts = _make_flows([(CLIENT, SERVER, 60, float(i)) for i in range(10)])
    custom = FlowStatsThresholds(small_packet_threshold=50)
    result = analyze_flow_stats(pkts, thresholds=custom)
    flow = result.flows[0]
    # Median = 60 > 50, donc pas interactif, pas transfert, pas obfusque -> normal
    assert flow.classification == CLASSIFICATION_NORMAL


# -- Issue #742 : gardes des distributions vides ------------------------------


def test_entropie_distribution_vide_et_flux_sans_taille():
    """Lignes 167-168 : entropie d'un Counter vide = 0.0 ; lignes 177-181 :
    un flux sans distribution de tailles est classe normal."""
    from collections import Counter

    from netcross_core.security.flow_stats import (
        CLASSIFICATION_NORMAL,
        FlowStat,
        FlowStatsThresholds,
        _classify_flow,
        _shannon_entropy,
    )

    assert _shannon_entropy(Counter()) == 0.0
    flux = FlowStat(src="10.0.0.1", dst="10.0.0.2")
    assert _classify_flow(flux, FlowStatsThresholds()) == CLASSIFICATION_NORMAL
