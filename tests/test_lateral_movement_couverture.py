"""
netcross_core.security.lateral_movement -- couverture des chemins limites
(issue #715, suite de #665).

`tests/test_lateral_movement.py` (issue #149) couvre les cinq détecteurs sur
leurs cas nominaux. Ce fichier ajoute ce qui restait non couvert : entrées
sans adresse IP, sans drapeaux TCP ou sans port de destination, cibles non
consécutives ou IPv6, tentatives étalées hors fenêtre, ports source non
éphémères, paquets à destination de l'extérieur.

Reste volontairement non couvert : `detect_new_connections`, ligne 384 et
branche 383->384 (garde `if not pairs`). Elle est inatteignable : `new_pairs`
est un `defaultdict(set)` dont une clé n'est créée que par le `.add()` qui la
suit immédiatement, donc chaque valeur parcourue est non vide. La justification
complète est dans la description de la PR.
"""

from __future__ import annotations

import pytest
from loguru import logger

from netcross_core.security import lateral_movement as lm
from netcross_core.security.lateral_movement import (
    LateralMovementThresholds,
    _is_internal,
    _is_syn_only,
    detect_brute_force,
    detect_host_scans,
    detect_lateral_movement,
    detect_unusual_protocols,
)
from tests.conftest import make_pkt


@pytest.fixture
def journal():
    """Messages loguru émis pendant le test, sous la forme (niveau, message)."""
    logger.enable("netcross_core")
    lignes: list[tuple[str, str]] = []
    sink = logger.add(lambda m: lignes.append((m.record["level"].name, m.record["message"])), level="TRACE")
    yield lignes
    logger.remove(sink)


def _vu(journal, niveau, fragment):
    return any(n == niveau and fragment in m for n, m in journal)


# --- _is_internal : entrée qui n'est pas une adresse IP ---------------------


@pytest.mark.parametrize("valeur", ["", "aa:bb:cc:dd:ee:ff", "pas-une-ip", "999.1.1.1", None])
def test_is_internal_valeur_non_ip_est_externe(valeur, journal):
    """Une adresse absente ou non IP (trame L2, adresse MAC) n'est jamais interne."""
    assert _is_internal(valeur) is False
    assert _vu(journal, "TRACE", "adresse non IP")
    assert _vu(journal, "DEBUG", "except ValueError -> retour False")


def test_trames_l2_sans_adresse_ip_ne_produisent_aucun_evenement():
    """Des trames dont src/dst sont des adresses MAC ne déclenchent aucun des
    cinq détecteurs, même avec une baseline non vide."""
    thresholds = LateralMovementThresholds(new_connection_baseline_pairs=frozenset({("10.0.0.1", "10.0.0.2")}))
    pkts = [
        make_pkt(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff", sport=50000, dport=445, flags="S.......")
        for _ in range(30)
    ]
    result = detect_lateral_movement(pkts, thresholds)
    assert result.events == []
    assert result.suspicious is False


# --- _is_syn_only : paquet sans drapeaux -------------------------------------


@pytest.mark.parametrize("flags", [None, ""])
def test_is_syn_only_sans_drapeaux_est_faux(flags, journal):
    """Pas de drapeaux (UDP, ICMP) : ce n'est pas un SYN."""
    assert _is_syn_only(flags) is False
    assert _vu(journal, "DEBUG", "si not flags -> retour False")


def test_scans_ignorent_les_paquets_sans_drapeaux_tcp():
    """15 hôtes x 20 ports en UDP (flags absents) : rien à signaler avec le
    filtre SYN par défaut ; sans ce filtre, les mêmes paquets sont bien un scan
    (témoin : le silence vient du filtre, pas de paquets trop pauvres)."""
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{host}", proto="UDP", dport=port + 1000, flags=None)
        for host in range(1, 16)
        for port in range(1, 21)
    ]
    assert detect_lateral_movement(pkts).events == []

    sans_filtre = detect_lateral_movement(pkts, LateralMovementThresholds(scan_syn_only=False))
    assert {e.event_type for e in sans_filtre.events} == {"port_scan", "host_scan"}


# --- detect_port_scans : paquet sans port de destination ---------------------


def test_balayage_icmp_est_un_host_scan_pas_un_port_scan():
    """Un paquet sans port de destination (ICMP) n'ajoute aucune cible au scan de
    ports, mais un balayage ping de 29 hôtes consécutifs reste un host_scan."""
    thresholds = LateralMovementThresholds(scan_syn_only=False)
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{host}", proto="ICMP", sport=None, dport=None, flags=None)
        for host in range(1, 30)
    ]
    result = detect_lateral_movement(pkts, thresholds)
    assert {e.event_type for e in result.events} == {"host_scan"}


# --- detect_host_scans -------------------------------------------------------


def test_host_scan_cible_non_ip_ecartee_en_amont(journal):
    """Avec le vrai _is_internal, une cible non IP est écartée avant le calcul
    des plages : la garde de detect_host_scans n'est jamais atteinte."""
    pkts = [make_pkt(src="192.168.1.100", dst=f"hote-{i}", dport=445, flags="S.......") for i in range(12)]
    assert detect_host_scans(pkts, LateralMovementThresholds()) == []
    assert not _vu(journal, "DEBUG", "cibles non IP ignorées")


def test_host_scan_cible_non_ip_garde_defensive(monkeypatch, journal):
    """Garde défensive de detect_host_scans (ip_address lève ValueError).

    Inatteignable avec le vrai _is_internal, qui valide déjà chaque cible avec
    ipaddress.ip_address : on le remplace par une doublure qui laisse tout
    passer, comme si les deux contrôles divergeaient un jour."""
    monkeypatch.setattr(lm, "_is_internal", lambda _ip: True)
    pkts = [make_pkt(src="192.168.1.100", dst=f"hote-{i}", dport=445, flags="S.......") for i in range(12)]
    assert detect_host_scans(pkts, LateralMovementThresholds()) == []
    assert _vu(journal, "DEBUG", "cibles non IP ignorées")


def test_host_scan_ignore_les_cibles_ipv6():
    """Le regroupement par /24 ne vaut que pour IPv4 : 12 cibles IPv6 (ULA) ne
    forment jamais une plage consécutive."""
    pkts = [
        make_pkt(src="fd00::100", dst=f"fd00::{i:x}", sport=50000, dport=445, flags="S.......") for i in range(1, 13)
    ]
    assert detect_host_scans(pkts, LateralMovementThresholds()) == []


def test_host_scan_non_detecte_cibles_non_consecutives():
    """12 hôtes du même /24 mais une adresse sur deux : jamais 5 consécutives."""
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{2 * i + 1}", sport=50000, dport=445, flags="S.......")
        for i in range(12)
    ]
    assert detect_host_scans(pkts, LateralMovementThresholds()) == []


def test_host_scan_retient_la_plus_longue_plage_avant_une_rupture():
    """.1 à .7 puis .20 à .22 : la plage de 7, close par la rupture, doit être
    conservée face à la dernière plage (3), sinon 3 < 5 et rien n'est détecté."""
    hotes = [*range(1, 8), *range(20, 23)]
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{h}", sport=50000, dport=445, flags="S.......") for h in hotes
    ]
    events = detect_host_scans(pkts, LateralMovementThresholds())
    assert len(events) == 1
    assert "10 hotes distincts, 7 consecutifs" in events[0].details
    assert events[0].score == 0.7


# --- detect_brute_force ------------------------------------------------------


def test_brute_force_non_detecte_tentatives_etalees_hors_fenetre():
    """20 sessions SSH vers 2 hôtes, une toutes les 100 s : la fenêtre de 300 s
    n'en contient jamais plus de 4 (seuil : 10)."""
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{(i % 2) + 1}", sport=50000 + i, dport=22, ts=100.0 * i)
        for i in range(20)
    ]
    assert detect_brute_force(pkts, LateralMovementThresholds()) == []


def test_brute_force_non_detecte_sessions_vers_un_seul_hote():
    """20 sessions distinctes (ports source distincts) vers UN seul hôte : le
    nombre de tentatives est atteint mais pas le nombre d'hôtes (seuil : 2)."""
    pkts = [make_pkt(src="192.168.1.100", dst="192.168.1.1", sport=50000 + i, dport=22, ts=float(i)) for i in range(20)]
    assert detect_brute_force(pkts, LateralMovementThresholds()) == []


# --- detect_unusual_protocols ------------------------------------------------


def test_unusual_protocol_ignore_les_adresses_externes():
    """SMB/RDP vers ou depuis une adresse publique n'est pas interne."""
    pkts = [
        make_pkt(src="192.168.1.100", dst="8.8.8.8", sport=50000, dport=445),
        make_pkt(src="8.8.8.8", dst="192.168.1.100", sport=50000, dport=3389),
    ]
    assert detect_unusual_protocols(pkts, LateralMovementThresholds()) == []


@pytest.mark.parametrize("sport", [None, 445, 1024])
def test_unusual_protocol_ignore_port_source_non_ephemere(sport):
    """Port source absent ou <= 1024 (borne incluse) : pas un poste utilisateur."""
    pkts = [make_pkt(src="192.168.1.100", dst="192.168.1.50", sport=sport, dport=445)]
    assert detect_unusual_protocols(pkts, LateralMovementThresholds()) == []


def test_unusual_protocol_port_source_1025_detecte():
    """Borne : 1025 est le premier port source retenu."""
    pkts = [make_pkt(src="192.168.1.100", dst="192.168.1.50", sport=1025, dport=445)]
    events = detect_unusual_protocols(pkts, LateralMovementThresholds())
    assert len(events) == 1
    assert events[0].event_type == "unusual_protocol"
    assert "SMB" in events[0].details
