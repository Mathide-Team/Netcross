"""
netcross_core.security.dga + fast_flux -- tests (issue #152, SCENARIO-6).

Couvre :
- DGA : domaine a haute entropie detecte, domaine legitime non detecte
- Fast flux : rotation d'IPs via corrélation DNS+TCP, ratio NXDOMAIN
- Anti faux positifs : liste blanche, domaines ignores, seuils
"""

from __future__ import annotations

import shutil

import pytest

from netcross_core.security.dga import (
    DgaAlert,
    DgaResult,
    DgaThresholds,
    detect_dga,
)
from netcross_core.security.fast_flux import (
    FastFluxAlert,
    FastFluxResult,
    FastFluxThresholds,
    detect_fast_flux,
)
from tests.conftest import make_pkt

# --- DGA tests -------------------------------------------------------------


def test_dga_domaine_haute_entropie_detecte():
    """Un domaine DGA type (xkqjfwbvt.com) doit etre detecte."""
    pkts = [
        make_pkt(dns_qry_name="xkqjfwbvt.com", dns_is_response=False),
        make_pkt(dns_qry_name="xkqjfwbvt.com", dns_is_response=True, dns_rcode=0),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) >= 1
    assert result.alerts[0].domain == "xkqjfwbvt.com"
    assert result.alerts[0].score >= 0.6
    assert result.suspicious


def test_dga_domaine_legitime_non_detecte():
    """google.com ne doit pas etre detecte (liste blanche)."""
    pkts = [
        make_pkt(dns_qry_name="www.google.com", dns_is_response=False),
        make_pkt(dns_qry_name="www.google.com", dns_is_response=True, dns_rcode=0),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) == 0


def test_dga_cloudflare_non_detecte():
    """cloudflare.com ne doit pas etre detecte."""
    pkts = [
        make_pkt(dns_qry_name="cdn.cloudflare.com", dns_is_response=False),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) == 0


def test_dga_domaine_court_non_detecte():
    """Un sous-domaine court (abc.com) ne doit pas declencher d'alerte."""
    pkts = [
        make_pkt(dns_qry_name="abc.com", dns_is_response=False),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) == 0


def test_dga_domaine_normal_non_detecte():
    """Un domaine normal lisible ne doit pas etre detecte."""
    pkts = [
        make_pkt(dns_qry_name="my-blog.example.com", dns_is_response=False),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) == 0


def test_dga_nxdomain_eleve_aggrave_score():
    """Un ratio NXDOMAIN eleve doit augmenter le score DGA."""
    dga_domain = "qjwvn3k1n2.com"
    pkts = [
        make_pkt(dns_qry_name=dga_domain, dns_is_response=False, ts=0.0),
        make_pkt(dns_qry_name=dga_domain, dns_is_response=True, dns_rcode=3, ts=1.0),
        make_pkt(dns_qry_name=dga_domain, dns_is_response=False, ts=2.0),
        make_pkt(dns_qry_name=dga_domain, dns_is_response=True, dns_rcode=3, ts=3.0),
        make_pkt(dns_qry_name=dga_domain, dns_is_response=False, ts=4.0),
        make_pkt(dns_qry_name=dga_domain, dns_is_response=True, dns_rcode=3, ts=5.0),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) >= 1
    # Le ratio NXDOMAIN doit etre remonte dans l'alerte
    alert = result.alerts[0]
    assert alert.nxdomain_ratio >= 0.5


def test_dga_score_dans_intervalle_0_1():
    """Tous les scores doivent etre dans [0, 1]."""
    pkts = [
        make_pkt(dns_qry_name="xkqjfwbvt.com", dns_is_response=False),
    ]
    result = detect_dga(pkts)
    for alert in result.alerts:
        assert 0.0 <= alert.score <= 1.0


def test_dga_domain_scores_calcules():
    """domain_scores doit contenir tous les domaines evaluates."""
    pkts = [
        make_pkt(dns_qry_name="xkqjfwbvt.com", dns_is_response=False),
        make_pkt(dns_qry_name="my-blog.example.com", dns_is_response=False),
    ]
    result = detect_dga(pkts)
    domains = {d["domain"] for d in result.domain_scores}
    assert "xkqjfwbvt.com" in domains
    assert "example.com" in domains


def test_dga_thresholds_configurables():
    """Un seuil plus eleve doit reduire le nombre d'alertes."""
    pkts = [
        make_pkt(dns_qry_name="xkqjfwbvt.com", dns_is_response=False),
    ]
    # Seuil par defaut
    result_default = detect_dga(pkts)
    # Seuil tres eleve
    thresholds = DgaThresholds(score_threshold=0.99)
    result_high = detect_dga(pkts, thresholds)
    assert len(result_default.alerts) >= len(result_high.alerts)


def test_dga_ignored_domains():
    """in-addr.arpa et local doivent etre ignores."""
    pkts = [
        make_pkt(dns_qry_name="1.2.3.4.in-addr.arpa", dns_is_response=False),
        make_pkt(dns_qry_name="host.local", dns_is_response=False),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) == 0
    assert len(result.domain_scores) == 0


# --- Fast flux tests -------------------------------------------------------


def _make_dns_query(src: str, domain: str, ts: float) -> object:
    return make_pkt(src=src, dns_qry_name=domain, dns_is_response=False, ts=ts, proto="UDP", dport=53)


def _make_dns_response(src: str, domain: str, ts: float, rcode: int = 0) -> object:
    return make_pkt(src=src, dns_qry_name=domain, dns_is_response=True, dns_rcode=rcode, ts=ts, proto="UDP", sport=53)


def _make_tcp_conn(src: str, dst: str, ts: float) -> object:
    return make_pkt(src=src, dst=dst, ts=ts, proto="TCP", flags="S.......")


def _make_dns_answer(domain: str, ts: float, ips: list[str], point: str = "A") -> object:
    """Reponse DNS reussie annoncant ``ips`` (champ dns_answers, #344)."""
    return make_pkt(
        point=point,
        src="10.0.0.53",
        dst="192.168.1.100",
        dns_qry_name=domain,
        dns_is_response=True,
        dns_rcode=0,
        dns_answers=tuple(ips),
        ts=ts,
        proto="UDP",
        sport=53,
    )


def _rotation(domain: str, n_resp: int = 6, per_resp: int = 1, step: float = 30.0, point: str = "A") -> list:
    """n_resp reponses, chacune avec per_resp IPs nouvelles."""
    pkts = []
    k = 0
    for r in range(n_resp):
        ips = []
        for _ in range(per_resp):
            k += 1
            ips.append(f"203.0.113.{k}")
        pkts.append(_make_dns_answer(domain, r * step, ips, point=point))
    return pkts


def test_fast_flux_rotation_ip_detecte():
    """6 reponses annoncant 6 IPs differentes en 3 min -> fast flux."""
    domain = "suspicious.example.com"
    result = detect_fast_flux(_rotation(domain))
    alerts = [a for a in result.alerts if a.alert_type == "ip_rotation"]
    assert len(alerts) == 1
    assert alerts[0].domain == domain
    assert len(alerts[0].ips) == 6
    assert "6 reponses DNS" in alerts[0].reason


def test_fast_flux_12_reponses_de_4_ips_changeantes_detecte():
    """Critere de #344 : 12 reponses de 4 IPs qui changent -> alerte."""
    result = detect_fast_flux(_rotation("flux.example.net", n_resp=12, per_resp=4, step=20.0))
    alerts = [a for a in result.alerts if a.alert_type == "ip_rotation"]
    assert len(alerts) == 1
    assert alerts[0].score == 1.0


def test_fast_flux_client_qui_resout_puis_scanne_non_detecte():
    """Critere de #344 (faux positif de l'audit) : un poste resout un nom
    (1 IP) puis contacte 50 machines -> aucune alerte."""
    src = "192.168.1.100"
    domain = "intranet.example.com"
    pkts = [_make_dns_query(src, domain, 0.0), _make_dns_answer(domain, 0.1, ["10.1.1.1"])]
    pkts.extend(_make_tcp_conn(src, f"10.2.0.{i + 1}", 1.0 + i) for i in range(50))
    result = detect_fast_flux(pkts)
    assert [a for a in result.alerts if a.alert_type == "ip_rotation"] == []


def test_fast_flux_connexions_tcp_seules_ne_suffisent_plus():
    """L'ancien signal (requete + connexions TCP) ne declenche plus rien."""
    src = "192.168.1.100"
    domain = "suspicious.example.com"
    pkts = [_make_dns_query(src, domain, 0.0)]
    pkts.extend(_make_tcp_conn(src, f"203.0.113.{i + 1}", float(i + 1)) for i in range(6))
    assert detect_fast_flux(pkts).alerts == []


def test_fast_flux_une_seule_reponse_round_robin_non_detecte():
    """Une reponse unique a 8 enregistrements = round-robin, pas rotation."""
    ips = [f"198.51.100.{i}" for i in range(1, 9)]
    result = detect_fast_flux([_make_dns_answer("rr.example.com", 0.0, ips)])
    assert result.alerts == []


def test_fast_flux_peu_d_ips_non_detecte():
    """Deux reponses stables (2 IPs) -> sous le seuil de 5."""
    domain = "normal.example.com"
    pkts = [_make_dns_answer(domain, float(i), ["203.0.113.1", "203.0.113.2"]) for i in range(10)]
    result = detect_fast_flux(pkts)
    assert [a for a in result.alerts if a.alert_type == "ip_rotation"] == []


def test_fast_flux_hors_fenetre_non_detecte():
    """Reponses espacees de 100 s avec une fenetre de 60 s -> pas d'alerte."""
    thresholds = FastFluxThresholds(window_seconds=60.0)
    result = detect_fast_flux(_rotation("test.example.com", step=100.0), thresholds)
    assert [a for a in result.alerts if a.alert_type == "ip_rotation"] == []


def test_fast_flux_domaine_legitime_non_detecte():
    """google.com en liste blanche -> pas d'alerte."""
    result = detect_fast_flux(_rotation("www.google.com"))
    assert result.alerts == []


def test_fast_flux_une_alerte_par_point_ou_la_rotation_est_vue():
    """La rotation n'est rapportee qu'aux points qui voient les reponses."""
    pkts = _rotation("suspicious.example.com", point="LAN")
    pkts.append(_make_dns_answer("suspicious.example.com", 0.0, ["203.0.113.1"], point="WAN"))
    alerts = [a for a in detect_fast_flux(pkts).alerts if a.alert_type == "ip_rotation"]
    assert [a.point for a in alerts] == ["LAN"]


def test_fast_flux_nxdomain_eleve_detecte():
    """Un domaine avec 70%+ de NXDOMAIN -> alerte high_nxdomain."""
    domain = "dga-suspicious.example.com"
    src = "192.168.1.100"
    pkts = []
    for i in range(10):
        pkts.append(_make_dns_query(src, domain, float(i)))
        pkts.append(_make_dns_response(src, domain, float(i + 0.5), rcode=3))
    result = detect_fast_flux(pkts)
    nxdomain_alerts = [a for a in result.alerts if a.alert_type == "high_nxdomain"]
    assert len(nxdomain_alerts) >= 1
    assert nxdomain_alerts[0].nxdomain_ratio >= 0.7


def test_fast_flux_nxdomain_bas_non_detecte():
    """Un domaine avec peu de NXDOMAIN -> pas d'alerte high_nxdomain."""
    domain = "normal.example.com"
    src = "192.168.1.100"
    pkts = []
    for i in range(10):
        pkts.append(_make_dns_query(src, domain, float(i)))
        pkts.append(_make_dns_response(src, domain, float(i + 0.5), rcode=0))
    result = detect_fast_flux(pkts)
    nxdomain_alerts = [a for a in result.alerts if a.alert_type == "high_nxdomain"]
    assert len(nxdomain_alerts) == 0


def test_fast_flux_score_dans_intervalle_0_1():
    """Tous les scores doivent etre dans [0, 1]."""
    result = detect_fast_flux(_rotation("suspicious.example.com", n_resp=20))
    assert result.alerts
    for alert in result.alerts:
        assert 0.0 <= alert.score <= 1.0


def test_fast_flux_ignored_domains():
    """in-addr.arpa et local doivent etre ignores."""
    result = detect_fast_flux(_rotation("1.2.3.4.in-addr.arpa") + _rotation("host.local"))
    assert len(result.alerts) == 0


def test_fast_flux_thresholds_configurables():
    """Un min_ips plus eleve supprime l'alerte."""
    pkts = _rotation("test.example.com")
    assert detect_fast_flux(pkts).alerts
    assert detect_fast_flux(pkts, FastFluxThresholds(min_ips=10)).alerts == []


# --- Dataclass tests -------------------------------------------------------


def test_dga_alert_dataclass():
    alert = DgaAlert(
        domain="xkqjfwbvt.com",
        score=0.75,
        reason="entropie 3.5",
        points=("A",),
        entropy=3.5,
        consonant_ratio=0.7,
        rare_bigram_ratio=0.6,
        length=10,
        nxdomain_ratio=0.0,
    )
    assert alert.domain == "xkqjfwbvt.com"
    assert alert.score == 0.75


def test_fast_flux_alert_dataclass():
    alert = FastFluxAlert(
        domain="suspicious.example.com",
        alert_type="ip_rotation",
        score=0.8,
        reason="rotation d'IPs",
        points=("A",),
        ips=["1.2.3.4", "5.6.7.8"],
        nxdomain_ratio=0.0,
    )
    assert alert.domain == "suspicious.example.com"
    assert alert.alert_type == "ip_rotation"
    assert len(alert.ips) == 2


def test_dga_result_suspicious():
    result = DgaResult()
    assert result.suspicious is False
    result.alerts.append(DgaAlert(domain="test.com", score=0.7, reason="test", points=("A",)))
    assert result.suspicious is True


def test_fast_flux_result_suspicious():
    result = FastFluxResult()
    assert result.suspicious is False
    result.alerts.append(
        FastFluxAlert(domain="test.com", alert_type="ip_rotation", score=0.8, reason="test", points=("A",))
    )
    assert result.suspicious is True


# --- Bout en bout avec tshark (#344) ----------------------------------------


def _dns_response_frame(txn: int, name: str, ips: list[str]) -> bytes:
    import struct

    def csum(b: bytes) -> int:
        if len(b) % 2:
            b += b"\0"
        s = sum(struct.unpack(f"!{len(b) // 2}H", b))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def ip4(a: str) -> bytes:
        return bytes(int(x) for x in a.split("."))

    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    answers = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + ip4(a) for a in ips)
    dns = struct.pack("!HHHHHH", txn, 0x8180, 1, len(ips), 0, 0) + qname + struct.pack("!HH", 1, 1) + answers
    udp = struct.pack("!HHHH", 53, 40000, 8 + len(dns), 0) + dns
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), txn, 0, 64, 17, 0, ip4("10.0.0.53"), ip4("10.0.0.5"))
    iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
    return b"\x00\x11\x22\x33\x44\x55" * 2 + b"\x08\x00" + iph + udp


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent")
def test_fast_flux_bout_en_bout_capture_reelle(tmp_path):
    """Capture forgee lue par tshark : 6 reponses DNS a 2 IPs chacune, toutes
    differentes -> dns_answers renseigne et une alerte ip_rotation."""
    import struct

    from netcross_core.parsing import parse_capture

    frames = [
        _dns_response_frame(i + 1, "flux.example.net", [f"203.0.113.{2 * i + 1}", f"203.0.113.{2 * i + 2}"])
        for i in range(6)
    ]
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        data += struct.pack("<IIII", 1_700_000_000 + 30 * i, 0, len(f), len(f)) + f
    path = tmp_path / "flux.pcap"
    path.write_bytes(data)

    pkts = parse_capture("LAN", str(path))
    assert pkts[0].dns_answers == ("203.0.113.1", "203.0.113.2")
    alerts = [a for a in detect_fast_flux(pkts).alerts if a.alert_type == "ip_rotation"]
    assert len(alerts) == 1
    assert len(alerts[0].ips) == 12


# -- Issue #738 : gardes des heuristiques DGA ---------------------------------


def test_ratios_sans_lettres_valent_zero():
    """Lignes 269-270 et 280-281 : sans lettre, les ratios valent 0.0."""
    from netcross_core.security.dga import _consonant_ratio, _rare_bigram_ratio

    assert _consonant_ratio("1234-5678") == 0.0
    assert _rare_bigram_ratio("1") == 0.0


def test_detect_dga_nom_reduit_a_rien_ignore():
    """Ligne 380 : un nom DNS qui se reduit a une chaine vide ("..") est
    ignore sans erreur."""
    pkt = make_pkt(point="A", dns_qry_name="..")
    result = detect_dga([pkt])
    assert result.alerts == []
    assert result.domain_scores == []
