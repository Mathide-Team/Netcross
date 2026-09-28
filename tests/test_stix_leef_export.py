"""
Exports LEEF 2.0 et STIX 2.1 (issue #279).
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

import pytest

import netcross_report.siem_export as siem
from netcross_core.models import Report
from netcross_report.stix_export import (
    STIX_SCO_NAMESPACE,
    exploit_pattern,
    export_stix,
    format_timestamp,
    identity_object,
    to_stix_bundle,
    write_stix,
)

T0 = dt.datetime(2026, 3, 4, 10, 0, 0, tzinfo=dt.UTC)
T1 = dt.datetime(2026, 3, 4, 11, 30, 0, 250000, tzinfo=dt.UTC)


def _report() -> Report:
    r = Report(points=["LAN"])
    r.service_fingerprints = [
        {"service": "OpenSSH", "version": "7.4", "host": "10.0.0.5", "port": 22, "point": "LAN", "protocol": "ssh"},
        {"service": "nginx", "version": None, "host": "2001:db8::1", "port": 443, "point": "LAN"},
    ]
    r.security_findings = [
        {
            "severity": "elevee",
            "category": "cve",
            "cve_id": "CVE-2018-15473",
            "cvss": 5.3,
            "detail": "OpenSSH user enumeration",
            "service": "OpenSSH",
            "version": "7.4",
            "host": "10.0.0.5",
            "port": 22,
            "point": "LAN",
        },
        {
            "severity": "elevee",
            "category": "exploit",
            "detail": "Log4Shell (LOG4SHELL) depuis 203.0.113.9 -- CVE-2021-44228",
            "host": "10.0.0.5",
            "port": 8080,
            "point": "LAN",
            "src": "203.0.113.9",
            "signature_id": "LOG4SHELL",
            "cves": ["CVE-2021-44228"],
        },
        {
            "severity": "moyenne",
            "category": "anomalie",
            "detail": "certificat auto-signe",
            "host": "10.0.0.5",
            "port": 443,
            "point": "LAN",
        },
        {"severity": "moyenne", "category": "anomalie", "detail": "tunneling DNS vers x.example", "point": "LAN"},
    ]
    return r


def _by_type(bundle: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for obj in bundle["objects"]:
        out.setdefault(obj["type"], []).append(obj)
    return out


# -- STIX : criteres d'acceptation ---------------------------------------------


def test_stix_identique_octet_pour_octet():
    a = export_stix(_report(), observed_from=T0, observed_until=T1)
    b = export_stix(_report(), observed_from=T0, observed_until=T1)
    assert a == b
    # l'ordre des constats ne change pas le bundle
    r = _report()
    r.security_findings.reverse()
    r.service_fingerprints.reverse()
    assert export_stix(r, observed_from=T0, observed_until=T1) == a


def test_stix_aucun_indicator_pour_une_observation():
    r = _report()
    r.security_findings = [f for f in r.security_findings if f["category"] != "exploit"]
    types = _by_type(to_stix_bundle(r, observed_from=T0, observed_until=T1))
    assert "indicator" not in types
    assert types["observed-data"] and types["note"] and types["vulnerability"]


def test_stix_repartition():
    bundle = to_stix_bundle(_report(), observed_from=T0, observed_until=T1)
    types = _by_type(bundle)
    ids = {o["id"] for o in bundle["objects"]}
    (indicator,) = types["indicator"]
    assert indicator["pattern"] == (
        "[network-traffic:src_ref.value = '203.0.113.9' AND network-traffic:dst_ref.value = '10.0.0.5' "
        "AND network-traffic:dst_port = 8080]"
    )
    assert indicator["indicator_types"] == ["malicious-activity"]
    assert indicator["confidence"] == 70
    assert indicator["external_references"] == [{"source_name": "cve", "external_id": "CVE-2021-44228"}]
    (vuln,) = types["vulnerability"]
    assert vuln["name"] == "CVE-2018-15473" and vuln["x_netcross_cvss"] == 5.3
    (rel,) = types["relationship"]
    assert rel["relationship_type"] == "has" and rel["target_ref"] == vuln["id"]
    software = {o["id"]: o for o in types["software"]}
    assert software[rel["source_ref"]] == {
        "type": "software",
        "spec_version": "2.1",
        "id": rel["source_ref"],
        "name": "OpenSSH",
        "version": "7.4",
    }
    assert {o["value"] for o in types["ipv4-addr"]} == {"10.0.0.5"}
    assert types["ipv6-addr"][0]["value"] == "2001:db8::1"
    ssh = next(t for t in types["network-traffic"] if t.get("dst_port") == 22)
    assert ssh["protocols"] == ["tcp", "ssh"]
    nginx = next(t for t in types["network-traffic"] if t.get("dst_port") == 443 and "ipv6" in t["protocols"])
    assert nginx["dst_ref"].startswith("ipv6-addr--")
    # chaque objet porte created_by_ref -> identite Netcross, et toute reference se resout
    identity = identity_object()
    for obj in bundle["objects"]:
        if obj["type"] in {"observed-data", "vulnerability", "indicator", "note", "relationship", "report"}:
            assert obj["created_by_ref"] == identity["id"]
            assert obj["created"] == "2026-03-04T10:00:00.000Z"
        for key, value in obj.items():
            refs = value if key.endswith("_refs") else [value] if key.endswith("_ref") else []
            assert set(refs) <= ids, (obj["type"], key)
    # la note sans hote est rattachee au report
    (rep,) = types["report"]
    orphan = next(n for n in types["note"] if "tunneling" in n["content"])
    assert orphan["object_refs"] == [rep["id"]]
    assert rep["published"] == "2026-03-04T11:30:00.250Z"


def test_stix_id_sco_conforme_a_la_specification():
    """Identifiant deterministe STIX 2.1 §2.9 : UUIDv5, espace de noms
    00abedb4-..., proprietes contributives canoniques."""
    import uuid

    bundle = to_stix_bundle(_report(), observed_from=T0)
    ip = next(o for o in bundle["objects"] if o["type"] == "ipv4-addr")
    expected = uuid.uuid5(STIX_SCO_NAMESPACE, '{"value":"10.0.0.5"}')
    assert ip["id"] == f"ipv4-addr--{expected}"


def test_stix_rapport_vide_et_sans_date():
    bundle = to_stix_bundle(Report())
    assert [o["type"] for o in bundle["objects"]] == ["identity"]
    assert to_stix_bundle(Report()) == bundle


def test_stix_constats_non_representables_comptes():
    r = Report()
    r.security_findings = [
        {"severity": "elevee", "category": "exploit", "detail": "x", "host": "pas-une-ip"},
        {"severity": "elevee", "category": "cve", "detail": "sans id"},
    ]
    r.service_fingerprints = [{"version": "1"}]
    (rep,) = _by_type(to_stix_bundle(r))["report"]
    assert rep["x_netcross_skipped"] == {"cve sans identifiant": 1, "exploit sans adresse": 1, "service sans nom": 1}


def test_exploit_pattern_echappement():
    assert exploit_pattern({"host": "10.0.0.1"}) == "[network-traffic:dst_ref.value = '10.0.0.1']"
    assert exploit_pattern({"host": "x'y"}) is None
    assert exploit_pattern({"src": "::1", "port": 70000}) == "[network-traffic:src_ref.value = '::1']"


def test_format_timestamp():
    assert format_timestamp(dt.datetime(2026, 1, 1, 12, 0, 0, 123456)) == "2026-01-01T12:00:00.123Z"
    paris = dt.timezone(dt.timedelta(hours=2))
    assert format_timestamp(dt.datetime(2026, 6, 1, 14, 0, tzinfo=paris)) == "2026-06-01T12:00:00.000Z"


def test_stix_valide_contre_le_schema_oasis(tmp_path):
    validator = pytest.importorskip("stix2validator")
    path = write_stix(_report(), tmp_path / "b.json", observed_from=T0, observed_until=T1)
    results = validator.validate_file(path, validator.ValidationOptions(version="2.1"))
    errors = [str(e) for obj in results.object_results for e in obj.errors]
    assert results.is_valid, errors
    # avertissements (« SHOULD ») assumes et documentes dans docs/siem-export.md :
    # 103 UUIDv5 deterministes au lieu de v4, 202 software -has-> vulnerability,
    # 301 network-traffic sans port source, 401 proprietes x_netcross_*
    codes = {str(w).split("{", 1)[1][:3] for obj in results.object_results for w in obj.warnings}
    assert codes <= {"103", "202", "301", "401"}, codes


# -- LEEF ------------------------------------------------------------------------


class _Frozen:
    @staticmethod
    def now():
        return dt.datetime(2026, 1, 2, 3, 4, 5, 678000, tzinfo=dt.UTC)

    @staticmethod
    def fromtimestamp(ts, tz=None):
        return dt.datetime.fromtimestamp(ts, tz=tz)


@pytest.fixture
def frozen(monkeypatch):
    import types

    monkeypatch.setattr(siem, "_dt", types.SimpleNamespace(datetime=_Frozen, UTC=dt.UTC))


def test_leef_format(frozen):
    lines = siem.export_leef(_report())
    assert len(lines) == 4
    header, body = lines[1].split("|x09|", 1)
    assert header == "LEEF:2.0|Netcross|Netcross|1.0|100"
    attrs = dict(kv.split("=", 1) for kv in body.split("\t"))
    assert attrs["cat"] == "exploit" and attrs["sev"] == "8"
    assert attrs["src"] == "203.0.113.9" and attrs["dst"] == "10.0.0.5" and attrs["dstPort"] == "8080"
    assert attrs["devTime"] == "Jan 02 2026 03:04:05.678 UTC"
    assert attrs["devTimeFormat"] == "MMM dd yyyy HH:mm:ss.SSS z"
    assert attrs["point"] == "LAN"
    assert siem.export_leef(_report())[0].count("cveId=CVE-2018-15473") == 1


def test_leef_echappement(frozen):
    r = Report()
    r.security_findings = [
        {"severity": "faible", "category": "a|b", "detail": "k=v\tsuite\nligne \\ fin", "point": "P|1"}
    ]
    (line,) = siem.export_leef(r)
    assert "\n" not in line
    body = line.split("|x09|", 1)[1]
    fields = body.split("\t")
    assert fields[0] == "cat=a|b"
    assert fields[-1] == "msg=k\\=v\\tsuite\\nligne \\\\ fin"
    assert "point=P|1" in fields
    assert siem._escape_leef_header("A|B\\C") == "A\\|B\\\\C"


def test_leef_et_cef_partagent_les_enregistrements(frozen):
    records = siem._to_siem_records(_report())
    assert [r.sig_id for r in records] == [300, 100, 200, 200]
    assert len(siem.to_cef(records)) == len(siem.to_leef(records)) == 4


def test_write_siem(tmp_path, frozen):
    r = _report()
    for fmt in siem.SIEM_FORMATS:
        path = siem.write_siem(r, tmp_path / f"out.{fmt}", fmt, observed_from=T0)
        content = Path(path).read_text(encoding="utf-8")
        assert content.startswith({"cef": "CEF:0|", "leef": "LEEF:2.0|", "stix": "{"}[fmt])
    json.loads((tmp_path / "out.stix").read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="format SIEM inconnu"):
        siem.write_siem(r, tmp_path / "x", "syslog")


# -- CLI -------------------------------------------------------------------------


def _analyzer(monkeypatch, *argv):
    import cross_capture_analyzer_cli as cli

    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *map(str, argv)])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def test_cli_siem_export_sans_sortie(monkeypatch, capsys):
    assert _analyzer(monkeypatch, "--capture", "A=x.pcap", "--security-report", "--siem-export", "stix") == 1
    assert "vont ensemble" in capsys.readouterr().err


def test_cli_siem_export_sans_security_report(tmp_path, monkeypatch, capsys):
    code = _analyzer(monkeypatch, "--capture", "A=x.pcap", "--siem-export", "leef", "--siem-output", tmp_path / "o")
    assert code == 1
    assert "--siem-export necessite --security-report" in capsys.readouterr().err


def test_cli_siem_export_format_inconnu(tmp_path, monkeypatch):
    assert _analyzer(monkeypatch, "--siem-export", "syslog", "--siem-output", tmp_path / "o") == 2


# -- Issue #713 : gardes du constructeur de bundle STIX -----------------------


def test_builder_ip_invalide_et_traffic_avec_source():
    """Lignes 183-186 et 204 : une IP invalide est ignoree ; un trafic
    avec source porte src_ref."""
    from netcross_report.stix_export import _Builder

    b = _Builder("2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z")
    assert b.ip("pas-une-ip") is None
    dst = b.ip("10.0.0.2")
    src = b.ip("10.0.0.1")
    ref = b.traffic(dst_ref=dst, dst_port=443, src_ref=src, protocol="tcp")
    assert ref is not None
    assert b.objects[ref]["src_ref"] == src


def test_cve_sans_service_et_anomalie_avec_source():
    """Lignes 269-270 et 341 : CVE sans service -> pas de software ;
    anomalie avec IP source -> la source est referencee."""
    from netcross_report.stix_export import _add_anomaly, _add_cve, _Builder

    b = _Builder("2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z")
    _add_cve(b, {"cve_id": "CVE-2024-0001"})
    assert any(o["type"] == "vulnerability" for o in b.objects.values())
    assert not any(o["type"] == "software" for o in b.objects.values())

    orphans = []
    _add_anomaly(b, {"host": "10.0.0.2", "src": "10.0.0.9", "category": "scan"}, orphans)
    assert orphans == []
    assert any(o.get("value") == "10.0.0.9" for o in b.objects.values())
