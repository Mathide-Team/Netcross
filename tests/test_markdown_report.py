"""
netcross_report.markdown_report -- vérifie que le rapport Markdown produit
est structurellement correct et cohérent avec les autres formats (PDF,
JSON). Issue #761.
"""

from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.models import ChecksumError, Report
from netcross_report.markdown_report import build_markdown_report_document, generate_markdown_report
from netcross_report.synthesis import build_findings


def _report(**overrides):
    r = Report(points=["A", "B"], pairs=[("A", "B")])
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


def test_generate_markdown_report_ecrit_fichier(tmp_path):
    r = _report()
    out = tmp_path / "report.md"
    result = generate_markdown_report(r, out)
    assert result == out
    content = out.read_text(encoding="utf-8")
    assert "# Analyse croisée de captures réseau" in content
    assert "Score de santé" in content


def test_markdown_report_vide_ne_leve_pas():
    r = _report()
    md = build_markdown_report_document(r)
    assert isinstance(md, str)
    assert "Analyse croisée" in md
    assert "Métriques par point" in md


def test_markdown_report_scenario_realiste():
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, flags="S", seq=1),
        make_pkt(point="B", sport=1, ts=0.01, flags="S", seq=1),
        make_pkt(point="A", sport=2, ts=1.0),  # perdu en B
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    md = build_markdown_report_document(r)
    assert "Métriques par point" in md
    assert "| A |" in md
    assert "| B |" in md
    # au moins un finding (perte en B)
    assert "Constats" in md


def test_markdown_report_inclut_checksum_errors():
    r = _report(
        checksum_errors=[
            ChecksumError(point="A", frame_number=42, protocol="IP", checksum="0x1234"),
            ChecksumError(point="B", frame_number=7, protocol="TCP", checksum="0x5678"),
        ]
    )
    md = build_markdown_report_document(r)
    assert "Intégrité de capture" in md
    assert "0x1234" in md
    assert "0x5678" in md
    assert "IP" in md
    assert "TCP" in md
    assert "2 checksum(s)" in md


def test_markdown_report_sans_checksum_n_affiche_pas_section():
    r = _report(checksum_errors=[])
    md = build_markdown_report_document(r)
    assert "Intégrité de capture" not in md


def test_markdown_report_inclut_meta():
    r = _report()
    md = build_markdown_report_document(r, meta={"Ticket": "INC-1234", "Auteur": "Mathilde"})
    assert "INC-1234" in md
    assert "Mathilde" in md


def test_markdown_report_inclut_findings_fournis():
    r = _report()
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100  # 10% -> anomalie
    findings = build_findings(r)
    md = build_markdown_report_document(r, findings=findings)
    assert "Constats" in md
    assert "Pertes" in md or "anomalie" in md


def test_markdown_report_inclut_topology():
    r = _report()
    r.topology_edges = [
        ("A", "B", {"confidence": 0.9, "common_flows": 15, "votes": "4-1", "coverage": 0.85})
    ]
    md = build_markdown_report_document(r)
    assert "Topologie" in md
    assert "A -> B" in md
    assert "90%" in md


def test_markdown_report_format_titres_et_tableaux():
    """Issue #761 : le rapport doit avoir des titres (##) et des tableaux."""
    r = _report()
    md = build_markdown_report_document(r)
    # au moins un titre de niveau 1 et un de niveau 2
    assert md.startswith("# ")
    assert "## " in md
    # au moins un tableau (ligne avec |)
    assert "|" in md
