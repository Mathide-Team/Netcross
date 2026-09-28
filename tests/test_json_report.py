"""
netcross_report.json_report -- verifie que le JSON produit est valide,
structurellement complet, et coherent avec le meme calcul de findings/
triage que pdf.py (memes fonctions reutilisees : build_findings,
rank_segments).
"""

import json

from conftest import make_pkt

from netcross_core.baseline_diff import DiffFinding, diff_reports
from netcross_core.compliance import evaluate_compliance
from netcross_core.correlate import build_conversations, build_flows, correlate
from netcross_core.models import ChecksumError, Report
from netcross_core.wireshark_expert import build_wireshark_expert_events
from netcross_report.expert_events import build_diagnoses, build_expert_events
from netcross_report.json_report import generate_json_diff, generate_json_report
from netcross_report.synthesis import Finding, build_findings
from netcross_report.triage import health_label, health_score, rank_segments


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def test_generate_json_report_structure_de_base(tmp_path):
    r = Report(points=["A", "B"], pairs=[("A", "B")])
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100  # 10% -> anomalie

    out = tmp_path / "report.json"
    result_path = generate_json_report(r, out)

    assert result_path == out
    doc = _read(out)
    assert doc["title"] == "Analyse croisee de captures reseau"
    assert doc["points"] == ["A", "B"]
    assert doc["pairs"] == [["A", "B"]]
    assert doc.get("generated_at")
    assert doc["meta"] == {}
    assert any(f["category"] == "Pertes" and f["severity"] == "anomalie" for f in doc["findings"])
    assert doc["triage"]  # au moins un segment classe
    assert "tls_findings" not in doc
    assert "quic_findings" not in doc


def test_generate_json_report_meta_reportee_telle_quelle(tmp_path):
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out, meta={"Ticket": "INC-1234", "Auteur": "Mathilde"})
    doc = _read(out)
    assert doc["meta"] == {"Ticket": "INC-1234", "Auteur": "Mathilde"}


def test_generate_json_report_findings_precalcules_pas_recalcules(tmp_path):
    r = Report(points=["A"])
    r.loss_count["A"] = 50
    r.seen_count["A"] = 100  # aurait declenche un finding "Pertes" si recalcule
    out = tmp_path / "report.json"
    generate_json_report(r, out, findings=[])
    doc = _read(out)
    assert doc["findings"] == []
    assert doc["triage"] == []


# -- preuves (evidence, Session 32) --


def test_json_report_expose_evidence_quand_presente(tmp_path):
    r = Report(points=["A", "B"], pairs=[("A", "B")])
    r.pmtud_blackhole[("A", "B")] = 1
    r.pmtud_blackhole_examples[("A", "B")] = ["seq=123 retransmis 4x"]
    out = tmp_path / "report.json"
    generate_json_report(r, out)
    doc = _read(out)
    pmtud = [f for f in doc["findings"] if f["category"] == "PMTUD"]
    assert pmtud[0]["evidence"] == [{"point": "A -> B", "text": "seq=123 retransmis 4x"}]


def test_json_report_evidence_pmtud_expose_le_numero_de_trame(tmp_path):
    """Session 35 : quand Report.pmtud_blackhole_frames est peuple, la
    ligne d'evidence JSON gagne une cle frame_number (PacketEvidence),
    absente dans le cas ci-dessus (pmtud_blackhole_frames non peuple)."""
    r = Report(points=["A", "B"], pairs=[("A", "B")])
    r.pmtud_blackhole[("A", "B")] = 1
    r.pmtud_blackhole_examples[("A", "B")] = ["seq=123 retransmis 4x"]
    r.pmtud_blackhole_frames[("A", "B")] = [42]
    out = tmp_path / "report.json"
    generate_json_report(r, out)
    doc = _read(out)
    pmtud = [f for f in doc["findings"] if f["category"] == "PMTUD"]
    assert pmtud[0]["evidence"] == [{"point": "A -> B", "text": "seq=123 retransmis 4x", "frame_number": 42}]


def test_json_report_evidence_arp_expose_aussi_le_numero_de_trame(tmp_path):
    """Session 37 : extension de PacketEvidence au-dela du pilote PMTUD --
    confirme ici que la serialisation JSON (generique, _evidence_list_dict)
    fonctionne sans aucune modification pour une autre categorie (ARP)."""
    r = Report(points=["A"])
    r.arp_ip_conflict["A"] = 1
    r.arp_ip_conflict_examples["A"] = ["10.0.0.9 revendiquee par 2 MAC"]
    r.arp_ip_conflict_frames["A"] = [7]
    out = tmp_path / "report.json"
    generate_json_report(r, out)
    doc = _read(out)
    arp = [f for f in doc["findings"] if f["category"] == "ARP"]
    assert arp[0]["evidence"] == [{"point": "A", "text": "10.0.0.9 revendiquee par 2 MAC", "frame_number": 7}]


def test_json_report_pas_de_cle_evidence_si_absente(tmp_path):
    r = Report(points=["A"])
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100
    out = tmp_path / "report.json"
    generate_json_report(r, out)
    doc = _read(out)
    pertes = [f for f in doc["findings"] if f["category"] == "Pertes"]
    assert "evidence" not in pertes[0]


def test_json_diff_finding_sans_evidence_pas_de_cle(tmp_path):
    """Un DiffFinding construit sans kwarg `evidence` (defaut : liste vide,
    voir baseline_diff.DiffFinding) ne doit pas exposer la cle -- meme
    lecture duck-type (getattr) que before/after/sample_size, voir
    json_report._finding_dict. Depuis la Session 33, DiffFinding PEUT
    porter une evidence (voir test_json_diff_expose_evidence_de_diff_
    reports ci-dessous pour le cas positif via le vrai diff_reports())."""
    df = DiffFinding("regression", "Pertes", "A", "pertes en hausse", before=1.0, after=10.0)
    out = tmp_path / "diff.json"
    generate_json_diff(
        [df],
        Report(points=["A"]),
        Report(points=["A"]),
        out,
    )
    doc = _read(out)
    assert "evidence" not in doc["findings"][0]


def test_json_diff_expose_evidence_de_diff_reports(tmp_path):
    """Depuis la Session 33, netcross_core.baseline_diff.diff_reports()
    peuple `DiffFinding.evidence` sur certaines categories (voir
    baseline_diff.py) -- confirme ici que generate_json_diff() l'expose
    sans aucune modification necessaire cote json_report.py (le meme
    mecanisme generique que pour Finding, Session 32)."""
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.pmtud_blackhole[("A", "B")] = 1
    current.pmtud_blackhole_examples[("A", "B")] = ["seq=42 retransmis 3x"]
    findings = diff_reports(baseline, current)
    out = tmp_path / "diff.json"
    generate_json_diff(findings, baseline, current, out)
    doc = _read(out)
    pmtud = [f for f in doc["findings"] if f["category"] == "PMTUD"]
    assert pmtud[0]["evidence"] == [{"point": "A -> B", "text": "seq=42 retransmis 3x"}]


# -- objets de contrat de la Session 0 (Session 36) --


def test_generate_json_report_sans_les_nouvelles_cles_par_defaut(tmp_path):
    """flows/conversations/expert_events/diagnoses/compliance/
    wireshark_expert_events sont optionnels -- absents si non fournis,
    meme convention que tls_findings/quic_findings."""
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out)
    doc = _read(out)
    for key in ("flows", "conversations", "expert_events", "diagnoses", "compliance", "wireshark_expert_events"):
        assert key not in doc


def test_generate_json_report_expose_flows_et_conversations(tmp_path):
    pkts = [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", sport=1, length=100)]
    flows = correlate(pkts)
    flow_objs = build_flows(flows)
    conversations = build_conversations(flow_objs)
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out, flows=flow_objs, conversations=conversations)
    doc = _read(out)
    assert doc["flows"][0]["endpoints"] == ["10.0.0.1", "10.0.0.2"]
    assert doc["flows"][0]["packet_count"] == {"A": 1}
    assert doc["conversations"][0]["endpoints"] == ["10.0.0.1", "10.0.0.2"]
    assert doc["conversations"][0]["packet_count"] == 1


def test_generate_json_report_expose_expert_events_et_diagnoses(tmp_path):
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    r.pmtud_blackhole_examples[("A", "B")] = ["seq=123 retransmis 4x"]
    findings = build_findings(r)
    events = build_expert_events(findings)
    diagnoses = build_diagnoses(events)
    out = tmp_path / "report.json"
    generate_json_report(r, out, findings=findings, expert_events=events, diagnoses=diagnoses)
    doc = _read(out)
    pmtud_event = next(ev for ev in doc["expert_events"] if ev["category"] == "PMTUD")
    assert pmtud_event["cause"] is None
    assert pmtud_event["impact"] is None
    assert pmtud_event["evidence"] == [{"point": "A -> B", "text": "seq=123 retransmis 4x"}]
    diag = next(d for d in doc["diagnoses"] if d["segment"] == "A -> B")
    assert any(ev["category"] == "PMTUD" for ev in diag["events"])


def test_generate_json_report_expose_compliance(tmp_path):
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    compliance = evaluate_compliance(r)
    out = tmp_path / "report.json"
    generate_json_report(r, out, compliance=compliance)
    doc = _read(out)
    pmtud_ref = next(c for c in doc["compliance"] if c["reference"]["id"] == "rfc6349-pmtud-no-blackhole")
    assert pmtud_ref["status"] == "VIOLATION"
    assert pmtud_ref["observed"] == 1.0


# -- wireshark_expert_events (Session 1, FEATURES.md section 13.3) --


def test_generate_json_report_expose_wireshark_expert_events(tmp_path):
    pkts = [make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",)) for _ in range(3)]
    wireshark_events = build_wireshark_expert_events(pkts)
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out, wireshark_expert_events=wireshark_events)
    doc = _read(out)
    ev = doc["wireshark_expert_events"][0]
    assert ev["category"] == "Wireshark/TShark"
    assert ev["source"] == "tshark"
    assert "3 occurrence(s)" in ev["message"]


def test_generate_json_report_wireshark_expert_events_expose_confidence_et_occurrences(tmp_path):
    # Session 40 : confidence/first_seen/last_seen, calcules uniquement
    # cote wireshark_expert_events (voir expert_model.ExpertEvent).
    pkts = [make_pkt(point="A", ts=t, expert_flags=("tcp_tcp_analysis_retransmission",)) for t in (1.0, 2.0)]
    wireshark_events = build_wireshark_expert_events(pkts)
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out, wireshark_expert_events=wireshark_events)
    doc = _read(out)
    ev = doc["wireshark_expert_events"][0]
    assert ev["confidence"] == 0.7  # flag connu de _KNOWN_FLAGS, pas de detail natif
    assert ev["first_seen"] == 1.0
    assert ev["last_seen"] == 2.0


def test_generate_json_report_expert_events_confidence_et_occurrences_toujours_none(tmp_path):
    # Cote "netcross" (Finding -> ExpertEvent), toujours None a ce jour.
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    findings = build_findings(r)
    events = build_expert_events(findings)
    out = tmp_path / "report.json"
    generate_json_report(r, out, findings=findings, expert_events=events)
    doc = _read(out)
    assert all(ev["confidence"] is None for ev in doc["expert_events"])
    assert all(ev["first_seen"] is None for ev in doc["expert_events"])


def test_generate_json_report_wireshark_expert_events_expose_layer_protocol(tmp_path):
    # Session 41 : layer/protocol, calcules uniquement cote
    # wireshark_expert_events (voir expert_model.ExpertEvent).
    pkts = [make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",))]
    wireshark_events = build_wireshark_expert_events(pkts)
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out, wireshark_expert_events=wireshark_events)
    doc = _read(out)
    ev = doc["wireshark_expert_events"][0]
    assert ev["layer"] == "transport"
    assert ev["protocol"] == "TCP"


def test_generate_json_report_expert_events_layer_protocol_toujours_none(tmp_path):
    # Cote "netcross" (Finding -> ExpertEvent), toujours None a ce jour.
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    findings = build_findings(r)
    events = build_expert_events(findings)
    out = tmp_path / "report.json"
    generate_json_report(r, out, findings=findings, expert_events=events)
    doc = _read(out)
    assert all(ev["layer"] is None for ev in doc["expert_events"])
    assert all(ev["protocol"] is None for ev in doc["expert_events"])


def test_generate_json_report_wireshark_expert_events_expose_flow_keys(tmp_path):
    # Session 43 : flow_keys, calcule uniquement cote wireshark_expert_events
    # (voir expert_model.ExpertEvent) -- tuple converti en liste pour rester
    # serialisable JSON, meme convention que Conversation.flow_keys.
    from netcross_core.correlate import flow_key

    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",))
    wireshark_events = build_wireshark_expert_events([pkt])
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out, wireshark_expert_events=wireshark_events)
    doc = _read(out)
    ev = doc["wireshark_expert_events"][0]
    assert ev["flow_keys"] == [list(flow_key(pkt))]


def test_generate_json_report_expert_events_flow_keys_toujours_vide(tmp_path):
    # Cote "netcross" (Finding -> ExpertEvent), toujours [] a ce jour.
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    findings = build_findings(r)
    events = build_expert_events(findings)
    out = tmp_path / "report.json"
    generate_json_report(r, out, findings=findings, expert_events=events)
    doc = _read(out)
    assert all(ev["flow_keys"] == [] for ev in doc["expert_events"])


def test_generate_json_report_wireshark_expert_events_expose_packet_evidence(tmp_path):
    # Session 44 : packet_evidence, calcule uniquement cote
    # wireshark_expert_events -- point/frame_number, meme format que la
    # cle frame_number optionnelle deja portee par evidence.
    pkt = make_pkt(point="A", frame_number=7, expert_flags=("tcp_tcp_analysis_retransmission",))
    wireshark_events = build_wireshark_expert_events([pkt])
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out, wireshark_expert_events=wireshark_events)
    doc = _read(out)
    ev = doc["wireshark_expert_events"][0]
    assert ev["packet_evidence"] == [{"point": "A", "frame_number": 7}]


def test_generate_json_report_expert_events_packet_evidence_toujours_vide(tmp_path):
    # Cote "netcross" (Finding -> ExpertEvent), toujours [] a ce jour.
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    findings = build_findings(r)
    events = build_expert_events(findings)
    out = tmp_path / "report.json"
    generate_json_report(r, out, findings=findings, expert_events=events)
    doc = _read(out)
    assert all(ev["packet_evidence"] == [] for ev in doc["expert_events"])


def test_generate_json_report_wireshark_expert_events_expose_remediation(tmp_path):
    # Session 45 : remediation, calcule uniquement cote
    # wireshark_expert_events -- texte redige lu depuis _REMEDIATION pour
    # un flag deja connu de _KNOWN_FLAGS.
    from netcross_core.wireshark_expert import _REMEDIATION

    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_zero_window",))
    wireshark_events = build_wireshark_expert_events([pkt])
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out, wireshark_expert_events=wireshark_events)
    doc = _read(out)
    ev = doc["wireshark_expert_events"][0]
    assert ev["remediation"] == _REMEDIATION["tcp_tcp_analysis_zero_window"]


def test_generate_json_report_wireshark_expert_events_remediation_none_si_flag_inconnu(tmp_path):
    # Un flag EK jamais repertorie n'a pas de remediation inventee.
    pkt = make_pkt(point="A", expert_flags=("tcp_un_flag_jamais_vu",))
    wireshark_events = build_wireshark_expert_events([pkt])
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out, wireshark_expert_events=wireshark_events)
    doc = _read(out)
    assert doc["wireshark_expert_events"][0]["remediation"] is None


def test_generate_json_report_expert_events_remediation_toujours_none(tmp_path):
    # Cote "netcross" (Finding -> ExpertEvent), toujours None a ce jour.
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    findings = build_findings(r)
    events = build_expert_events(findings)
    out = tmp_path / "report.json"
    generate_json_report(r, out, findings=findings, expert_events=events)
    doc = _read(out)
    assert all(ev["remediation"] is None for ev in doc["expert_events"])


def test_generate_json_report_expert_events_et_wireshark_expert_events_separes(tmp_path):
    # Distinction centrale de la Session 1 : jamais fondus dans une seule
    # liste, cle JSON distincte, source distincte.
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    findings = build_findings(r)
    events = build_expert_events(findings)
    pkts = [make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",))]
    wireshark_events = build_wireshark_expert_events(pkts)
    out = tmp_path / "report.json"
    generate_json_report(r, out, findings=findings, expert_events=events, wireshark_expert_events=wireshark_events)
    doc = _read(out)
    assert all(ev["source"] == "netcross" for ev in doc["expert_events"])
    assert all(ev["source"] == "tshark" for ev in doc["wireshark_expert_events"])


# -- parite generate_json_diff (Session 37, suite de la Session 36) --


def test_generate_json_diff_sans_les_nouvelles_cles_par_defaut(tmp_path):
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    out = tmp_path / "diff.json"
    generate_json_diff([], baseline, current, out)
    doc = _read(out)
    for key in ("flows", "conversations", "expert_events", "diagnoses", "compliance", "wireshark_expert_events"):
        assert key not in doc


def test_generate_json_diff_expose_flows_conversations_expert_events_diagnoses_compliance(tmp_path):
    pkts = [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", sport=1, length=100)]
    flows = correlate(pkts)
    flow_objs = build_flows(flows)
    conversations = build_conversations(flow_objs)

    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.pmtud_blackhole[("A", "B")] = 1
    current.pmtud_blackhole_examples[("A", "B")] = ["seq=42 retransmis 3x"]
    findings = diff_reports(baseline, current)
    expert_events = build_expert_events(findings)
    diagnoses = build_diagnoses(expert_events)
    compliance = evaluate_compliance(current)

    out = tmp_path / "diff.json"
    generate_json_diff(
        findings,
        baseline,
        current,
        out,
        flows=flow_objs,
        conversations=conversations,
        expert_events=expert_events,
        diagnoses=diagnoses,
        compliance=compliance,
    )
    doc = _read(out)
    assert doc["flows"][0]["endpoints"] == ["10.0.0.1", "10.0.0.2"]
    assert doc["conversations"][0]["endpoints"] == ["10.0.0.1", "10.0.0.2"]
    pmtud_event = next(ev for ev in doc["expert_events"] if ev["category"] == "PMTUD")
    assert pmtud_event["cause"] is None
    diag = next(d for d in doc["diagnoses"] if d["segment"] == "A -> B")
    assert any(ev["category"] == "PMTUD" for ev in diag["events"])
    pmtud_ref = next(c for c in doc["compliance"] if c["reference"]["id"] == "rfc6349-pmtud-no-blackhole")
    assert pmtud_ref["status"] == "VIOLATION"


def test_generate_json_diff_expose_wireshark_expert_events(tmp_path):
    # Meme convention que sur generate_json_report ci-dessus : toujours
    # cote COURANT uniquement (voir docstring generate_json_diff).
    pkts = [make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",)) for _ in range(2)]
    wireshark_events = build_wireshark_expert_events(pkts)
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    out = tmp_path / "diff.json"
    generate_json_diff([], baseline, current, out, wireshark_expert_events=wireshark_events)
    doc = _read(out)
    ev = doc["wireshark_expert_events"][0]
    assert ev["source"] == "tshark"
    assert "2 occurrence(s)" in ev["message"]


def test_generate_json_report_tls_quic_integres_au_triage_et_exposes(tmp_path):
    r = Report(points=["A", "B"])
    tls_findings = [Finding("anomalie", "TLS", "A -> B", "handshake qui echoue")]
    quic_findings = [Finding("info", "QUIC", "A", "vu a tous les points")]
    out = tmp_path / "report.json"
    generate_json_report(r, out, findings=[], tls_findings=tls_findings, quic_findings=quic_findings)
    doc = _read(out)
    assert doc["tls_findings"] == [
        {"severity": "anomalie", "category": "TLS", "segment": "A -> B", "message": "handshake qui echoue"}
    ]
    assert doc["quic_findings"] == [
        {"severity": "info", "category": "QUIC", "segment": "A", "message": "vu a tous les points"}
    ]
    # le triage doit avoir vu passer le finding TLS (severite ponderee > 0)
    segments = {s["segment"] for s in doc["triage"]}
    assert "A -> B" in segments


def test_generate_json_report_est_du_json_valide_meme_sans_findings(tmp_path):
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out)
    # ne leve pas, structure minimale correcte
    doc = _read(out)
    assert doc["points"] == ["A"]
    assert doc["findings"] == []
    assert doc["triage"] == []


def test_generate_json_diff_structure_de_base(tmp_path):
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    findings = [
        DiffFinding("regression", "Pertes", "A -> B", "pertes en hausse", before=1.0, after=6.0),
        DiffFinding("stable", "TCP", "A", "rien de nouveau"),
    ]
    out = tmp_path / "diff.json"
    generate_json_diff(findings, baseline, current, out)
    doc = _read(out)
    assert doc["title"] == "Comparaison avant / apres"
    assert doc["baseline_points"] == ["A", "B"]
    assert doc["current_points"] == ["A", "B"]
    regr = next(f for f in doc["findings"] if f["severity"] == "regression")
    assert regr["before"] == 1.0
    assert regr["after"] == 6.0
    stable = next(f for f in doc["findings"] if f["severity"] == "stable")
    assert "before" not in stable and "after" not in stable
    assert doc["triage"]  # la regression doit se classer


def test_generate_json_diff_tls_quic_baseline_et_courant_separes(tmp_path):
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    out = tmp_path / "diff.json"
    tls_baseline = [Finding("info", "TLS", "A", "ok en baseline")]
    tls_current = [Finding("anomalie", "TLS", "A", "casse en courant")]
    generate_json_diff(
        [],
        baseline,
        current,
        out,
        tls_findings_baseline=tls_baseline,
        tls_findings_current=tls_current,
    )
    doc = _read(out)
    assert doc["tls_findings_baseline"][0]["message"] == "ok en baseline"
    assert doc["tls_findings_current"][0]["message"] == "casse en courant"
    assert "quic_findings_baseline" not in doc
    assert "quic_findings_current" not in doc
    # pas fondus dans le triage/la table de constats principale (meme
    # decision de conception que generate_diff_pdf, voir claude.md Session 8)
    assert doc["findings"] == []
    assert doc["triage"] == []


# -- score de confiance (sample_size / low_confidence) --


def test_generate_json_report_finding_sample_size_expose_si_fourni(tmp_path):
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    findings = [Finding("anomalie", "Pertes", "A", "10 paquets manquants", sample_size=100)]
    generate_json_report(r, out, findings=findings)
    doc = _read(out)
    assert doc["findings"][0]["sample_size"] == 100


def test_generate_json_report_finding_sans_sample_size_absent_du_dict(tmp_path):
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    findings = [Finding("anomalie", "VLAN", "A", "changement de VLAN")]
    generate_json_report(r, out, findings=findings)
    doc = _read(out)
    assert "sample_size" not in doc["findings"][0]


# -- lien vers le catalogue de regles (rule_id, Session 48) --


def test_generate_json_report_finding_rule_id_expose_si_couvert(tmp_path):
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    findings = [Finding("a_surveiller", "TCP", "A", "3 paquets avec fenetre TCP=0", rule_id="tcp_zero_window")]
    generate_json_report(r, out, findings=findings)
    doc = _read(out)
    assert doc["findings"][0]["rule_id"] == "tcp_zero_window"


def test_generate_json_report_finding_sans_rule_id_absent_du_dict(tmp_path):
    # Meme convention que sample_size ci-dessus : cle absente plutot que
    # None explicite -- voir docstring de _finding_dict (json_report.py).
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    findings = [Finding("anomalie", "TLS", "A", "certificat hors validite")]
    generate_json_report(r, out, findings=findings)
    doc = _read(out)
    assert "rule_id" not in doc["findings"][0]


def test_generate_json_report_expert_events_rule_id_expose_cote_netcross(tmp_path):
    # Session 48 : seul champ recopie depuis un Finding "netcross" plutot
    # que calcule uniquement cote "tshark" -- voir docstring de module
    # d'expert_model.py (miroir exact de remediation).
    r = Report(points=["A"])
    r.zero_window["A"] = 3
    findings = build_findings(r)
    events = build_expert_events(findings)
    out = tmp_path / "report.json"
    generate_json_report(r, out, findings=findings, expert_events=events)
    doc = _read(out)
    ev = next(e for e in doc["expert_events"] if e["category"] == "TCP")
    assert ev["rule_id"] == "tcp_zero_window"


def test_generate_json_report_wireshark_expert_events_rule_id_toujours_none(tmp_path):
    # expert_rules.py catalogue des detecteurs Netcross, pas les signaux
    # bruts du dissecteur tshark -- voir docstring d'expert_model.py.
    pkts = [make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",))]
    wireshark_events = build_wireshark_expert_events(pkts)
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out, wireshark_expert_events=wireshark_events)
    doc = _read(out)
    assert doc["wireshark_expert_events"][0]["rule_id"] is None


def test_generate_json_report_triage_expose_low_confidence(tmp_path):
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    findings = [Finding("anomalie", "Pertes", "A", "1 paquet manquant sur peu d'echantillons", sample_size=1)]
    generate_json_report(r, out, findings=findings)
    doc = _read(out)
    assert doc["triage"][0]["low_confidence"] is True


def test_generate_json_diff_finding_sample_size_expose_si_fourni(tmp_path):
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    out = tmp_path / "diff.json"
    findings = [DiffFinding("regression", "Latence", "A", "latence en hausse", sample_size=2)]
    generate_json_diff(findings, baseline, current, out)
    doc = _read(out)
    assert doc["findings"][0]["sample_size"] == 2


# -- score de sante synthetique (0-100) --


def test_generate_json_report_expose_health_score_coherent_avec_le_triage(tmp_path):
    r = Report(points=["A", "B"])
    findings = [Finding("anomalie", "Pertes", "A", "10 paquets manquants")]
    out = tmp_path / "report.json"
    generate_json_report(r, out, findings=findings)
    doc = _read(out)
    expected = health_score(rank_segments(findings))
    assert doc["health_score"] == expected
    assert doc["health_label"] == health_label(expected)


def test_generate_json_report_health_score_100_sans_findings(tmp_path):
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out, findings=[])
    doc = _read(out)
    assert doc["health_score"] == 100
    assert doc["health_label"] == "bon"


def test_generate_json_diff_expose_health_score_coherent_avec_le_triage(tmp_path):
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    findings = [DiffFinding("regression", "Pertes", "A", "pertes en hausse")]
    out = tmp_path / "diff.json"
    generate_json_diff(findings, baseline, current, out)
    doc = _read(out)
    expected = health_score(rank_segments(findings))
    assert doc["health_score"] == expected
    assert doc["health_label"] == health_label(expected)


def test_generate_json_diff_health_score_100_sans_regression(tmp_path):
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    out = tmp_path / "diff.json"
    generate_json_diff([], baseline, current, out)
    doc = _read(out)
    assert doc["health_score"] == 100
    assert doc["health_label"] == "bon"


# -- rule_engine_findings (Session 70, job3) --------------------------------


def test_generate_json_report_avec_rule_engine_findings(tmp_path):
    """La cle 'rule_engine' contient les Finding produits par le moteur
    declaratif, regroupes par rule_id, en omettant les regles sans Finding."""
    from netcross_report import available_rule_ids, evaluate

    r = Report(points=["A", "B"])
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100  # 10% -> anomalie (>= 5%)

    rule_engine_findings = {}
    for rule_id in available_rule_ids():
        rule_engine_findings[rule_id] = evaluate(rule_id, r)

    out = tmp_path / "rule_engine.json"
    generate_json_report(r, out, rule_engine_findings=rule_engine_findings)
    doc = _read(out)

    assert "rule_engine" in doc
    re = doc["rule_engine"]
    # loss_per_segment doit etre present (10% > 5%)
    assert "loss_per_segment" in re
    assert len(re["loss_per_segment"]) == 1
    f = re["loss_per_segment"][0]
    assert f["severity"] == "anomalie"
    assert f["category"] == "Pertes"
    assert f["segment"] == "A"
    assert f["rule_id"] == "loss_per_segment"

    # Les regles sans Finding ne doivent pas apparaitre
    for rule_id, findings_list in rule_engine_findings.items():
        if not findings_list:
            assert rule_id not in re


def test_generate_json_report_sans_rule_engine_findings_pas_de_cle(tmp_path):
    """Sans rule_engine_findings, la cle 'rule_engine' est absente du JSON."""
    r = Report(points=["A"])
    out = tmp_path / "no_rule_engine.json"
    generate_json_report(r, out)
    doc = _read(out)
    assert "rule_engine" not in doc


def test_generate_json_report_rule_engine_findings_none_pas_de_cle(tmp_path):
    """rule_engine_findings=None -> cle absente (meme convention que les autres objets)."""
    r = Report(points=["A"])
    out = tmp_path / "none_rule_engine.json"
    generate_json_report(r, out, rule_engine_findings=None)
    doc = _read(out)
    assert "rule_engine" not in doc


def test_generate_json_report_rule_engine_findings_vide_dict_vide(tmp_path):
    """rule_engine_findings={} (aucune regle n'a declenche) -> cle 'rule_engine'
    presente mais dict vide."""
    r = Report(points=["A"])
    rule_engine_findings = {"loss_per_segment": [], "dns_nxdomain": []}
    out = tmp_path / "empty_rule_engine.json"
    generate_json_report(r, out, rule_engine_findings=rule_engine_findings)
    doc = _read(out)
    assert "rule_engine" in doc
    assert doc["rule_engine"] == {}


def test_generate_json_report_checksum_errors(tmp_path):
    # Job 43/issue #163 : toujours present (comme http_objects), liste
    # vide si aucune erreur -- pas conditionne a un parametre optionnel.
    r = Report(points=["A"])
    r.checksum_errors = [ChecksumError(point="A", frame_number=2, protocol="TCP", checksum="0x1111")]
    out = tmp_path / "report.json"
    generate_json_report(r, out)
    doc = _read(out)
    assert doc["checksum_errors"] == [{"point": "A", "frame_number": 2, "protocol": "TCP", "checksum": "0x1111"}]


def test_generate_json_report_checksum_errors_liste_vide_par_defaut(tmp_path):
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out)
    doc = _read(out)
    assert doc["checksum_errors"] == []
