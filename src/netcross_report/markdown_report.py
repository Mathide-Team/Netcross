"""
netcross_report.markdown_report -- generation d'un rapport au format Markdown
(issue #761).

Le rapport Markdown (`.md`) presente les memes constats, triage et score de
sante que le PDF et le JSON, dans un format lisible et aeré, exportable en
PDF via n'importe quel convertisseur Markdown vers PDF (pandoc, md-to-pdf,
etc.). Pur Python, aucune dependance externe -- contrairement a generate_pdf
qui necessite reportlab/matplotlib/networkx.

Meme convention d'absence que les autres generateurs : les sections
optionnelles (TLS, QUIC, securite, objets de session) sont absentes du
document si les objets correspondants n'ont pas ete fournis.
"""

from __future__ import annotations

from datetime import datetime, timezone

from netcross_core.logging_config import get_logger, summarize
from netcross_report.synthesis import Finding, build_findings
from netcross_report.triage import health_label, health_score, rank_segments

logger = get_logger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cell(value) -> str:
    """Texte sur une ligne, sans ``|`` nu : une barre verticale ou un saut de
    ligne dans une description (CVE, message d'expertise) casserait le
    tableau Markdown."""
    if value is None or value == "":
        return "—"
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _finding_row(f: Finding) -> str:
    """Ligne de tableau pour un Finding."""
    sample = f" ({f.sample_size} échantillons)" if f.sample_size else ""
    return f"| {f.severity} | {f.category} | {f.segment} | {f.message}{sample} |"


def _triage_row(seg) -> str:
    """Ligne de tableau pour un SegmentScore."""
    confidence = "faible" if seg.low_confidence else "normale"
    convergence = " ✓" if seg.convergent else ""
    return f"| {seg.segment} | {seg.score:.1f} | {confidence}{convergence} | {', '.join(seg.categories)} |"


def _metrics_table(r) -> str:
    """Tableau des métriques principales par point."""
    lines = [
        "| Point | Flux vus | Pertes | Retrans | RST | Fenêtre 0 | TTL instable |",
        "|-------|----------|--------|---------|-----|-----------|--------------|",
    ]
    for p in r.points:
        seen = r.seen_count.get(p, 0)
        loss = r.loss_count.get(p, 0)
        retrans = r.retrans.get(p, 0)
        rst = r.rst_count.get(p, 0)
        zero_w = r.zero_window.get(p, 0)
        ttl_unstable = r.ttl_unstable.get(p, 0)
        lines.append(f"| {p} | {seen} | {loss} | {retrans} | {rst} | {zero_w} | {ttl_unstable} |")
    return "\n".join(lines)


def _topology_section(r) -> str:
    """Section topologie déduite."""
    lines = ["## Topologie déduite\n"]
    if r.topology_edges:
        lines.append("| Source -> Destination | Confiance | Flux communs | Votes TTL | Couverture |")
        lines.append("|----------------------|-----------|--------------|-----------|------------|")
        for u, d, info in r.topology_edges:
            conf = info.get("confidence", 0) * 100
            flows = info.get("common_flows", 0)
            votes = info.get("votes", "")
            coverage = info.get("coverage", 1.0) * 100
            lines.append(f"| {u} -> {d} | {conf:.0f}% | {flows} | {votes} | {coverage:.0f}% |")
    else:
        lines.append("Aucune relation directionnelle fiable déduite.\n")
        if r.topology_isolated:
            lines.append("\n**Points isolés** (sans relation directionnelle claire) :\n")
            lines.extend(f"- {p}" for p in r.topology_isolated)
    if r.topology_ambiguous:
        lines.append("\n**Relations ambiguës** :\n")
        lines.extend(f"- {pair[0]} <-> {pair[1]}" for pair in r.topology_ambiguous)
    return "\n".join(lines)


def _checksum_section(r) -> str:
    """Section checksums IP/TCP/UDP invalides (issue #762)."""
    if not r.checksum_errors:
        return ""
    lines = ["## Intégrité de capture : checksums IP/TCP/UDP\n"]
    lines.append("| Point | Trame | Protocole | Checksum |")
    lines.append("|-------|-------|-----------|----------|")
    lines.extend(
        f"| {err.point} | {err.frame_number} | {err.protocol} | `{err.checksum}` |" for err in r.checksum_errors
    )
    lines.append(f"\n**Total : {len(r.checksum_errors)} checksum(s) invalide(s)**")
    return "\n".join(lines)


_SECURITY_ITEM_KINDS = (
    ("exploits", "Exploit"),
    ("cves", "CVE"),
    ("anomalies", "Anomalie"),
)


def _security_section(security_report) -> str:
    """Section rapport de sécurité (issue #218).

    Lit les clés réellement produites par ``security_report_to_dict()``
    (socle commun des sorties JSON/HTML/PDF) : tableau de bord, services,
    puis exploits, CVE et anomalies. Mêmes libellés que le rapport texte
    (``format_security_report``).
    """
    if security_report is None:
        return ""
    from netcross_report.security_report import security_report_to_dict

    sr = security_report_to_dict(security_report)
    d = sr["dashboard"]
    lines = ["## Rapport de sécurité\n", "### Tableau de bord\n"]
    lines.append(f"- Score de risque global : **{d['score']}/100** (niveau : **{d['level']}**)")
    lines.append(f"- Services détectés : **{d['services_total']}** (dont {d['services_vulnerable']} vulnérable(s))")
    lines.append(f"- Exploits détectés : **{d['exploits']}**")
    lines.append(
        f"- Anomalies : **{d['anomalies']}** ({d['anomalies_netcross']} Netcross, "
        f"{d['anomalies_expert_info']} Expert Info)"
    )
    lines.append(f"- CVE confirmées : **{d['cves']}**")
    lines.append("")

    if sr["services"]:
        lines.append("### Services détectés\n")
        lines.append("| Hôte | Port | Service | Version | Sévérité | CVE | Empreinte |")
        lines.append("|------|------|---------|---------|----------|-----|-----------|")
        for svc in sr["services"]:
            cves = ", ".join(svc["cve_ids"])
            fingerprint = svc["fingerprint_readable"] or svc["fingerprint"]
            lines.append(
                f"| {_cell(svc['host'])} | {_cell(svc['port'])} | {_cell(svc['service'])} | "
                f"{_cell(svc['version'])} | {_cell(svc['severity'])} | {_cell(cves)} | {_cell(fingerprint)} |"
            )
        lines.append("")

    items = [(label, item) for key, label in _SECURITY_ITEM_KINDS for item in sr[key]]
    if items:
        lines.append("### Constats de sécurité\n")
        lines.append("| Type | Sévérité | Hôte:Port | Point | Détail |")
        lines.append("|------|----------|-----------|-------|--------|")
        for label, item in items:
            target = f"{item['host'] or '—'}:{item['port'] if item['port'] is not None else '—'}"
            detail = f"{item['cve_id']} — {item['detail']}" if item["cve_id"] else item["detail"]
            lines.append(
                f"| {label} | {_cell(item['severity'])} | {_cell(target)} | {_cell(item['point'])} | {_cell(detail)} |"
            )

    return "\n".join(lines).rstrip("\n")


def _session_objects_section(session_objects, top_n=20) -> str:
    """Section objets enrichis (Session 0) : mêmes colonnes que le PDF
    (``netcross_report.pdf._expert_event_table`` / ``_diagnosis_table`` /
    ``_compliance_table``), lues sur les dataclasses de
    ``netcross_core.expert_model``."""
    if session_objects is None:
        return ""
    lines = ["## Expertise — objets enrichis\n"]

    events = session_objects.expert_events
    if events:
        lines.append("### Événements d'expertise\n")
        lines.append("| Gravité | Catégorie | Segment | Constat | Cause probable / impact | Source |")
        lines.append("|---------|-----------|---------|---------|-------------------------|--------|")
        for ev in events[:top_n]:
            cause = " -- ".join(x for x in (ev.cause, ev.impact) if x)
            lines.append(
                f"| {_cell(ev.severity)} | {_cell(ev.category)} | {_cell(ev.segment)} | "
                f"{_cell(ev.message)} | {_cell(cause)} | {_cell(ev.source)} |"
            )
        if len(events) > top_n:
            lines.append(f"\n*…et {len(events) - top_n} autre(s)*")

    if session_objects.diagnoses:
        lines.append("\n### Diagnostics par segment\n")
        lines.append("| Segment | Événements | Cause probable | Impact |")
        lines.append("|---------|------------|----------------|--------|")
        lines.extend(
            f"| {_cell(d.segment)} | {len(d.events)} | {_cell(d.cause)} | {_cell(d.impact)} |"
            for d in session_objects.diagnoses[:top_n]
        )

    if session_objects.compliance:
        lines.append("\n### Conformité\n")
        lines.append("| Statut | Référentiel | Mesure | Source |")
        lines.append("|--------|-------------|--------|--------|")
        for res in session_objects.compliance[:top_n]:
            ref = res.reference
            observed = "non mesuré" if res.observed is None else f"{res.observed:g} {ref.unit}".strip()
            mesure = f"{ref.metric} : {observed} (seuil {ref.operator} {ref.threshold:g} {ref.unit})".replace(" )", ")")
            lines.append(f"| {_cell(res.status)} | {_cell(ref.id)} | {_cell(mesure)} | {_cell(ref.source)} |")

    return "\n".join(lines)


def build_markdown_report_document(
    r,
    title="Analyse croisée de captures réseau",
    meta=None,
    findings=None,
    tls_findings=None,
    quic_findings=None,
    session_objects=None,
    security_report=None,
    rule_engine_findings=None,
    names=None,
) -> str:
    """
    Construit le document Markdown complet (sans l'écrire).

    r : objet Report (netcross_core.analyse). meta : dict optionnel de
    métadonnées libres (ex: {"Ticket": "INC-1234", "Auteur": "Mathilde"}).
    findings : liste de Finding déjà calculée (synthesis.build_findings(r))
    si l'appelant l'a déjà fait ; sinon calculée ici.
    tls_findings / quic_findings : listes optionnelles.
    session_objects : SessionObjects optionnel (issue #13).
    security_report : SecurityReport optionnel (issue #218).
    rule_engine_findings : dict optionnel {rule_id: [Finding, ...]}.
    names : dict optionnel {host: name} pour résolution de noms.
    """
    logger.debug(
        "build_markdown_report_document: r={} title={} meta={} findings={} tls_findings={} "
        "quic_findings={} session_objects={} security_report={} rule_engine_findings={} names={}",
        summarize(r, "r"),
        summarize(title, "title"),
        summarize(meta, "meta"),
        summarize(findings, "findings"),
        summarize(tls_findings, "tls_findings"),
        summarize(quic_findings, "quic_findings"),
        summarize(session_objects, "session_objects"),
        summarize(security_report, "security_report"),
        summarize(rule_engine_findings, "rule_engine_findings"),
        summarize(names, "names"),
    )
    if findings is None:
        findings = build_findings(r)
    ranked = rank_segments(list(findings) + list(tls_findings or []) + list(quic_findings or []))
    score = health_score(ranked)

    lines: list[str] = []

    # -- En-tête --
    lines.append(f"# {title}\n")
    lines.append(f"**Généré le** : {_now_iso()}")
    lines.append(f"**Points de capture** : {', '.join(r.points) if r.points else '—'}")
    lines.append(f"**Paires analysées** : {', '.join(f'{a} -> {b}' for a, b in r.pairs) if r.pairs else '—'}")
    if meta:
        lines.extend(f"**{k}** : {v}" for k, v in meta.items())
    lines.append("")

    # -- Score de santé --
    lines.append("## Score de santé\n")
    lines.append(f"- Score : **{score}/100**")
    lines.append(f"- État : **{health_label(score)}**")
    lines.append("")

    # -- Triage --
    if ranked:
        lines.append("## Triage — par où commencer\n")
        lines.append("| Segment | Score | Confiance | Catégories |")
        lines.append("|---------|-------|-----------|------------|")
        lines.extend(_triage_row(seg) for seg in ranked[:15])
        if len(ranked) > 15:
            lines.append(f"\n*…et {len(ranked) - 15} autre(s) segment(s)*")
        lines.append("")

    # -- Constats principaux --
    if findings:
        lines.append("## Constats\n")
        lines.append("| Sévérité | Catégorie | Segment | Message |")
        lines.append("|----------|-----------|---------|---------|")
        lines.extend(_finding_row(f) for f in findings)
        lines.append("")

    # -- Métriques par point --
    lines.append("## Métriques par point\n")
    lines.append(_metrics_table(r))
    lines.append("")

    # -- Pertes --
    loss_total = sum(r.loss_count.values()) if r.loss_count else 0
    if loss_total:
        lines.append("### Pertes\n")
        for p in r.points:
            loss = r.loss_count.get(p, 0)
            if loss:
                lines.append(f"- **{p}** : {loss} paquet(s) perdu(s)")
        lines.append("")

    # -- Topologie --
    lines.append(_topology_section(r))
    lines.append("")

    # -- Checksums (issue #762) --
    checksum_md = _checksum_section(r)
    if checksum_md:
        lines.append(checksum_md)
        lines.append("")

    # -- Objets HTTP --
    if r.http_objects:
        lines.append("## Objets HTTP transférés\n")
        lines.append("| Point | URI | Type | Taille |")
        lines.append("|-------|-----|------|--------|")
        for obj in r.http_objects:
            point = obj.get("point", "—")
            uri = obj.get("uri", "—")
            ctype = obj.get("content_type", "—")
            size = obj.get("size", "—")
            lines.append(f"| {point} | {uri} | {ctype} | {size} |")
        lines.append("")

    # -- Fichiers extraits --
    if r.extracted_files:
        lines.append("## Fichiers extraits\n")
        lines.append("| Point | Source | Nom | Taille | MD5 |")
        lines.append("|-------|--------|------|--------|-----|")
        for f in r.extracted_files:
            point = f.get("point", "—")
            proto = f.get("proto_source", "—")
            name = f.get("uri", "—")
            size = f.get("size", "—")
            md5 = f.get("hash_md5", "—")
            lines.append(f"| {point} | {proto} | {name} | {size} | `{md5}` |")
        lines.append("")

    # -- TLS / QUIC --
    if tls_findings:
        lines.append("## Diagnostics TLS\n")
        lines.extend(f"- **{f.severity}** — {f.segment} : {f.message}" for f in tls_findings)
        lines.append("")

    if quic_findings:
        lines.append("## Diagnostics QUIC\n")
        lines.extend(f"- **{f.severity}** — {f.segment} : {f.message}" for f in quic_findings)
        lines.append("")

    # -- Rapport de sécurité --
    security_md = _security_section(security_report)
    if security_md:
        lines.append(security_md)
        lines.append("")

    # -- Objets de session --
    session_md = _session_objects_section(session_objects)
    if session_md:
        lines.append(session_md)
        lines.append("")

    # -- Moteur de règles --
    if rule_engine_findings:
        lines.append("## Moteur de règles déclaratif\n")
        for rule_id, rule_findings in rule_engine_findings.items():
            if rule_findings:
                lines.append(f"### {rule_id}\n")
                lines.extend(f"- **{f.severity}** — {f.category} / {f.segment} : {f.message}" for f in rule_findings)
                lines.append("")

    # -- Annotations --
    if r.capture_comments or r.packet_comments:
        lines.append("## Commentaires pcapng\n")
        lines.extend(f"- [section] {c}" for c in r.capture_comments)
        lines.extend(f"- [paquet] {c}" for c in r.packet_comments)
        lines.append("")

    return "\n".join(lines)


def generate_markdown_report(
    r,
    output_path,
    title="Analyse croisée de captures réseau",
    **kwargs,
) -> str:
    """Écrit le rapport Markdown dans `output_path` et retourne le chemin.

    Mêmes arguments nommés que `build_markdown_report_document()` :
    meta, findings, tls_findings, quic_findings, session_objects,
    security_report, rule_engine_findings, names.
    """
    logger.debug("generate_markdown_report: output_path={}", summarize(output_path, "output_path"))
    doc = build_markdown_report_document(r, title=title, **kwargs)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    logger.debug("generate_markdown_report: écrit")
    return output_path
