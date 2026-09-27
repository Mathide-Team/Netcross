"""
netcross_report.pdf -- assemble le rapport PDF final (synthese, graphiques,
tableaux de detail) a partir d'un Report netcross_core, avec reportlab.
"""

import datetime
import tempfile

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from netcross_core.logging_config import get_logger, summarize
from netcross_report.charts import (
    DIFF_SEVERITY_SCHEME,
    chart_sequence_diagram,
    chart_severity_summary,
    generate_all_charts,
)
from netcross_report.path_metrics import build_path_metrics, degradation_summary, rank_path_segments
from netcross_report.synthesis import build_findings
from netcross_report.triage import HEALTH_LABELS, health_label, health_score, rank_segments

logger = get_logger(__name__)
SEVERITY_LABELS = {
    "anomalie": "Anomalie",
    "a_surveiller": "A surveiller",
    "info": "Info",
    # vocabulaire de baseline_diff.DiffFinding -- meme table de rendu
    # (_finding_table) reutilisee pour le rapport PDF de diff, voir
    # generate_diff_pdf() plus bas
    "regression": "Regression",
    "a_verifier": "A verifier",
    "amelioration": "Amelioration",
    "stable": "Stable",
}
SEVERITY_COLORS = {
    "anomalie": colors.HexColor("#ef4444"),
    "a_surveiller": colors.HexColor("#f59e0b"),
    "info": colors.HexColor("#94a3b8"),
    "regression": colors.HexColor("#ef4444"),
    "a_verifier": colors.HexColor("#f59e0b"),
    "amelioration": colors.HexColor("#22c55e"),
    "stable": colors.HexColor("#94a3b8"),
}

# Couleurs du badge "Score de sante" -- memes 4 tranches que
# netcross_report.triage.HEALTH_LABEL_THRESHOLDS, palette coherente avec
# SEVERITY_COLORS ci-dessus (rouge = anomalie/critique, ambre = a
# surveiller, vert reserve a "bon" ici -- amelioration l'utilise deja pour
# le vocabulaire diff, pas de collision possible : les deux ne
# s'affichent jamais dans le meme badge).
HEALTH_BADGE_COLORS = {
    "bon": colors.HexColor("#22c55e"),
    "a_surveiller": colors.HexColor("#f59e0b"),
    "degrade": colors.HexColor("#f97316"),
    "critique": colors.HexColor("#ef4444"),
}


# Plafonds de la section securite (issue #218). Un PDF est un document
# qu'on lit : 400 retransmissions correlees en anomalies produiraient 400
# lignes que personne ne parcourt. On plafonne, et on ECRIT le total reel
# sous le tableau plutot que de laisser croire a une liste exhaustive.
MAX_SECURITY_ROWS = 40
MAX_PDF_READABLE_LEN = 90


def _styles():
    logger.debug("_styles()")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("H1b", parent=styles["Heading1"], spaceBefore=18, spaceAfter=8))
    styles.add(ParagraphStyle("H2b", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6))
    styles.add(ParagraphStyle("Small", parent=styles["Normal"], fontSize=8, textColor=colors.grey))
    # "Cell" : cellules denses contenant des identifiants techniques non
    # coupables (rfc6349-retransmission-rate-2pct, tcp_retransmission_rate_pct).
    # reportlab coupe ces jetons en plein milieu quand ils depassent la
    # largeur de colonne -- et les espaces de largeur nulle s'affichent en
    # carre noir avec les polices de base. La seule parade fiable est donc
    # d'assurer que le jeton TIENT : corps reduit + colonnes dimensionnees
    # sur le plus long identifiant du catalogue (voir _compliance_table).
    styles.add(ParagraphStyle("Cell", parent=styles["Normal"], fontSize=7.5, leading=9.5))
    return styles


def _finding_table(findings, styles):
    logger.debug("_finding_table: findings={} styles={}", summarize(findings, "findings"), summarize(styles, "styles"))
    if not findings:
        return Paragraph("Aucun constat notable.", styles["Normal"])
    data = [["Gravite", "Categorie", "Segment", "Constat"]]
    data.extend(
        [
            SEVERITY_LABELS[f.severity],
            f.category,
            Paragraph(f.segment, styles["Normal"]),
            Paragraph(f.message, styles["Normal"]),
        ]
        for f in findings
    )
    t = Table(data, colWidths=[2.4 * cm, 2.6 * cm, 2.8 * cm, 8.5 * cm], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -1),
            [colors.white, colors.HexColor("#f9fafb")],
        ),
    ]
    for i, f in enumerate(findings, start=1):
        style.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLORS[f.severity]))
        style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style))
    return t


def _triage_table(ranked, styles, top_n=10):
    """ranked : liste de netcross_report.triage.SegmentScore, deja triee
    par score decroissant (rank_segments()). N'affiche que les segments
    convergents (>=2 categories) -- un segment avec un seul constat
    isole n'apporte rien de plus que ce que la table de constats montre
    deja, ce n'est pas ca qui doit orienter "par ou commencer"."""
    logger.debug(
        "_triage_table: ranked={} styles={} top_n={}",
        summarize(ranked, "ranked"),
        summarize(styles, "styles"),
        summarize(top_n, "top_n"),
    )
    convergent = [s for s in ranked if s.convergent]
    if not convergent:
        return Paragraph(
            "Aucun segment touche par plusieurs categories de constats a la fois "
            "-- pas de faisceau de preuves a signaler ici, voir la table de constats "
            "ci-dessous pour le detail exhaustif.",
            styles["Normal"],
        )
    data = [["Segment", "Score", "Categories touchees", "Constats"]]
    data.extend(
        [
            Paragraph(
                s.segment + (" (echantillon faible)" if s.low_confidence else ""),
                styles["Normal"],
            ),
            f"{s.score:.1f}",
            Paragraph(", ".join(s.categories), styles["Normal"]),
            str(len(s.findings)),
        ]
        for s in convergent[:top_n]
    )
    t = Table(data, colWidths=[3.5 * cm, 1.8 * cm, 7.7 * cm, 2.3 * cm], repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#f9fafb")],
                ),
            ]
        )
    )
    return t


def _health_badge(ranked, styles):
    """Paragraphe compact affiche juste au-dessus de la table de triage --
    condense la meme donnee (rank_segments()) en un seul chiffre pour une
    lecture en un coup d'oeil. Voir netcross_report.triage.health_score
    pour la formule et la note de conception (notamment sur ce que le
    score signifie quand `ranked` vient d'un diff plutot que d'un run
    simple)."""
    logger.debug("_health_badge: ranked={} styles={}", summarize(ranked, "ranked"), summarize(styles, "styles"))
    score = health_score(ranked)
    label = health_label(score)
    style = ParagraphStyle(
        "HealthBadge",
        parent=styles["Normal"],
        fontSize=13,
        fontName="Helvetica-Bold",
        textColor=HEALTH_BADGE_COLORS[label],
        spaceAfter=6,
    )
    return Paragraph(f"Score de sante : {score}/100 -- {HEALTH_LABELS[label]}", style)


# Couleurs des statuts de conformite (netcross_core.compliance) -- meme
# palette que SEVERITY_COLORS ci-dessus, en mappant l'intention plutot que
# le vocabulaire : VIOLATION est un ecart franc (rouge, comme anomalie),
# DEVIATION un ecart mineur dans la marge de tolerance (ambre, comme
# a_surveiller), INDETERMINE une metrique non mesurable sur cette capture
# (gris, comme info -- ce n'est pas un resultat, c'est une absence).
COMPLIANCE_COLORS = {
    "CONFORME": colors.HexColor("#22c55e"),
    "DEVIATION": colors.HexColor("#f59e0b"),
    "VIOLATION": colors.HexColor("#ef4444"),
    "INDETERMINE": colors.HexColor("#94a3b8"),
}

# Nombre de lignes affichees par table de la section "Expertise" : le PDF
# est un livrable de lecture, pas un export -- au-dela, une ligne de
# renvoi vers --json-report remplace la suite (meme discipline que le
# plafonnement du rendu console, voir netcross_report.session_objects).
EXPERT_TABLE_TOP_N = 15


def _grid_table(data, col_widths, highlight=None):
    """Table a en-tete sombre et lignes alternees -- exactement le style
    deja utilise par _finding_table/_triage_table ci-dessus, factorise ici
    parce que la section "Expertise" en ajoute quatre d'un coup.
    highlight : liste de (index_de_ligne, couleur) pour colorer la
    premiere colonne (gravite/statut), comme le fait _finding_table."""
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
    ]
    for row, color in highlight or []:
        style.append(("TEXTCOLOR", (0, row), (0, row), color))
        style.append(("FONTNAME", (0, row), (0, row), "Helvetica-Bold"))
    t.setStyle(TableStyle(style))
    return t


def _expert_event_table(events, styles, top_n=EXPERT_TABLE_TOP_N):
    """events : liste d'ExpertEvent (netcross_core.expert_model). Affiche
    cause/impact, qui sont precisement ce que le JSON exposait deja et que
    le PDF ignorait jusqu'ici -- une colonne vide quand le moteur de
    causalite n'a pas reconnu de pattern pour cet evenement (voir
    netcross_core.causality : seuls les rule_id participant a un pattern
    recoivent cause/impact)."""
    logger.debug(
        "_expert_event_table: events={} styles={} top_n={}",
        summarize(events, "events"),
        summarize(styles, "styles"),
        summarize(top_n, "top_n"),
    )
    if not events:
        return Paragraph("Aucun evenement d'expertise.", styles["Normal"])
    data = [["Gravite", "Categorie", "Segment", "Constat", "Cause probable / impact"]]
    shown = events[:top_n]
    for ev in shown:
        cause = " -- ".join(x for x in (ev.cause, ev.impact) if x)
        data.append(
            [
                SEVERITY_LABELS.get(ev.severity, ev.severity),
                Paragraph(ev.category, styles["Normal"]),
                Paragraph(ev.segment, styles["Normal"]),
                Paragraph(ev.message, styles["Normal"]),
                Paragraph(cause or "-", styles["Normal"]),
            ]
        )
    highlight = [
        (i, SEVERITY_COLORS[ev.severity]) for i, ev in enumerate(shown, start=1) if ev.severity in SEVERITY_COLORS
    ]
    return _grid_table(data, [1.9 * cm, 2.3 * cm, 2.6 * cm, 5.2 * cm, 4.3 * cm], highlight)


def _diagnosis_table(diagnoses, styles, top_n=EXPERT_TABLE_TOP_N):
    """diagnoses : liste de Diagnosis -- un par segment, cause/impact
    derives des ExpertEvent deja enrichis (netcross_core.causality)."""
    logger.debug(
        "_diagnosis_table: diagnoses={} styles={} top_n={}",
        summarize(diagnoses, "diagnoses"),
        summarize(styles, "styles"),
        summarize(top_n, "top_n"),
    )
    if not diagnoses:
        return Paragraph("Aucun diagnostic par segment.", styles["Normal"])
    data = [["Segment", "Evenements", "Cause probable", "Impact"]]
    data.extend(
        [
            Paragraph(d.segment, styles["Normal"]),
            str(len(d.events)),
            Paragraph(d.cause or "-", styles["Normal"]),
            Paragraph(d.impact or "-", styles["Normal"]),
        ]
        for d in diagnoses[:top_n]
    )
    return _grid_table(data, [3.4 * cm, 1.9 * cm, 5.5 * cm, 5.5 * cm])


def _compliance_table(results, styles, top_n=EXPERT_TABLE_TOP_N):
    """results : liste de ComplianceResult (netcross_core.compliance).
    Les ecarts d'abord (VIOLATION, puis DEVIATION) : meme intention que le
    triage "par ou commencer", l'operateur doit voir ce qui ne passe pas
    sans derouler la table entiere."""
    logger.debug(
        "_compliance_table: results={} styles={} top_n={}",
        summarize(results, "results"),
        summarize(styles, "styles"),
        summarize(top_n, "top_n"),
    )
    if not results:
        return Paragraph("Aucun referentiel evalue.", styles["Normal"])
    order = ["VIOLATION", "DEVIATION", "CONFORME", "INDETERMINE"]
    ranked = sorted(
        results,
        key=lambda res: (order.index(res.status) if res.status in order else len(order), res.reference.id),
    )
    # Metrique/observe/seuil tiennent dans une seule colonne "Mesure" :
    # six colonnes sur une A4 laissaient trop peu de largeur aux
    # identifiants, que reportlab coupait alors en plein mot.
    data = [["Statut", "Referentiel", "Mesure", "Source"]]
    shown = ranked[:top_n]
    for res in shown:
        ref = res.reference
        observed = "non mesure" if res.observed is None else f"{res.observed:g} {ref.unit}"
        data.append(
            [
                res.status,
                Paragraph(ref.id, styles["Cell"]),
                # metrique sur sa propre ligne : la valeur mesuree peut
                # etre un compteur a plusieurs chiffres, et on ne veut pas
                # qu'elle pousse le nom de la metrique hors de la colonne.
                Paragraph(
                    f"{ref.metric}<br/>{observed} (seuil {ref.operator} {ref.threshold:g} {ref.unit})",
                    styles["Cell"],
                ),
                Paragraph(ref.source, styles["Cell"]),
            ]
        )
    highlight = [
        (i, COMPLIANCE_COLORS[res.status]) for i, res in enumerate(shown, start=1) if res.status in COMPLIANCE_COLORS
    ]
    return _grid_table(data, [2.1 * cm, 4.3 * cm, 5.2 * cm, 5.4 * cm], highlight)


def _flow_table(flows, styles, top_n=EXPERT_TABLE_TOP_N):
    """flows : liste de Flow (netcross_core.expert_model). Tri par volume
    de paquets decroissant, libelle en second critere pour un ordre stable
    d'une execution a l'autre -- meme regle que le rendu console
    (netcross_report.session_objects)."""
    logger.debug(
        "_flow_table: flows={} styles={} top_n={}",
        summarize(flows, "flows"),
        summarize(styles, "styles"),
        summarize(top_n, "top_n"),
    )
    if not flows:
        return Paragraph("Aucun flux correle.", styles["Normal"])

    def _label(flow):
        if flow.endpoints:
            return f"{flow.endpoints[0]} <-> {flow.endpoints[1]}"
        return str(flow.key)

    ordered = sorted(flows, key=lambda f: (-sum(f.packet_count.values()), _label(f)))
    data = [["Flux", "Points de capture", "Paquets", "Octets"]]
    data.extend(
        [
            Paragraph(_label(f), styles["Normal"]),
            Paragraph(", ".join(f.points), styles["Normal"]),
            str(sum(f.packet_count.values())),
            str(sum(f.byte_count.values())),
        ]
        for f in ordered[:top_n]
    )
    return _grid_table(data, [6.2 * cm, 4.6 * cm, 2.6 * cm, 2.9 * cm])


def _fmt_num(value, unit="", decimals=1):
    """Valeur numerique ou tiret cadratin si la mesure n'existe pas. Un
    tiret et un "0.0" ne disent pas la meme chose : le premier signale une
    absence de mesure, le second une mesure nulle (voir SegmentMetrics)."""
    if value is None:
        return "\u2014"
    return f"{value:.{decimals}f}{unit}"


def _fmt_bps(value):
    """Debit en unite lisible (bit/s -> kbit/s -> Mbit/s -> Gbit/s), meme
    echelle decimale (1000) que les debits reseau usuels."""
    if value is None:
        return "\u2014"
    for unit, factor in (("Gbit/s", 1e9), ("Mbit/s", 1e6), ("kbit/s", 1e3)):
        if value >= factor:
            return f"{value / factor:.2f} {unit}"
    return f"{value:.0f} bit/s"


def _path_table(metrics, styles):
    """Un segment par ligne, dans l'ordre amont -> aval. Le libelle du
    segment le plus degrade (voir rank_path_segments) est mis en rouge gras
    directement dans le balisage du Paragraph : les commandes TEXTCOLOR /
    FONTNAME de _grid_table ne traversent pas un Paragraph (elles ne
    s'appliquent qu'aux cellules en texte brut, voir _finding_table). Le
    tableau
    garde l'ordre du chemin, qui est celui dans lequel on depanne, tout en
    designant sans ambiguite ou regarder d'abord."""
    logger.debug("_path_table: metrics={} styles={}", summarize(metrics, "metrics"), summarize(styles, "styles"))
    if not metrics:
        return Paragraph(
            "Aucun segment exploitable : ni topologie deduite, ni couple de points fourni.",
            styles["Normal"],
        )
    data = [["Segment", "Delai moy / P95 / P99 (ms)", "Gigue", "Perte aval", "Debit aval", "DSCP / frag", "Sauts"]]
    ranked = rank_path_segments(metrics)
    pire = ranked[0].label if ranked else None
    for seg in metrics:
        delays = " / ".join(_fmt_num(v) for v in (seg.delay_avg_ms, seg.delay_p95_ms, seg.delay_p99_ms))
        label = f'<b><font color="#b91c1c">{seg.label}</font></b>' if seg.label == pire else seg.label
        perte = "\u2014" if seg.loss_pct is None else f"{seg.loss_pct:.2f}% ({seg.loss_count})"
        data.append(
            [
                Paragraph(label, styles["Cell"]),
                Paragraph(delays if seg.samples else "\u2014", styles["Cell"]),
                Paragraph(_fmt_num(seg.jitter_ms), styles["Cell"]),
                Paragraph(perte, styles["Cell"]),
                Paragraph(_fmt_bps(seg.throughput_bps), styles["Cell"]),
                Paragraph(f"{seg.dscp_changes} / {seg.frag_new}", styles["Cell"]),
                Paragraph("\u2014" if seg.hops is None else str(seg.hops), styles["Cell"]),
            ]
        )
    return _grid_table(data, [3.4 * cm, 3.8 * cm, 1.5 * cm, 2.3 * cm, 2.3 * cm, 2.3 * cm, 1.4 * cm])


def path_section_story(metrics, styles, chart_path=None):
    """Flowables de la section "Chemin observe" (Job 16/issue #12,
    FEATURES.md 6.7) : une vue unique qui repond a "ou la qualite se
    degrade-t-elle ?".

    Les chiffres eux-memes figuraient deja dans le PDF, mais repartis entre
    quatre sections (latence, pertes, QoS, fragmentation) et classes par
    metrique, pas par segment -- impossible de suivre une plainte le long du
    chemin sans recouper trois pages a la main. Ici l'axe de lecture est le
    chemin, et la metrique le detail.

    metrics vide (aucun couple de points) renvoie une liste vide, donc
    aucune section : pas de titre orphelin dans un rapport a un seul point
    de capture, meme convention que expert_section_story().
    """
    logger.debug(
        "path_section_story: metrics={} styles={} chart_path={}",
        summarize(metrics, "metrics"),
        summarize(styles, "styles"),
        summarize(chart_path, "chart_path"),
    )
    if not metrics:
        return []
    story = [
        Paragraph("Chemin observe", styles["H1b"]),
        Paragraph(
            "Qualite mesuree segment par segment, de l'amont vers l'aval du chemin deduit. "
            "Les pertes sont comptees au point AVAL de chaque segment (paquet vu en amont, "
            "absent en aval), le delai et la gigue sur les paquets correles entre les deux "
            "points -- ils supposent donc des horloges synchronisees. Un tiret signale une "
            "metrique non mesurable sur ce segment, pas une valeur nulle.",
            styles["Normal"],
        ),
        Spacer(1, 0.2 * cm),
        Paragraph(f"<b>{degradation_summary(metrics)}</b>", styles["Normal"]),
        Spacer(1, 0.3 * cm),
        _path_table(metrics, styles),
    ]
    if chart_path:
        story += [Spacer(1, 0.3 * cm), Image(chart_path, width=15 * cm, height=8 * cm)]
    return story


def _scaled_image(path, max_w, max_h):
    """Image mise a l'echelle en conservant son rapport d'aspect reel (lu
    dans le PNG), bornee par max_w x max_h.

    Sans cela, imposer une largeur ET une hauteur a un Image reportlab
    deforme le dessin -- passe inapercu sur un histogramme, illisible sur
    un diagramme de sequence, dont la hauteur depend du nombre de lignes.
    """
    from PIL import Image as PILImage

    with PILImage.open(path) as im:
        img_w, img_h = im.size
    ratio = min(max_w / img_w, max_h / img_h)
    return Image(path, width=img_w * ratio, height=img_h * ratio)


def _sequence_table(view, styles):
    """Une ligne par paquet vu a un point -- c'est le critere d'acceptation
    de l'issue #11 ("chaque ligne reliee a un paquet et un point") : le
    dessin donne la forme de l'echange, cette table donne les references
    verifiables (numero de trame, point, taille) qu'on reporte dans
    Wireshark."""
    logger.debug("_sequence_table: view={} styles={}", summarize(view, "view"), summarize(styles, "styles"))
    data = [["Trame", "t (ms)", "Delta (ms)", "Source -> Destination", "Point", "Octets", "Detail"]]
    data.extend(
        [
            Paragraph("\u2014" if step.frame_number is None else str(step.frame_number), styles["Cell"]),
            Paragraph(f"{step.rel_ms:.1f}", styles["Cell"]),
            Paragraph(f"{step.delta_ms:.1f}", styles["Cell"]),
            Paragraph(f"{step.src} -> {step.dst}", styles["Cell"]),
            Paragraph(step.point, styles["Cell"]),
            Paragraph(str(step.length), styles["Cell"]),
            Paragraph(step.label, styles["Cell"]),
        ]
        for step in view.steps
    )
    return _grid_table(
        data,
        [1.5 * cm, 1.5 * cm, 1.7 * cm, 5.0 * cm, 2.6 * cm, 1.4 * cm, 3.3 * cm],
    )


def sequence_section_story(views, styles, chart_paths=None):
    """Flowables de la section "Sequence des echanges" (Job 14/issue #11,
    FEATURES.md 6.5) : un diagramme + une table de references par flux.

    `chart_paths` : liste parallele a `views` (None ou chemin manquant =
    table seule, jamais d'image absente silencieusement remplacee par un
    blanc). Liste vide de vues => aucune section, comme
    expert_section_story()/path_section_story().
    """
    logger.debug(
        "sequence_section_story: views={} styles={} chart_paths={}",
        summarize(views, "views"),
        summarize(styles, "styles"),
        summarize(chart_paths, "chart_paths"),
    )
    views = [v for v in (views or []) if v.steps]
    if not views:
        return []
    chart_paths = list(chart_paths or [])
    story = [
        Paragraph("Sequence des echanges", styles["H1b"]),
        Paragraph(
            "Chronologie des paquets d'un flux, hote par hote. Une ligne = un paquet vu a "
            "UN point de capture : le meme paquet traversant deux points apparait donc deux "
            "fois, et l'ecart entre ces deux lignes est son temps de transit -- c'est la "
            "mesure que seule une capture multi-points peut donner. Les dates sont relatives "
            "au premier paquet du flux ; le numero de trame permet de retrouver chaque ligne "
            "dans Wireshark.",
            styles["Normal"],
        ),
        Spacer(1, 0.3 * cm),
    ]
    for i, view in enumerate(views):
        if view.title:
            story.append(Paragraph(view.title, styles["H2b"]))
        if view.truncated:
            story.append(
                Paragraph(
                    f"{len(view.steps)} premieres lignes sur {view.total_steps} "
                    f"({view.truncated} non representee(s)) -- le debut de l'echange porte "
                    "le diagnostic, la suite est de la repetition.",
                    styles["Normal"],
                )
            )
        chart_path = chart_paths[i] if i < len(chart_paths) else None
        if chart_path:
            story.append(_scaled_image(chart_path, 16 * cm, 20 * cm))
            story.append(Spacer(1, 0.3 * cm))
        story.append(_sequence_table(view, styles))
        story.append(Spacer(1, 0.4 * cm))
    return story


def expert_section_story(session_objects, styles, top_n=EXPERT_TABLE_TOP_N):
    """Flowables de la section "Expertise" du PDF (Job 4/issue #13).

    session_objects : SessionObjects (netcross_report.session_objects) ou
    None -- None renvoie une liste vide, donc aucune section : un rapport
    produit sans ces objets doit rester identique a ce qu'il etait avant
    cette session (aucune page blanche, aucun titre orphelin).

    Fonction publique separee de generate_pdf() pour etre testable sans
    produire de PDF : les tests inspectent les Table/Paragraph renvoyes,
    la ou relire le PDF final imposerait d'en extraire le texte.
    """
    logger.debug(
        "expert_section_story: session_objects={} styles={} top_n={}",
        summarize(session_objects, "session_objects"),
        summarize(styles, "styles"),
        summarize(top_n, "top_n"),
    )
    if session_objects is None:
        return []
    story = [
        Paragraph("Expertise -- objets enrichis", styles["H1b"]),
        Paragraph(
            "Evenements d'expertise, diagnostics par segment, conformite aux referentiels "
            "et flux correles. Ces objets etaient jusqu'ici reserves a l'export JSON "
            "(--json-report) : cause probable et impact viennent du moteur de correlation "
            "causale, qui ne les renseigne que pour les symptomes co-occurrents reconnus "
            "sur un meme segment.",
            styles["Normal"],
        ),
        Spacer(1, 0.3 * cm),
        Paragraph("Evenements d'expertise", styles["H2b"]),
        _expert_event_table(session_objects.expert_events, styles, top_n),
        Spacer(1, 0.3 * cm),
        Paragraph("Diagnostics par segment", styles["H2b"]),
        _diagnosis_table(session_objects.diagnoses, styles, top_n),
        Spacer(1, 0.3 * cm),
        Paragraph("Conformite aux referentiels", styles["H2b"]),
        _compliance_table(session_objects.compliance, styles, top_n),
    ]
    # Les flux ne sont construits que si l'appelant a passe le dict brut
    # de correlate() (voir build_session_objects) : pas de table vide
    # quand l'information n'a pas ete demandee.
    if session_objects.flows:
        story += [
            Spacer(1, 0.3 * cm),
            Paragraph("Flux correles", styles["H2b"]),
            _flow_table(session_objects.flows, styles, top_n),
        ]
    # Signaux tshark BRUTS, jamais fondus dans les evenements netcross
    # ci-dessus (source "tshark" vs "netcross") -- meme separation que la
    # cle JSON dediee, voir netcross_core.wireshark_expert.
    if session_objects.wireshark_expert_events:
        story += [
            Spacer(1, 0.3 * cm),
            Paragraph("Expertise tshark (signaux bruts)", styles["H2b"]),
            _expert_event_table(session_objects.wireshark_expert_events, styles, top_n),
        ]
    return story


def _kv_table(rows, styles, col_widths=None):
    data = [[Paragraph(str(a), styles["Normal"]), Paragraph(str(b), styles["Normal"])] for a, b in rows]
    t = Table(data, colWidths=col_widths or [5 * cm, 10 * cm])
    t.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
            ]
        )
    )
    return t


_SEVERITY_PDF_COLORS = {
    "critique": colors.HexColor("#7f1d1d"),
    "elevee": colors.HexColor("#9a3412"),
    "moyenne": colors.HexColor("#854d0e"),
    "faible": colors.HexColor("#1e40af"),
}


def _securite_cible(host, port) -> str:
    if not host:
        return "-"
    return f"{host}:{port}" if port is not None else str(host)


def _securite_table_constats(items, styles, avec_cve: bool, message_vide: str):
    """Tableau d'un lot de constats de securite, ou le message explicite
    qu'il n'y en a pas -- jamais une section muette (issue #218)."""
    logger.debug(
        "_securite_table_constats: items={} styles={} avec_cve={} message_vide={}",
        summarize(items, "items"),
        summarize(styles, "styles"),
        summarize(avec_cve, "avec_cve"),
        summarize(message_vide, "message_vide"),
    )
    if not items:
        return Paragraph(message_vide, styles["Normal"])
    entetes = ["Gravite"] + (["CVE", "CVSS"] if avec_cve else []) + ["Detail", "Service", "Cible", "Point"]
    data = [[Paragraph(f"<b>{h}</b>", styles["Cell"]) for h in entetes]]
    highlight = []
    for rang, i in enumerate(items[:MAX_SECURITY_ROWS], start=1):
        service = i.get("service") or ""
        if service and i.get("version"):
            service = f"{service} {i['version']}"
        ligne = [Paragraph(i.get("severity") or "-", styles["Cell"])]
        if avec_cve:
            cvss = i.get("cvss")
            ligne += [
                Paragraph(i.get("cve_id") or "-", styles["Cell"]),
                Paragraph("-" if cvss is None else f"{cvss}", styles["Cell"]),
            ]
        ligne += [
            Paragraph(i.get("detail") or "-", styles["Cell"]),
            Paragraph(service or "-", styles["Cell"]),
            Paragraph(_securite_cible(i.get("host"), i.get("port")), styles["Cell"]),
            Paragraph(i.get("point") or "-", styles["Cell"]),
        ]
        data.append(ligne)
        couleur = _SEVERITY_PDF_COLORS.get(i.get("severity"))
        if couleur is not None:
            highlight.append((rang, couleur))
    largeurs = (
        [1.7 * cm, 2.6 * cm, 1.2 * cm, 5.6 * cm, 2.6 * cm, 2.6 * cm, 1.7 * cm]
        if avec_cve
        else [1.7 * cm, 8.4 * cm, 3.0 * cm, 2.9 * cm, 2.0 * cm]
    )
    return _grid_table(data, largeurs, highlight=highlight)


def _securite_table_detecteurs(items, styles, message_vide: str):
    """Constats des detecteurs Netcross regroupes par detecteur (#347) :
    chaque detecteur ayant produit un constat a au moins une ligne, avec
    son total ; au plus MAX_ROWS_PER_DETECTOR exemples par detecteur."""
    logger.debug(
        "_securite_table_detecteurs: items={} styles={} message_vide={}",
        summarize(items, "items"),
        summarize(styles, "styles"),
        summarize(message_vide, "message_vide"),
    )
    from netcross_report.security_report import MAX_ROWS_PER_DETECTOR, group_by_detector

    if not items:
        return Paragraph(message_vide, styles["Normal"])
    entetes = ["Gravite", "Detecteur", "Detail", "Cible", "Point"]
    data = [[Paragraph(f"<b>{h}</b>", styles["Cell"]) for h in entetes]]
    highlight = []
    for g in group_by_detector(items):
        for n, i in enumerate(g.items[:MAX_ROWS_PER_DETECTOR]):
            etiquette = f"<b>{g.label}</b> ({len(g.items)})" if n == 0 else ""
            data.append(
                [
                    Paragraph(i.get("severity") or "-", styles["Cell"]),
                    Paragraph(etiquette, styles["Cell"]),
                    Paragraph(i.get("detail") or "-", styles["Cell"]),
                    Paragraph(_securite_cible(i.get("host"), i.get("port")), styles["Cell"]),
                    Paragraph(i.get("point") or "-", styles["Cell"]),
                ]
            )
            couleur = _SEVERITY_PDF_COLORS.get(i.get("severity"))
            if couleur is not None:
                highlight.append((len(data) - 1, couleur))
        reste = len(g.items) - MAX_ROWS_PER_DETECTOR
        if reste > 0:
            data.append(
                [
                    Paragraph("", styles["Cell"]),
                    Paragraph("", styles["Cell"]),
                    Paragraph(f"... {reste} autre(s) constat(s) {g.label}", styles["Cell"]),
                    Paragraph("", styles["Cell"]),
                    Paragraph("", styles["Cell"]),
                ]
            )
    return _grid_table(data, [1.7 * cm, 3.4 * cm, 7.0 * cm, 2.9 * cm, 2.0 * cm], highlight=highlight)


def security_section_story(security_report, styles):
    """Section "Rapport de securite" du PDF (issue #218).

    Renvoie une liste vide si `security_report` est None : le PDF d'une
    analyse ou --security-report n'a pas ete demande n'a pas a porter une
    section de securite vide, qui laisserait croire qu'une analyse de
    securite a eu lieu et n'a rien trouve. L'appelant (la CLI) ne passe
    l'objet que si l'analyse a reellement tourne.

    En revanche, si l'objet est fourni, TOUTES ses sections sont ecrites,
    vides comprises, avec leur message d'absence -- c'est le manque qui a
    produit l'issue #259 : une donnee calculee, jamais rendue.
    """
    logger.debug(
        "security_section_story: security_report={} styles={}",
        summarize(security_report, "security_report"),
        summarize(styles, "styles"),
    )
    if security_report is None:
        return []
    from netcross_report.security_report import SEVERITIES, is_expert_info, security_report_to_dict

    data = security_report_to_dict(security_report)
    d = data["dashboard"]
    story = [PageBreak(), Paragraph("Rapport de securite", styles["H1b"])]
    story.append(
        Paragraph(
            "Detection passive : aucun paquet n'a ete emis vers les hotes listes. "
            "Une banniere ou une empreinte peut etre forgee ; un service absent de "
            "ce rapport n'est pas un service absent du reseau, seulement un service "
            "qui n'a pas parle pendant la capture.",
            styles["Small"],
        )
    )
    story.append(Spacer(1, 0.3 * cm))

    niveau = d["level"] or "aucun constat"
    story.append(Paragraph("Tableau de bord", styles["H2b"]))
    story.append(
        _kv_table(
            [
                ("Score de risque", f"{d['score']}/100 (niveau : {niveau})"),
                ("Services detectes", f"{d['services_total']} (dont {d['services_vulnerable']} vulnerable(s))"),
                ("Tentatives d'exploitation", str(d["exploits"])),
                ("Constats des detecteurs Netcross", str(d["anomalies_netcross"])),
                ("Alertes Expert Info correlees", str(d["anomalies_expert_info"])),
                ("CVE confirmees", str(d["cves"])),
                (
                    "Repartition par severite",
                    ", ".join(f"{sev}={d['by_severity'].get(sev, 0)}" for sev in SEVERITIES),
                ),
            ],
            styles,
        )
    )

    story.append(Paragraph("Services detectes", styles["H2b"]))
    if data["services"]:
        entetes = ["Criticite", "Service", "Cible", "Empreinte JA4/HASSH", "CVE", "Points"]
        rows = [[Paragraph(f"<b>{h}</b>", styles["Cell"]) for h in entetes]]
        highlight = []
        for rang, s in enumerate(data["services"][:MAX_SECURITY_ROWS], start=1):
            # L'empreinte et sa forme lisible (issue #259) : tronquee ici
            # parce qu'une liste complete de ciphers deborde la colonne,
            # mais la troncature est VISIBLE -- une troncature muette
            # ferait croire au lecteur qu'il a la liste entiere.
            empreinte = s.get("fingerprint") or "-"
            lisible = s.get("fingerprint_readable")
            if lisible:
                if len(lisible) > MAX_PDF_READABLE_LEN:
                    lisible = lisible[: MAX_PDF_READABLE_LEN - 3] + "..."
                empreinte = f"{empreinte}<br/><font size=6.5 color=#6b7280>{lisible}</font>"
            rows.append(
                [
                    Paragraph(s.get("severity") or "aucune CVE connue", styles["Cell"]),
                    Paragraph(f"{s['service']} {s.get('version') or ''}".strip(), styles["Cell"]),
                    Paragraph(_securite_cible(s.get("host"), s.get("port")), styles["Cell"]),
                    Paragraph(empreinte, styles["Cell"]),
                    Paragraph(", ".join(s.get("cve_ids") or []) or "-", styles["Cell"]),
                    Paragraph(", ".join(s.get("points") or []) or "-", styles["Cell"]),
                ]
            )
            couleur = _SEVERITY_PDF_COLORS.get(s.get("severity"))
            if couleur is not None:
                highlight.append((rang, couleur))
        story.append(
            _grid_table(
                rows,
                [2.2 * cm, 2.8 * cm, 2.6 * cm, 5.6 * cm, 2.2 * cm, 1.6 * cm],
                highlight=highlight,
            )
        )
    else:
        story.append(Paragraph("Aucun service identifie dans cette capture.", styles["Normal"]))

    # Issue #348 : les detecteurs Netcross et les alertes Expert Info de
    # Wireshark sont deux sources distinctes, deux sections distinctes.
    data["netcross"] = [i for i in data["anomalies"] if not is_expert_info(i)]
    data["expert_info"] = [i for i in data["anomalies"] if is_expert_info(i)]
    story.append(Paragraph("Tentatives d'exploitation detectees", styles["H2b"]))
    story.append(_securite_table_constats(data["exploits"], styles, False, "Aucune tentative d'exploitation detectee."))
    story.append(Paragraph("Anomalies (detecteurs Netcross)", styles["H2b"]))
    story.append(_securite_table_detecteurs(data["netcross"], styles, "Aucun constat des detecteurs Netcross."))
    story.append(Paragraph("Anomalies (alertes Expert Info correlees)", styles["H2b"]))
    story.append(_securite_table_constats(data["expert_info"], styles, False, "Aucune alerte Expert Info correlee."))
    story.append(Paragraph("CVE confirmees", styles["H2b"]))
    story.append(_securite_table_constats(data["cves"], styles, True, "Aucune CVE confirmee."))

    tronques = [
        (cle, len(data[cle]))
        for cle in ("services", "exploits", "expert_info", "cves")
        if len(data[cle]) > MAX_SECURITY_ROWS
    ]
    from netcross_report.security_report import MAX_ROWS_PER_DETECTOR, group_by_detector

    if any(len(g.items) > MAX_ROWS_PER_DETECTOR for g in group_by_detector(data["netcross"])):
        tronques.append(("detecteurs Netcross", len(data["netcross"])))
    if tronques:
        # Ne jamais tronquer en silence : le lecteur doit savoir combien de
        # lignes il ne voit pas, et ou les retrouver.
        detail = ", ".join(f"{cle} : {total} au total" for cle, total in tronques)
        story.append(Spacer(1, 0.2 * cm))
        story.append(
            Paragraph(
                f"Tableaux limites aux {MAX_SECURITY_ROWS} premieres lignes ({detail}). "
                "La liste complete est dans le --json-report ou le rendu HTML.",
                styles["Small"],
            )
        )
    return story


def generate_pdf(
    r,
    output_path,
    title="Analyse croisee de captures reseau",
    meta=None,
    findings=None,
    tls_findings=None,
    quic_findings=None,
    session_objects=None,
    sequence_views=None,
    security_report=None,
):
    """
    r : objet Report (netcross_core.analyse). output_path : chemin du PDF.
    meta : dict optionnel de metadonnees a afficher en page de garde
    (ex: {"Ticket": "INC-1234", "Auteur": "Mathilde"}).
    findings : liste de Finding deja calculee (synthesis.build_findings(r))
    si l'appelant l'a deja fait (evite un recalcul) ; sinon calculee ici.
    tls_findings / quic_findings : listes de TlsFinding optionnelles
    (netcross_core.tls_diagnostics.diagnose_tls / quic_diagnostics.diagnose_quic).
    Si fournies : affichees dans une section dediee ET integrees au triage
    "par ou commencer" en tete de rapport (memes categories/segments que les
    constats principaux -- rank_segments() est concu pour un melange des
    deux, voir netcross_report/triage.py).
    security_report : SecurityReport optionnel (issue #218, voir
    netcross_report.security_report.build_security_report). Si fourni, une
    section dediee est ajoutee au PDF : tableau de bord, services avec
    leurs empreintes JA4/HASSH, tentatives d'exploitation, anomalies et
    CVE. Absent, le PDF ne porte AUCUNE section de securite -- une section
    vide laisserait croire qu'une analyse de securite a eu lieu sans rien
    trouver, alors qu'elle n'a pas tourne.
    sequence_views : liste de SequenceView optionnelle (Job 14/issue #11,
    voir netcross_report.sequence_view.top_flow_views()). Absente ou vide,
    le rapport ne contient aucune section "Sequence des echanges" -- ces
    vues exigent les paquets bruts, que generate_pdf() ne recoit pas et ne
    doit pas recevoir (Report suffit a tout le reste du rapport).

    session_objects : SessionObjects optionnel (Job 4/issue #13, voir
    netcross_report.session_objects.build_session_objects()). Si fourni,
    une section "Expertise -- objets enrichis" est ajoutee avant l'annexe :
    evenements d'expertise avec cause/impact, diagnostics par segment,
    conformite aux referentiels, flux correles et signaux tshark bruts --
    tous reserves jusqu'ici a --json-report. Absent (None) -> section
    absente, le PDF reste identique a celui des sessions precedentes
    (meme convention d'absence que tls_findings/quic_findings ci-dessus,
    et jamais de recalcul ici : ces objets sont construits par l'appelant).
    """
    logger.debug(
        "generate_pdf: r={} output_path={} title={} meta={} findings={} tls_findings={} "
        "quic_findings={} session_objects={} sequence_views={} security_report={}",
        summarize(r, "r"),
        summarize(output_path, "output_path"),
        summarize(title, "title"),
        summarize(meta, "meta"),
        summarize(findings, "findings"),
        summarize(tls_findings, "tls_findings"),
        summarize(quic_findings, "quic_findings"),
        summarize(session_objects, "session_objects"),
        summarize(sequence_views, "sequence_views"),
        summarize(security_report, "security_report"),
    )
    if findings is None:
        findings = build_findings(r)
    ranked = rank_segments(list(findings) + list(tls_findings or []) + list(quic_findings or []))

    with tempfile.TemporaryDirectory() as tmpdir:
        charts = generate_all_charts(r, findings, tmpdir)
        styles = _styles()
        story = []

        # -- page de garde --
        story.append(Spacer(1, 3 * cm))
        story.append(Paragraph(title, styles["Title"]))
        story.append(Spacer(1, 0.5 * cm))
        now = datetime.datetime.now().astimezone().strftime("%d/%m/%Y %H:%M")
        info_rows = [("Genere le", now), ("Points de capture", ", ".join(r.points))]
        if meta:
            seen_keys = {k for k, _ in info_rows}
            info_rows += [(k, v) for k, v in meta.items() if k not in seen_keys]
        story.append(_kv_table(info_rows, styles))
        story.append(PageBreak())

        # -- par ou commencer (triage) --
        story.append(Paragraph("Par ou commencer", styles["H1b"]))
        story.append(
            Paragraph(
                "Segments touches par au moins 2 categories de constats differentes en "
                "meme temps -- signature d'un faisceau de preuves convergent plutot que "
                "d'un indice isole. Ne remplace pas la lecture complete des sections "
                "suivantes, mais indique par ou commencer a regarder.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.3 * cm))
        story.append(_health_badge(ranked, styles))
        story.append(_triage_table(ranked, styles))
        story.append(PageBreak())

        # -- synthese --
        story.append(Paragraph("Synthese", styles["H1b"]))
        n_anom = sum(1 for f in findings if f.severity == "anomalie")
        n_surv = sum(1 for f in findings if f.severity == "a_surveiller")
        story.append(
            Paragraph(
                f"{n_anom} anomalie(s) et {n_surv} point(s) a surveiller identifies "
                f"automatiquement a partir des seuils definis dans l'outil. Chaque ligne "
                f"renvoie a un chiffre mesure, detaille dans les sections suivantes.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.3 * cm))
        if "severity" in charts:
            story.append(Image(charts["severity"], width=8 * cm, height=6 * cm))
        story.append(Spacer(1, 0.3 * cm))
        story.append(_finding_table(findings, styles))
        story.append(PageBreak())

        # -- vue d'ensemble graphique --
        story.append(Paragraph("Vue d'ensemble", styles["H1b"]))
        if "topology" in charts:
            story.append(Paragraph("Topologie deduite", styles["H2b"]))
            story.append(_scaled_image(charts["topology"], 16 * cm, 13 * cm))
            story.append(Spacer(1, 0.3 * cm))
        for key, caption in [
            ("throughput", "Debit par point"),
            ("latency", "Latence par segment"),
            ("loss", "Pertes par point"),
        ]:
            if key in charts:
                story.append(Paragraph(caption, styles["H2b"]))
                story.append(Image(charts[key], width=14 * cm, height=7 * cm))
                story.append(Spacer(1, 0.3 * cm))
        story.append(PageBreak())

        # -- chemin observe (Job 16/issue #12) : place juste apres la vue
        # d'ensemble et AVANT les sections par metrique, parce qu'elle sert
        # a decider quelle metrique aller lire ensuite -- la mettre en
        # annexe aurait inverse l'ordre de lecture reel.
        path_story = path_section_story(build_path_metrics(r), styles, charts.get("path_quality"))
        if path_story:
            story.extend(path_story)
            story.append(PageBreak())

        # -- sequence des echanges (Job 14/issue #11) : apres le chemin
        # (ou la degradation se situe) et avant les graphiques temporels --
        # on descend du chemin vers le flux, puis du flux vers le paquet.
        seq_views = [v for v in (sequence_views or []) if v.steps]
        if seq_views:
            seq_charts = [
                chart_sequence_diagram(v, f"{tmpdir}/chart_sequence_{i}.png") for i, v in enumerate(seq_views)
            ]
            story.extend(sequence_section_story(seq_views, styles, seq_charts))
            story.append(PageBreak())

        # -- graphiques temporels top-N (protocole/port/IP/DSCP) --
        # un seul point trace (voir netcross_report.charts.generate_topn_charts
        # et chart_topn_timeseries pour le choix documente) -- absent du
        # dict `charts` si r.topn_timeseries est vide (all_packets vide) ou
        # si aucune des 4 dimensions n'a produit de graphique pour ce point.
        topn_keys = [k for k in charts if k.startswith("topn_")]
        if topn_keys:
            topn_point = r.points[0] if r.points else "?"
            story.append(Paragraph("Evolution temporelle (top-N)", styles["H1b"]))
            story.append(
                Paragraph(
                    f"Debit ventile par categorie au fil du temps, point {topn_point} uniquement "
                    "(voir la documentation pour les captures a plusieurs points : additionner "
                    "plusieurs points sur un meme graphique compterait certains paquets en double). "
                    'Les categories les moins volumineuses sont regroupees sous "autres".',
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 0.3 * cm))
            for dimension, caption in [
                ("protocol", "Par protocole"),
                ("port", "Par port de destination"),
                ("ip", "Par IP de destination"),
                ("dscp", "Par marquage DSCP"),
            ]:
                key = f"topn_{dimension}"
                if key in charts:
                    story.append(Paragraph(caption, styles["H2b"]))
                    story.append(Image(charts[key], width=16 * cm, height=6 * cm))
                    story.append(Spacer(1, 0.3 * cm))
            story.append(PageBreak())

        # -- detail par module --
        story.append(Paragraph("Detail par module", styles["H1b"]))

        story.append(Paragraph("Sauts de routeur (delta TTL)", styles["H2b"]))
        rows = []
        for a, b in r.pairs:
            deltas = r.hop_delta.get((a, b))
            if not deltas:
                continue
            from collections import Counter

            mode_delta, mode_n = Counter(deltas).most_common(1)[0]
            rows.append(
                (
                    f"{a} -> {b}",
                    f"{abs(mode_delta)} saut(s) ({mode_n}/{len(deltas)} flux)",
                )
            )
        if rows:
            story.append(_kv_table(rows, styles))
        else:
            story.append(Paragraph("Aucune donnee.", styles["Normal"]))
        story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph("QoS (DSCP)", styles["H2b"]))
        rows = [(f"{a} -> {b}", f"{n} paquet(s) remarque(s)") for (a, b), n in r.qos_change.items() if n]
        story.append(_kv_table(rows, styles) if rows else Paragraph("Aucun changement.", styles["Normal"]))
        story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph("Fragmentation / MTU", styles["H2b"]))
        rows = [
            (f"{a} -> {b}", f"{n} datagramme(s) nouvellement fragmente(s)") for (a, b), n in r.frag_new.items() if n
        ]
        story.append(_kv_table(rows, styles) if rows else Paragraph("Aucune fragmentation.", styles["Normal"]))
        story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph("Encapsulation / tunnels", styles["H2b"]))
        rows = []
        for p in r.points:
            stacks = sorted(r.encap_seen.get(p, []))
            if stacks:
                rows.append((p, ", ".join(stacks)))
        story.append(_kv_table(rows, styles) if rows else Paragraph("Aucun tunnel detecte.", styles["Normal"]))
        story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph("TCP avance", styles["H2b"]))
        rows = []
        for p in r.points:
            if r.zero_window.get(p):
                rows.append((f"{p} : fenetre=0", r.zero_window[p]))
            if r.dup_ack.get(p):
                rows.append((f"{p} : ACK dupliques", r.dup_ack[p]))
            if r.rst_count.get(p):
                rows.append((f"{p} : RST", r.rst_count[p]))
            if r.retrans.get(p):
                rows.append((f"{p} : retransmissions", r.retrans[p]))
        story.append(_kv_table(rows, styles) if rows else Paragraph("Rien de notable.", styles["Normal"]))
        story.append(Spacer(1, 0.3 * cm))

        if r.rtp_streams:
            story.append(Paragraph("Flux RTP (voix/visio)", styles["H2b"]))
            data = [["Flux", "Perte", "Delai", "MOS"]]
            for s in r.rtp_streams[:30]:
                last_point = r.points[-1] if r.points else None
                loss = s["loss_pct"].get(last_point, 0.0) if last_point else 0.0
                short_label = s["label"].split(" (SSRC=")[0]
                data.append(
                    [
                        Paragraph(short_label, styles["Normal"]),
                        f"{loss:.1f}%",
                        f"{s['delay_ms']:.0f}ms" if s["delay_ms"] is not None else "-",
                        f"{s['mos']:.2f}" if s["mos"] is not None else "-",
                    ]
                )
            t = Table(data, colWidths=[7 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                    ]
                )
            )
            story.append(t)
            story.append(Spacer(1, 0.3 * cm))

        if r.dhcp_msg_count:
            story.append(Paragraph("DHCP", styles["H2b"]))
            rows = []
            for p in r.points:
                counts = r.dhcp_msg_count.get(p, {})
                if counts:
                    rows.append((p, ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))))
            story.append(_kv_table(rows, styles) if rows else Paragraph("Rien.", styles["Normal"]))
            story.append(Spacer(1, 0.3 * cm))

        if r.sip_msg_count:
            story.append(Paragraph("SIP", styles["H2b"]))
            rows = []
            for p in r.points:
                counts = r.sip_msg_count.get(p, {})
                if counts:
                    rows.append((p, ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))))
            story.append(_kv_table(rows, styles) if rows else Paragraph("Rien.", styles["Normal"]))

        if tls_findings or quic_findings:
            story.append(Spacer(1, 0.3 * cm))
            story.append(Paragraph("Diagnostics TLS / QUIC", styles["H2b"]))
            story.append(
                Paragraph(
                    "Pipeline de decodage independant qui relit les memes captures "
                    "(voir netcross_core.tls_diagnostics / quic_diagnostics) -- ces "
                    "constats sont deja inclus dans le triage en tete de rapport.",
                    styles["Small"],
                )
            )
            story.append(Spacer(1, 0.2 * cm))
            if tls_findings:
                story.append(Paragraph("TLS", styles["Heading3"]))
                story.append(_finding_table(tls_findings, styles))
                story.append(Spacer(1, 0.3 * cm))
            if quic_findings:
                story.append(Paragraph("QUIC / HTTP3", styles["Heading3"]))
                story.append(_finding_table(quic_findings, styles))

        # -- rapport de securite (issue #218) --
        story.extend(security_section_story(security_report, styles))

        # -- expertise (objets enrichis de la Session 0, issue #13) --
        expert_story = expert_section_story(session_objects, styles)
        if expert_story:
            story.append(PageBreak())
            story.extend(expert_story)

        story.append(Spacer(1, 1 * cm))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))
        story.append(
            Paragraph(
                "Rapport genere automatiquement par cross_capture_analyzer (netcross). "
                "Les verdicts de saturation/policing/bufferbloat/injection sont des indices "
                "statistiques, a confirmer avec les journaux des equipements suspectes.",
                styles["Small"],
            )
        )

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
        )
        doc.build(story)

    return output_path


def generate_diff_pdf(
    findings,
    baseline,
    current,
    output_path,
    title="Comparaison avant / apres",
    meta=None,
    tls_findings_baseline=None,
    tls_findings_current=None,
    quic_findings_baseline=None,
    quic_findings_current=None,
):
    """
    Rapport PDF pour un diff baseline_diff.diff_reports() -- pendant de
    generate_pdf() pour DiffFinding plutot que Finding. Plus court : pas
    de vue d'ensemble graphique (topologie/debit/latence/pertes propres
    a UN Report), seulement triage + synthese + table de constats,
    puisque c'est baseline_diff qui a deja fait le travail de comparaison
    chiffre entre les deux Report.

    findings : liste de DiffFinding (baseline_diff.diff_reports()).
    baseline, current : les deux Report compares (pour la page de garde
    uniquement -- listes de points).
    tls_findings_baseline / tls_findings_current / quic_findings_baseline /
    quic_findings_current : listes de TlsFinding optionnelles
    (netcross_core.tls_diagnostics.diagnose_tls / quic_diagnostics.diagnose_quic),
    executees separement sur le baseline et sur le run courant par
    l'appelant (cross_capture_diff_cli.py --tls/--quic). Affichees dans
    une section dediee, baseline et courant l'un sous l'autre -- PAS
    fondues dans le triage/la table de constats ci-dessus : ces deux
    modules ne connaissent qu'un etat a un instant donne (severites
    anomalie/a_surveiller/info), pas une paire avant/apres comme
    DiffFinding (regression/a_verifier/amelioration) ; les melanger aurait
    fausse le decompte de _severity_ affiche dans le graphique de synthese
    (chart_severity_summary, vocabulaire DIFF_SEVERITY_SCHEME) sans
    apporter de vraie semantique de diff en echange. Voir claude.md pour
    la discussion complete de ce choix.
    """
    logger.debug(
        "generate_diff_pdf: findings={} baseline={} current={} output_path={} title={} meta={} "
        "tls_findings_baseline={} tls_findings_current={} quic_findings_baseline={} "
        "quic_findings_current={}",
        summarize(findings, "findings"),
        summarize(baseline, "baseline"),
        summarize(current, "current"),
        summarize(output_path, "output_path"),
        summarize(title, "title"),
        summarize(meta, "meta"),
        summarize(tls_findings_baseline, "tls_findings_baseline"),
        summarize(tls_findings_current, "tls_findings_current"),
        summarize(quic_findings_baseline, "quic_findings_baseline"),
        summarize(quic_findings_current, "quic_findings_current"),
    )
    ranked = rank_segments(findings)

    with tempfile.TemporaryDirectory() as tmpdir:
        styles = _styles()
        story = []

        # -- page de garde --
        story.append(Spacer(1, 3 * cm))
        story.append(Paragraph(title, styles["Title"]))
        story.append(Spacer(1, 0.5 * cm))
        now = datetime.datetime.now().astimezone().strftime("%d/%m/%Y %H:%M")
        info_rows = [
            ("Genere le", now),
            ("Points baseline", ", ".join(baseline.points)),
            ("Points courant", ", ".join(current.points)),
        ]
        if meta:
            seen_keys = {k for k, _ in info_rows}
            info_rows += [(k, v) for k, v in meta.items() if k not in seen_keys]
        story.append(_kv_table(info_rows, styles))
        story.append(PageBreak())

        # -- par ou commencer (triage) --
        story.append(Paragraph("Par ou commencer", styles["H1b"]))
        story.append(
            Paragraph(
                "Segments cumulant le plus d'ecarts (regressions et points a verifier "
                "pesant plus qu'une amelioration), et/ou touches par plusieurs "
                "categories a la fois.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.3 * cm))
        story.append(_health_badge(ranked, styles))
        story.append(_triage_table(ranked, styles))
        story.append(PageBreak())

        # -- constats --
        story.append(Paragraph("Constats", styles["H1b"]))
        n_reg = sum(1 for f in findings if f.severity == "regression")
        n_ver = sum(1 for f in findings if f.severity == "a_verifier")
        n_ame = sum(1 for f in findings if f.severity == "amelioration")
        story.append(
            Paragraph(
                f"{n_reg} regression(s), {n_ver} point(s) a verifier, {n_ame} "
                f"amelioration(s) identifies entre les deux runs.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.3 * cm))
        chart_path = f"{tmpdir}/chart_severity.png"
        if chart_severity_summary(findings, chart_path, scheme=DIFF_SEVERITY_SCHEME):
            story.append(Image(chart_path, width=8 * cm, height=6 * cm))
        story.append(Spacer(1, 0.3 * cm))
        story.append(_finding_table(findings, styles))

        if tls_findings_baseline or tls_findings_current or quic_findings_baseline or quic_findings_current:
            story.append(PageBreak())
            story.append(Paragraph("Diagnostics TLS / QUIC -- baseline vs courant", styles["H1b"]))
            story.append(
                Paragraph(
                    "Pipeline de decodage independant, execute separement sur le baseline "
                    "et sur le run courant (voir netcross_core.tls_diagnostics / "
                    "quic_diagnostics) -- pas de diff semantique entre les deux, ces deux "
                    "modules ne connaissent qu'un etat a un instant donne. Comparer les "
                    "deux sous-sections a l'oeil plutot que de chercher un ecart chiffre.",
                    styles["Small"],
                )
            )
            story.append(Spacer(1, 0.3 * cm))
            if tls_findings_baseline or tls_findings_current:
                story.append(Paragraph("TLS -- Baseline", styles["Heading3"]))
                story.append(_finding_table(tls_findings_baseline or [], styles))
                story.append(Spacer(1, 0.2 * cm))
                story.append(Paragraph("TLS -- Courant", styles["Heading3"]))
                story.append(_finding_table(tls_findings_current or [], styles))
                story.append(Spacer(1, 0.3 * cm))
            if quic_findings_baseline or quic_findings_current:
                story.append(Paragraph("QUIC/HTTP3 -- Baseline", styles["Heading3"]))
                story.append(_finding_table(quic_findings_baseline or [], styles))
                story.append(Spacer(1, 0.2 * cm))
                story.append(Paragraph("QUIC/HTTP3 -- Courant", styles["Heading3"]))
                story.append(_finding_table(quic_findings_current or [], styles))

        story.append(Spacer(1, 1 * cm))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))
        story.append(
            Paragraph(
                "Rapport de comparaison genere automatiquement par cross_capture_diff "
                "(netcross). Chaque ecart releve un seuil explicite (voir "
                "netcross_core.baseline_diff) ; a confirmer avec le contexte operationnel "
                "(changement volontaire, charge differente entre les deux runs...).",
                styles["Small"],
            )
        )

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
        )
        doc.build(story)

    return output_path
