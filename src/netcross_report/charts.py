"""netcross_report.charts -- graphiques matplotlib exportes en PNG pour le PDF."""

import statistics

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

from netcross_core.correlate import TOPN_OTHER_LABEL
from netcross_core.logging_config import get_logger, summarize
from netcross_report.path_metrics import build_path_metrics

logger = get_logger(__name__)


def chart_topology(r, path):
    """
    Diagramme de la topologie deduite : noeuds = points de capture,
    disposes par couches (generations topologiques) de l'amont vers
    l'aval, arcs annotes de la confiance TTL. Points de branchement,
    convergence et isoles distingues par couleur.
    """
    if not r.topology_edges:
        logger.debug("chart_topology: retour None")
        return None

    import networkx as nx
    from matplotlib.patches import Patch

    G = nx.DiGraph()  # noqa: N806 -- convention NetworkX (G pour un objet Graph/DiGraph,
    # reprise telle quelle de la documentation/des exemples officiels de la bibliotheque).
    G.add_nodes_from(r.points)
    for u, d, info in r.topology_edges:
        G.add_edge(u, d, **info)

    try:
        generations = list(nx.topological_generations(G))
    except nx.NetworkXUnfeasible:
        logger.exception("échec dans chart_topology")
        generations = None  # ne devrait pas arriver (reduction transitive deja acyclique)

    pos = {}
    if generations:
        for layer_idx, layer_nodes in enumerate(generations):
            for i, node in enumerate(sorted(layer_nodes)):
                pos[node] = (layer_idx, -i)
    if not pos or len(pos) < len(G.nodes()):
        pos.update(nx.spring_layout(G, seed=42, pos=pos or None))

    max_layer_size = max((len(layer) for layer in generations), default=1) if generations else len(G.nodes())
    fig_height = max(3.0, min(8.0, 1.4 * max_layer_size + 1.2))
    fig, ax = plt.subplots(figsize=(9, fig_height))

    node_colors = []
    for n in G.nodes():
        if n in r.topology_branch_points:
            node_colors.append("#f59e0b")
        elif n in r.topology_merge_points:
            node_colors.append("#8b5cf6")
        elif n in r.topology_isolated:
            node_colors.append("#94a3b8")
        else:
            node_colors.append("#3b82f6")

    nx.draw_networkx_nodes(
        G,
        pos,
        ax=ax,
        node_color=node_colors,
        node_size=1600,
        edgecolors="white",
        linewidths=1.5,
    )
    nx.draw_networkx_labels(G, pos, ax=ax, font_size=9, font_color="white", font_weight="bold")
    nx.draw_networkx_edges(
        G,
        pos,
        ax=ax,
        arrowsize=18,
        arrowstyle="-|>",
        node_size=1600,
        connectionstyle="arc3,rad=0.08",
        edge_color="#475569",
        width=1.4,
    )

    edge_labels = {(u, d): f"{info['confidence'] * 100:.0f}%" for u, d, info in r.topology_edges}
    nx.draw_networkx_edge_labels(
        G,
        pos,
        edge_labels=edge_labels,
        ax=ax,
        font_size=7,
        bbox={"boxstyle": "round,pad=0.1", "fc": "white", "ec": "none", "alpha": 0.8},
    )

    ax.set_title("Topologie deduite (delta TTL + recouvrement de flux)")
    ax.axis("off")
    ax.margins(0.15, 0.25)

    legend_elems = [
        Patch(facecolor="#3b82f6", label="Point normal"),
        Patch(facecolor="#f59e0b", label="Branchement"),
        Patch(facecolor="#8b5cf6", label="Convergence"),
        Patch(facecolor="#94a3b8", label="Isole (peu/pas de trafic commun)"),
    ]
    ax.legend(
        handles=legend_elems,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.02),
        ncol=4,
        fontsize=7,
        framealpha=0.9,
    )

    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.debug("chart_topology: retour path")
    return path


def _save(fig, path):
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    logger.debug("_save: fin")


def chart_throughput(r, path):
    logger.debug("chart_throughput: r={} path={}", summarize(r, "r"), summarize(path, "path"))
    points = [p for p in r.points if r.throughput.get(p)]
    if not points:
        logger.debug("chart_throughput: retour None")
        return None
    avgs = [statistics.mean(r.throughput[p].values()) * 8 / 1000 / r.bucket_seconds for p in points]
    maxs = [max(r.throughput[p].values()) * 8 / 1000 / r.bucket_seconds for p in points]
    fig, ax = plt.subplots(figsize=(6, 3))
    x = range(len(points))
    ax.bar([i - 0.2 for i in x], avgs, width=0.4, label="moyen", color="#3b82f6")
    ax.bar([i + 0.2 for i in x], maxs, width=0.4, label="max", color="#93c5fd")
    ax.set_xticks(list(x))
    ax.set_xticklabels(points)
    ax.set_ylabel("kbps")
    ax.set_title("Debit par point")
    ax.legend()
    _save(fig, path)
    logger.debug("chart_throughput: retour path")
    return path


def chart_latency(r, path):
    logger.debug("chart_latency: r={} path={}", summarize(r, "r"), summarize(path, "path"))
    pairs = [(a, b) for (a, b) in r.pairs if r.latency.get((a, b))]
    if not pairs:
        logger.debug("chart_latency: retour None")
        return None
    labels = [f"{a}->{b}" for a, b in pairs]
    avgs = [statistics.mean(r.latency[(a, b)]) for a, b in pairs]
    jitters = [statistics.pstdev(r.latency[(a, b)]) if len(r.latency[(a, b)]) > 1 else 0 for a, b in pairs]
    fig, ax = plt.subplots(figsize=(6, 3))
    x = range(len(pairs))
    ax.bar(x, avgs, yerr=jitters, capsize=4, color="#10b981")
    ax.set_xlim(-0.6, len(labels) - 0.4)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylabel("ms")
    ax.set_title("Latence moyenne par segment (barre d'erreur = gigue)")
    _save(fig, path)
    logger.debug("chart_latency: retour path")
    return path


def chart_loss(r, path):
    logger.debug("chart_loss: r={} path={}", summarize(r, "r"), summarize(path, "path"))
    points = [p for p in r.points if r.loss_count.get(p, 0) > 0]
    if not points:
        logger.debug("chart_loss: retour None")
        return None
    values = [r.loss_count[p] for p in points]
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.bar(points, values, color="#ef4444")
    ax.set_ylabel("paquets manquants")
    ax.set_title("Pertes par point")
    _save(fig, path)
    logger.debug("chart_loss: retour path")
    return path


TOPN_DIMENSION_TITLES = {
    "protocol": "Protocole",
    "port": "Port de destination",
    "ip": "IP de destination",
    "dscp": "Marquage DSCP",
}

# Palette qualitative (pas de degrade, categories sans ordre naturel) --
# "autres" (agregat de la longue traine, voir netcross_core.correlate.
# compute_topn_series) est toujours en dernier et grise, distinct des
# vraies categories quel que soit le nombre de series de ce graphique.
_TOPN_PALETTE = ["#3b82f6", "#f59e0b", "#10b981", "#ef4444", "#8b5cf6", "#06b6d4", "#f472b6"]
_TOPN_OTHER_COLOR = "#cbd5e1"


def chart_topn_timeseries(r, point, dimension, path):
    """
    Aire empilee du debit par categorie au fil du temps, pour UN point de
    capture et UNE dimension ("protocol"/"port"/"ip"/"dscp" -- voir
    netcross_core.correlate.TOPN_DIMENSIONS). None si aucune donnee pour
    ce point/cette dimension (point absent de r.topn_timeseries, ou point
    sans aucun paquet).

    Un seul point est trace par appel (pas tous les points empiles
    ensemble) : superposer plusieurs points sur la meme figure melangerait
    des paquets potentiellement vus en double (le meme paquet peut
    traverser plusieurs points de capture), cassant la lisibilite de
    l'aire empilee -- meme raison que compute_topn_series() classe le
    top-N independamment par point plutot que globalement. Voir
    generate_topn_charts() pour le choix du/des point(s) traces dans le
    rapport.
    """
    logger.debug(
        "chart_topn_timeseries: r={} point={} dimension={} path={}",
        summarize(r, "r"),
        summarize(point, "point"),
        summarize(dimension, "dimension"),
        summarize(path, "path"),
    )
    by_cat = r.topn_timeseries.get(dimension, {}).get(point)
    if not by_cat:
        logger.debug("chart_topn_timeseries: retour None")
        return None

    all_buckets = sorted({b for buckets in by_cat.values() for b in buckets})
    if not all_buckets:
        logger.debug("chart_topn_timeseries: retour None")
        return None

    # "autres" (s'il existe) trace en dernier et grise -- le reste dans
    # l'ordre decroissant de volume total, pour un empilement lisible
    # (categories dominantes en bas).
    cats = [c for c in by_cat if c != TOPN_OTHER_LABEL]
    cats.sort(key=lambda c: sum(by_cat[c].values()), reverse=True)
    if TOPN_OTHER_LABEL in by_cat:
        cats.append(TOPN_OTHER_LABEL)

    x = [(b - all_buckets[0]) * r.bucket_seconds for b in all_buckets]
    series = [[by_cat[c].get(b, 0) * 8 / 1000 / r.bucket_seconds for b in all_buckets] for c in cats]
    colors = [
        _TOPN_OTHER_COLOR if c == TOPN_OTHER_LABEL else _TOPN_PALETTE[i % len(_TOPN_PALETTE)]
        for i, c in enumerate(cats)
    ]

    fig, ax = plt.subplots(figsize=(9, 3.2))
    ax.stackplot(x, series, labels=cats, colors=colors)
    ax.set_xlabel("secondes depuis le debut de la capture")
    ax.set_ylabel("kbps")
    ax.set_title(f"{TOPN_DIMENSION_TITLES.get(dimension, dimension)} au fil du temps -- point {point}")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=min(len(cats), 4), fontsize=7, framealpha=0.9)
    _save(fig, path)
    logger.debug("chart_topn_timeseries: retour path")
    return path


def generate_topn_charts(r, tmpdir, point=None):
    """
    Genere les 4 graphiques temporels top-N (protocole/port/IP/DSCP) pour
    UN SEUL point de capture -- par defaut le premier de r.points (choix
    documente : voir chart_topn_timeseries pour pourquoi on n'empile pas
    plusieurs points ensemble, et FEATURES.md pour la discussion complete
    de cette limitation assumee). `point` permet de cibler un autre point
    que le premier sans reanalyser la capture.

    Renvoie {dimension: chemin_png} pour les dimensions ayant produit un
    graphique (dimension absente du dict si aucune donnee).
    """
    logger.debug(
        "generate_topn_charts: r={} tmpdir={} point={}",
        summarize(r, "r"),
        summarize(tmpdir, "tmpdir"),
        summarize(point, "point"),
    )
    if point is None:
        point = r.points[0] if r.points else None
    if point is None:
        logger.debug("generate_topn_charts: retour dict")
        return {}
    charts = {}
    for dimension in r.topn_timeseries:
        path = f"{tmpdir}/chart_topn_{dimension}.png"
        result = chart_topn_timeseries(r, point, dimension, path)
        if result:
            charts[dimension] = result
    logger.debug("generate_topn_charts: retour charts")
    return charts


DEFAULT_SEVERITY_SCHEME = [
    ("anomalie", "Anomalies", "#ef4444"),
    ("a_surveiller", "A surveiller", "#f59e0b"),
    ("info", "Info", "#94a3b8"),
]

# vocabulaire de baseline_diff.DiffFinding -- reutilise ce meme graphique
# pour le rapport PDF de comparaison avant/apres (voir pdf.generate_diff_pdf)
DIFF_SEVERITY_SCHEME = [
    ("regression", "Regressions", "#ef4444"),
    ("a_verifier", "A verifier", "#f59e0b"),
    ("amelioration", "Ameliorations", "#22c55e"),
]


def chart_severity_summary(findings, path, scheme=None):
    logger.debug(
        "chart_severity_summary: findings={} path={} scheme={}",
        summarize(findings, "findings"),
        summarize(path, "path"),
        summarize(scheme, "scheme"),
    )
    scheme = scheme or DEFAULT_SEVERITY_SCHEME
    counts = {key: 0 for key, _, _ in scheme}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    if sum(counts.values()) == 0:
        logger.debug("chart_severity_summary: retour None")
        return None
    labels = [label for _, label, _ in scheme]
    values = [counts[key] for key, _, _ in scheme]
    bar_colors = [color for _, _, color in scheme]
    fig, ax = plt.subplots(figsize=(4, 3))
    ax.bar(labels, values, color=bar_colors)
    ax.set_title("Constats par gravite")
    for i, v in enumerate(values):
        if v:
            ax.text(i, v, str(v), ha="center", va="bottom")
    _save(fig, path)
    logger.debug("chart_severity_summary: retour path")
    return path


def chart_path_quality(metrics, path):
    """
    Qualite le long du chemin observe : delai P95 (barres, axe de gauche)
    et taux de perte (courbe, axe de droite) segment par segment, dans
    l'ordre amont -> aval.

    Deux echelles sur un meme graphique parce que c'est precisement leur
    superposition qui repond a la question de la section : un pic de delai
    SANS perte et un pic de delai AVEC perte ne se diagnostiquent pas
    pareil (file d'attente vs rupture). Les tracer separement obligerait a
    comparer deux images a l'oeil.

    Les segments non mesures sont conserves en abscisse -- un trou dans la
    mesure est une information de terrain (horloges non synchronisees, pas
    de trafic commun), le masquer ferait croire a un chemin plus court
    qu'il ne l'est. `None` si aucun segment.
    """
    logger.debug("chart_path_quality: metrics={} path={}", summarize(metrics, "metrics"), summarize(path, "path"))
    if not metrics:
        logger.debug("chart_path_quality: retour None")
        return None

    labels = [seg.label for seg in metrics]
    p95 = [seg.delay_p95_ms if seg.delay_p95_ms is not None else 0.0 for seg in metrics]
    loss = [seg.loss_pct if seg.loss_pct is not None else 0.0 for seg in metrics]

    fig, ax = plt.subplots(figsize=(9, max(3.2, 0.8 * len(labels) + 2.0)))
    x = range(len(labels))
    ax.bar(x, p95, color="#3b82f6", width=0.45, label="Delai P95 (ms)")
    ax.set_ylabel("Delai P95 (ms)", color="#1d4ed8")
    ax.tick_params(axis="y", labelcolor="#1d4ed8")
    ax.set_xlim(-0.6, len(labels) - 0.4)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)

    ax2 = ax.twinx()
    ax2.plot(list(x), loss, color="#ef4444", marker="o", linewidth=1.6, label="Perte (%)")
    ax2.set_ylabel("Perte au point aval (%)", color="#b91c1c")
    ax2.tick_params(axis="y", labelcolor="#b91c1c")
    ax2.set_ylim(bottom=0)

    for i, seg in enumerate(metrics):
        if seg.delay_p95_ms is None and seg.loss_pct is None:
            ax.annotate(
                "non mesure",
                (i, 0),
                textcoords="offset points",
                xytext=(0, 6),
                ha="center",
                fontsize=7,
                color="#64748b",
            )

    ax.set_title("Qualite par segment du chemin (amont -> aval)")
    ax.grid(axis="y", linestyle=":", alpha=0.4)
    handles = ax.get_legend_handles_labels()[0] + ax2.get_legend_handles_labels()[0]
    ax.legend(handles=handles, loc="upper left", fontsize=7, framealpha=0.9)
    _save(fig, path)
    logger.debug("chart_path_quality: retour path")
    return path


_SEQUENCE_POINT_COLORS = ["#3b82f6", "#f59e0b", "#10b981", "#8b5cf6", "#ef4444", "#06b6d4"]


def chart_sequence_diagram(view, path):
    """
    Diagramme de sequence d'un flux : les hotes en colonnes (lignes de vie
    verticales), le temps qui descend, une fleche par paquet vu a un point.

    La couleur de la fleche identifie le POINT DE CAPTURE, pas le
    protocole : deux fleches de meme couleur a quelques millisecondes
    d'ecart se lisent comme un meme paquet vu deux fois, ce qui est
    precisement l'information qu'apporte une capture multi-points. Chaque
    fleche porte son numero de trame quand la capture le fournit, pour que
    la ligne du dessin soit retrouvable dans Wireshark.

    `None` si la vue n'a aucune etape ou un seul hote (une fleche qui part
    et revient au meme endroit ne dessine rien de lisible).
    """
    logger.debug("chart_sequence_diagram: view={} path={}", summarize(view, "view"), summarize(path, "path"))
    if not view or not view.steps or len(view.hosts) < 2:
        logger.debug("chart_sequence_diagram: retour None")
        return None

    x = {host: i for i, host in enumerate(view.hosts)}
    colors_by_point = {
        point: _SEQUENCE_POINT_COLORS[i % len(_SEQUENCE_POINT_COLORS)] for i, point in enumerate(view.points)
    }
    n = len(view.steps)
    fig, ax = plt.subplots(figsize=(9, max(3.5, min(22.0, 0.52 * n + 2.0))))

    for host, xi in x.items():
        ax.axvline(xi, color="#cbd5e1", linewidth=1.0, zorder=1)
        ax.text(xi, 0.6, host, ha="center", va="bottom", fontsize=8, fontweight="bold")

    for i, step in enumerate(view.steps):
        y = -i
        x0, x1 = x[step.src], x[step.dst]
        color = colors_by_point[step.point]
        if x0 == x1:
            # src et dst du meme cote (broadcast/ARP vers une adresse non
            # vue ailleurs) : une fleche nulle ne se voit pas, on marque le
            # point sur la ligne de vie.
            ax.plot([x0], [y], marker="o", color=color, markersize=5, zorder=3)
        else:
            ax.annotate(
                "",
                xy=(x1, y),
                xytext=(x0, y),
                arrowprops={"arrowstyle": "-|>", "color": color, "linewidth": 1.3, "shrinkA": 2, "shrinkB": 2},
                zorder=3,
            )
        trame = f"#{step.frame_number} " if step.frame_number is not None else ""
        ax.text(
            (x0 + x1) / 2,
            y + 0.12,
            f"{trame}{step.label}",
            ha="center",
            va="bottom",
            fontsize=6.5,
            color="#1f2937",
        )
        ax.text(
            -0.55,
            y,
            f"{step.rel_ms:.1f} ms",
            ha="right",
            va="center",
            fontsize=6.5,
            color="#64748b",
        )

    ax.set_xlim(-1.35, len(view.hosts) - 0.4)
    ax.set_ylim(-n + 0.5, 1.6)
    ax.set_title(f"Sequence des echanges -- {view.title}" if view.title else "Sequence des echanges")
    ax.axis("off")
    handles = [Line2D([0], [0], color=colors_by_point[p], linewidth=2, label=f"Vu a {p}") for p in view.points]
    if view.truncated:
        handles.append(Line2D([0], [0], color="none", label=f"{view.truncated} paquet(s) non represente(s)"))
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.01), ncol=2, fontsize=7, framealpha=0.9)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.debug("chart_sequence_diagram: retour path")
    return path


def chart_comm_map(cmap, path):
    """
    Cartographie des communications : un noeud par hote, une fleche par sens
    d'echange. Taille du noeud et epaisseur de la fleche proportionnelles au
    volume ; une arete portant des signaux d'expertise (retransmissions,
    expert_flags) est tracee en rouge.

    Disposition en ressort (spring layout, graine fixe) : contrairement a la
    topologie des points de capture, un graphe d'hotes n'a pas de sens
    "amont -> aval" a respecter, et forcer des couches inventerait une
    hierarchie qui n'existe pas. La graine fixe garantit qu'une meme capture
    donne deux fois le meme dessin -- indispensable des lors que l'image
    illustre un rapport.

    `None` si la carte est vide (aucune arete apres filtrage).
    """
    logger.debug("chart_comm_map: cmap={} path={}", summarize(cmap, "cmap"), summarize(path, "path"))
    if not cmap or not cmap.edges:
        logger.debug("chart_comm_map: retour None")
        return None

    import networkx as nx
    from matplotlib.patches import Patch

    G = nx.DiGraph()  # noqa: N806 -- convention NetworkX, voir chart_topology
    for node in cmap.nodes:
        G.add_node(node.host, volume=node.bytes)
    for edge in cmap.edges:
        G.add_edge(edge.src, edge.dst, volume=edge.bytes, anomalies=edge.anomalies)

    pos = nx.spring_layout(G, seed=42, k=0.9)
    fig, ax = plt.subplots(figsize=(9, max(4.5, min(9.0, 0.45 * len(cmap.nodes) + 3.0))))

    max_bytes = max((n.bytes for n in cmap.nodes), default=1) or 1
    node_sizes = [400 + 1800 * (n.bytes / max_bytes) for n in cmap.nodes]
    node_colors = ["#ef4444" if n.anomalies else "#3b82f6" for n in cmap.nodes]
    nx.draw_networkx_nodes(
        G,
        pos,
        nodelist=[n.host for n in cmap.nodes],
        node_size=node_sizes,
        node_color=node_colors,
        edgecolors="white",
        linewidths=1.2,
        ax=ax,
    )
    # Etiquettes DECALEES sous les noeuds, sur fond blanc : une adresse IP
    # est plus large qu'un disque de graphe, et centree elle chevauchait les
    # fleches voisines (constate au premier rendu).
    labels_pos = {host: (x, y - 0.11) for host, (x, y) in pos.items()}
    nx.draw_networkx_labels(
        G,
        labels_pos,
        ax=ax,
        font_size=7,
        bbox={"boxstyle": "round,pad=0.15", "fc": "white", "ec": "#cbd5e1", "alpha": 0.9},
    )

    max_edge = max((e.bytes for e in cmap.edges), default=1) or 1
    for edge in cmap.edges:
        nx.draw_networkx_edges(
            G,
            pos,
            edgelist=[(edge.src, edge.dst)],
            ax=ax,
            width=0.8 + 2.6 * (edge.bytes / max_edge),
            edge_color="#ef4444" if edge.anomalies else "#475569",
            arrowsize=14,
            arrowstyle="-|>",
            connectionstyle="arc3,rad=0.12",
            node_size=1200,
        )
    edge_labels = {(e.src, e.dst): ",".join(sorted(e.protocols)) or "?" for e in cmap.edges}
    nx.draw_networkx_edge_labels(
        G,
        pos,
        edge_labels=edge_labels,
        ax=ax,
        font_size=6,
        rotate=False,
        bbox={"boxstyle": "round,pad=0.1", "fc": "white", "ec": "none", "alpha": 0.75},
    )

    ax.set_title(f"Communications observees ({len(cmap.edges)} arete(s) sur {cmap.total_edges})")
    ax.axis("off")
    ax.margins(0.12)
    ax.legend(
        handles=[
            Patch(facecolor="#3b82f6", label="Hote sans signal d'expertise"),
            Patch(facecolor="#ef4444", label="Signal d'expertise (retransmission, flag tshark)"),
        ],
        loc="upper center",
        bbox_to_anchor=(0.5, -0.01),
        ncol=2,
        fontsize=7,
        framealpha=0.9,
    )
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.debug("chart_comm_map: retour path")
    return path


def generate_all_charts(r, findings, tmpdir):
    logger.debug(
        "generate_all_charts: r={} findings={} tmpdir={}",
        summarize(r, "r"),
        summarize(findings, "findings"),
        summarize(tmpdir, "tmpdir"),
    )
    charts = {}
    for name, fn, args in [
        ("topology", chart_topology, (r,)),
        ("throughput", chart_throughput, (r,)),
        ("latency", chart_latency, (r,)),
        ("loss", chart_loss, (r,)),
        ("severity", chart_severity_summary, (findings,)),
        ("path_quality", chart_path_quality, (build_path_metrics(r),)),
    ]:
        path = f"{tmpdir}/chart_{name}.png"
        result = fn(*args, path)
        if result:
            charts[name] = result
    # graphiques temporels top-N : cles prefixees ("topn_protocol", ...)
    # pour ne pas entrer en collision avec les cles ci-dessus, un point
    # unique (voir generate_topn_charts) -- pas de parametre `point` ici,
    # generate_all_charts() reste l'entree "sans reglage" utilisee par
    # generate_pdf ; passer un autre point se fait en appelant
    # generate_topn_charts() directement (voir __init__.py).
    for dimension, path in generate_topn_charts(r, tmpdir).items():
        charts[f"topn_{dimension}"] = path
    logger.debug("generate_all_charts: retour charts")
    return charts
