"""
netcross_report.path_metrics -- metriques de qualite par segment du chemin
observe (Job 16/issue #12, FEATURES.md section 6.7).

Le rapport PDF disait deja, separement, "voici la topologie deduite" et
"voici les constats par segment". Il ne repondait pas a la question que
pose un operateur devant une plainte de lenteur : **ou, le long du chemin,
la qualite se degrade-t-elle ?** Les chiffres existaient tous dans
`Report`, mais eparpilles (`latency`, `loss_count`, `qos_change`,
`frag_new`, `hop_delta`, `throughput`...) et jamais rassembles segment par
segment, dans l'ordre du chemin.

Ce module fait exactement cela, et rien de plus : il REGROUPE des valeurs
deja calculees par `netcross_core.analyse()`. Aucun seuil, aucun verdict,
aucune severite n'est introduit ici -- c'est le role de
`netcross_report.synthesis`/`rule_engine`. Les formules reprennent celles
deja utilisees ailleurs dans le projet, pour qu'un meme chiffre ne prenne
jamais deux valeurs selon la sortie qui l'affiche :

  * delai moyen et percentiles : `build_baseline_profile()`
    (`netcross_core.baseline_profile`), donc meme convention
    d'interpolation que les profils de reference ;
  * gigue : `statistics.pstdev()` des delais, comme
    `netcross_core.report_text.print_report()` -- ecart-type de
    POPULATION, volontairement different du `std` (echantillon) du profil
    de reference ci-dessus : la console affiche cette valeur sous le nom
    "gigue" depuis le debut, le PDF ne doit pas en afficher une autre ;
  * taux de perte : `loss_count / seen_count` au point aval, comme
    `netcross_report.synthesis.build_findings()`.

L'ordre des segments suit le chemin deduit (`Report.topology_edges`) quand
il est disponible, sinon l'ordre de `Report.pairs`. Le tri topologique est
refait ici en une dizaine de lignes (algorithme de Kahn) plutot que via
networkx : ce module doit rester importable sans dependance externe, comme
le reste de `netcross_report` hors `pdf`/`charts`.

Couche : `netcross_report` peut importer `netcross_core`, jamais l'inverse.
"""

import statistics
from dataclasses import dataclass

from netcross_core.baseline_profile import build_baseline_profile
from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)


@dataclass
class SegmentMetrics:
    """Qualite observee sur UN segment (couple de points de capture
    consecutifs). Un champ a `None` signifie "non mesurable sur ce
    segment" (aucun paquet correle, horloges non exploitables...), jamais
    "zero" : un delai inconnu et un delai nul ne se lisent pas de la meme
    facon dans un rapport remis a un tiers.
    """

    upstream: str
    downstream: str
    # -- delai (ms), None si aucun couple de paquets correle --
    samples: int = 0
    delay_avg_ms: float | None = None
    delay_p50_ms: float | None = None
    delay_p95_ms: float | None = None
    delay_p99_ms: float | None = None
    jitter_ms: float | None = None
    # -- pertes au point AVAL du segment --
    loss_count: int = 0
    loss_pct: float | None = None
    # -- debit moyen observe au point aval (bits/s), None si non mesure --
    throughput_bps: float | None = None
    # -- compteurs deja agreges par segment dans Report --
    dscp_changes: int = 0
    frag_new: int = 0
    pmtud_blackhole: int = 0
    retrans: int = 0
    hops: int | None = None
    hop_outliers: int = 0

    @property
    def label(self) -> str:
        """Libelle du segment, identique a celui des Finding
        (`f"{a} -> {b}"`) : le lecteur doit pouvoir rapprocher une ligne de
        ce tableau d'un constat du triage sans traduction mentale."""
        logger.debug("SegmentMetrics.label: retour chaîne formatée")
        return f"{self.upstream} -> {self.downstream}"

    @property
    def measured(self) -> bool:
        """Vrai si au moins une metrique de qualite a pu etre mesuree. Un
        segment non mesure est affiche quand meme (son absence de donnees
        est une information), mais il ne participe pas au classement des
        degradations."""
        logger.debug("SegmentMetrics.measured: retour self.samples > 0 or self.loss_count > 0 or bool(s…")
        return self.samples > 0 or self.loss_count > 0 or bool(self.dscp_changes or self.frag_new)


def _topological_points(report) -> list[str]:
    """Points de capture ordonnes de l'amont vers l'aval d'apres
    `topology_edges` (algorithme de Kahn, ordre alphabetique a rang egal
    pour rester deterministe d'une execution a l'autre). Les points absents
    du graphe sont rendus a la fin, dans l'ordre de `report.points`.

    Retourne `[]` si la topologie n'a pas ete deduite ou contient un cycle
    -- l'appelant retombe alors sur l'ordre de `report.pairs`, qui est
    toujours defini.
    """
    logger.debug("_topological_points: report={}", summarize(report, "report"))
    edges = list(getattr(report, "topology_edges", None) or [])
    if not edges:
        logger.debug("_topological_points: si not edges -> retour liste vide")
        return []
    successors: dict[str, list[str]] = {}
    in_degree: dict[str, int] = {}
    for u, d, _info in edges:
        successors.setdefault(u, []).append(d)
        in_degree.setdefault(u, 0)
        in_degree[d] = in_degree.get(d, 0) + 1
    ordered: list[str] = []
    ready = sorted(n for n, deg in in_degree.items() if deg == 0)
    while ready:
        node = ready.pop(0)
        ordered.append(node)
        for nxt in sorted(successors.get(node, ())):
            in_degree[nxt] -= 1
            if in_degree[nxt] == 0:
                ready.append(nxt)
        ready.sort()
    if len(ordered) != len(in_degree):
        logger.debug("_topological_points: si len(ordered) != len(in_degree) -> retour liste vide")
        return []  # cycle : on ne pretend pas connaitre l'ordre du chemin
    ordered.extend(p for p in report.points if p not in in_degree)
    logger.debug("_topological_points: retour ordered={}", summarize(ordered, "ordered"))
    return ordered


def _ordered_pairs(report) -> list[tuple[str, str]]:
    """Couples (amont, aval) de `report.pairs`, ordonnes le long du chemin
    deduit quand c'est possible. `report.pairs` reste la source de verite
    des segments EXISTANTS : la topologie ne sert qu'a les trier, jamais a
    en ajouter ou en retirer."""
    logger.debug("_ordered_pairs: report={}", summarize(report, "report"))
    pairs = list(report.pairs)
    order = _topological_points(report)
    if not order:
        logger.debug("_ordered_pairs: si not order -> retour pairs={}", summarize(pairs, "pairs"))
        return pairs
    rank = {point: i for i, point in enumerate(order)}
    fallback = len(rank)
    logger.debug("_ordered_pairs: retour sorted(…)")
    return sorted(pairs, key=lambda ab: (rank.get(ab[0], fallback), rank.get(ab[1], fallback)))


def _throughput_bps(report, point) -> float | None:
    """Debit moyen au point donne, en bits/s : octets totaux du point
    divises par la duree couverte par ses tranches temporelles. `None` si
    aucune tranche (option de debit non calculee sur ce run)."""
    buckets = (report.throughput or {}).get(point) or {}
    if not buckets:
        logger.debug("_throughput_bps: si not buckets -> retour None")
        return None
    duration = max(len(buckets), 1) * (report.bucket_seconds or 1.0)
    logger.debug("_throughput_bps: retour sum(buckets.values()) * 8.0 / duration")
    return sum(buckets.values()) * 8.0 / duration


def build_path_metrics(report) -> list[SegmentMetrics]:
    """Une entree par segment de `report.pairs`, ordonnee le long du chemin
    observe. Pure fonction de regroupement : aucune capture relue, aucun
    seuil applique."""
    logger.debug("build_path_metrics: report={}", summarize(report, "report"))
    metrics = []
    for a, b in _ordered_pairs(report):
        delays = list(report.latency.get((a, b), []) or [])
        seg = SegmentMetrics(upstream=a, downstream=b, samples=len(delays))
        if delays:
            profile = build_baseline_profile("delay_ms", delays)
            seg.delay_avg_ms = profile.mean
            seg.delay_p50_ms = profile.percentiles.get("P50")
            seg.delay_p95_ms = profile.percentiles.get("P95")
            seg.delay_p99_ms = profile.percentiles.get("P99")
            seg.jitter_ms = statistics.pstdev(delays) if len(delays) > 1 else 0.0
        seg.loss_count = report.loss_count.get(b, 0)
        seen = report.seen_count.get(b, 0)
        if seen:
            seg.loss_pct = 100.0 * seg.loss_count / seen
        seg.throughput_bps = _throughput_bps(report, b)
        seg.dscp_changes = report.qos_change.get((a, b), 0)
        seg.frag_new = report.frag_new.get((a, b), 0)
        seg.pmtud_blackhole = report.pmtud_blackhole.get((a, b), 0)
        seg.retrans = report.retrans.get(b, 0)
        hop_deltas = list(report.hop_delta.get((a, b), []) or [])
        if hop_deltas:
            seg.hops = int(statistics.median(hop_deltas))
        seg.hop_outliers = report.hop_delta_outliers.get((a, b), 0)
        metrics.append(seg)
    logger.debug("build_path_metrics: retour metrics={}", summarize(metrics, "metrics"))
    return metrics


def rank_path_segments(metrics) -> list[SegmentMetrics]:
    """Segments mesures, du plus degrade au moins degrade : **pertes
    d'abord**, delai P95 ensuite, gigue en dernier recours.

    Ce n'est pas un score compose : un segment qui perd des paquets passe
    devant un segment simplement lent, quel que soit l'ecart de delai. Un
    paquet perdu est une panne fonctionnelle (retransmission, coupure de
    session), un delai eleve une degradation de confort -- meme hierarchie
    que les severites de `netcross_report.synthesis` (Pertes = anomalie des
    5%, latence = a_surveiller). Les segments non mesures sont exclus :
    les classer les mettrait a egalite avec des segments sains alors qu'on
    ne sait rien d'eux.
    """
    logger.debug("rank_path_segments: metrics={}", summarize(metrics, "metrics"))
    return sorted(
        (seg for seg in metrics if seg.measured),
        key=lambda seg: (
            -(seg.loss_pct or 0.0),
            -(seg.delay_p95_ms or 0.0),
            -(seg.jitter_ms or 0.0),
            seg.label,
        ),
    )


def degradation_summary(metrics) -> str:
    """Phrase de tete de section : ou la qualite se degrade-t-elle ?
    Descriptive et chiffree, jamais prescriptive -- les recommandations
    restent du ressort des Finding/ExpertEvent."""
    logger.debug("degradation_summary: metrics={}", summarize(metrics, "metrics"))
    ranked = rank_path_segments(metrics)
    if not metrics:
        logger.debug('degradation_summary: si not metrics -> retour "Aucun segment exploitable : la topolog…')
        return "Aucun segment exploitable : la topologie n'a pas pu etre deduite de ces captures."
    if not ranked:
        logger.debug("degradation_summary: si not ranked -> retour 'Aucune metrique de qualite mesurable s…")
        return (
            "Aucune metrique de qualite mesurable sur les segments observes "
            "(ni delai, ni perte, ni remarquage) -- horloges non synchronisees "
            "ou trafic commun insuffisant entre les points."
        )
    pire = ranked[0]
    details = []
    if pire.loss_pct is not None and pire.loss_count:
        details.append(f"{pire.loss_count} paquet(s) perdu(s) ({pire.loss_pct:.1f}%)")
    if pire.delay_p95_ms is not None:
        details.append(f"delai P95 {pire.delay_p95_ms:.1f} ms")
    if pire.jitter_ms:
        details.append(f"gigue {pire.jitter_ms:.1f} ms")
    if not details:
        details.append("aucune metrique chiffree")
    logger.debug("degradation_summary: retour f'Segment le plus degrade : (pire.label) -- ' + '…")
    return f"Segment le plus degrade : {pire.label} -- " + ", ".join(details) + "."
