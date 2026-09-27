"""
netcross_core.baseline_diff -- compare deux Report (avant/apres un
correctif, site A / site B, ou toute paire de scenarios comparables) et
produit des constats de regression/amelioration.

Module volontairement independant : il ne fait que lire des objets
Report deja construits par analyse() -- il n'importe, ne modifie et ne
depend d'aucun autre fichier de netcross_core (parsing/analysis/models/
correlate/synthesis). Deux Report peuvent donc etre produits par deux
appels a analyse() completement separes (voir cross_capture_diff_cli.py)
sans aucun etat partage entre les deux runs.

Hypothese de base : les memes labels de point sont reutilises entre le
baseline et le courant (ex: "LAN", "WAN", "DC" des deux cotes) -- c'est
ce qui permet de dire "le point WAN allait bien avant, il degrade
maintenant" plutot que de comparer des points sans rapport. Si un label
n'existe que d'un cote, on le signale explicitement plutot que de
l'ignorer silencieusement.
"""

from __future__ import annotations

import csv
import statistics
from dataclasses import dataclass, field

from netcross_core.expert_model import EvidenceLink, PacketEvidence
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Report

logger = get_logger(__name__)

SEVERITY_ORDER = {"regression": 0, "a_verifier": 1, "amelioration": 2, "stable": 3}


@dataclass
class DiffFinding:
    severity: str  # "regression" | "amelioration" | "a_verifier" | "stable"
    category: str
    segment: str  # nom du point, ou "A -> B" pour un arc
    message: str
    before: float | None = None
    after: float | None = None
    # taille de l'echantillon derriere une VALEUR ESTIMEE (taux, moyenne, MOS) --
    # cote "apres" en priorite (l'etat qu'on evalue maintenant). Volontairement
    # absent sur les comparaisons de compteurs bruts (_compare_count) : un
    # evenement observe une seule fois est une preuve directe, pas une
    # estimation fragile -- voir synthesis.py pour la meme distinction.
    sample_size: int | None = None
    # Preuve textuelle deja collectee dans Report (Session 33 -- suite de
    # l'EvidenceLink introduit en Session 32 pour Finding). Decision de
    # conception tranchee ici (laissee ouverte en Session 32) : la preuve
    # vient toujours du rapport COURANT (meme priorite "apres" que
    # sample_size ci-dessus), jamais du baseline ni des deux a la fois --
    # c'est l'etat courant qui justifie une regression, le baseline ne sert
    # que de point de comparaison numerique. Volontairement absent sur les
    # categories qui n'ont pas de champ `*_examples`/liste correspondant sur
    # Report (pertes, latence, la plupart des compteurs TCP...), meme
    # principe que synthesis.py.
    evidence: list[EvidenceLink] = field(default_factory=list)


def _pct(n: float, d: float) -> float:
    logger.debug("_pct: retour conditionnel")
    return (n / d * 100.0) if d else 0.0


def _mean(values: list[float]) -> float | None:
    logger.debug("_mean: retour conditionnel")
    return statistics.mean(values) if values else None


def _p95(values: list[float]) -> float | None:
    if not values:
        logger.debug("_p95: retour None")
        return None
    s = sorted(values)
    idx = min(len(s) - 1, round(0.95 * (len(s) - 1)))
    logger.debug("_p95: retour element")
    return s[idx]


def _fmt(v: float | None, unit: str = "") -> str:
    logger.debug("_fmt: retour conditionnel")
    return "n/a" if v is None else f"{v:.1f}{unit}"


def _evidence(point: str, texts, frames: list[int | None] | None = None) -> list[EvidenceLink]:
    """Meme fonction que netcross_report.synthesis._evidence, dupliquee ici
    plutot que partagee : netcross_core ne peut pas importer depuis
    netcross_report (contrat de couches impose par import-linter, voir
    pyproject.toml), et ce module reste par ailleurs volontairement
    independant du reste de netcross_core (voir docstring de module) --
    meme discipline de duplication assumee que `_run_live_captures` entre
    les deux CLI (Session 16).

    `frames` (Session 37, optionnel) : liste parallele de numeros de
    trame (`Report.*_frames`, MEME index que `texts`) -- chaque
    `EvidenceLink` gagne alors un `packet` (PacketEvidence) plutot que
    `None`. Meme mecanisme que la version netcross_report.synthesis
    (Session 35, pilote PMTUD ; Session 37, etendu aux huit autres
    categories deja porteuses d'un EvidenceLink textuel sur DiffFinding)."""
    if not frames:
        logger.debug("_evidence: retour liste")
        return [EvidenceLink(point, t) for t in texts]
    links = []
    for t, fn in zip(texts, frames):
        packet = PacketEvidence(point, fn) if fn is not None else None
        links.append(EvidenceLink(point, t, packet=packet))
    logger.debug("_evidence: retour links")
    return links


def _http_error_evidence(examples: list[str], status_class: int, frames: list[int | None] | None = None):
    """Meme filtre que netcross_report.synthesis._http_error_evidence
    (duplique pour la meme raison de couches, voir _evidence ci-dessus) :
    http_error_examples melange 4xx et 5xx a la collecte, la distinction ne
    peut se faire qu'ici sur le suffixe "-> NNN" de chaque exemple.

    `frames` (Session 37, optionnel) : liste parallele de numeros de trame
    (`Report.http_error_frames`, MEME index que `examples`), filtree avec
    le meme critere que les textes. Renvoie (textes_filtres,
    frames_filtrees) -- frames_filtrees vide si `frames` n'est pas
    fourni."""
    texts = []
    filtered_frames = []
    for i, ex in enumerate(examples):
        try:
            code = int(ex.rsplit(" ", 1)[-1])
        except ValueError:
            logger.exception("échec dans _http_error_evidence")
            continue
        if code // 100 == status_class:
            texts.append(ex)
            if frames is not None and i < len(frames):
                filtered_frames.append(frames[i])
    logger.debug("_http_error_evidence: retour tuple")
    return texts, filtered_frames


def _common_points(baseline: Report, current: Report) -> tuple[list[str], list[str], list[str]]:
    """Renvoie (points_communs, presents_seulement_avant, presents_seulement_apres)."""
    logger.debug(
        "_common_points: baseline={} current={}",
        summarize(baseline, "baseline"),
        summarize(current, "current"),
    )
    b, c = set(baseline.points), set(current.points)
    common = sorted(b & c)
    only_before = sorted(b - c)
    only_after = sorted(c - b)
    logger.debug("_common_points: retour tuple")
    return common, only_before, only_after


def _compare_rate(
    findings: list[DiffFinding],
    category: str,
    segment: str,
    before_n: int,
    before_d: int,
    after_n: int,
    after_d: int,
    min_pp: float = 2.0,
    label: str = "taux",
    evidence: list[EvidenceLink] | None = None,
) -> None:
    """
    Compare un taux avant/apres (ex: pertes / paquets vus). Ne remonte un
    constat que si l'ecart depasse min_pp points de pourcentage --
    evite le bruit sur des ecarts de 0.1% qui n'ont aucune signification
    operationnelle.
    """
    logger.debug(
        "_compare_rate: findings={} category={} segment={} before_n={} before_d={} after_n={} "
        "after_d={} min_pp={} label={} evidence={}",
        summarize(findings, "findings"),
        summarize(category, "category"),
        summarize(segment, "segment"),
        summarize(before_n, "before_n"),
        summarize(before_d, "before_d"),
        summarize(after_n, "after_n"),
        summarize(after_d, "after_d"),
        summarize(min_pp, "min_pp"),
        summarize(label, "label"),
        summarize(evidence, "evidence"),
    )
    before_rate = _pct(before_n, before_d)
    after_rate = _pct(after_n, after_d)
    delta = after_rate - before_rate
    if abs(delta) < min_pp:
        logger.debug("_compare_rate: retour (None implicite)")
        return
    severity = "regression" if delta > 0 else "amelioration"
    findings.append(
        DiffFinding(
            severity,
            category,
            segment,
            f"{label} {before_rate:.1f}% ({before_n}/{before_d}) -> {after_rate:.1f}% ({after_n}/{after_d})",
            before_rate,
            after_rate,
            sample_size=after_d,
            evidence=evidence or [],
        )
    )
    logger.debug("_compare_rate: fin")


def _compare_count(
    findings: list[DiffFinding],
    category: str,
    segment: str,
    before: int,
    after: int,
    min_delta: int = 3,
    rel_threshold: float = 0.5,
    label: str = "occurrences",
    higher_is_worse: bool = True,
    evidence: list[EvidenceLink] | None = None,
) -> None:
    """
    Compare un compteur brut (RST localises, SYN sans reponse, NAK
    DHCP...). Un constat n'est remonte que si l'ecart absolu ET l'ecart
    relatif depassent les seuils -- un passage de 1 a 4 (delta=3,
    +300%) est significatif, un passage de 400 a 403 (delta=3, +0.75%)
    ne l'est pas.
    """
    logger.debug(
        "_compare_count: findings={} category={} segment={} before={} after={} min_delta={} "
        "rel_threshold={} label={} higher_is_worse={} evidence={}",
        summarize(findings, "findings"),
        summarize(category, "category"),
        summarize(segment, "segment"),
        summarize(before, "before"),
        summarize(after, "after"),
        summarize(min_delta, "min_delta"),
        summarize(rel_threshold, "rel_threshold"),
        summarize(label, "label"),
        summarize(higher_is_worse, "higher_is_worse"),
        summarize(evidence, "evidence"),
    )
    delta = after - before
    if abs(delta) < min_delta:
        logger.debug("_compare_count: retour (None implicite)")
        return
    rel = abs(delta) / before if before else float("inf")
    if rel < rel_threshold:
        logger.debug("_compare_count: retour (None implicite)")
        return
    got_worse = delta > 0 if higher_is_worse else delta < 0
    severity = "regression" if got_worse else "amelioration"
    findings.append(
        DiffFinding(
            severity,
            category,
            segment,
            f"{label} : {before} -> {after} ({delta:+d})",
            float(before),
            float(after),
            evidence=evidence or [],
        )
    )
    logger.debug("_compare_count: fin")


def _compare_latency(
    findings: list[DiffFinding],
    segment: str,
    before: list[float],
    after: list[float],
    min_ms: float = 5.0,
    rel_threshold: float = 0.2,
) -> None:
    logger.debug(
        "_compare_latency: findings={} segment={} before={} after={} min_ms={} rel_threshold={}",
        summarize(findings, "findings"),
        summarize(segment, "segment"),
        summarize(before, "before"),
        summarize(after, "after"),
        summarize(min_ms, "min_ms"),
        summarize(rel_threshold, "rel_threshold"),
    )
    b_mean, a_mean = _mean(before), _mean(after)
    if b_mean is None or a_mean is None:
        if before and not after:
            findings.append(
                DiffFinding(
                    "a_verifier",
                    "Latence",
                    segment,
                    f"latence mesurable avant ({b_mean:.1f}ms) mais plus aucun echantillon apres",
                    sample_size=len(before),
                )
            )
        elif after and not before:
            findings.append(
                DiffFinding(
                    "a_verifier",
                    "Latence",
                    segment,
                    f"aucun echantillon avant, latence mesurable apres ({a_mean:.1f}ms)",
                    sample_size=len(after),
                )
            )
        logger.debug("_compare_latency: retour (None implicite)")
        return
    delta = a_mean - b_mean
    rel = abs(delta) / b_mean if b_mean else float("inf")
    if abs(delta) < min_ms or rel < rel_threshold:
        logger.debug("_compare_latency: retour (None implicite)")
        return
    severity = "regression" if delta > 0 else "amelioration"
    b_p95, a_p95 = _p95(before), _p95(after)
    findings.append(
        DiffFinding(
            severity,
            "Latence",
            segment,
            f"latence moyenne {b_mean:.1f}ms -> {a_mean:.1f}ms ({delta:+.1f}ms), "
            f"p95 {_fmt(b_p95, 'ms')} -> {_fmt(a_p95, 'ms')}",
            b_mean,
            a_mean,
            sample_size=len(after),
        )
    )
    logger.debug("_compare_latency: fin")


def diff_reports(
    baseline: Report,
    current: Report,
    loss_min_pp: float = 2.0,
    latency_min_ms: float = 5.0,
) -> list[DiffFinding]:
    """
    Compare deux Report deja calcules par analyse() et renvoie une
    liste de DiffFinding triee par severite (regression d'abord).

    baseline : le scenario de reference (avant le correctif, site A...)
    current  : le scenario a evaluer (apres le correctif, site B...)
    """
    logger.debug(
        "diff_reports(points_before={}, points_after={}, loss_min_pp={})",
        len(baseline.points),
        len(current.points),
        loss_min_pp,
    )
    common_points, only_before, only_after = _common_points(baseline, current)

    findings: list[DiffFinding] = [
        DiffFinding(
            "a_verifier",
            "Perimetre",
            p,
            "point present dans le baseline mais absent du run courant -- comparaison "
            "impossible sur ce point, verifier que la capture correspondante existe bien",
        )
        for p in only_before
    ]
    findings.extend(
        DiffFinding(
            "a_verifier",
            "Perimetre",
            p,
            "point present dans le run courant mais absent du baseline -- pas de reference pour juger si c'est normal",
        )
        for p in only_after
    )

    # -- pertes --
    for p in common_points:
        _compare_rate(
            findings,
            "Pertes",
            p,
            baseline.loss_count.get(p, 0),
            baseline.seen_count.get(p, 0) or 1,
            current.loss_count.get(p, 0),
            current.seen_count.get(p, 0) or 1,
            min_pp=loss_min_pp,
            label="taux de pertes",
        )

    # -- TCP avance --
    for p in common_points:
        _compare_count(
            findings,
            "TCP",
            p,
            baseline.rst_localized.get(p, 0),
            current.rst_localized.get(p, 0),
            label="RST injectes localement",
        )
        _compare_count(
            findings,
            "TCP",
            p,
            baseline.syn_no_synack.get(p, 0),
            current.syn_no_synack.get(p, 0),
            label="SYN sans reponse",
        )
        _compare_count(
            findings,
            "TCP",
            p,
            baseline.syn_reply_missing.get(p, 0),
            current.syn_reply_missing.get(p, 0),
            label="SYN-ACK ne remontant pas ici",
        )
        _compare_count(
            findings,
            "TCP",
            p,
            baseline.zero_window.get(p, 0),
            current.zero_window.get(p, 0),
            label="fenetres TCP=0",
        )
        _compare_count(
            findings,
            "TCP",
            p,
            baseline.dup_ack.get(p, 0),
            current.dup_ack.get(p, 0),
            label="ACK dupliques",
        )
        _compare_count(
            findings,
            "TCP",
            p,
            baseline.retrans_rto.get(p, 0),
            current.retrans_rto.get(p, 0),
            label="retransmissions par timeout (RTO)",
        )
        _compare_count(
            findings,
            "TCP",
            p,
            baseline.retrans_spurious.get(p, 0),
            current.retrans_spurious.get(p, 0),
            label="retransmissions inutiles (deja acquittees)",
        )
        _compare_count(
            findings,
            "TCP",
            p,
            baseline.retrans_fast.get(p, 0),
            current.retrans_fast.get(p, 0),
            label="retransmissions rapides (3 ACK dupliques)",
        )
        _compare_count(
            findings,
            "ARP",
            p,
            baseline.arp_ip_conflict.get(p, 0),
            current.arp_ip_conflict.get(p, 0),
            min_delta=1,
            rel_threshold=0.0,
            label="adresse(s) IP en conflit (revendiquees par plusieurs MAC)",
            evidence=_evidence(
                p, current.arp_ip_conflict_examples.get(p, []), current.arp_ip_conflict_frames.get(p, [])
            ),
        )
        _compare_count(
            findings,
            "STP",
            p,
            baseline.stp_topology_change.get(p, 0),
            current.stp_topology_change.get(p, 0),
            min_delta=1,
            rel_threshold=0.0,
            label="evenement(s) de changement de topologie STP (TCN ou bit TC)",
        )
        _compare_count(
            findings,
            "STP",
            p,
            baseline.stp_root_change.get(p, 0),
            current.stp_root_change.get(p, 0),
            min_delta=1,
            rel_threshold=0.0,
            label="reelection(s) du pont racine STP",
            evidence=_evidence(
                p, current.stp_root_change_examples.get(p, []), current.stp_root_change_frames.get(p, [])
            ),
        )
        _compare_count(
            findings,
            "TLS",
            p,
            baseline.tls_cert_invalid_dates.get(p, 0),
            current.tls_cert_invalid_dates.get(p, 0),
            min_delta=1,
            rel_threshold=0.0,
            label="certificat(s) TLS hors de leur fenetre de validite",
            evidence=_evidence(
                p,
                current.tls_cert_invalid_dates_examples.get(p, []),
                current.tls_cert_invalid_dates_frames.get(p, []),
            ),
        )
        _compare_count(
            findings,
            "TLS",
            p,
            baseline.tls_handshake_no_reply.get(p, 0),
            current.tls_handshake_no_reply.get(p, 0),
            min_delta=1,
            rel_threshold=0.0,
            label="negociation(s) TLS sans reponse (ClientHello sans ServerHello)",
            evidence=_evidence(
                p,
                current.tls_handshake_no_reply_examples.get(p, []),
                current.tls_handshake_no_reply_frames.get(p, []),
            ),
        )
        _compare_count(
            findings,
            "TLS",
            p,
            baseline.tls_handshake_incomplete.get(p, 0),
            current.tls_handshake_incomplete.get(p, 0),
            min_delta=1,
            rel_threshold=0.0,
            label="negociation(s) TLS interrompue(s) (ServerHello sans donnees applicatives)",
            evidence=_evidence(
                p,
                current.tls_handshake_incomplete_examples.get(p, []),
                current.tls_handshake_incomplete_frames.get(p, []),
            ),
        )
        _compare_count(
            findings,
            "Routage",
            p,
            baseline.ttl_unstable.get(p, 0),
            current.ttl_unstable.get(p, 0),
            label="flux a TTL variable",
        )

    # -- fragmentation / MTU --
    for p in common_points:
        _compare_count(
            findings,
            "Fragmentation",
            p,
            baseline.frag_count.get(p, 0),
            current.frag_count.get(p, 0),
            label="datagrammes fragmentes",
        )
        _compare_count(
            findings,
            "Fragmentation",
            p,
            baseline.icmp_frag_needed.get(p, 0),
            current.icmp_frag_needed.get(p, 0),
            min_delta=1,
            rel_threshold=0.0,
            label="ICMP Fragmentation Needed",
            higher_is_worse=False,
        )
        # Equivalent IPv6 (Session 22) -- meme raisonnement que ci-dessus :
        # plus de messages ICMPv6 Packet Too Big observes = PMTUD IPv6 qui
        # fonctionne mieux (moins susceptible d'etre filtre), pas une
        # regression.
        _compare_count(
            findings,
            "Fragmentation",
            p,
            baseline.icmpv6_too_big.get(p, 0),
            current.icmpv6_too_big.get(p, 0),
            min_delta=1,
            rel_threshold=0.0,
            label="ICMPv6 Packet Too Big",
            higher_is_worse=False,
        )

    # -- DHCP --
    for p in common_points:
        _compare_count(
            findings,
            "DHCP",
            p,
            baseline.dhcp_nak_count.get(p, 0),
            current.dhcp_nak_count.get(p, 0),
            min_delta=1,
            rel_threshold=0.0,
            label="DHCPNAK",
        )

    # -- DNS --
    for p in common_points:
        _compare_count(
            findings,
            "DNS",
            p,
            baseline.dns_nxdomain_count.get(p, 0),
            current.dns_nxdomain_count.get(p, 0),
            min_delta=1,
            rel_threshold=0.0,
            label="reponses NXDOMAIN",
        )
        _compare_count(
            findings,
            "DNS",
            p,
            baseline.dns_servfail_count.get(p, 0),
            current.dns_servfail_count.get(p, 0),
            min_delta=1,
            rel_threshold=0.0,
            label="reponses SERVFAIL",
        )
        _compare_count(
            findings,
            "DNS",
            p,
            len(baseline.dns_timeout.get(p, [])),
            len(current.dns_timeout.get(p, [])),
            min_delta=1,
            rel_threshold=0.0,
            label="requetes DNS sans reponse",
            evidence=_evidence(p, current.dns_timeout.get(p, []), current.dns_timeout_frames.get(p, [])),
        )

    # -- duree moyenne de resolution DNS (globale, pas par point : une
    # transaction DNS peut n'apparaitre qu'a un seul point de capture) --
    b_dns_mean, a_dns_mean = _mean(baseline.dns_duration_ms), _mean(current.dns_duration_ms)
    if b_dns_mean is not None and a_dns_mean is not None:
        delta = a_dns_mean - b_dns_mean
        if abs(delta) >= 50.0 and (b_dns_mean == 0 or abs(delta) / b_dns_mean >= 0.2):
            severity = "regression" if delta > 0 else "amelioration"
            findings.append(
                DiffFinding(
                    severity,
                    "DNS",
                    "global",
                    f"duree moyenne de resolution DNS {b_dns_mean:.1f}ms -> {a_dns_mean:.1f}ms ({delta:+.1f}ms)",
                    b_dns_mean,
                    a_dns_mean,
                    sample_size=len(current.dns_duration_ms),
                )
            )

    # -- HTTP -- (pas de comparaison de http_missing, meme choix que pour
    # dhcp_missing/dns_missing/sip_missing : jamais compares en baseline_diff
    # dans ce fichier, uniquement remontes via synthesis.py/report_text.py)
    for p in common_points:
        _compare_count(
            findings,
            "HTTP",
            p,
            baseline.http_client_error_count.get(p, 0),
            current.http_client_error_count.get(p, 0),
            label="reponses HTTP 4xx (erreur client)",
            evidence=_evidence(
                p,
                *_http_error_evidence(current.http_error_examples.get(p, []), 4, current.http_error_frames.get(p, [])),
            ),
        )
        _compare_count(
            findings,
            "HTTP",
            p,
            baseline.http_server_error_count.get(p, 0),
            current.http_server_error_count.get(p, 0),
            min_delta=1,
            rel_threshold=0.0,
            label="reponses HTTP 5xx (erreur serveur)",
            evidence=_evidence(
                p,
                *_http_error_evidence(current.http_error_examples.get(p, []), 5, current.http_error_frames.get(p, [])),
            ),
        )
        _compare_count(
            findings,
            "HTTP",
            p,
            len(baseline.http_timeout.get(p, [])),
            len(current.http_timeout.get(p, [])),
            min_delta=1,
            rel_threshold=0.0,
            label="requetes HTTP sans reponse",
            evidence=_evidence(p, current.http_timeout.get(p, []), current.http_timeout_frames.get(p, [])),
        )

    # -- duree moyenne de reponse HTTP (globale, pas par point : comme DNS,
    # une transaction HTTP peut n'apparaitre qu'a un seul point de capture) --
    b_http_mean, a_http_mean = _mean(baseline.http_response_time_ms), _mean(current.http_response_time_ms)
    if b_http_mean is not None and a_http_mean is not None:
        delta = a_http_mean - b_http_mean
        if abs(delta) >= 50.0 and (b_http_mean == 0 or abs(delta) / b_http_mean >= 0.2):
            severity = "regression" if delta > 0 else "amelioration"
            findings.append(
                DiffFinding(
                    severity,
                    "HTTP",
                    "global",
                    f"duree moyenne de reponse HTTP {b_http_mean:.1f}ms -> {a_http_mean:.1f}ms ({delta:+.1f}ms)",
                    b_http_mean,
                    a_http_mean,
                    sample_size=len(current.http_response_time_ms),
                )
            )

    # -- temps de traitement serveur --
    for p in common_points:
        b_times = baseline.server_think_time.get(p, [])
        a_times = current.server_think_time.get(p, [])
        b_mean, a_mean = _mean(b_times), _mean(a_times)
        if b_mean is not None and a_mean is not None:
            delta = a_mean - b_mean
            if abs(delta) >= latency_min_ms and (b_mean == 0 or abs(delta) / b_mean >= 0.2):
                severity = "regression" if delta > 0 else "amelioration"
                findings.append(
                    DiffFinding(
                        severity,
                        "Reseau/Serveur",
                        p,
                        f"temps de traitement serveur moyen {b_mean:.1f}ms -> {a_mean:.1f}ms ({delta:+.1f}ms)",
                        b_mean,
                        a_mean,
                        sample_size=len(a_times),
                    )
                )

    # -- latence, QoS, VLAN, saturation par segment (paires de points) --
    all_pairs = sorted(
        set(baseline.latency)
        | set(current.latency)
        | set(baseline.qos_change)
        | set(current.qos_change)
        | set(baseline.pmtud_blackhole)
        | set(current.pmtud_blackhole)
        | set(baseline.idle_timeout_dropped)
        | set(current.idle_timeout_dropped)
        | set(baseline.tls_cert_mismatch)
        | set(current.tls_cert_mismatch)
        | set(baseline.mss_clamped)
        | set(current.mss_clamped)
        | set(baseline.wscale_stripped)
        | set(current.wscale_stripped)
        | set(baseline.sack_stripped)
        | set(current.sack_stripped)
    )
    for a, b in all_pairs:
        if a not in common_points or b not in common_points:
            continue
        seg = f"{a} -> {b}"
        _compare_latency(
            findings,
            seg,
            baseline.latency.get((a, b), []),
            current.latency.get((a, b), []),
            min_ms=latency_min_ms,
        )
        _compare_count(
            findings,
            "QoS",
            seg,
            baseline.qos_change.get((a, b), 0),
            current.qos_change.get((a, b), 0),
            label="paquets remarques DSCP",
        )
        _compare_count(
            findings,
            "QoS",
            seg,
            baseline.pcp_change.get((a, b), 0),
            current.pcp_change.get((a, b), 0),
            label="flux avec PCP modifie",
        )
        _compare_count(
            findings,
            "VLAN",
            seg,
            baseline.vlan_change.get((a, b), 0),
            current.vlan_change.get((a, b), 0),
            label="flux changeant de VLAN",
        )
        _compare_count(
            findings,
            "Routage",
            seg,
            baseline.hop_delta_outliers.get((a, b), 0),
            current.hop_delta_outliers.get((a, b), 0),
            label="flux au nombre de sauts different",
        )
        _compare_count(
            findings,
            "Fragmentation",
            seg,
            baseline.frag_new.get((a, b), 0),
            current.frag_new.get((a, b), 0),
            label="datagrammes fragmentes apparaissant ici",
        )
        _compare_count(
            findings,
            "PMTUD",
            seg,
            baseline.pmtud_blackhole.get((a, b), 0),
            current.pmtud_blackhole.get((a, b), 0),
            min_delta=1,
            rel_threshold=0.0,
            label="segments TCP bloques sans signal ICMP(v6) de MTU (noir PMTUD)",
            evidence=_evidence(
                seg, current.pmtud_blackhole_examples.get((a, b), []), current.pmtud_blackhole_frames.get((a, b), [])
            ),
        )
        _compare_count(
            findings,
            "NAT/Pare-feu",
            seg,
            baseline.idle_timeout_dropped.get((a, b), 0),
            current.idle_timeout_dropped.get((a, b), 0),
            min_delta=1,
            rel_threshold=0.0,
            label="flux TCP ne reprenant jamais apres un silence prolonge (coupure NAT/FW silencieuse)",
            evidence=_evidence(
                seg, current.idle_timeout_examples.get((a, b), []), current.idle_timeout_frames.get((a, b), [])
            ),
        )
        _compare_count(
            findings,
            "TLS",
            seg,
            baseline.tls_cert_mismatch.get((a, b), 0),
            current.tls_cert_mismatch.get((a, b), 0),
            min_delta=1,
            rel_threshold=0.0,
            label="connexion(s) TLS avec un certificat different entre les deux points",
            evidence=_evidence(
                seg,
                current.tls_cert_mismatch_examples.get((a, b), []),
                current.tls_cert_mismatch_frames.get((a, b), []),
            ),
        )
        _compare_count(
            findings,
            "TCP",
            seg,
            baseline.mss_clamped.get((a, b), 0),
            current.mss_clamped.get((a, b), 0),
            label="handshakes avec MSS reduit en cours de route",
            evidence=_evidence(
                seg, current.mss_clamped_examples.get((a, b), []), current.mss_clamped_frames.get((a, b), [])
            ),
        )
        _compare_count(
            findings,
            "TCP",
            seg,
            baseline.wscale_stripped.get((a, b), 0),
            current.wscale_stripped.get((a, b), 0),
            min_delta=1,
            rel_threshold=0.0,
            label="handshakes ayant perdu l'option Window Scale",
        )
        _compare_count(
            findings,
            "TCP",
            seg,
            baseline.sack_stripped.get((a, b), 0),
            current.sack_stripped.get((a, b), 0),
            min_delta=1,
            rel_threshold=0.0,
            label="handshakes ayant perdu l'option SACK Permitted",
        )

        b_verdict = baseline.saturation_verdict.get((a, b))
        a_verdict = current.saturation_verdict.get((a, b))
        if b_verdict and a_verdict and b_verdict != a_verdict:
            b_bad = any(w in b_verdict for w in ("saturation", "policing", "limitation"))
            a_bad = any(w in a_verdict for w in ("saturation", "policing", "limitation"))
            if a_bad and not b_bad:
                severity = "regression"
            elif b_bad and not a_bad:
                severity = "amelioration"
            else:
                severity = "a_verifier"
            findings.append(
                DiffFinding(
                    severity,
                    "Saturation",
                    seg,
                    f'verdict change : "{b_verdict}" -> "{a_verdict}"',
                )
            )

    # -- RTP / qualite voix : appariement par label sans le SSRC (src:port -> dst:port) --
    def _rtp_by_label(report: Report) -> dict[str, dict]:
        out = {}
        for s in report.rtp_streams:
            if s.get("mos") is None:
                continue
            key = s["label"].split(" (SSRC=")[0]
            out[key] = s
        logger.debug("_rtp_by_label: retour out")
        return out

    b_rtp, a_rtp = _rtp_by_label(baseline), _rtp_by_label(current)
    for label in sorted(set(b_rtp) & set(a_rtp)):
        b_mos, a_mos = b_rtp[label]["mos"], a_rtp[label]["mos"]
        delta = a_mos - b_mos
        if abs(delta) < 0.2:
            continue
        severity = "regression" if delta < 0 else "amelioration"
        findings.append(
            DiffFinding(
                severity,
                "RTP/Voix",
                label,
                f"MOS {b_mos:.2f} -> {a_mos:.2f} ({delta:+.2f})",
                b_mos,
                a_mos,
                sample_size=a_rtp[label].get("sample_count"),
            )
        )

    # -- topologie : arcs qui apparaissent/disparaissent entre les deux runs --
    b_edges = {(u, d) for u, d, _ in baseline.topology_edges}
    a_edges = {(u, d) for u, d, _ in current.topology_edges}
    for u, d in sorted(b_edges - a_edges):
        if u in common_points and d in common_points:
            findings.append(
                DiffFinding(
                    "a_verifier",
                    "Topologie",
                    f"{u} -> {d}",
                    "cet arc etait present dans le baseline, plus detecte dans le run courant "
                    "(chemin reroute, ou simplement pas assez de flux communs cette fois)",
                )
            )
    for u, d in sorted(a_edges - b_edges):
        if u in common_points and d in common_points:
            findings.append(
                DiffFinding(
                    "a_verifier",
                    "Topologie",
                    f"{u} -> {d}",
                    "nouvel arc detecte, absent du baseline -- changement de routage possible",
                )
            )

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.category, f.segment))
    logger.debug("diff_reports: retour findings")
    return findings


def print_diff_report(findings: list[DiffFinding]) -> None:
    logger.debug("print_diff_report(findings={})", len(findings))
    print("=" * 70)
    print("COMPARAISON AVANT / APRES (baseline vs courant)")
    print("=" * 70)

    if not findings:
        print("\nAucun ecart significatif detecte entre les deux runs.")
        logger.debug("print_diff_report: retour (None implicite)")
        return

    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_ORDER}
    print(
        f"\n{counts['regression']} regression(s), {counts['amelioration']} amelioration(s), "
        f"{counts['a_verifier']} point(s) a verifier"
    )

    current_severity = None
    for f in findings:
        if f.severity != current_severity:
            current_severity = f.severity
            title = {
                "regression": "-- REGRESSIONS (ca allait mieux avant) --",
                "a_verifier": "-- A VERIFIER (changement sans verdict clair) --",
                "amelioration": "-- AMELIORATIONS --",
                "stable": "-- STABLE --",
            }[f.severity]
            print(f"\n{title}")
        print(f"  [{f.category:14s}] {f.segment:20s} : {f.message}")
    logger.debug("print_diff_report: fin")


def write_diff_csv(findings: list[DiffFinding], path: str) -> None:
    logger.debug("write_diff_csv: findings={} path={}", summarize(findings, "findings"), summarize(path, "path"))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["severite", "categorie", "segment", "message", "avant", "apres"])
        for f in findings:
            writer.writerow(
                [
                    f.severity,
                    f.category,
                    f.segment,
                    f.message,
                    "" if f.before is None else f.before,
                    "" if f.after is None else f.after,
                ]
            )
    logger.debug("write_diff_csv: fin")
