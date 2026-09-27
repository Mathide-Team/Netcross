"""
netcross_core.client_diff -- comparaison "client vs client" : meme
capture, memes points, seule la source (l'IP du poste) change. Troisieme
axe de comparaison, orthogonal aux deux deja existants dans ce projet :
"point A vs point B" (topologique, voir analysis.py) et "avant vs apres"
(temporel, voir baseline_diff.py).

Design repris tel que documente dans idees.md / netcross_pistes_evolution2.md
Sec.2 (Google Drive, dossier de suivi netcross) : "l'analyse comparative la
plus frequente n'est souvent ni point A vs point B ni avant vs apres, mais
'ce client fonctionne, pas l'autre' -- meme capture, meme instant, memes
points, seule la source change". Le Report actuel agrege tout par point
(loss_count[point], latency[(a,b)]...) sans distinguer la source : un
poste en echec total est noye dans la moyenne des postes qui
fonctionnent -- ce module comble ce point aveugle sans nouveau moteur
d'analyse ou de diff.

Module independant (meme discipline que baseline_diff.py) : fichier
neuf, ne modifie ni parsing.py, ni analysis.py, ni models.py, ni
correlate.py. Reutilise uniquement analyse() (une fois par client, meme
pattern que baseline_diff.py qui appelle deja analyse() deux fois) et
diff_reports() en mode N-way (chaque client diffe contre un client de
reference -- aucun nouveau moteur de diff, meme fonction, un autre axe
de comparaison).
"""

from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass, field

from netcross_core.analysis import analyse
from netcross_core.baseline_diff import diff_reports
from netcross_core.correlate import correlate
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Report

logger = get_logger(__name__)

_SEVERITY_MARKERS = {
    "regression": "[REGRESSION]",
    "amelioration": "[MIEUX]",
    "a_verifier": "[A VERIFIER]",
    "stable": "[STABLE]",
}


@dataclass
class ClientSignature:
    """Signatures deja partiellement capturees ailleurs dans le projet
    (dhcp_vendor_class, sip_user_agent), simplement agregees ici par
    client -- aucune nouvelle extraction de paquet. Objectif (idees.md
    Sec.2 point 4) : transformer un "client B diverge" en "client B
    diverge, et son vendor DHCP / User-Agent SIP differe", un signal
    plus proche de "version logicielle differente" qu'un pur ecart
    reseau. Le futur JA3/version TLS mentionne dans le meme document
    n'existe pas encore dans tls_diagnostics.py -- non repris ici, a
    ajouter le jour ou ce champ existera vraiment (pas de champ
    fantome)."""

    dhcp_vendor_classes: Counter = field(default_factory=Counter)
    sip_user_agents: Counter = field(default_factory=Counter)


@dataclass
class ClientReport:
    client: str
    ips: tuple[str, ...]
    packet_count: int
    report: Report
    signature: ClientSignature


@dataclass
class ClientComparisonResult:
    reference: str
    clients: dict[str, ClientReport]  # tous les clients, reference incluse
    diffs: dict[str, list]  # nom -> list[DiffFinding], reference exclue


def group_packets_by_client(all_packets, client_group):
    """
    Repartit all_packets par client selon un groupement explicite
    {nom: {ip1, ip2, ...}} -- voir idees.md : "--client-group
    PosteA=10.0.0.5,PosteB=10.0.0.12" pour les cas simples, un groupe
    avec plusieurs IP pour les cas multi-IP/DHCP (roaming, plusieurs
    interfaces). Pkt.src existe deja dans le modele : rien a y ajouter.

    Un paquet est assigne a un client des que pk.src OU pk.dst
    correspond a une IP du groupe -- l'analyse par client doit voir le
    trafic dans les deux sens (la reponse serveur vers ce poste compte
    aussi pour lui), pas seulement les paquets qu'il emet.

    Consequence assumee : un paquet peut apparaitre dans plusieurs
    groupes de clients a la fois (trafic direct entre deux postes tous
    deux dans le perimetre de comparaison) -- rare en pratique (l'usage
    vise est client -> serveur), non filtre specifiquement ici.
    """
    logger.debug(
        "group_packets_by_client: all_packets={} client_group={}",
        summarize(all_packets, "all_packets"),
        summarize(client_group, "client_group"),
    )
    by_client = {name: [] for name in client_group}
    for pk in all_packets:
        for name, ips in client_group.items():
            if pk.src in ips or pk.dst in ips:
                by_client[name].append(pk)
    logger.debug(
        "group_packets_by_client: {} client(s) -> {}",
        len(by_client),
        {name: len(pkts) for name, pkts in by_client.items()},
    )
    return by_client


def _build_signature(packets):
    sig = ClientSignature()
    for pk in packets:
        if pk.dhcp_vendor_class:
            sig.dhcp_vendor_classes[pk.dhcp_vendor_class] += 1
        if pk.sip_user_agent:
            sig.sip_user_agents[pk.sip_user_agent] += 1
    return sig


def build_client_report(
    client,
    ips,
    packets,
    points_order=None,
    bucket_seconds=1.0,
    nat_tolerant=False,
    nat_window_ms=200,
    rtp_clock_rate=8000,
):
    """Un ClientReport par client -- meme pattern que baseline_diff.py,
    qui appelle deja analyse() deux fois (avant/apres) : ici, une fois
    par client, sur le sous-ensemble de la capture qui lui est
    rattache. points_order est partage entre tous les clients (memes
    points de capture, seule la source change) -- sans quoi les
    Report deviendraient incomparables entre eux."""
    flows = correlate(packets, nat_tolerant, nat_window_ms)
    report = analyse(flows, points_order, packets, bucket_seconds, nat_tolerant, rtp_clock_rate)
    return ClientReport(
        client=client,
        ips=tuple(sorted(ips)),
        packet_count=len(packets),
        report=report,
        signature=_build_signature(packets),
    )


def compare_clients(
    all_packets,
    client_group,
    reference=None,
    points_order=None,
    bucket_seconds=1.0,
    nat_tolerant=False,
    nat_window_ms=200,
    rtp_clock_rate=8000,
    loss_min_pp=2.0,
    latency_min_ms=5.0,
):
    """
    Point d'entree principal.

    client_group : dict {nom_client: iterable_d_ips}, au moins 2 entrees.
    reference     : nom du client de reference (celui qui fonctionne, ou
                    le comportement majoritaire) -- chaque AUTRE client
                    est diffe contre lui (mode N-way, idees.md Sec.2
                    point 3). Par defaut : le premier client du dict
                    (ordre d'insertion Python, donc l'ordre --client-group
                    cote CLI).

    Renvoie un ClientComparisonResult : un ClientReport par client
    (reference incluse) et un dict de DiffFinding par client compare
    (reference exclue -- rien a diffee contre elle-meme).
    """
    logger.debug(
        "compare_clients: all_packets={} client_group={} reference={} points_order={} "
        "bucket_seconds={} nat_tolerant={} nat_window_ms={} rtp_clock_rate={} loss_min_pp={} "
        "latency_min_ms={}",
        summarize(all_packets, "all_packets"),
        summarize(client_group, "client_group"),
        summarize(reference, "reference"),
        summarize(points_order, "points_order"),
        summarize(bucket_seconds, "bucket_seconds"),
        summarize(nat_tolerant, "nat_tolerant"),
        summarize(nat_window_ms, "nat_window_ms"),
        summarize(rtp_clock_rate, "rtp_clock_rate"),
        summarize(loss_min_pp, "loss_min_pp"),
        summarize(latency_min_ms, "latency_min_ms"),
    )
    if len(client_group) < 2:
        logger.debug("compare_clients: refus, ValueError")
        raise ValueError(
            "compare_clients necessite au moins 2 clients (reference incluse) pour produire une comparaison."
        )

    reference = reference or next(iter(client_group))
    if reference not in client_group:
        logger.debug("compare_clients: refus, ValueError")
        raise ValueError(f"Client de reference inconnu : {reference!r} (clients disponibles : {sorted(client_group)})")

    by_client = group_packets_by_client(all_packets, client_group)

    clients = {}
    for name, ips in client_group.items():
        clients[name] = build_client_report(
            name,
            ips,
            by_client[name],
            points_order,
            bucket_seconds,
            nat_tolerant,
            nat_window_ms,
            rtp_clock_rate,
        )

    ref_report = clients[reference].report
    diffs = {}
    for name, cr in clients.items():
        if name == reference:
            continue
        diffs[name] = diff_reports(ref_report, cr.report, loss_min_pp, latency_min_ms)

    logger.debug(
        "compare_clients: référence={}, {} client(s) comparé(s), {} écart(s) total(aux)",
        reference,
        len(diffs),
        sum(len(v) for v in diffs.values()),
    )
    return ClientComparisonResult(reference=reference, clients=clients, diffs=diffs)


def _print_signature(sig, indent="  "):
    if sig.dhcp_vendor_classes:
        top = sig.dhcp_vendor_classes.most_common(3)
        print(f"{indent}DHCP vendor class : " + ", ".join(f"{v} ({n})" for v, n in top))
    if sig.sip_user_agents:
        top = sig.sip_user_agents.most_common(3)
        print(f"{indent}SIP User-Agent    : " + ", ".join(f"{v} ({n})" for v, n in top))


def print_client_comparison(result: ClientComparisonResult) -> None:
    """Sortie console, meme esprit que print_diff_report : le client de
    reference d'abord (banniere dediee, comme les bannieres BASELINE/
    COURANT deja utilisees pour TLS/QUIC en Session 8), puis chaque
    client compare avec son verdict."""
    logger.debug("print_client_comparison: result={}", summarize(result, "result"))
    print("\n" + "=" * 70)
    print("COMPARAISON CLIENT VS CLIENT")
    print("=" * 70)

    ref = result.clients[result.reference]
    print(f"\n-- CLIENT: {ref.client} (reference) --")
    print(f"  IP(s) : {', '.join(ref.ips) if ref.ips else 'n/a'}")
    print(f"  {ref.packet_count} paquet(s) rattache(s) a ce client")
    _print_signature(ref.signature)

    for name, findings in result.diffs.items():
        cr = result.clients[name]
        print(f"\n-- CLIENT: {name} (vs {result.reference}) --")
        print(f"  IP(s) : {', '.join(cr.ips) if cr.ips else 'n/a'}")
        print(f"  {cr.packet_count} paquet(s) rattache(s) a ce client")
        _print_signature(cr.signature)
        if not findings:
            print("  Aucun ecart significatif detecte par rapport a la reference.")
            continue
        regressions = sum(1 for f in findings if f.severity == "regression")
        if regressions:
            print(f"  {regressions} ecart(s) 'regression' (ce client va moins bien que la reference) :")
        for f in findings:
            marker = _SEVERITY_MARKERS.get(f.severity, f.severity.upper())
            before = "n/a" if f.before is None else f"{f.before:.2f}"
            after = "n/a" if f.after is None else f"{f.after:.2f}"
            print(f"    {marker} [{f.category}] {f.segment} : {f.message} (reference={before}, {name}={after})")


def write_client_diff_csv(result: ClientComparisonResult, path: str) -> None:
    """CSV plat, memes colonnes que write_diff_csv (baseline_diff.py)
    plus une colonne 'client' en tete -- une ligne par (client,
    DiffFinding). Le client de reference n'a pas de ligne (rien a
    diffee contre lui-meme)."""
    logger.debug("write_client_diff_csv: result={} path={}", summarize(result, "result"), summarize(path, "path"))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["client", "reference", "severite", "categorie", "segment", "message", "avant", "apres"])
        row_count = 0
        for name, findings in result.diffs.items():
            for f in findings:
                writer.writerow(
                    [
                        name,
                        result.reference,
                        f.severity,
                        f.category,
                        f.segment,
                        f.message,
                        "" if f.before is None else f.before,
                        "" if f.after is None else f.after,
                    ]
                )
                row_count += 1
    logger.debug("write_client_diff_csv: {} ligne(s) écrite(s) dans {}", row_count, path)
