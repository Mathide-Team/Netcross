"""
netcross_core.analysis -- coeur analytique : construit un Report a partir
des flux correles (pertes, latence, TTL/topologie, QoS, fragmentation,
saturation/bufferbloat, TCP avance, VLAN, decalage d'horloge, RTP,
decomposition reseau/serveur, DHCP, SIP, DNS, HTTP).
"""

import statistics
import time
from collections import Counter, defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from itertools import combinations
from typing import Any

from netcross_core.application import (
    TransactionThresholds,
    build_dns_transactions,
    build_http_transactions,
    classify_transaction,
)
from netcross_core.content import extract_http_objects
from netcross_core.correlate import TOPN_DIMENSIONS, compute_throughput, compute_topn_series
from netcross_core.extract.carver import detect_extracted_files
from netcross_core.forensic import detect_sequence_gaps
from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt, Report
from netcross_core.parsing import compute_mos
from netcross_core.security.exfiltration import detect_exfiltration
from netcross_core.security.expert_correlation import apply_expert_correlation

logger = get_logger(__name__)


def _taille(valeur: Any) -> Any:
    """Résumé loggable d'un champ de Report : somme des compteurs d'un dict
    {point: n}, taille d'une collection, valeur sinon (jamais l'objet entier)."""
    if isinstance(valeur, dict):
        valeurs = list(valeur.values())
        if valeurs and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in valeurs):
            return sum(valeurs)
        return len(valeur)
    if isinstance(valeur, (list, tuple, set, frozenset)):
        return len(valeur)
    return valeur


def _resume(r: Report, *champs: str) -> str:
    """``champ=taille`` pour chaque champ de ``r`` rempli par une phase."""
    return " ".join(f"{champ}={_taille(getattr(r, champ, None))}" for champ in champs)


@contextmanager
def _phase(nom: str) -> Iterator[None]:
    """Chronometre une phase de analyse() (niveau DEBUG)."""
    debut = time.perf_counter()
    yield
    logger.debug("analyse : phase {} en {:.3f} s", nom, time.perf_counter() - debut)


def analyse(
    flows,
    points_order,
    all_packets,
    bucket_seconds=1.0,
    nat_tolerant=False,
    rtp_clock_rate=8000,
    topn=5,
    idle_timeout_seconds=None,
    exclude_duplicates=False,
    duplicate_counts=None,
):
    # Job 41/issue #161 : exclude_duplicates (defaut False -> comportement
    # historique inchange) retire de `flows` ET de `all_packets` les paquets
    # marques Pkt.is_duplicate (voir netcross_core.forensic.
    # detect_cross_capture_duplicates, a appeler avant). Refait ici meme si
    # l'appelant a deja utilise correlate(exclude_duplicates=True) : analyse()
    # ne doit pas dependre de la facon dont `flows` a ete construit, et la
    # passe est quasi gratuite quand il n'y a plus rien a retirer.
    # duplicate_counts : resultat de detect_cross_capture_duplicates(),
    # reporte tel quel dans Report.duplicate_count (analyse() ne detecte
    # rien elle-meme -- pas de double detection si l'appelant l'a deja faite).
    debut_analyse = time.perf_counter()
    if exclude_duplicates:
        all_packets = [pk for pk in all_packets if not pk.is_duplicate]
        flows = _without_duplicates(flows)
    logger.info("analyse : {} points, {} flux, {} paquets", len(points_order or []), len(flows), len(all_packets))
    points = points_order or sorted({pt for f in flows.values() for pt in f})

    with _phase("infer_topology"):
        topo_edges, topo_ambiguous, topo_isolated, topo_branch, topo_merge = _infer_topology(flows, points)
    topo_low_coverage = {(u, d) for u, d, info in topo_edges if info.get("coverage", 1.0) < 0.8}

    logger.debug(
        "analyse : topologie {} arête(s), {} ambiguë(s), {} isolé(s)",
        len(topo_edges),
        len(topo_ambiguous),
        len(topo_isolated),
    )
    used_topology_for_order = False
    if points_order:
        # itertools.pairwise() serait plus idiomatique mais demande Python 3.10+ ;
        # zip() reste compatible avec le python3 3.9 par defaut de Rocky/RHEL 9.
        pairs = list(zip(points, points[1:]))  # noqa: RUF007
    elif topo_edges:
        pairs = [(u, d) for u, d, _info in topo_edges]
        used_topology_for_order = True
    else:
        pairs = [(a, b) for i, a in enumerate(points) for b in points[i + 1 :]]

    logger.debug(
        "analyse : {} paire(s) ({})",
        len(pairs),
        "ordre imposé" if points_order else ("topologie" if used_topology_for_order else "toutes les paires"),
    )
    r = Report(
        points=points,
        pairs=pairs,
        bucket_seconds=bucket_seconds,
        rtp_clock_rate=rtp_clock_rate,
    )
    r.duplicates_excluded = exclude_duplicates
    for pair, count in (duplicate_counts or {}).items():
        r.duplicate_count[pair] = count
    # Commentaires de paquets pcapng (Job 39/issue #159) -- pre-formates
    # "point — trame N : texte" pour le rapport (Report.packet_comments,
    # voir models.py). Remplis APRES le filtrage exclude_duplicates
    # ci-dessus, pour la meme coherence que le reste du rapport : un paquet
    # exclu de tous les compteurs n'apparait pas non plus ici.
    r.packet_comments = [
        f"{pkt.point} — trame {pkt.frame_number} : {pkt.comment}" for pkt in all_packets if pkt.comment
    ]
    with _phase("compute_throughput"):
        r.throughput = compute_throughput(all_packets, bucket_seconds)
    r.topn_timeseries = {dim: compute_topn_series(all_packets, bucket_seconds, dim, topn) for dim in TOPN_DIMENSIONS}
    r.topology_edges = topo_edges
    r.topology_ambiguous = topo_ambiguous
    r.topology_isolated = topo_isolated
    r.topology_branch_points = topo_branch
    r.topology_merge_points = topo_merge
    r.topology_used_for_order = used_topology_for_order
    r.http_objects = [obj.__dict__ for obj in extract_http_objects(all_packets)]
    # SCENARIO-4 (#150) : extraction de fichiers (HTTP, email, SMB, FTP)
    with _phase("detect_extracted_files"):
        extraction = detect_extracted_files(all_packets)
    r.extracted_files = [
        {
            "point": f.point,
            "proto_source": f.proto_source,
            "src": f.src,
            "dst": f.dst,
            "ts": f.ts,
            "uri": f.uri,
            "content_type": f.content_type,
            "size": f.size,
            "hash_md5": f.hash_md5,
            "hash_sha256": f.hash_sha256,
            "type_detected": f.type_detected,
            "frame_number": f.frame_number,
        }
        for f in extraction.files
    ]
    with _phase("application_transactions"):
        _analyse_application_transactions(r, all_packets)
    if points_order:
        r.topology_order_conflicts = _check_order_consistency(points_order, topo_edges)

    for pk in all_packets:
        if pk.vlan_id is not None:
            r.vlan_seen[pk.point].add(pk.vlan_id)
        if pk.encap_tags:
            r.encap_seen[pk.point].add(" > ".join(pk.encap_tags))

    for point in points:
        r.seen_count[point] = 0

    conversation_points = _conversation_points(flows)

    for key, per_point in flows.items():
        present_points = [p for p in points if p in per_point]
        is_tcp = key[0] == "TCP"
        conversation_seen = conversation_points.get(_conversation_key(key))

        for p in present_points:
            r.seen_count[p] += 1
            pkts_here = per_point[p]

            if is_tcp and len(pkts_here) > 1:
                # un ACK pur et un segment de donnees peuvent legitimement
                # partager le meme seq (l'ACK ne consomme pas de sequence) :
                # on ne compte une retransmission/ACK duplique que si on a
                # plusieurs paquets du MEME type (avec ou sans payload)
                data_pkts = [pk for pk in pkts_here if pk.payload_hash is not None]
                ctrl_pkts = [pk for pk in pkts_here if pk.payload_hash is None]
                if len(data_pkts) > 1:
                    r.retrans[p] += len(data_pkts) - 1
                if len(ctrl_pkts) > 1:
                    r.dup_ack[p] += len(ctrl_pkts) - 1

            if is_tcp and any(pkt.window == 0 for pkt in pkts_here):
                r.zero_window[p] += 1

            if is_tcp and any(pkt.flags and "R" in pkt.flags for pkt in pkts_here):
                r.rst_count[p] += 1

            ttls_here = {pkt.ttl for pkt in pkts_here if pkt.ttl is not None}
            if len(ttls_here) > 1:
                r.ttl_unstable[p] += 1

        if is_tcp and len(present_points) == 1 and len(points) >= 2:
            only_pkts = per_point[present_points[0]]
            if any(pkt.flags and "R" in pkt.flags for pkt in only_pkts):
                r.rst_localized[present_points[0]] += 1

        if points_order and present_points:
            first_seen_idx = points.index(present_points[0])
            for idx, p in enumerate(points):
                if idx > first_seen_idx and p not in per_point and any(points[j] in per_point for j in range(idx)):
                    # Issue #352 : ne pas confondre un flux hors chemin avec
                    # une perte reelle. Si ce couple d'hotes n'echange JAMAIS
                    # rien a ce point (ni aller ni retour, aucune connexion),
                    # le flux n'emprunte pas ce segment (scan local au LAN,
                    # trafic qui sort par un autre lien) : hors chemin.
                    if conversation_seen is not None and p not in conversation_seen:
                        r.off_path_count[p] += 1
                        continue
                    # Sur le chemin : une perte n'est comptee qu'au premier
                    # point manquant (vu au point IMMEDIATEMENT precedent),
                    # pas une seconde fois a chaque point plus en aval.
                    prev_point = points[idx - 1]
                    if prev_point not in per_point:
                        continue
                    r.loss_count[p] += 1
                    nearest_j = max(j for j in range(idx) if points[j] in per_point)
                    a_point = points[nearest_j]
                    ts_a = min(pkt.ts for pkt in per_point[a_point])
                    r.loss_event_buckets[(a_point, p)].append(int(ts_a // bucket_seconds))

        for a, b in pairs:
            if a in per_point and b in per_point:
                pkt_a = min(per_point[a], key=lambda pkt: pkt.ts)
                pkt_b = min(per_point[b], key=lambda pkt: pkt.ts)

                lat_ms = (pkt_b.ts - pkt_a.ts) * 1000.0
                r.latency[(a, b)].append(lat_ms)
                r.latency_by_bucket[(a, b)][int(pkt_a.ts // bucket_seconds)].append(lat_ms)

                dscp_changed = pkt_a.dscp != pkt_b.dscp
                if dscp_changed:
                    r.qos_change[(a, b)] += 1

                if pkt_a.ttl is not None and pkt_b.ttl is not None:
                    # issue #352 : valeur absolue -- dans le sens retour (b ->
                    # a) le TTL est plus haut en b, et le delta signe (-1)
                    # faisait compter chaque reponse comme « nombre de sauts
                    # different ». Le nombre de sauts du segment est |delta|
                    # dans les deux sens.
                    delta = abs(pkt_a.ttl - pkt_b.ttl)
                    r.hop_delta[(a, b)].append(delta)
                    if dscp_changed:
                        if delta == 0:
                            r.qos_l2_remark[(a, b)] += 1
                        else:
                            r.qos_l3_remark[(a, b)] += 1

                if pkt_a.vlan_id is not None and pkt_b.vlan_id is not None:
                    if pkt_a.vlan_id != pkt_b.vlan_id:
                        r.vlan_change[(a, b)] += 1
                    if (
                        pkt_a.vlan_prio is not None
                        and pkt_b.vlan_prio is not None
                        and pkt_a.vlan_prio != pkt_b.vlan_prio
                    ):
                        r.pcp_change[(a, b)] += 1
                elif pkt_a.vlan_id is not None and pkt_b.vlan_id is None:
                    r.vlan_tag_flip[(a, b)]["tagged_to_untagged"] += 1
                elif pkt_a.vlan_id is None and pkt_b.vlan_id is not None:
                    r.vlan_tag_flip[(a, b)]["untagged_to_tagged"] += 1

                if pkt_a.encap_tags != pkt_b.encap_tags:
                    r.encap_change[(a, b)] += 1
                    if len(r.encap_change_examples[(a, b)]) < 5:
                        tag_a = " > ".join(pkt_a.encap_tags) or "(aucune)"
                        tag_b = " > ".join(pkt_b.encap_tags) or "(aucune)"
                        r.encap_change_examples[(a, b)].append(f"{tag_a}  ->  {tag_b}")

            elif (
                not points_order
                and used_topology_for_order
                and a in per_point
                and b not in per_point
                and (a, b) not in topo_low_coverage
            ):
                if conversation_seen is not None and b not in conversation_seen:
                    r.off_path_count[b] += 1  # issue #352 : hors chemin, pas une perte
                    continue
                # perte sur cet arc direct de la topologie deduite. On exclut
                # les arcs a faible couverture (l'aval ne voit qu'une partie
                # du trafic de l'amont -- branchement, ECMP, ou aller/retour
                # qui empruntent des chemins differents) : un flux absent en
                # aval peut tout a fait avoir legitimement emprunte un autre
                # chemin, on ne peut pas distinguer ca d'une vraie perte sans
                # information supplementaire, donc on ne rapporte rien plutot
                # que de se tromper (faux positif systematique sinon).
                r.loss_count[b] += 1
                ts_a = min(pkt.ts for pkt in per_point[a])
                r.loss_event_buckets[(a, b)].append(int(ts_a // bucket_seconds))

    for pair, deltas in r.hop_delta.items():
        if not deltas:
            continue
        mode_delta = Counter(deltas).most_common(1)[0][0]
        r.hop_delta_outliers[pair] = sum(1 for d in deltas if d != mode_delta)

    # -- fragmentation / MTU --
    # Generique IPv4/IPv6 des que pk.ip_id est renseigne (voir
    # pcap_parser.packet et netcross_core.models.Pkt.ip_id) -- aucune
    # branche par famille d'adresse necessaire ici. r.frag_count profite
    # donc directement de la fragmentation IPv6 (ipv6.fragment) une fois
    # ip_id peuple par pcap_parser. En revanche r.frag_new/
    # encap_frag_correlated ("un datagramme non fragmente en amont
    # devient fragmente en aval") ont une limite IPv6-specifique assumee
    # : un datagramme IPv6 jamais fragmente n'a par construction AUCUN
    # ip_id a exposer (contrairement a IPv4, ou ip.id est un champ
    # ordinaire toujours present) -- l'appariement (src, dst, ip_id)
    # ci-dessous ne peut donc jamais matcher le meme datagramme non
    # fragmente au point amont avec sa version fragmentee en aval cote
    # IPv6 ; seule une fragmentation deja presente aux DEUX points (et
    # partageant le meme identifiant 32 bits) sera correctement suivie.
    frag_track = defaultdict(dict)  # dgram_key -> {point: fragmente ?}
    encap_track = defaultdict(dict)  # dgram_key -> {point: pile d'encapsulation}
    for pk in all_packets:
        # ICMPv6 "Packet Too Big" (type 2) AVANT le "continue" ci-dessous,
        # volontairement en dehors du garde-fou pk.ip_id -- contrairement
        # a un message ICMPv4 (qui herite toujours d'un ip.id present sur
        # TOUT paquet IPv4, fragmente ou non, voir pcap_parser.packet),
        # ce message ICMPv6 n'a lui-meme quasiment jamais d'en-tete
        # d'extension Fragment (c'est un petit message de controle, pas
        # un gros datagramme) : son propre ip_id vaut donc None dans
        # l'immense majorite des cas -- le compter seulement si ip_id
        # est present l'aurait fait passer inapercu presque a chaque
        # fois. Verifie empiriquement (tshark 4.2.2, pcap scapy
        # synthetique, voir claude.md Session 22).
        if pk.proto == "ICMPv6" and pk.icmpv6_type == 2:
            r.icmpv6_too_big[pk.point] += 1
        if pk.ip_id is None:
            continue
        if pk.proto == "ICMP" and pk.icmp_type == 3 and pk.icmp_code == 4:
            r.icmp_frag_needed[pk.point] += 1
        if pk.is_fragment:
            r.frag_count[pk.point] += 1
        dgram_key = (pk.src, pk.dst, pk.ip_id)
        frag_track[dgram_key][pk.point] = frag_track[dgram_key].get(pk.point, False) or pk.is_fragment
        encap_track[dgram_key].setdefault(pk.point, pk.encap_tags)

    for dgram_key, per_point_frag in frag_track.items():
        per_point_encap = encap_track.get(dgram_key, {})
        for a, b in pairs:
            if a in per_point_frag and b in per_point_frag and not per_point_frag[a] and per_point_frag[b]:
                r.frag_new[(a, b)] += 1
                # correlation stricte : seulement si CE MEME datagramme a
                # aussi change de pile d'encapsulation sur ce segment
                if per_point_encap.get(a) != per_point_encap.get(b):
                    r.encap_frag_correlated[(a, b)] += 1

    with _phase("pmtud"):
        _analyse_pmtud(r, flows, pairs)
    # idle_timeout_seconds=None (defaut) -> _IDLE_TIMEOUT_SECONDS via le
    # defaut de _analyse_idle_timeout, expose desormais en CLI
    # (--idle-timeout-seconds, voir cross_capture_analyzer_cli.py/
    # cross_capture_diff_cli.py).
    if idle_timeout_seconds is None:
        with _phase("idle_timeout"):
            _analyse_idle_timeout(r, all_packets, pairs)
    else:
        with _phase("idle_timeout"):
            _analyse_idle_timeout(r, all_packets, pairs, idle_timeout_seconds)
    with _phase("arp_ip_conflict"):
        _analyse_arp_ip_conflict(r, all_packets)
    with _phase("stp_instability"):
        _analyse_stp_instability(r, all_packets)
    with _phase("tls_certificate"):
        _analyse_tls_certificate(r, all_packets, pairs)
    with _phase("tls_handshake"):
        _analyse_tls_handshake(r, all_packets)
    with _phase("retransmission_types"):
        _analyse_retransmission_types(r, all_packets)
    with _phase("tcp_expert_signals"):
        _analyse_tcp_expert_signals(r, all_packets)
    # Trous de sequence TCP (Job 42/issue #162) : suivi par connexion et par
    # point sur les paquets bruts -- pas sur `flows`, dont la cle porte le
    # numero de sequence (un "flow" y est un segment, pas une connexion).
    with _phase("detect_sequence_gaps"):
        r.sequence_gaps = detect_sequence_gaps(all_packets)
    # Alertes Expert Info applicatives + sequences TCP anormales -> suspicions
    # fuzzing/overflow/dos (issue #137).
    with _phase("apply_expert_correlation"):
        apply_expert_correlation(r, all_packets)
    with _phase("saturation"):
        _analyse_saturation(r)
    with _phase("bufferbloat"):
        _analyse_bufferbloat(r)
    with _phase("handshake"):
        _analyse_handshake(r, flows, points, points_order, nat_tolerant)
    with _phase("tcp_options"):
        _analyse_tcp_options(r, flows, pairs, nat_tolerant, points_order)
    with _phase("rtp"):
        _analyse_rtp(r, all_packets, points, points_order, rtp_clock_rate)
    with _phase("response_time"):
        _analyse_response_time(r, flows, all_packets, points, points_order)
    with _phase("dhcp"):
        _analyse_dhcp(r, all_packets, points, points_order)
    with _phase("sip"):
        _analyse_sip(r, all_packets, points, points_order)
    from netcross_core.voip import build_calls

    with _phase("build_calls"):
        calls, r.voip_quality_distribution = build_calls(all_packets, r.rtp_streams)
    r.voip_calls = [call.to_dict() for call in calls]
    with _phase("dns"):
        _analyse_dns(r, all_packets, points, points_order)
    with _phase("http"):
        _analyse_http(r, all_packets, points, points_order)

    # SCENARIO-2 (#148) : exfiltration de donnees (transferts volumineux
    # vers l'exterieur) -- detectee depuis les champs Pkt deja disponibles.
    with _phase("detect_exfiltration"):
        r.exfiltration_alerts = detect_exfiltration(all_packets).alerts

    logger.debug(
        "analyse : terminée en {:.3f} s, {} paire(s), {}",
        time.perf_counter() - debut_analyse,
        len(pairs),
        _resume(r, "loss_count", "retrans", "rst_count", "off_path_count", "zero_window"),
    )
    return r


def _conversation_key(key) -> tuple | None:
    """Couple d'hotes (non oriente, tous ports et sens confondus) d'une cle
    de flux stricte `(proto, src, sport, dst, dport, key_id)` ; None en mode
    --nat-tolerant (cle ("NAT", proto, payload_hash, bucket), adresses
    reecrites entre points) : la distinction hors chemin / perte n'y est
    pas faite.

    Granularite choisie (issue #352) : si ces deux hotes echangent quoi que
    ce soit a un point (autre connexion, sens retour), le chemin entre eux
    passe par ce point et un paquet absent y est une PERTE -- y compris une
    connexion entierement perdue (SYN jamais arrive). Seul un couple jamais
    vu a ce point (scan local, trafic qui sort par un autre lien) est hors
    chemin."""
    if len(key) != 6 or key[0] == "NAT":
        logger.trace("_conversation_key: clé NAT ou non standard, pas de conversation")
        return None
    _proto, src, _sport, dst, _dport, _key_id = key
    return tuple(sorted((src, dst), key=repr))


def _conversation_points(flows) -> dict[tuple, set[str]]:
    """Points ou chaque couple d'hotes a ete vu, dans un sens ou l'autre (issue #352)."""
    seen: dict[tuple, set[str]] = defaultdict(set)
    for key, per_point in flows.items():
        conversation = _conversation_key(key)
        if conversation is not None:
            seen[conversation].update(per_point)
    return seen


def _without_duplicates(flows):
    """Copie de `flows` (cle -> {point: [Pkt, ...]}, voir correlate()) sans
    les paquets marques is_duplicate ; les points, puis les flux, devenus
    vides sont retires (un point sans paquet n'a pas « vu » le flux)."""
    kept_flows = {}
    for key, per_point in flows.items():
        kept_points = {}
        for point, pkts in per_point.items():
            live = [pk for pk in pkts if not pk.is_duplicate]
            if live:
                kept_points[point] = live
        if kept_points:
            kept_flows[key] = kept_points
    logger.debug("_without_duplicates: {} -> {} flux", len(flows), len(kept_flows))
    return kept_flows


# Seuil de _analyse_pmtud() -- taille minimale (octets, longueur de trame
# capturee) pour qu'un segment retransmis soit considere comme "assez
# gros pour que la fragmentation soit en cause" (ecarte les retransmissions
# de control (SYN/ACK courts) qui ne temoignent d'aucun probleme de MTU).
_PMTUD_MIN_SEGMENT_BYTES = 512


def _analyse_pmtud(r: Report, flows, pairs):
    """
    Detecte les noirs PMTUD : un segment TCP de taille significative,
    retransmis plusieurs fois au point amont d'un segment reseau sans
    jamais atteindre le point aval, et pour lequel aucun signal ICMP(v6)
    de MTU insuffisant n'a ete observe nulle part au point amont sur
    l'ensemble de la capture.

    Deux variantes selon la famille d'adresse du flux (Session 22 --
    IPv4 seul jusque-la), determinee via la presence de ":" dans
    l'adresse source de la cle de flux (voir
    netcross_core.correlate.flow_key -- key[1] = pk.src en mode strict) :

    - IPv4 (RFC 1191) : le bit DF doit etre actif sur TOUTES les
      tentatives observees en amont -- un segment retransmis SANS DF
      actif ne temoigne d'aucun probleme de MTU (l'emetteur autorise
      deja explicitement la fragmentation en route par un routeur
      intermediaire, ce n'est donc pas le scenario vise). Signal ICMP
      correspondant : Fragmentation Needed (type 3, code 4), voir
      r.icmp_frag_needed.
    - IPv6 (RFC 8201) : PAS de verification DF -- ce bit n'existe pas
      cote IPv6 (pk.df toujours False, voir pcap_parser.packet), et la
      semantique qu'il exprime cote IPv4 ("ne pas fragmenter CE paquet",
      par opposition a un paquet qui autoriserait un routeur a le
      fragmenter) est de toute facon IMPLICITE pour TOUT paquet IPv6 :
      seule la source peut fragmenter en IPv6, jamais un routeur
      intermediaire en cours de route (RFC 8200 S4.5) -- un routeur qui
      ne peut pas transmettre un segment IPv6 trop gros n'a categoriquement
      aucune autre option que de le rejeter, qu'un bit DF soit present ou
      non. Un noir PMTUD IPv6 est donc plausible des que le reste des
      conditions (retransmissions repetees, jamais vu en aval, taille
      significative) est reuni, sans condition supplementaire equivalente
      a DF. Signal ICMPv6 correspondant : Packet Too Big (type 2), voir
      r.icmpv6_too_big.

    Signature classique commune aux deux variantes : un routeur
    intermediaire ne peut pas transmettre ce segment (MTU insuffisant sur
    ce lien -- typiquement un tunnel qui ajoute des octets d'en-tete, voir
    aussi la section fragmentation/encapsulation) et devrait le signaler
    par ICMP(v6), mais ce message est filtre (pare-feu bloquant tout
    l'ICMP) ou jamais emis -- l'emetteur ne reduit alors jamais la taille
    de ses segments et la connexion stagne indefiniment plutot que
    d'echouer proprement.

    Appelee apres le bloc fragmentation/MTU de analyse() : necessite
    r.icmp_frag_needed ET r.icmpv6_too_big deja completement peuples pour
    savoir si l'absence de retour ICMP(v6) au point amont est reelle.

    Limite assumee (documentee, comme le reste du module) : le
    rapprochement avec le message ICMP(v6) se fait sur la capture entiere
    au point amont, pas sur une fenetre temporelle precise autour de CE
    segment precis -- necessiterait de decoder le paquet IP embarque dans
    la charge utile ICMP(v6) pour un appariement par flux exact, hors
    perimetre de cette passe (voir FEATURES.md). Comme pour le reste de
    cette fonction, non applicable en mode --nat-tolerant : la cle de
    flux y devient ("NAT", proto, payload_hash, bucket) -- key[0] != "TCP"
    dans ce cas, donc deja exclue par la garde ci-dessous (limitation
    preexistante, pas affectee par l'ajout IPv6).
    """
    for key, per_point in flows.items():
        if key[0] != "TCP":
            continue
        is_ipv6 = ":" in key[1]  # key[1] = pk.src (voir flow_key, mode strict)
        for a, b in pairs:
            if a not in per_point or b in per_point:
                continue  # pas de perte sur ce segment pour ce flux precis
            pkts_a = per_point[a]
            data_pkts_a = [pk for pk in pkts_a if pk.payload_hash is not None]
            if len(data_pkts_a) < 2:
                continue  # pas de retransmission observee en amont
            if is_ipv6:
                icmp_signal_seen = r.icmpv6_too_big.get(a, 0) > 0
            else:
                if not all(pk.df for pk in data_pkts_a):
                    continue  # DF pas actif sur toutes les tentatives -> pas le scenario vise
                icmp_signal_seen = r.icmp_frag_needed.get(a, 0) > 0
            max_len = max(pk.length for pk in data_pkts_a)
            if max_len < _PMTUD_MIN_SEGMENT_BYTES:
                continue  # segment trop petit pour que la fragmentation soit en cause
            if icmp_signal_seen:
                continue  # ICMP(v6) bien remonte en amont -> pas un noir
            r.pmtud_blackhole[(a, b)] += 1
            if len(r.pmtud_blackhole_examples[(a, b)]) < 5:
                sample = pkts_a[0]
                signal_suffix = "IPv6, pas de bit DF" if is_ipv6 else "DF actif"
                r.pmtud_blackhole_examples[(a, b)].append(
                    f"{sample.src}:{sample.sport} -> {sample.dst}:{sample.dport} "
                    f"({len(data_pkts_a)} tentative(s), {max_len} octets, {signal_suffix})"
                )
                # meme index que l'exemple texte ci-dessus -- voir
                # Report.pmtud_blackhole_frames et netcross_report.synthesis.
                r.pmtud_blackhole_frames[(a, b)].append(sample.frame_number)
    logger.debug("_analyse_pmtud: {}", _resume(r, "pmtud_blackhole"))


# Seuil de _analyse_idle_timeout() -- silence minimal (secondes) entre
# deux paquets consecutifs au point amont pour considerer qu'un flux a
# traverse une periode d'inactivite susceptible d'avoir expire une
# entree de table d'etat NAT/pare-feu. Volontairement conservateur :
# largement au-dela d'un keepalive TCP applicatif classique (souvent
# 20-30s, HTTP keep-alive/SSH ServerAliveInterval), mais bien en deca du
# minimum recommande par la RFC 5382 SS5 pour un NAT conforme (>= 2h04,
# 7440s) -- de nombreux equipements NAT/pare-feu grand public ou
# d'entree de gamme appliquent en pratique un timeout d'etat TCP etabli
# beaucoup plus court que cette recommandation (quelques dizaines de
# secondes a quelques minutes) sans jamais le publier. Ce seuil ne vise
# pas a identifier LE timeout exact d'un equipement precis (impossible a
# deduire d'une seule capture sans le documenter par construction) mais
# a filtrer les silences applicatifs courants (une requete utilisateur
# occasionnelle sur une session interactive) pour ne retenir que les
# silences longs, seuls compatibles avec l'hypothese "table d'etat
# expiree".
_IDLE_TIMEOUT_SECONDS = 60.0


def _analyse_idle_timeout(r: Report, all_packets, pairs, idle_timeout_seconds=_IDLE_TIMEOUT_SECONDS):
    """
    Detecte les coupures NAT/pare-feu silencieuses : une connexion TCP
    (5-tuple directionnel, PAS un segment individuel -- voir note de
    conception ci-dessous) deja vue des DEUX cotes d'un segment reseau
    (a, b), dont le plus grand silence entre deux paquets consecutifs au
    point amont depasse `idle_timeout_seconds`, et dont le trafic qui
    reprend en amont APRES ce silence n'est plus jamais revu au point
    aval.

    Signature typique : une session TCP de longue duree (session
    interactive peu active, connexion applicative persistante) traverse
    un equipement NAT/pare-feu a etat ; pendant une periode d'inactivite
    plus longue que le timeout (non documente) de cet equipement, son
    entree de table d'etat est silencieusement purgee ; quand le trafic
    reprend, l'equipement ne reconnait plus le flux et le rejette --
    sans emettre de RST (sinon ce serait un rejet explicite, diagnostic
    different et deja couvert par r.rst_localized/r.rst_count), d'ou le
    qualificatif "silencieuse".

    A la difference de _analyse_pmtud ci-dessus (qui ne regarde qu'un
    flux jamais vu du tout en aval), ce detecteur exige au contraire que
    la connexion ait ete vue en aval AVANT la reprise -- c'est
    precisement cette reprise avortee APRES un etablissement reussi qui
    distingue une coupure NAT/FW en cours de session d'une simple perte
    de flux classique (deja couverte par r.loss_count).

    Note de conception -- pourquoi ce detecteur regroupe par 5-tuple sur
    all_packets plutot que de reutiliser `flows` (comme _analyse_pmtud) :
    `flows` (netcross_core.correlate.flow_key) est indexe par 5-tuple
    directionnel + `key_id`, et `key_id` vaut le numero de SEQUENCE TCP
    pour ce protocole (voir pcap_parser.packet::build_packet) -- chaque
    entree de `flows` represente donc un SEGMENT precis (et ses
    eventuelles retransmissions, qui partagent le meme seq), pas une
    connexion TCP entiere (qui enchaine des segments a seq croissante,
    donc des cles `flows` DIFFERENTES au fil du temps). Le silence vise
    ici est celui d'une session TOUTE ENTIERE (plus aucun octet envoye,
    quel que soit le segment) suivi d'une REPRISE avec de la donnee
    NOUVELLE (donc un seq different, donc une autre cle `flows`) --
    inobservable en iterant sur `flows` tel quel, qui ne verrait jamais
    la reprise et le silence comme faisant partie du meme flux. Ce
    detecteur reconstruit donc sa propre vue par connexion directement
    depuis all_packets, meme technique que _analyse_rtp ci-dessous pour
    ses flux RTP (5-tuple + SSRC, egalement hors du perimetre naturel de
    `flows`).

    Limites assumees (documentees, comme le reste de ce module) :
    - Un seul silence est retenu par connexion/segment reseau (le plus
      grand) -- une connexion qui traverserait plusieurs longs silences
      distincts avant de finalement ne plus jamais reapparaitre en aval
      n'est comptee qu'une fois, comme pmtud_blackhole ne compte qu'un
      noir par flux.
    - Aucune verification explicite de l'absence de FIN/RST juste avant
      le silence : une connexion proprement close puis suivie bien plus
      tard d'un paquet residuel partageant le meme 5-tuple (nouvelle
      connexion avec reutilisation rapide du meme port ephemere, rare
      mais possible sous forte charge) pourrait en theorie etre
      confondue avec une coupure silencieuse. Juge negligeable en
      pratique mais non verifie positivement.
    - Scope volontairement limite a TCP (pas UDP) : la notion de
      "session" avec etablissement/silence/reprise n'a de sens direct
      que pour un protocole avec etat ; un equivalent UDP (ex: timeout
      NAT sur un flux RTP) est un chantier a part, deja partiellement
      couvert cote perte/gigue par r.rtp_streams (_analyse_rtp) sans
      notion explicite de silence prolonge.
    - Ne distingue pas une coupure NAT/FW en cours de capture d'une
      capture qui s'arrete juste apres la reprise en amont, avant que le
      paquet ait eu le temps d'atteindre (ou d'etre rejete avant) le
      point aval -- meme limite structurelle que "jamais vu en aval"
      pour la perte classique (r.loss_count).
    """
    conn_ts: defaultdict[tuple[str, int | None, str, int | None], defaultdict[str, list[tuple[float, int | None]]]] = (
        defaultdict(lambda: defaultdict(list))
    )  # (src,sport,dst,dport) -> point -> [(ts, frame_number), ...]
    for pk in all_packets:
        if pk.proto != "TCP":
            continue
        conn_ts[(pk.src, pk.sport, pk.dst, pk.dport)][pk.point].append((pk.ts, pk.frame_number))

    for (src, sport, dst, dport), per_point in conn_ts.items():
        for a, b in pairs:
            if a not in per_point or b not in per_point:
                continue  # il faut avoir vu la connexion etablie aux DEUX points au moins une fois
            ts_a = sorted(per_point[a])
            ts_b = sorted(per_point[b])
            if len(ts_a) < 2:
                continue  # pas assez de paquets en amont pour mesurer un silence
            gap, _gap_start, gap_end = max(
                ((ts_a[i + 1][0] - ts_a[i][0], ts_a[i], ts_a[i + 1]) for i in range(len(ts_a) - 1)),
                key=lambda g: g[0],
            )
            if gap < idle_timeout_seconds:
                continue
            # "avant la reprise" se compare a gap_end (debut de la reprise
            # en amont), PAS au debut du trou : le point aval voit toujours
            # le trafic un peu APRES le point amont (delai de propagation),
            # donc son dernier paquet "avant le trou" a un ts strictement
            # superieur au debut du trou dans le cas normal -- comparer au
            # debut du trou ferait manquer quasiment tous les cas reels.
            if not any(t[0] < gap_end[0] for t in ts_b):
                continue  # la connexion n'avait meme pas ete vue en aval avant la reprise -> pas ce scenario
            if any(t[0] >= gap_end[0] for t in ts_b):
                continue  # le trafic repris en amont a bien ete revu en aval -> pas une coupure
            r.idle_timeout_dropped[(a, b)] += 1
            if len(r.idle_timeout_examples[(a, b)]) < 5:
                r.idle_timeout_examples[(a, b)].append(
                    f"{src}:{sport} -> {dst}:{dport} (silence de {gap:.0f}s en {a}, "
                    f"trafic jamais revu en {b} apres reprise)"
                )
                # gap_end = (ts, frame_number) du paquet qui reprend le
                # trafic en amont -- meme index/plafond que l'exemple texte
                # ci-dessus, voir Report.idle_timeout_frames (Session 37).
                r.idle_timeout_frames[(a, b)].append(gap_end[1])
    logger.debug("_analyse_idle_timeout: {}", _resume(r, "idle_timeout_dropped"))


def _analyse_arp_ip_conflict(r: Report, all_packets):
    """
    Detecte un conflit d'adresse IP (deux hotes differents qui
    revendiquent la meme adresse IP sur le meme segment de diffusion),
    via le trafic ARP observe -- symptome classique : connexions
    intermittentes, deux postes qui "se coupent" alternativement l'un
    l'autre, IP flottante mal configuree en double, ou simple erreur de
    plan d'adressage statique.

    Principe : chaque paquet ARP (requete OU reponse, RFC 826) porte
    dans son propre champ "sender" une revendication implicite "je suis
    cette IP, voici ma MAC" -- utile meme sur une requete who-has, dont
    le but premier est justement d'apprendre la MAC du DESTINATAIRE (pas
    de l'emetteur, deja connue de l'emetteur lui-meme, mais annoncee
    dans le paquet pour permettre une reponse directe). Si, AU MEME
    POINT de capture, la meme IP source apparait avec plus d'une adresse
    MAC differente au fil de la capture, c'est un conflit -- que les
    paquets en cause soient des requetes, des reponses, ou des annonces
    gratuites (RFC 5227) n'a pas d'importance pour cette detection, tous
    portent la meme information "sender IP <-> sender MAC" utilisable de
    la meme facon.

    Volontairement une detection PAR POINT (pas par paire de points
    amont/aval comme la plupart des autres detecteurs de ce module) : un
    conflit d'adresse se voit deja au sein d'un seul point de capture
    (deux hotes sur le meme segment de diffusion), une correlation
    inter-points n'apporte rien de plus ici -- ARP n'etant de toute
    facon jamais relaye par un routeur (voir netcross_core.correlate.
    correlate(), qui exclut deliberement ARP de `flows` pour cette
    raison), une comparaison amont/aval n'aurait techniquement plus
    aucun sens pour ce protocole.

    Limites assumees :
    - Aucune fenetre temporelle : deux MAC revendiquant la meme IP a
      n'importe quel moment de la capture (meme tres espacees dans le
      temps) sont considerees en conflit. Un remplacement legitime de
      materiel (carte reseau changee, VM reconstruite avec une nouvelle
      MAC mais en gardant la meme IP statique) au cours d'une capture
      TRES longue pourrait en theorie etre confondu avec un vrai
      conflit -- juge tres improbable a l'echelle d'une capture de
      diagnostic ponctuelle (minutes a quelques heures, pas des jours),
      mais non filtre explicitement.
    - Pas de distinction entre un vrai conflit persistant (deux hotes
      mal configures en continu) et un failover legitime a base d'IP
      flottante (VRRP/keepalived, HA de pare-feu...) qui migre
      volontairement une IP d'une MAC a une autre lors d'un basculement
      -- les deux se traduisent de la meme facon cote ARP (nouvelle MAC
      qui revendique une IP deja vue avec une autre). Distinguer les
      deux demanderait de connaitre la configuration reseau (IP
      virtuelles declarees), hors de portee d'une simple lecture de
      capture.
    """
    seen: defaultdict[str, defaultdict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )  # point -> IP -> {MAC, ...}
    last_pkt: defaultdict[str, dict[str, Pkt]] = defaultdict(
        dict
    )  # point -> IP -> dernier Pkt ARP observe (pour PacketEvidence, Session 37)
    for pk in all_packets:
        if pk.proto != "ARP" or pk.arp_sender_mac is None or pk.src is None:
            continue
        seen[pk.point][pk.src].add(pk.arp_sender_mac)
        last_pkt[pk.point][pk.src] = pk

    for point, by_ip in seen.items():
        for ip, macs in by_ip.items():
            if len(macs) < 2:
                continue
            r.arp_ip_conflict[point] += 1
            if len(r.arp_ip_conflict_examples[point]) < 5:
                r.arp_ip_conflict_examples[point].append(
                    f"{ip} revendique par {len(macs)} adresses MAC differentes : {', '.join(sorted(macs))}"
                )
                r.arp_ip_conflict_frames[point].append(last_pkt[point][ip].frame_number)
    logger.debug("_analyse_arp_ip_conflict: {}", _resume(r, "arp_ip_conflict"))


def _analyse_stp_instability(r: Report, all_packets):
    """
    Detecte une instabilite du Spanning Tree Protocol (IEEE 802.1D/w/s)
    au sein d'un point de capture : tempete de changements de topologie,
    ou reelections repetees du pont racine -- deux signatures classiques
    d'une boucle de commutation ou d'un lien/port qui flappe (bascule
    haut/bas de facon repetee).

    Deux compteurs independants :

    1. `stp_topology_change` -- un evenement de changement de topologie
       est signale de DEUX facons possibles, considerees equivalentes
       ici : soit une BPDU de type TCN (Topology Change Notification,
       0x80 -- emise par le pont qui detecte le changement, propagee
       vers la racine), soit une Configuration BPDU avec le bit TC actif
       (`stp.flags.tc`, classification NATIVE tshark -- emise ENSUITE
       par le pont racine pour propager l'information a tout le reseau,
       pendant la duree du "max age" apres reception d'un TCN). Compter
       les deux comme un seul et meme phenomene (plutot que de choisir
       arbitrairement l'un ou l'autre) maximise la detection : selon
       l'endroit exact du reseau ou la capture est prise, on peut voir
       l'un sans l'autre. Un reseau STP stable n'emet quasiment jamais
       ce genre de trame (topologie figee) ; une boucle ou un port qui
       flappe en genere en rafale, souvent plusieurs par seconde.

    2. `stp_root_change` -- le pont racine annonce (priorite + adresse
       MAC concatenees, `Pkt.stp_root_id`) change de valeur d'une
       Configuration BPDU a la suivante, AU MEME POINT. Une reelection
       ponctuelle (une seule fois dans toute la capture) peut etre
       benigne (ex: mise sous tension d'un nouveau pont a plus haute
       priorite en debut de capture) ; des reelections REPETEES pendant
       la capture sont, elles, un signal fort d'instabilite. Ce
       detecteur remonte le compte brut (comme la plupart des autres
       detecteurs de ce module) plutot que d'imposer un seuil subjectif
       de "combien est trop" -- au lecteur du rapport de juger selon le
       contexte (une seule occurrence en tout debut de capture n'a pas
       le meme poids que dix occurrences reparties sur toute sa duree).

    Volontairement des detections PAR POINT (pas par paire de points
    amont/aval) : STP, comme ARP, n'est jamais relaye par un routeur
    (voir netcross_core.correlate.correlate(), qui exclut deliberement
    STP de `flows` pour cette raison) -- une comparaison amont/aval
    n'aurait techniquement plus aucun sens pour ce protocole.

    Limites assumees :
    - "Flapping de port" au sens strict (un port de COMMUTATEUR qui
      bascule haut/bas de facon repetee) n'est PAS directement observable
      depuis une capture reseau : cette information vit dans la table
      d'etat interne du commutateur (SNMP/syslog), pas sur le fil. Ce
      detecteur observe la CONSEQUENCE visible sur le fil (tempete de
      changements de topologie, reelections de racine) plutot que la
      cause exacte (quel port precis, sur quel commutateur) -- limite
      architecturale honnete d'un outil base sur la capture de trafic,
      pas un oubli.
    - Ne distingue pas une tempete causee par une vraie boucle physique
      d'une tempete causee par un lien qui flappe pour une autre raison
      (auto-negotiation instable, cable defectueux, alimentation PoE
      instable...) -- le signal remonte "le reseau est instable", pas
      sa cause racine exacte, cohérent avec le reste des detecteurs de
      ce module qui remontent des symptomes observables plutot que des
      causes inferees.
    """
    stp_pkts = [pk for pk in all_packets if pk.proto == "STP"]
    for pk in stp_pkts:
        if pk.stp_bpdu_type == 0x80 or pk.stp_flags_tc:
            r.stp_topology_change[pk.point] += 1

    # Comparaison "racine precedente -> racine actuelle" PAR POINT, donc
    # triee explicitement par horodatage a l'interieur de chaque point --
    # ne suppose PAS que all_packets est deja globalement chronologique
    # entre points (il ne l'est pas forcement : le CLI concatene les
    # paquets point par point, voir cross_capture_analyzer_cli.py, pas
    # un merge par horodatage global). Meme discipline defensive que
    # _analyse_idle_timeout ci-dessus (sorted() plutot que de faire
    # confiance a l'ordre d'entree).
    by_point = defaultdict(list)
    for pk in stp_pkts:
        if pk.stp_root_id is not None:
            by_point[pk.point].append(pk)
    for point, pkts in by_point.items():
        pkts.sort(key=lambda p: p.ts)
        previous = None
        for pk in pkts:
            if previous is not None and previous != pk.stp_root_id:
                r.stp_root_change[point] += 1
                if len(r.stp_root_change_examples[point]) < 5:
                    r.stp_root_change_examples[point].append(f"racine changee de {previous} vers {pk.stp_root_id}")
                    r.stp_root_change_frames[point].append(pk.frame_number)
            previous = pk.stp_root_id
    logger.debug("_analyse_stp_instability: {}", _resume(r, "stp_topology_change", "stp_root_change"))


def _parse_tls_cert_date(s: str | None) -> datetime | None:
    """Convertit une date de certificat telle que rendue par tshark
    ("YYYY-MM-DD HH:MM:SS (UTC)", verifie empiriquement -- voir
    extract_tls_certificate/claude.md Session 26) en datetime UTC.
    Renvoie None si le format ne correspond pas a ce qui est attendu --
    pas de reconstruction approximative en cas de doute, meme discipline
    que parse_client_hello/parse_server_hello dans tls_diagnostics.py."""
    if s is None:
        return None
    try:
        return datetime.strptime(s.removesuffix(" (UTC)"), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        logger.debug("_parse_tls_cert_date: format de date inattendu {!r}", s)
        return None


def _analyse_tls_certificate(r: Report, all_packets, pairs):
    """
    Deux diagnostics independants a partir du certificat FEUILLE
    presente lors d'un handshake TLS (voir pcap_parser.protocols.
    extract_tls_certificate pour le detail du perimetre -- notamment
    l'absence volontaire de Subject/Issuer, et l'invisibilite du
    certificat en TLS 1.3 sans SSLKEYLOGFILE) :

    1. `tls_cert_invalid_dates` (PAR POINT, comme ARP/STP) : le
       certificat est presente HORS de sa fenetre de validite au moment
       ou le handshake a ete capture -- soit deja expire (notAfter <
       horodatage du paquet), soit pas encore valide (notBefore >
       horodatage du paquet, plus rare mais possible : horloge serveur
       desynchronisee, certificat deploye en avance). Comparaison
       effectuee contre l'horodatage du PAQUET lui-meme (l'instant ou le
       certificat a ete presente), pas contre l'heure actuelle -- une
       analyse a froid d'une capture ancienne doit rester correcte : un
       certificat valide au moment de la capture mais expire depuis ne
       doit PAS etre signale a tort.
    2. `tls_cert_mismatch` (PAR PAIRE de points, comme pmtud_blackhole/
       idle_timeout_dropped) : pour une meme connexion (5-tuple), le
       numero de serie du certificat presente differe entre le point
       amont et le point aval -- un serveur ne change normalement PAS
       de certificat au sein d'une meme connexion TCP. Signature
       possible d'une interception/substitution TLS en cours de chemin
       (proxy d'inspection, dispositif MITM) qui presente SON PROPRE
       certificat au lieu de relayer tel quel celui du vrai serveur --
       ou, plus benin, un load-balancer/reverse-proxy en aval qui
       termine le TLS avec un certificat different de celui du serveur
       reel en amont (architecture legitime mais bonne a savoir).

    Limites assumees :
    - Une seule paire (notBefore, notAfter) par connexion et par point
      (la derniere observee ecrase la precedente en cas de handshakes
      TLS multiples sur la meme connexion -- reprise de session,
      renegociation) : simplification deliberee, la grande majorite des
      connexions n'ont qu'un seul handshake initial.
    - Ne verifie PAS la chaine de confiance PKI (autorite de
      certification, revocation) : hors de portee d'une capture reseau
      passive, qui n'a pas acces au magasin de confiance du client (voir
      aussi extract_tls_certificate).
    - Le format de date attendu est verifie empiriquement contre tshark
      4.2.2 (voir _parse_tls_cert_date) ; une version de tshark qui
      rendrait un format different ferait silencieusement ignorer le
      paquet concerne (pas de plantage) plutot que de mal interpreter
      une date.
    """
    for pk in all_packets:
        if pk.tls_cert_serial is None:
            continue
        not_before = _parse_tls_cert_date(pk.tls_cert_not_before)
        not_after = _parse_tls_cert_date(pk.tls_cert_not_after)
        if not_before is None or not_after is None:
            continue
        seen_at = datetime.fromtimestamp(pk.ts, tz=timezone.utc)
        if seen_at > not_after:
            r.tls_cert_invalid_dates[pk.point] += 1
            if len(r.tls_cert_invalid_dates_examples[pk.point]) < 5:
                r.tls_cert_invalid_dates_examples[pk.point].append(
                    f"certificat (numero de serie {pk.tls_cert_serial}) deja expire depuis le "
                    f"{not_after:%Y-%m-%d}, presente le {seen_at:%Y-%m-%d}"
                )
                r.tls_cert_invalid_dates_frames[pk.point].append(pk.frame_number)
        elif seen_at < not_before:
            r.tls_cert_invalid_dates[pk.point] += 1
            if len(r.tls_cert_invalid_dates_examples[pk.point]) < 5:
                r.tls_cert_invalid_dates_examples[pk.point].append(
                    f"certificat (numero de serie {pk.tls_cert_serial}) pas encore valide avant le "
                    f"{not_before:%Y-%m-%d}, presente le {seen_at:%Y-%m-%d}"
                )
                r.tls_cert_invalid_dates_frames[pk.point].append(pk.frame_number)

    serial_by_point: defaultdict[str, dict[tuple[str, int | None, str, int | None], tuple[str, int | None]]] = (
        defaultdict(dict)
    )  # point -> (src, sport, dst, dport) -> (numero de serie, frame_number)
    for pk in all_packets:
        if pk.tls_cert_serial is None:
            continue
        serial_by_point[pk.point][(pk.src, pk.sport, pk.dst, pk.dport)] = (pk.tls_cert_serial, pk.frame_number)

    for a, b in pairs:
        conns_a = serial_by_point.get(a, {})
        conns_b = serial_by_point.get(b, {})
        for conn, (serial_a, frame_a) in conns_a.items():
            entry_b = conns_b.get(conn)
            if entry_b is None or entry_b[0] == serial_a:
                continue
            serial_b = entry_b[0]
            r.tls_cert_mismatch[(a, b)] += 1
            if len(r.tls_cert_mismatch_examples[(a, b)]) < 5:
                src, sport, dst, dport = conn
                r.tls_cert_mismatch_examples[(a, b)].append(
                    f"{src}:{sport} -> {dst}:{dport} : numero de serie {serial_a} en {a}, {serial_b} en {b}"
                )
                r.tls_cert_mismatch_frames[(a, b)].append(frame_a)
    logger.debug("_analyse_tls_certificate: {}", _resume(r, "tls_cert_invalid_dates", "tls_cert_mismatch"))


def _analyse_tls_handshake(r: Report, all_packets):
    """
    Session 54 -- decision architecturale documentee depuis la Session
    49 (voir claude.md/expert_rules.py) : "negociations TLS incompletes"
    (FEATURES.md section 6.2) rejoint desormais ce pipeline Report/
    Finding, PAR POINT, en lisant les champs NATIFS de
    pcap_parser.protocols.extract_tls_handshake -- PAS en import(ant) ni
    en reutilisant netcross_core.tls_diagnostics (module volontairement
    independant, voir sa docstring de module : il re-parse lui-meme les
    octets de la charge utile TCP pour obtenir des informations plus
    riches -- SNI, version/cipher negocies -- hors de portee de ce
    detecteur-ci, plus modeste par construction). Les deux modules
    partagent desormais un but voisin (diagnostiquer une negociation TLS
    qui ne va pas a son terme) mais aucun code : deux techniques
    differentes, deux types de sortie differents (Finding catalogable
    ici via `rule_id`, TlsFinding independant la-bas), assumes comme
    tels plutot que fusionnes de force.

    Deux signaux, PAR POINT (comme tls_cert_invalid_dates ci-dessus --
    AUCUNE correlation entre points necessaire, contrairement a
    tls_cert_mismatch) :

    1. `tls_handshake_no_reply` : un ClientHello est vu pour une
       connexion (5-tuple) a ce point, mais AUCUN ServerHello n'est
       JAMAIS observe ensuite pour cette meme connexion, a ce meme
       point, dans le reste de la capture -- silence total apres
       l'ouverture de la negociation.
    2. `tls_handshake_incomplete` : un ServerHello EST vu pour cette
       connexion a ce point (la negociation a demarre des deux cotes),
       mais aucun enregistrement application_data n'est JAMAIS observe
       ensuite pour cette meme connexion, a ce meme point -- la
       negociation demarre puis s'interrompt avant son terme.

    Correlation par connexion NON orientee (tuple des deux extremites
    (ip, port) tries) plutot que par 5-tuple directionnel strict (a la
    difference de _analyse_handshake ci-dessus, qui a besoin de
    retrouver un SYN-ACK precis emis dans le sens INVERSE du SYN) :
    ClientHello/ServerHello/application_data peuvent chacun apparaitre
    dans l'un OU l'autre sens selon le message, un seul point de vue
    suffit pour cette connexion a CE point -- pas besoin de savoir quel
    cote a emis quoi, seulement CE QUI a ete vu pour cette connexion.

    Limites assumees (memes principes que _analyse_tls_certificate
    ci-dessus, voir aussi extract_tls_handshake) :
    - Ne distingue PAS "la negociation est reellement bloquee" de "la
      capture s'est arretee avant que la suite n'arrive" -- comme
      dns_timeout/syn_no_synack, une limite structurelle de toute
      analyse PAR POINT sur une capture forcement finie.
    - TLS 1.3 deguise en application_data (content_type=23) les
      messages de handshake qui suivent le ServerHello (Encrypted
      Extensions, Certificate, CertificateVerify, Finished -- pour la
      compatibilite des intermediaires qui n'attendent que des types
      d'enregistrement TLS 1.2 classiques) : `tls_handshake_incomplete`
      peut donc se declencher a tort dans de RARES cas ou une
      negociation TLS 1.3 s'interrompt juste apres le premier de ces
      messages deguises mais avant tout VRAI transfert applicatif --
      limite deja documentee de la meme maniere dans
      netcross_core.tls_diagnostics (meme ambiguite de protocole, pas
      une erreur d'implementation propre a ce module).
    - Une seule negociation par connexion et par point (la premiere vue
      fait foi) : simplification deliberee, comme tls_cert_invalid_dates
      ci-dessus.
    """
    # point -> connexion non orientee (deux extremites triees) -> etat
    state: dict = defaultdict(dict)
    for pk in all_packets:
        if not (pk.tls_client_hello or pk.tls_server_hello or pk.tls_application_data):
            continue
        conn = tuple(sorted(((pk.src, pk.sport), (pk.dst, pk.dport))))
        entry = state[pk.point].setdefault(
            conn,
            {"client_hello": False, "server_hello": False, "application_data": False, "frame": None, "desc": None},
        )
        if pk.tls_client_hello and entry["frame"] is None:
            entry["frame"] = pk.frame_number
            entry["desc"] = f"{pk.src}:{pk.sport} -> {pk.dst}:{pk.dport}"
        entry["client_hello"] = entry["client_hello"] or pk.tls_client_hello
        entry["server_hello"] = entry["server_hello"] or pk.tls_server_hello
        entry["application_data"] = entry["application_data"] or pk.tls_application_data

    for point, conns in state.items():
        for info in conns.values():
            if not info["client_hello"]:
                continue
            if not info["server_hello"]:
                r.tls_handshake_no_reply[point] += 1
                if len(r.tls_handshake_no_reply_examples[point]) < 5:
                    r.tls_handshake_no_reply_examples[point].append(
                        f"{info['desc']} : ClientHello envoye, aucun ServerHello observe a ce point"
                    )
                    r.tls_handshake_no_reply_frames[point].append(info["frame"])
            elif not info["application_data"]:
                r.tls_handshake_incomplete[point] += 1
                if len(r.tls_handshake_incomplete_examples[point]) < 5:
                    r.tls_handshake_incomplete_examples[point].append(
                        f"{info['desc']} : ServerHello recu, aucune donnee applicative observee ensuite a ce point"
                    )
                    r.tls_handshake_incomplete_frames[point].append(info["frame"])
    logger.debug("_analyse_tls_handshake: {}", _resume(r, "tls_handshake_no_reply", "tls_handshake_incomplete"))


def _analyse_retransmission_types(r: Report, all_packets):
    """
    Classe chaque retransmission TCP par cause probable, en lisant
    directement la classification NATIVE de tshark (tcp.analysis.
    retransmission / .fast_retransmission / .spurious_retransmission,
    voir pcap_parser.packet et ek_fields.has_expert_flag) plutot que de
    reimplementer une heuristique maison -- le moteur d'etat TCP complet
    de tshark (dup-acks recents dans le sens inverse, fenetre, ACK deja
    vu...) fait deja ce travail mieux que ce que ce projet pourrait
    reproduire simplement.

    Trois compteurs par point, mutuellement exclusifs cote netcross (mais
    PAS au niveau des champs tshark bruts eux-memes : is_retransmission
    reste actif meme quand is_fast_retransmission/is_spurious_
    retransmission le sont aussi -- verifie empiriquement, claude.md
    Session 10, voir docstring de RawPacket. Priorite appliquee ici,
    spurious > fast > simple, du plus specifique au plus general, pour
    ne compter chaque paquet qu'une seule fois) :
    - retrans_fast : reaction reactive a 3 ACK dupliques (ou saut de
      MSS), recuperation rapide -- signe d'un TCP qui fonctionne
      normalement face a une perte isolee, pas alarmant en soi ;
    - retrans_rto : renvoi apres expiration du minuteur de retransmission
      (aucun ACK duplique recent pour declencher un renvoi rapide) --
      recuperation plus lente, plus souvent le signe d'un lien
      significativement perturbe ou d'un reordonnancement qui masque les
      ACK dupliques ;
    - retrans_spurious : la donnee renvoyee avait en realite deja ete
      acquittee (visible dans CETTE capture) -- le renvoi n'etait pas
      necessaire, l'ACK n'etait simplement pas encore arrive assez tot ;
      indique souvent un minuteur de retransmission mal calibre par
      rapport au vrai RTT, ou un chemin de retour ACK asymetrique/plus
      lent.

    Limite assumee : cette classification est calculee par tshark
    INDEPENDAMMENT pour chaque fichier de capture (un point = un fichier
    = un processus tshark), a partir de ce que CE point peut voir. La
    condition "fast retransmission" de Wireshark exige notamment d'avoir
    vu le dernier ACK il y a moins de 20ms -- un point de capture eloigne
    de l'emetteur (RTT important jusqu'a ce point) peut donc constater
    une classification differente de ce qu'un point plus proche de
    l'emetteur observerait pour la MEME retransmission reelle sur le fil.
    Comportement de tshark lui-meme, pas une approximation ajoutee par ce
    module.
    """
    for pk in all_packets:
        if pk.proto != "TCP":
            continue
        if pk.is_spurious_retransmission:
            r.retrans_spurious[pk.point] += 1
        elif pk.is_fast_retransmission:
            r.retrans_fast[pk.point] += 1
        elif pk.is_retransmission:
            r.retrans_rto[pk.point] += 1
    logger.debug("_analyse_retransmission_types: {}", _resume(r, "retrans_spurious", "retrans_fast", "retrans_rto"))


def _analyse_tcp_expert_signals(r: Report, all_packets):
    """
    Exploite les signaux d'expertise TCP NATIFS de tshark (tcp.analysis.*)
    au-dela des trois retransmissions deja decodees en booleens RawPacket
    (voir _analyse_retransmission_types) : out-of-order, lost segment,
    window update. Compte par point, complementaire des heuristiques
    retrans/dup_ack/zero_window (qui restent pour compatibilite avec
    l'existant -- baseline_diff notamment).

    Objectif (issue #21) : mieux distinguer perte reelle, reordonnancement,
    retransmission rapide et RTO. tshark dispose d'un moteur d'etat TCP
    complet qui classe chaque segment ; on reutilise sa classification plutot
    que de la reimplementer.

    - out_of_order (tcp.analysis.out_of_order) : segment recu dans le
      desordre -- REORDONNANCEMENT, pas une perte. Distinct des
      retransmissions (conditions mutuellement exclusives cote tshark) :
      isole les vraies pertes des simples remises dans le desordre.
    - lost_segment (tcp.analysis.lost_segment) : tshark a infere qu'un
      segment a ete perdu (trou dans la numerotation de sequence non
      recu dans cette capture) -- signal de PERTE REELLE, plus precis
      que l'heuristique retrans (qui compte aussi le reordonnancement).
    - window_update (tcp.analysis.window_update) : changement de fenetre
      de reception -- ni perte ni retransmission, mais signal utile pour
      diagnostiquer un recepteur qui limite le debit (couple avec
      zero_window ci-dessus).

    Source : RawPacket.expert_flags, qui capte deja TOUS les noms de
    condition _ws_expert (voir pcap_parser.ek_fields.expert_flag_names) --
    aucun decodage supplementaire cote pcap_parser, on exploite juste ce
    champ deja calcule. Les noms EK normalises suivent la convention
    tcp_tcp_analysis_<suffixe> (prefixe double, comme tcp_tcp_srcport).
    """
    for pk in all_packets:
        if pk.proto != "TCP":
            continue
        flags = pk.expert_flags
        if "tcp_tcp_analysis_out_of_order" in flags:
            r.out_of_order[pk.point] += 1
        if "tcp_tcp_analysis_lost_segment" in flags:
            r.lost_segment[pk.point] += 1
        if "tcp_tcp_analysis_window_update" in flags:
            r.window_update[pk.point] += 1
    logger.debug("_analyse_tcp_expert_signals: {}", _resume(r, "out_of_order", "lost_segment", "window_update"))


def _analyse_application_transactions(r: Report, all_packets: list[Pkt]):
    """
    Construit et classifie les transactions applicatives (Job 23, §6.9/§6.10).

    Modèle : Flow -> protocole applicatif -> requête/réponse -> transaction
    -> temps réseau + temps serveur + temps total -> classification.

    Couvre HTTP et DNS. La distinction automatique produit :
    - normal : temps total sous le seuil du protocole
    - missing_response : requête sans réponse (perte / serveur / proxy)
    - network_slow : lenteur + signaux TCP (retrans, lost_segment, out_of_order)
    - server_slow : server_time_ms mesuré et dominant
    - application_slow : lenteur sans preuve réseau ni serveur

    Les transactions sont stockées dans Report.application_transactions
    (liste de dicts, comme http_objects) pour consommation par les modules
    d'analyse et de rapport.
    """
    # Collecte des signaux réseau par flux TCP (5-tuple directionnel)
    network_signals: dict[tuple[str, str, int | None, int | None], list[str]] = {}
    for pk in all_packets:
        if pk.proto != "TCP":
            continue
        flow_key = (pk.src, pk.dst, pk.sport, pk.dport)
        signals = network_signals.setdefault(flow_key, [])
        if pk.is_retransmission:
            signals.append("retransmission")
        if pk.is_fast_retransmission:
            signals.append("fast_retransmission")
        if "tcp_tcp_analysis_lost_segment" in pk.expert_flags:
            signals.append("lost_segment")
        if "tcp_tcp_analysis_out_of_order" in pk.expert_flags:
            signals.append("out_of_order")

    thresholds = TransactionThresholds()
    transactions = []

    # HTTP : apparieer requêtes/réponses par flux TCP
    for txn in build_http_transactions(all_packets, network_signals):
        txn.classification = classify_transaction(txn, thresholds)
        transactions.append(txn)

    # DNS : apparieer requêtes/réponses par clé (point, endpoints, txn_id, query)
    for txn in build_dns_transactions(all_packets):
        txn.classification = classify_transaction(txn, thresholds)
        transactions.append(txn)

    transactions.sort(key=lambda t: t.request_ts or 0.0)
    r.application_transactions = [t.to_dict() for t in transactions]
    logger.debug("_analyse_application_transactions: {}", _resume(r, "application_transactions"))


def _analyse_saturation(r: Report):
    """Correle les pertes avec le debit du point amont au moment ou elles surviennent."""
    for pair, buckets in r.loss_event_buckets.items():
        a, _b = pair
        tp_a = r.throughput.get(a, {})
        all_vals = list(tp_a.values())
        if not all_vals or not buckets:
            continue
        loss_vals = [tp_a.get(buck, 0) for buck in buckets]
        max_all = max(all_vals)
        try:
            p75 = statistics.quantiles(all_vals, n=4)[2] if len(all_vals) >= 4 else statistics.mean(all_vals)
        except statistics.StatisticsError as exc:
            logger.debug("_analyse_saturation: quantiles impossibles pour {} ({}), moyenne utilisée", a, exc)
            p75 = statistics.mean(all_vals)

        frac_high = sum(1 for v in loss_vals if v >= p75) / len(loss_vals)
        mean_loss = statistics.mean(loss_vals)
        stdev_loss = statistics.pstdev(loss_vals) if len(loss_vals) > 1 else 0.0
        rel_stdev = (stdev_loss / mean_loss) if mean_loss else 0.0

        if frac_high >= 0.7 and rel_stdev < 0.15 and max_all and mean_loss >= 0.85 * max_all:
            verdict = (
                "pertes concentrees sur un palier de debit tres stable, proche du "
                "maximum observe -> limitation/policing probable (seuil configure) "
                "plutot qu'une saturation progressive"
            )
        elif frac_high >= 0.6:
            verdict = "pertes fortement correlees aux pics de debit -> saturation de lien ou de buffer sur ce segment"
        elif frac_high <= 0.3:
            verdict = (
                "pertes NON correlees a un debit eleve -> cause probablement physique, "
                "filtrage actif ou congestion ailleurs, pas une saturation de ce segment"
            )
        else:
            verdict = "correlation debit/pertes partielle, pas de signature nette -> a confirmer avec plus de donnees"

        r.saturation_verdict[pair] = verdict
    logger.debug("_analyse_saturation: {}", _resume(r, "saturation_verdict"))


def _analyse_bufferbloat(r: Report):
    """Compare la latence en charge faible vs en charge forte sur le point amont du segment."""
    for pair, buckets_lat in r.latency_by_bucket.items():
        a, _b = pair
        tp_a = r.throughput.get(a, {})
        common = [buck for buck in buckets_lat if buck in tp_a]
        if len(common) < 4:
            continue
        sorted_by_tp = sorted(common, key=lambda buck: tp_a[buck])
        n = len(sorted_by_tp)
        low_q = sorted_by_tp[: max(1, n // 4)]
        high_q = sorted_by_tp[-max(1, n // 4) :]
        low_samples = [ms for buck in low_q for ms in buckets_lat[buck]]
        high_samples = [ms for buck in high_q for ms in buckets_lat[buck]]
        if not low_samples or not high_samples:
            continue
        low_lat = statistics.mean(low_samples)
        high_lat = statistics.mean(high_samples)
        if low_lat > 0 and high_lat >= 1.5 * low_lat and (high_lat - low_lat) > 5:
            r.bufferbloat_hint[pair] = (low_lat, high_lat)
    logger.debug("_analyse_bufferbloat: {}", _resume(r, "bufferbloat_hint"))


def _analyse_handshake(r: Report, flows, points, points_order, nat_tolerant):
    """
    Relie chaque SYN a son eventuelle reponse SYN-ACK (via ack == seq+1) pour
    detecter les connexions bloquees (aucune reponse nulle part) ou dont la
    reponse ne remonte pas jusqu'a certains points (blocage localise). Sert
    aussi a estimer le decalage d'horloge entre points (formule NTP) quand
    le SYN et le SYN-ACK sont tous deux vus aux deux points d'une paire.
    Necessite la correlation stricte par 5-tuple (desactive en mode
    --nat-tolerant) et un ordre de points.
    """
    if nat_tolerant or not points_order:
        logger.debug(
            "_analyse_handshake: ignorée (nat_tolerant={} ordre des points={})", nat_tolerant, bool(points_order)
        )
        return

    synack_lookup = defaultdict(list)
    syn_entries = []
    for key, per_point in flows.items():
        if key[0] != "TCP":
            continue
        _, src, sport, dst, dport, _key_id = key
        sample = next(iter(per_point.values()))[0]
        flags = sample.flags or ""
        if "S" in flags and "A" in flags:
            synack_lookup[(src, sport, dst, dport)].append((sample.ack, per_point))
        elif "S" in flags and "A" not in flags:
            syn_entries.append((src, sport, dst, dport, sample.seq, per_point))

    for src, sport, dst, dport, seq, per_point in syn_entries:
        if seq is None:
            continue
        expected_ack = seq + 1
        candidates = synack_lookup.get((dst, dport, src, sport), [])
        matched = next((pp for (ack_val, pp) in candidates if ack_val == expected_ack), None)
        syn_points = [p for p in points if p in per_point]
        if not syn_points:
            continue
        if matched is None:
            farthest = syn_points[-1]
            r.syn_no_synack[farthest] += 1
        else:
            reply_points = set(matched.keys())
            syn_points_set = set(per_point.keys())
            for p in syn_points:
                if p not in reply_points:
                    r.syn_reply_missing[p] += 1

            # decalage d'horloge : formule NTP classique offset = ((t2-t1)-(t4-t3))/2,
            # necessite que le SYN ET le SYN-ACK soient tous deux vus aux deux points
            # de la paire (aller-retour complet visible des deux cotes)
            for a, b in r.pairs:
                if a in syn_points_set and b in syn_points_set and a in reply_points and b in reply_points:
                    t1 = min(pkt.ts for pkt in per_point[a])
                    t2 = min(pkt.ts for pkt in per_point[b])
                    t3 = min(pkt.ts for pkt in matched[b])
                    t4 = min(pkt.ts for pkt in matched[a])
                    offset_ms = ((t2 - t1) - (t4 - t3)) / 2 * 1000.0
                    r.clock_offset_samples[(a, b)].append(offset_ms)

    for pair, samples in r.clock_offset_samples.items():
        mean_off = statistics.mean(samples)
        stdev_off = statistics.pstdev(samples) if len(samples) > 1 else 0.0
        r.clock_offset_estimate[pair] = (mean_off, stdev_off, len(samples))
    logger.debug("_analyse_handshake: {}", _resume(r, "clock_offset_estimate", "syn_no_synack", "syn_reply_missing"))


def _analyse_tcp_options(r: Report, flows, pairs, nat_tolerant, points_order):
    """
    Compare les options TCP negociees au handshake (MSS, Window Scale,
    SACK Permitted -- tcp.options.mss_val/.wscale.shift/.sack_perm, voir
    pcap_parser.packet) entre points adjacents, pour le MEME paquet SYN
    ou SYN-ACK (meme 5-tuple + meme seq, comme le reste du module).

    Trois signaux distincts :
    - mss_clamped : la valeur MSS annoncee CHANGE entre le point amont et
      le point aval -- un equipement intermediaire (VPN, tunnel...) a
      reecrit l'option. Le plus souvent une adaptation deliberee et
      benefique (evite justement un noir PMTUD, voir _analyse_pmtud) :
      severite "info", pas une anomalie en soi.
    - wscale_stripped : l'option Window Scale est presente en amont mais
      absente en aval -- un equipement l'a retiree. Consequence reelle :
      le window scaling se desactive pour toute la connexion des qu'un
      seul des deux cotes ne le propose pas, plafonnant la fenetre TCP
      effective a 65535 octets -- un plafond de debit classique sur les
      liens a fort produit debit x latence (WAN, satellite).
    - sack_stripped : meme logique pour SACK Permitted -- consequence :
      recuperation de perte moins efficace (renvoi de fenetre entiere au
      lieu des seuls segments manquants, voir _analyse_retransmission_types
      pour le symptome correspondant cote retransmissions).

    Necessite une correlation stricte par 5-tuple (comme _analyse_handshake,
    desactive en mode --nat-tolerant) et un ordre de points explicite ou
    inferable (`pairs` en depend deja) -- une reecriture d'option par un
    equipement NAT/proxy transparent ne casse pas la correlation tant que
    le 5-tuple et le seq restent identiques sur le fil, ce qui est le cas
    normal pour un middlebox qui ne fait que reecrire des options, pas un
    relais applicatif complet (qui casserait de toute facon la
    correlation existante, pas seulement celle-ci).
    """
    if nat_tolerant or not points_order:
        logger.debug(
            "_analyse_tcp_options: ignorée (nat_tolerant={} ordre des points={})", nat_tolerant, bool(points_order)
        )
        return
    for key, per_point in flows.items():
        if key[0] != "TCP":
            continue
        sample = next(iter(per_point.values()))[0]
        if "S" not in (sample.flags or ""):
            continue  # options de handshake uniquement (SYN ou SYN-ACK)
        for a, b in pairs:
            if a not in per_point or b not in per_point:
                continue
            pa, pb = per_point[a][0], per_point[b][0]
            if pa.mss_val is not None and pb.mss_val is not None and pa.mss_val != pb.mss_val:
                r.mss_clamped[(a, b)] += 1
                if len(r.mss_clamped_examples[(a, b)]) < 5:
                    r.mss_clamped_examples[(a, b)].append(
                        f"{pa.src}:{pa.sport} -> {pa.dst}:{pa.dport} : MSS {pa.mss_val} en {a} -> {pb.mss_val} en {b}"
                    )
                    r.mss_clamped_frames[(a, b)].append(pa.frame_number)
            if pa.wscale_shift is not None and pb.wscale_shift is None:
                r.wscale_stripped[(a, b)] += 1
            if pa.sack_permitted and not pb.sack_permitted:
                r.sack_stripped[(a, b)] += 1
    logger.debug("_analyse_tcp_options: {}", _resume(r, "mss_clamped", "wscale_stripped", "sack_stripped"))


def _analyse_rtp(r: Report, all_packets, points, points_order, clock_rate):
    """
    Regroupe les paquets RTP par flux (5-tuple + SSRC). Par point : perte
    (via deroulement des n° de sequence 16 bits) et gigue (formule
    d'interarrival jitter RFC 3550). Delai bout-en-bout approx via le
    premier et le dernier point de --order (corrige du decalage d'horloge
    estime si disponible), puis MOS/R-factor (E-model simplifie G.711)
    sur la base de la perte au point le plus proche du recepteur.
    """
    streams: defaultdict[tuple[str, str, int | None, int | None, int | None], defaultdict[str, list[Pkt]]] = (
        defaultdict(lambda: defaultdict(list))
    )
    for pk in all_packets:
        if pk.proto == "UDP" and pk.is_rtp:
            skey = (pk.src, pk.dst, pk.sport, pk.dport, pk.rtp_ssrc)
            streams[skey][pk.point].append(pk)

    for skey, per_point in streams.items():
        src, dst, sport, dport, ssrc = skey
        loss_pct, jitter_ms = {}, {}

        for p, pkts in per_point.items():
            pkts_sorted = sorted(pkts, key=lambda x: x.ts)

            unwrapped, offset, prev_raw = [], 0, None
            for pkt in pkts_sorted:
                s = pkt.rtp_seq
                if s is None:
                    continue
                if prev_raw is not None:
                    diff = s - prev_raw
                    if diff < -32768:
                        offset += 65536
                    elif diff > 32768:
                        offset -= 65536
                unwrapped.append(s + offset)
                prev_raw = s
            if unwrapped:
                expected = max(unwrapped) - min(unwrapped) + 1
                received = len(set(unwrapped))
                loss_pct[p] = max(0.0, (expected - received) / expected * 100.0) if expected > 0 else 0.0

            jitter, prev_r, prev_s = 0.0, None, None
            for pkt in pkts_sorted:
                rr, ss = pkt.ts, pkt.rtp_ts / clock_rate
                if prev_r is not None:
                    d = (rr - prev_r) - (ss - prev_s)
                    jitter += (abs(d) - jitter) / 16.0
                prev_r, prev_s = rr, ss
            jitter_ms[p] = jitter * 1000.0

        delay_ms = None
        if points_order and len(points) >= 2:
            a0, b_n = points[0], points[-1]
            if a0 in per_point and b_n in per_point:
                t_a = min(pkt.ts for pkt in per_point[a0])
                t_b = min(pkt.ts for pkt in per_point[b_n])
                delay_ms = (t_b - t_a) * 1000.0
                offset_info = r.clock_offset_estimate.get((a0, b_n))
                if offset_info:
                    delay_ms -= offset_info[0]

        r_factor = mos = None
        ref_point = points[-1] if points_order and points[-1] in loss_pct else None
        if ref_point is None and loss_pct:
            ref_point = next(iter(loss_pct))
        if ref_point is not None and delay_ms is not None:
            r_factor, mos = compute_mos(delay_ms, loss_pct.get(ref_point, 0.0))

        # sample_count : nombre de paquets RTP vus au point de reference utilise
        # pour le calcul de loss_pct/MOS -- taille de l'echantillon sur laquelle
        # repose l'estimation, pas le nombre total de paquets du flux sur tous
        # les points (voir synthesis.py/triage.py, "score de confiance").
        sample_count = len(per_point.get(ref_point, [])) if ref_point is not None else None

        first_ts = (
            min((pkt.ts for pkt in per_point.get(ref_point, [])), default=None) if ref_point is not None else None
        )

        r.rtp_streams.append(
            {
                "label": f"{src}:{sport} -> {dst}:{dport} (SSRC=0x{ssrc:08x})",
                "loss_pct": loss_pct,
                "jitter_ms": jitter_ms,
                "delay_ms": delay_ms,
                "r_factor": r_factor,
                "mos": mos,
                "sample_count": sample_count,
                "first_ts": first_ts,
                "first_ts_by_point": {p: min(pkt.ts for pkt in pkts) for p, pkts in per_point.items() if pkts},
            }
        )
    logger.debug("_analyse_rtp: {}", _resume(r, "rtp_streams"))


def _analyse_response_time(r: Report, flows, all_packets, points, points_order):
    """
    Decompose une transaction TCP en temps reseau (deja mesure ailleurs) et
    temps de traitement serveur : ecart entre le dernier octet de requete
    recu par le point le plus proche du serveur et le premier octet de
    reponse qui en repart. Necessite --order (pour savoir quel point est
    cote serveur) et le SYN de chaque connexion capture (pour identifier
    qui est le client).
    """
    if not points_order:
        logger.debug("_analyse_response_time: ignorée, pas d'ordre des points")
        return
    ref_point = points[-1]

    client_of = {}
    for key, per_point in flows.items():
        if key[0] != "TCP":
            continue
        sample = next(iter(per_point.values()))[0]
        flags = sample.flags or ""
        if "S" in flags and "A" not in flags:
            _, src, sport, dst, dport, _key_id = key
            conn_id = tuple(sorted([(src, sport), (dst, dport)]))
            client_of[conn_id] = (src, sport, dst, dport)

    conn_packets = defaultdict(list)
    for pk in all_packets:
        if pk.proto != "TCP" or pk.point != ref_point or pk.payload_hash is None:
            continue
        conn_id = tuple(sorted([(pk.src, pk.sport), (pk.dst, pk.dport)]))
        conn_packets[conn_id].append(pk)

    for conn_id, pkts in conn_packets.items():
        client_info = client_of.get(conn_id)
        if client_info is None:
            continue  # SYN non capture a ce point : impossible d'identifier le client avec certitude
        client_ip, client_port, server_ip, server_port = client_info

        turns = []
        last_c2s_ts = None
        for pk in sorted(pkts, key=lambda x: x.ts):
            is_c2s = pk.src == client_ip and pk.sport == client_port
            if is_c2s:
                last_c2s_ts = pk.ts
            elif last_c2s_ts is not None:
                turns.append((pk.ts - last_c2s_ts) * 1000.0)
                last_c2s_ts = None

        if turns:
            label = f"{client_ip}:{client_port} -> {server_ip}:{server_port}"
            r.server_think_time[label].extend(turns)
    logger.debug("_analyse_response_time: {}", _resume(r, "server_think_time"))


def _analyse_dhcp(r: Report, all_packets, points, points_order):
    """
    Suit chaque transaction DHCP (par xid) a travers les points de capture :
    perte d'un message DISCOVER/OFFER/REQUEST/ACK/NAK entre deux points,
    duree totale DISCOVER->ACK, et identifiants serveur/vendor-class tels
    que trouves dans les paquets (pas une empreinte OS/logiciel garantie --
    de nombreux serveurs DHCP ne renseignent pas ces options de facon
    distinctive).
    """
    tx: defaultdict[str, defaultdict[str, list[Pkt]]] = defaultdict(lambda: defaultdict(list))  # xid -> point -> [Pkt]
    for pk in all_packets:
        if pk.dhcp_msg_type is None:
            continue
        tx[pk.dhcp_xid][pk.point].append(pk)
        r.dhcp_msg_count[pk.point][pk.dhcp_msg_type] += 1
        if pk.dhcp_msg_type == "nak":
            r.dhcp_nak_count[pk.point] += 1
        if pk.dhcp_server_id or pk.dhcp_vendor_class:
            tag = pk.dhcp_server_id or "?"
            if pk.dhcp_vendor_class:
                tag += f" (vendor-class: {pk.dhcp_vendor_class})"
            r.dhcp_server_seen[pk.point].add(tag)

    for xid, per_point in tx.items():
        if points_order:
            for a, b in r.pairs:
                types_a = {pk.dhcp_msg_type for pk in per_point.get(a, [])}
                types_b = {pk.dhcp_msg_type for pk in per_point.get(b, [])}
                for mt in types_a - types_b:
                    r.dhcp_missing[(a, b)].append(f"xid=0x{xid:08x} : {mt} vu en {a}, absent en {b}")

        discover_ts = min(
            (pk.ts for pkts in per_point.values() for pk in pkts if pk.dhcp_msg_type == "discover"),
            default=None,
        )
        ack_ts = min(
            (pk.ts for pkts in per_point.values() for pk in pkts if pk.dhcp_msg_type == "ack"),
            default=None,
        )
        if discover_ts is not None and ack_ts is not None and ack_ts >= discover_ts:
            r.dhcp_duration_ms.append((ack_ts - discover_ts) * 1000.0)
    logger.debug(
        "_analyse_dhcp: {}",
        _resume(
            r,
            "dhcp_msg_count",
            "dhcp_nak_count",
            "dhcp_server_seen",
            "dhcp_duration_ms",
            "dhcp_missing",
        ),
    )


def _analyse_sip(r: Report, all_packets, points, points_order):
    """
    Suit chaque appel SIP (par Call-ID) a travers les points de capture :
    message manquant sur un segment, duree d'etablissement (INVITE->200),
    reponses finales d'echec (4xx/5xx/6xx), et User-Agent/Server tels que
    trouves dans les en-tetes (aucune identification de PBX au-dela de ce
    texte litteral -- un systeme non-SIP comme le NOE Alcatel proprietaire
    n'est pas couvert ici, faute de specification publique).
    """
    calls: defaultdict[str, defaultdict[str, list[Pkt]]] = defaultdict(
        lambda: defaultdict(list)
    )  # call_id -> point -> [Pkt]
    for pk in all_packets:
        if pk.sip_msg_type is None or pk.sip_call_id is None:
            continue
        calls[pk.sip_call_id][pk.point].append(pk)
        r.sip_msg_count[pk.point][pk.sip_msg_type] += 1
        if pk.sip_user_agent:
            r.sip_agents_seen[pk.point].add(f"User-Agent: {pk.sip_user_agent}")
        if pk.sip_server:
            r.sip_agents_seen[pk.point].add(f"Server: {pk.sip_server}")

    failed_already = set()
    for call_id, per_point in calls.items():
        if points_order:
            for a, b in r.pairs:
                types_a = {pk.sip_msg_type for pk in per_point.get(a, [])}
                types_b = {pk.sip_msg_type for pk in per_point.get(b, [])}
                for mt in types_a - types_b:
                    r.sip_missing[(a, b)].append(f"Call-ID {call_id[:40]} : {mt} vu en {a}, absent en {b}")

        invite_ts = min(
            (pk.ts for pkts in per_point.values() for pk in pkts if pk.sip_msg_type == "INVITE"),
            default=None,
        )
        ok_ts = min(
            (
                pk.ts
                for pkts in per_point.values()
                for pk in pkts
                if pk.sip_msg_type and pk.sip_msg_type.startswith("200") and pk.sip_cseq and "INVITE" in pk.sip_cseq
            ),
            default=None,
        )
        if invite_ts is not None and ok_ts is not None and ok_ts >= invite_ts:
            r.sip_setup_duration_ms.append((ok_ts - invite_ts) * 1000.0)

        if call_id not in failed_already:
            for pkts in per_point.values():
                for pk in pkts:
                    if pk.sip_msg_type and pk.sip_cseq and "INVITE" in pk.sip_cseq:
                        code = pk.sip_msg_type.split(" ", 1)[0]
                        if code.isdigit() and code[0] in ("4", "5", "6"):
                            r.sip_failed_calls.append(f"Call-ID {call_id[:40]} : echec {pk.sip_msg_type}")
                            failed_already.add(call_id)
                            break
                if call_id in failed_already:
                    break
    logger.debug(
        "_analyse_sip: {}",
        _resume(
            r,
            "sip_msg_count",
            "sip_agents_seen",
            "sip_setup_duration_ms",
            "sip_missing",
            "sip_failed_calls",
        ),
    )


# Codes RCODE DNS (RFC 1035 section 4.1.1) actionnables pour le diagnostic
# reseau -- les autres valeurs (FormErr, NotImp, Refused...) ne sont pas
# des symptomes reseau typiques et ne sont donc pas comptees a part ici.
_DNS_RCODE_SERVFAIL = 2
_DNS_RCODE_NXDOMAIN = 3


def _analyse_dns(r: Report, all_packets, points, points_order):
    """
    Suit chaque transaction DNS (par identifiant de transaction sur 16
    bits, dns.id) a travers les points de capture : message (requete ou
    reponse) manquant sur un segment, requetes pour lesquelles aucune
    reponse n'a ete observee nulle part dans la capture (timeout
    applicatif ou serveur/resolveur injoignable), reponses NXDOMAIN
    (domaine inexistant -- pas forcement un probleme reseau, mais utile
    en contexte) et SERVFAIL (echec de resolution cote serveur, souvent
    pris a tort pour un probleme reseau -- c'est precisement l'angle
    mort que cette fonction comble), et duree query -> reponse.

    Limite assumee (meme famille que pour dhcp.xid/sip Call-ID, jamais
    mentionnee explicitement pour ceux-ci faute d'etre pertinente a leur
    echelle) : l'identifiant de transaction DNS ne fait que 16 bits,
    contre 32 pour dhcp.xid -- sur une capture tres longue et tres
    chargee en requetes DNS concurrentes, une reutilisation d'id avant
    qu'une transaction precedente ne soit terminee est theoriquement
    possible et n'est pas geree specifiquement ici (les deux
    transactions seraient alors vues comme une seule, a tort).
    """
    tx: defaultdict[str, defaultdict[str, list[Pkt]]] = defaultdict(
        lambda: defaultdict(list)
    )  # txn_id -> point -> [Pkt]
    for pk in all_packets:
        if pk.dns_txn_id is None:
            continue
        tx[pk.dns_txn_id][pk.point].append(pk)
        if pk.dns_is_response:
            r.dns_response_count[pk.point] += 1
            if pk.dns_rcode == _DNS_RCODE_NXDOMAIN:
                r.dns_nxdomain_count[pk.point] += 1
            elif pk.dns_rcode == _DNS_RCODE_SERVFAIL:
                r.dns_servfail_count[pk.point] += 1
        else:
            r.dns_query_count[pk.point] += 1

    for txn_id, per_point in tx.items():
        if points_order:
            for a, b in r.pairs:
                types_a = {pk.dns_is_response for pk in per_point.get(a, [])}
                types_b = {pk.dns_is_response for pk in per_point.get(b, [])}
                for is_resp in types_a - types_b:
                    label = "reponse" if is_resp else "requete"
                    qname = next((pk.dns_qry_name for pk in per_point[a] if pk.dns_qry_name), "?")
                    r.dns_missing[(a, b)].append(f"id=0x{txn_id:04x} ({qname}) : {label} vue en {a}, absente en {b}")

        query_ts = min(
            (pk.ts for pkts in per_point.values() for pk in pkts if not pk.dns_is_response),
            default=None,
        )
        response_ts = min(
            (pk.ts for pkts in per_point.values() for pk in pkts if pk.dns_is_response),
            default=None,
        )
        if query_ts is not None and response_ts is not None and response_ts >= query_ts:
            r.dns_duration_ms.append((response_ts - query_ts) * 1000.0)
        elif query_ts is not None and response_ts is None:
            qname = next(
                (pk.dns_qry_name for pkts in per_point.values() for pk in pkts if pk.dns_qry_name),
                "?",
            )
            first_point = min(per_point, key=lambda p: min(pk.ts for pk in per_point[p]))
            r.dns_timeout[first_point].append(f"id=0x{txn_id:04x} ({qname}) : aucune reponse observee dans la capture")
            # requete elle-meme (pas de reponse pour ce txn_id) -- meme
            # index/plafond que dns_timeout ci-dessus, PacketEvidence
            # (Session 37).
            query_pk = next(
                (pk for pkts in per_point.values() for pk in pkts if not pk.dns_is_response),
                None,
            )
            r.dns_timeout_frames[first_point].append(query_pk.frame_number if query_pk else None)
    logger.debug(
        "_analyse_dns: {}",
        _resume(
            r,
            "dns_response_count",
            "dns_query_count",
            "dns_nxdomain_count",
            "dns_duration_ms",
            "dns_servfail_count",
            "dns_timeout",
            "dns_missing",
        ),
    )


def _analyse_http(r: Report, all_packets, points, points_order):
    """
    Suit chaque transaction HTTP/1.x (voir "Cle de transaction" ci-dessous)
    a travers les points de capture : message (requete ou reponse)
    manquant sur un segment, requetes jamais suivies d'une reponse observee
    nulle part dans la capture, et reponses d'erreur 4xx/5xx (avec
    quelques exemples concrets par point, methode+URI+code).

    Duree requete -> reponse : lue directement dans http.time, calculee
    NATIVEMENT par le dissecteur HTTP de tshark lui-meme -- a la
    difference de DHCP/SIP/DNS ci-dessus, qui n'ont pas d'equivalent
    tshark et doivent la recomposer a la main via min(ts requete)/
    min(ts reponse) sur toute la capture. Verifie empiriquement (tshark
    4.2.2, capture HTTP/1.1 reelle generee sur loopback, voir claude.md
    Session 17) : http.time est bien calcule par transaction (pas une
    moyenne globale), present uniquement sur le paquet de reponse. Pas
    de tentative de recalcul manuel ici : plus precis que l'approche
    DNS/DHCP/SIP, pas de raison de la dupliquer avec une version moins
    fiable.

    HTTP/2 (meme trace sur TCP) et HTTP/3 (QUIC/UDP, deja couvert
    separement par _analyse... non, par quic_diagnostics -- pipeline
    independant, SNI uniquement) ont chacun un dissecteur tshark distinct
    -- hors perimetre ici, voir pcap_parser.protocols.extract_http.

    Cle de transaction : (identifiant de connexion TCP -- 5-tuple non
    ordonne, meme definition que _analyse_response_time ci-dessus --,
    URI, Nieme occurrence de cette URI sur cette connexion a CE point).
    PAS une simple position ordinale dans la connexion (requete no1, no2,
    no3...) : une position ordinale pure se desynchroniserait des qu'une
    requete entiere est perdue sur un segment alors que les requetes
    suivantes (sur une URI differente) survivent -- la position de la
    requete suivante glisserait d'un cran a un point mais pas a l'autre,
    provoquant un faux negatif sur la requete reellement perdue et un
    faux positif sur celle qui la suit (qui, elle, est bien arrivee).
    Identifier par URI evite ce glissement des que les requetes
    successives d'une meme connexion portent sur des ressources
    differentes -- cas largement majoritaire en navigation reelle/API.

    Limite assumee, meme famille que la reutilisation d'un identifiant
    DNS 16 bits (Session 13) : si la MEME URI est rejouee plusieurs fois
    sur la meme connexion (ex: polling d'un endpoint de sante) ET qu'une
    occurrence precise est perdue entierement a un point donne, le meme
    glissement peut se reproduire entre les occurrences restantes de
    cette URI -- non gere specifiquement ici.
    """
    tx: defaultdict[tuple[Any, str, int], defaultdict[str, list[Pkt]]] = defaultdict(
        lambda: defaultdict(list)
    )  # (conn_id, uri, occurrence) -> point -> [Pkt]
    occ_counters: defaultdict[tuple[str, Any, str], int] = defaultdict(
        int
    )  # (point, conn_id, uri) -> occurrence en cours a ce point

    for pk in sorted(all_packets, key=lambda p: p.ts):
        if not (pk.http_is_request or pk.http_is_response):
            continue
        conn_id = tuple(sorted([(pk.src, pk.sport), (pk.dst, pk.dport)]))
        uri = pk.http_uri or "?"
        counter_key = (pk.point, conn_id, uri)
        if pk.http_is_request:
            occ_counters[counter_key] += 1
            r.http_request_count[pk.point] += 1
        # Une reponse vue avant toute requete correspondante a ce point
        # (capture demarree en cours de transaction) reste rattachee a
        # l'occurrence 1 plutot que 0 -- max() evite une cle "occurrence=0"
        # qui ne collerait avec aucune requete future.
        occ = max(occ_counters[counter_key], 1)
        tx[(conn_id, uri, occ)][pk.point].append(pk)

        if pk.http_is_response:
            r.http_response_count[pk.point] += 1
            if pk.http_response_time_ms is not None:
                r.http_response_time_ms.append(pk.http_response_time_ms)
            code = pk.http_status_code
            if code is not None:
                r.http_status_count[pk.point][str(code)] += 1
                if 400 <= code < 500:
                    r.http_client_error_count[pk.point] += 1
                elif 500 <= code < 600:
                    r.http_server_error_count[pk.point] += 1

    for (_conn_id, uri, _occ), per_point in tx.items():
        if points_order:
            for a, b in r.pairs:
                types_a = {pk.http_is_response for pk in per_point.get(a, [])}
                types_b = {pk.http_is_response for pk in per_point.get(b, [])}
                for is_resp in types_a - types_b:
                    label = "reponse" if is_resp else "requete"
                    r.http_missing[(a, b)].append(f"{uri} : {label} vue en {a}, absente en {b}")

        has_request = has_response = False
        for point, pkts in per_point.items():
            method = next((pk.http_method for pk in pkts if pk.http_is_request and pk.http_method), None)
            for pk in pkts:
                if pk.http_is_request:
                    has_request = True
                elif pk.http_is_response:
                    has_response = True
                    if (
                        pk.http_status_code is not None
                        and pk.http_status_code >= 400
                        and (len(r.http_error_examples[point]) < 5)
                    ):
                        r.http_error_examples[point].append(f"{method or '?'} {uri} -> {pk.http_status_code}")
                        # meme index/plafond que http_error_examples --
                        # PacketEvidence (Session 37).
                        r.http_error_frames[point].append(pk.frame_number)

        if has_request and not has_response:
            first_point = min(per_point, key=lambda p: min(pk.ts for pk in per_point[p]))
            r.http_timeout[first_point].append(f"{uri} : aucune reponse observee dans la capture")
            # requete elle-meme (pas de reponse pour cette transaction) --
            # meme index/plafond que http_timeout ci-dessus, PacketEvidence
            # (Session 37).
            request_pk = next(
                (pk for pkts in per_point.values() for pk in pkts if pk.http_is_request),
                None,
            )
            r.http_timeout_frames[first_point].append(request_pk.frame_number if request_pk else None)
    logger.debug(
        "_analyse_http: {}",
        _resume(
            r,
            "http_request_count",
            "http_response_count",
            "http_status_count",
            "http_timeout",
            "http_response_time_ms",
            "http_client_error_count",
            "http_server_error_count",
            "http_missing",
        ),
    )


def _descend(edge_lookup, start):
    """Fermeture transitive des descendants de `start` dans un dict {noeud: [enfants]}.
    Utilise uniquement pour la reduction transitive des arcs deduits (pas pour
    la detection de perte, qui ne regarde que les arcs directs -- voir analyse())."""
    seen = set()
    stack = list(edge_lookup.get(start, []))
    while stack:
        cur = stack.pop()
        if cur not in seen:
            seen.add(cur)
            stack.extend(edge_lookup.get(cur, []))
    return seen


# Seuils de _infer_topology() -- constantes module (et non locales a la fonction)
# pour rester en minuscules cote N806 sans devoyer leur role de vrais seuils fixes.
_TOPOLOGY_MIN_COMMON = 3
_TOPOLOGY_MIN_JACCARD = 0.05
_TOPOLOGY_MIN_MAJORITY = 0.7


def _infer_topology(flows, points):
    """
    Deduit l'ordre/la topologie des points de capture sans --order, a partir
    de deux signaux par paire de points :
      - le delta de TTL sur les flux vus aux deux points (qui indique le
        sens de propagation, comme le module de sauts de routeur) ;
      - le recouvrement de flux (Jaccard) entre les deux points, qui permet
        de distinguer une vraie relation amont/aval d'un simple manque de
        preuve, et de detecter les chemins paralleles (deux points en aval
        du meme point mais qui ne se recoupent pas entre eux).

    Retourne (edges, ambiguous, isolated, branch_points, merge_points).
    `edges` est deja reduit transitivement : un arc X->Z n'est garde que
    s'il n'est pas deja explique par un chemin indirect X->...->Z via
    d'autres arcs deduits (pour n'afficher que les sauts "directs").
    """
    total_flows_at = defaultdict(int)
    pair_stats = {}
    for per_point in flows.values():
        pts_here = list(per_point.keys())
        for p in pts_here:
            total_flows_at[p] += 1
        for x, y in combinations(sorted(pts_here), 2):
            stats = pair_stats.setdefault(
                (x, y),
                {
                    "common": 0,
                    "x_gt_y": 0,
                    "y_gt_x": 0,
                    "eq": 0,
                    "compared": 0,
                },
            )
            stats["common"] += 1
            pkt_x = min(per_point[x], key=lambda pk: pk.ts)
            pkt_y = min(per_point[y], key=lambda pk: pk.ts)
            if pkt_x.ttl is not None and pkt_y.ttl is not None:
                stats["compared"] += 1
                if pkt_x.ttl > pkt_y.ttl:
                    stats["x_gt_y"] += 1
                elif pkt_y.ttl > pkt_x.ttl:
                    stats["y_gt_x"] += 1
                else:
                    stats["eq"] += 1

    candidate_edges = []
    ambiguous = []
    for (x, y), stats in pair_stats.items():
        common = stats["common"]
        if common < _TOPOLOGY_MIN_COMMON:
            continue
        union = total_flows_at[x] + total_flows_at[y] - common
        jaccard = common / union if union else 0.0
        if jaccard < _TOPOLOGY_MIN_JACCARD:
            continue  # trop peu de trafic partage entre ces deux points

        compared = stats["compared"]
        if compared == 0:
            ambiguous.append((x, y, "TTL indisponible pour comparer ces deux points"))
            continue

        votes_x, votes_y = stats["x_gt_y"], stats["y_gt_x"]
        total_votes = votes_x + votes_y
        if total_votes == 0:
            ambiguous.append(
                (
                    x,
                    y,
                    (
                        f"{stats['eq']} flux avec TTL identique -> probablement le "
                        f"meme segment L2 (pas de routeur entre {x} et {y})"
                    ),
                )
            )
            continue

        majority = max(votes_x, votes_y) / total_votes
        if majority < _TOPOLOGY_MIN_MAJORITY:
            ambiguous.append(
                (
                    x,
                    y,
                    (
                        f"TTL contradictoire entre {x} et {y} ({votes_x} vs {votes_y} "
                        f"votes) -> chemins multiples/ECMP probables entre ces deux points"
                    ),
                )
            )
            continue

        upstream, downstream = (x, y) if votes_x > votes_y else (y, x)
        # taux de couverture : part du trafic total de l'amont que l'on
        # retrouve effectivement en aval. Bas (<80%) meme avec un vote TTL
        # unanime => l'aval ne voit qu'UNE PARTIE du trafic de l'amont
        # (branchement, ECMP, ou aller/retour qui empruntent des chemins
        # differents) -- dans ce cas on ne peut pas fiablement dire qu'un
        # flux absent en aval est "perdu", il a peut-etre juste emprunte
        # une autre branche. Utilise pour desactiver la detection de perte
        # sur cet arc (voir analyse()), quelle qu'en soit la cause exacte.
        coverage = common / total_flows_at[upstream] if total_flows_at[upstream] else 0.0
        candidate_edges.append(
            (
                upstream,
                downstream,
                {
                    "confidence": majority,
                    "common_flows": common,
                    "jaccard": jaccard,
                    "votes": f"{max(votes_x, votes_y)}/{total_votes}",
                    "coverage": coverage,
                },
            )
        )

    # reduction transitive : un arc n'est garde que s'il n'est pas deja
    # explique par un chemin indirect via d'autres arcs deduits
    edge_lookup = defaultdict(list)
    for u, d, _info in candidate_edges:
        edge_lookup[u].append(d)

    direct_edges = []
    for u, d, info in candidate_edges:
        indirect = any(d in _descend(edge_lookup, mid) for mid in edge_lookup.get(u, []) if mid != d)
        if not indirect:
            direct_edges.append((u, d, info))

    connected = {u for u, d, _ in direct_edges} | {d for u, d, _ in direct_edges}
    isolated = [p for p in points if p not in connected]

    out_deg, in_deg = defaultdict(int), defaultdict(int)
    for u, d, _info in direct_edges:
        out_deg[u] += 1
        in_deg[d] += 1
    branch_points = [p for p in points if out_deg[p] >= 2]
    merge_points = [p for p in points if in_deg[p] >= 2]

    logger.debug(
        "_infer_topology: {} arête(s) directe(s), {} branchement(s), {} fusion(s)",
        len(direct_edges),
        len(branch_points),
        len(merge_points),
    )
    return direct_edges, ambiguous, isolated, branch_points, merge_points


def _check_order_consistency(points_order, topo_edges):
    """Signale les arcs deduits qui contredisent l'ordre --order fourni par l'utilisateur."""
    order_pos = {p: i for i, p in enumerate(points_order)}
    conflicts = []
    for u, d, info in topo_edges:
        if u in order_pos and d in order_pos and order_pos[u] > order_pos[d]:
            conflicts.append(
                f"--order place {d} avant {u}, mais le TTL indique plutot {u} -> {d} "
                f"(confiance {info['confidence'] * 100:.0f}%, {info['common_flows']} flux communs)"
            )
    logger.debug("_check_order_consistency: {} conflit(s) avec l'ordre imposé", len(conflicts))
    return conflicts
