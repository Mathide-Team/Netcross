"""
netcross_core.report_text -- mise en forme du Report en sortie texte
console et en CSV de detail. Le rendu PDF (a venir) consommera le meme
objet Report sans dependre de ce module.
"""

import csv
import statistics
from collections import Counter, defaultdict

from netcross_core.forensic import annotations_by_tag
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import (
    SEQ_GAP_CAPTURE_DROP,
    SEQ_GAP_INDETERMINATE,
    SEQ_GAP_NETWORK_LOSS,
    ChecksumError,
    PacketAnnotation,
    Report,
    SequenceGap,
)

logger = get_logger(__name__)

# -- link type lisible (issue #263) -------------------------------------------

# Codes DLT (Data Link Type) les plus courants, tels que numerotes par
# libpcap. capinfos donne l'encapsulation sous forme de nom ("ether"),
# le cadrage binaire du fichier donne le code numerique (1) : les deux
# sources coexistent dans le rapport, et un lecteur n'a aucune raison de
# connaitre la table par coeur. Liste volontairement courte -- libpcap en
# definit plus de 250, seuls ceux qu'on rencontre reellement dans des
# captures reseau d'entreprise sont traduits.
_DLT_NAMES = {
    0: "BSD loopback",
    1: "Ethernet",
    6: "IEEE 802.5 Token Ring",
    9: "PPP",
    105: "IEEE 802.11 (WiFi)",
    113: "Linux cooked (SLL)",
    127: "IEEE 802.11 radiotap",
    141: "MTP2",
    143: "DOCSIS",
    147: "usage prive",
    201: "Bluetooth HCI H4",
    228: "IPv4 brut",
    229: "IPv6 brut",
    239: "Netlink NFLOG",
    276: "Linux cooked v2 (SLL2)",
}


def _linktype_lisible(code) -> str:
    """Rend un code DLT affichable : "1 (Ethernet)" si connu, "1" sinon.

    Un code inconnu est affiche tel quel plutot que masque : mieux vaut un
    nombre brut que rien du tout, et sa presence dans un rapport est
    precisement ce qui permettra d'enrichir la table le jour ou un
    utilisateur remonte une encapsulation exotique.
    """
    if code is None:
        logger.debug("_linktype_lisible: si code is None -> retour '?'")
        return "?"
    nom = _DLT_NAMES.get(code)
    logger.debug("_linktype_lisible: retour f'(code) ((nom))' if nom else str(code)")
    return f"{code} ({nom})" if nom else str(code)


def _print_multi_point_sections(r: Report):
    """Sections qui comparent des points entre eux : topologie, pertes, trafic
    hors chemin, latence, decalage d'horloge, sauts de routeur, QoS. Sans objet
    pour une capture unique (issue #474 lot 2) : print_report ne les appelle
    qu'a partir de deux points."""
    print("\n-- Topologie deduite (delta TTL + recouvrement de flux entre points) --")
    if r.topology_edges:
        for u, d, info in r.topology_edges:
            print(
                f"  {u} -> {d}  (confiance {info['confidence'] * 100:.0f}%, "
                f"{info['common_flows']} flux communs, votes TTL {info['votes']}, "
                f"couverture {info.get('coverage', 1.0) * 100:.0f}%)"
            )
            if info.get("coverage", 1.0) < 0.8:
                print(
                    f"      -> {d} ne voit qu'une partie du trafic de {u} (branchement, ECMP, "
                    f"ou aller/retour par des chemins differents) : detection de perte "
                    f"desactivee sur cet arc pour eviter les faux positifs"
                )
        if r.topology_used_for_order:
            print(
                "  (--order non fourni : cet ordre deduit a ete utilise pour le reste de "
                "l'analyse -- pertes, latence, QoS, etc.)"
            )
        if r.topology_branch_points:
            print(f"  points de branchement (le trafic se divise ici) : {r.topology_branch_points}")
        if r.topology_merge_points:
            print(f"  points de convergence (le trafic fusionne ici) : {r.topology_merge_points}")
    else:
        print(
            "  aucune relation directionnelle fiable deduite (pas assez de flux communs, "
            "ou TTL indisponible/incoherent entre les points)"
        )

    if r.topology_ambiguous:
        print("\n-- Relations ambigues entre points (chemins multiples possibles) --")
        for x, y, reason in r.topology_ambiguous:
            print(f"  {x} <-> {y} : {reason}")

    if r.topology_isolated:
        print(f"\n-- Points sans relation directionnelle claire avec les autres : {r.topology_isolated} --")
        print(
            "  peu ou pas de trafic en commun avec le reste -- verifier le positionnement "
            "de la capture, ou il s'agit bien d'un chemin entierement distinct"
        )

    if r.topology_order_conflicts:
        print("\n-- ATTENTION : --order fourni contredit la topologie deduite --")
        for c in r.topology_order_conflicts:
            print(f"  {c}")

    if r.loss_count:
        print("\n-- Pertes potentielles (paquet vu en amont, absent a ce point) --")
        for p in r.points:
            if r.loss_count[p]:
                print(f"  {p:15s} : {r.loss_count[p]} paquets manquants")
    else:
        print("\n-- Pertes : aucune detectee (ou aucun ordre/topologie exploitable) --")

    off_path = {p: n for p, n in r.off_path_count.items() if n}
    if off_path:
        # issue #352 : ni perte ni anomalie -- trafic qui n'emprunte pas ce segment
        print("\n-- Trafic hors chemin (hotes n'echangeant jamais rien a ce point) --")
        for p in r.points:
            if off_path.get(p):
                print(f"  {p:15s} : {off_path[p]} paquets hors chemin (non comptes comme pertes)")

    print("\n-- Latence / gigue entre points (necessite horloges synchronisees) --")
    for a, b in r.pairs:
        vals = r.latency.get((a, b), [])
        if not vals:
            continue
        avg = statistics.mean(vals)
        jitter = statistics.pstdev(vals) if len(vals) > 1 else 0.0
        print(
            f"  {a} -> {b} : n={len(vals)}  moy={avg:.2f}ms  "
            f"min={min(vals):.2f}ms  max={max(vals):.2f}ms  gigue={jitter:.2f}ms"
        )
        offset_info = r.clock_offset_estimate.get((a, b))
        if offset_info:
            mean_off, stdev_off, n_off = offset_info
            corrected = avg - mean_off
            print(
                f"      -> decalage d'horloge estime : {mean_off:+.2f}ms "
                f"(ecart-type {stdev_off:.2f}ms, {n_off} handshake(s) TCP) "
                f"=> latence corrigee ~= {corrected:.2f}ms"
            )

    if r.clock_offset_estimate:
        print("\n-- Decalage d'horloge estime entre points (via handshakes TCP) --")
        print("   Hypothese : chemin reseau symetrique (delai aller = delai retour).")
        print("   Un decalage important et instable indique une horloge non synchronisee")
        print("   (NTP absent/casse) ou un chemin reellement asymetrique -> a prendre comme")
        print("   indice, pas comme mesure de precision, surtout si l'ecart-type est eleve.")
        for (a, b), (mean_off, stdev_off, n_off) in r.clock_offset_estimate.items():
            print(f"  {a} <-> {b} : {mean_off:+.2f}ms (ecart-type {stdev_off:.2f}ms, n={n_off} handshake(s))")

    print("\n-- Sauts de routeur (delta TTL) entre points --")
    for a, b in r.pairs:
        deltas = r.hop_delta.get((a, b), [])
        if not deltas:
            continue
        mode_delta, mode_n = Counter(deltas).most_common(1)[0]
        outliers = r.hop_delta_outliers.get((a, b), 0)
        sens = "amont->aval" if mode_delta >= 0 else "aval->amont (sens inverse au flux attendu)"
        print(
            f"  {a} -> {b} : {abs(mode_delta)} saut(s) routeur le plus frequent ({mode_n}/{len(deltas)} flux, {sens})"
        )
        if outliers:
            print(
                f"      -> {outliers} flux avec un nombre de sauts different : "
                f"chemin ECMP different ou re-routage a surveiller"
            )

    if len(r.points) > 2 and all((a, b) in r.hop_delta and r.hop_delta[(a, b)] for a, b in r.pairs):
        chain_parts = [r.points[0]]
        total_hops = 0
        for a, b in r.pairs:
            mode_delta = Counter(r.hop_delta[(a, b)]).most_common(1)[0][0]
            total_hops += abs(mode_delta)
            chain_parts.append(f"-[{abs(mode_delta)} saut(s)]->{b}")
        print(f"\n-- Chaine de sauts {r.points[0]} -> {r.points[-1]} --")
        print("  " + " ".join(chain_parts) + f"  (total: {total_hops} saut(s))")

    print("\n-- Changements de marquage QoS (DSCP) entre points --")
    any_qos = False
    for a, b in r.pairs:
        n = r.qos_change.get((a, b), 0)
        if n:
            any_qos = True
            l2 = r.qos_l2_remark.get((a, b), 0)
            l3 = r.qos_l3_remark.get((a, b), 0)
            print(
                f"  {a} -> {b} : {n} paquets avec DSCP modifie "
                f"(dont {l2} sans saut de routeur -> equipement L2 en cause, "
                f"{l3} avec saut de routeur -> remarquage L3, routeur non identifie precisement)"
            )
    if not any_qos:
        print("  aucun changement detecte")
    logger.debug("_print_multi_point_sections: fin")


def print_report(r: Report):
    logger.debug("print_report: r={}", summarize(r, "r"))
    print("=" * 70)
    print("ANALYSE CROISEE DE CAPTURES")
    print("=" * 70)

    print("\n-- Paquets/flux identifies par point --")
    for p in r.points:
        print(f"  {p:15s} : {r.seen_count[p]}")

    if r.duplicate_count:
        # Job 41/issue #161 -- section absente si la detection n'a pas ete
        # demandee ou n'a rien trouve : la sortie historique reste inchangee.
        print("\n-- Doublons inter-captures (meme payload vu a deux points quasi simultanement) --")
        for (a, b), n in sorted(r.duplicate_count.items()):
            print(f"  {a} <-> {b} : {n} paquet(s) duplique(s)")
        if r.duplicates_excluded:
            print("  (ces doublons sont EXCLUS des compteurs, debits et de la correlation de ce rapport)")
        else:
            print(
                "  ATTENTION : ces doublons sont ENCORE COMPTES dans les statistiques "
                "ci-dessous (paquets/octets potentiellement doubles) -- "
                "--exclude-duplicates les en retire."
            )

    if r.capture_comments or r.packet_comments:
        # Job 39/issue #159 -- section absente si la capture ne porte aucun
        # commentaire pcapng (cas le plus frequent) : la sortie historique
        # reste inchangee. Deux sous-parties, deux origines distinctes (voir
        # Report.capture_comments/packet_comments dans models.py).
        print("\n-- Commentaires pcapng --")
        for c in r.capture_comments:
            print(f"  [section] {c}")
        for c in r.packet_comments:
            print(f"  [paquet] {c}")

    if r.capture_infos:
        # Job 38/issue #158 -- metadonnees de capture (format, snaplen,
        # paquets perdus...). Section absente si capinfos est absent ou si
        # aucune metadonnee n'a pu etre lue : la sortie historique reste
        # inchangee.
        print("\n-- Metadonnees de capture --")
        for info in r.capture_infos:
            label = info["label"]
            ftype = info.get("file_type") or "?"
            version = info.get("version") or "?"
            pkts = info.get("packet_count")
            # encapsulation : link type au niveau FICHIER, tel que lu par
            # capinfos ("ether"). Il etait extrait et propage jusqu'ici
            # depuis le Job 38 mais jamais affiche (issue #263) -- or c'est
            # la seule source de link type quand le cadrage binaire du
            # fichier n'a pas pu etre lu (cas d'une capture compressee),
            # auquel cas "interfaces" est vide et le detail par interface
            # ci-dessous n'affiche rien du tout.
            encap = info.get("encapsulation")
            resume = f"  {label} : {ftype} v{version}"
            if encap:
                resume += f", encapsulation {encap}"
            if pkts is not None:
                resume += f", {pkts} paquets"
            print(resume)
            snaplen = info.get("snaplen")
            if snaplen is not None:
                print(f"      snaplen : {snaplen}")
            dur = info.get("duration_seconds")
            if dur is not None:
                print(f"      duree : {dur:.3f}s")
            hw = info.get("hardware")
            if hw:
                print(f"      materiel : {hw}")
            os_name = info.get("operating_system")
            if os_name:
                print(f"      OS : {os_name}")
            app = info.get("application")
            if app:
                print(f"      application : {app}")
            dropped_if = info.get("dropped_by_interface")
            dropped_os = info.get("dropped_by_os")
            if dropped_if is not None or dropped_os is not None:
                parts = []
                if dropped_if is not None:
                    parts.append(f"interface : {dropped_if}")
                if dropped_os is not None:
                    parts.append(f"OS : {dropped_os}")
                print(f"      paquets perdus ({', '.join(parts)})")
            interfaces = info.get("interfaces", [])
            if not encap and not interfaces:
                # Regle de tracabilite du projet : une information absente
                # est signalee, pas omise. Sans cette ligne, un rapport sur
                # une capture dont ni capinfos ni le cadrage binaire n'ont
                # livre le link type serait indistinguable d'un rapport ou
                # la question ne se pose pas.
                print("      link type : non renseigne (ni capinfos, ni cadrage du fichier)")
            for iface in interfaces:
                iface_name = iface.get("name") or f"iface{iface.get('index', '?')}"
                iface_parts = [f"linktype {_linktype_lisible(iface.get('linktype'))}"]
                if iface.get("snaplen") is not None:
                    iface_parts.append(f"snaplen {iface['snaplen']}")
                recv = iface.get("received")
                if recv is not None:
                    iface_parts.append(f"recus {recv}")
                drop_if = iface.get("dropped_by_interface")
                drop_os = iface.get("dropped_by_os")
                if drop_if is not None:
                    iface_parts.append(f"perdus(iface) {drop_if}")
                if drop_os is not None:
                    iface_parts.append(f"perdus(os) {drop_os}")
                print(f"      [{iface_name}] {', '.join(iface_parts)}")

    if len(r.points) >= 2:
        _print_multi_point_sections(r)
    else:
        # issue #474 lot 2 : une seule capture -> pas de bruit multi-points
        print(
            "\n-- Capture unique : sections multi-points omises (topologie, pertes, "
            "latence, sauts de routeur, QoS entre points) --"
        )
    if any(r.ttl_unstable.values()):
        print("\n-- Instabilite de route intra-flux (TTL variable pour un meme flux) --")
        for p in r.points:
            if r.ttl_unstable[p]:
                print(
                    f"  {p:15s} : {r.ttl_unstable[p]} flux avec TTL variable "
                    f"(routage asymetrique / load-balancing par paquet possible)"
                )

    print("\n-- VLAN 802.1Q --")
    any_vlan = any(r.vlan_seen.values())
    if any_vlan:
        for p in r.points:
            vlans = sorted(r.vlan_seen[p])
            if vlans:
                print(f"  {p:15s} : VLAN(s) observe(s) = {vlans}")
        for a, b in r.pairs:
            n = r.vlan_change.get((a, b), 0)
            if n:
                print(
                    f"  {a} -> {b} : {n} flux changent d'ID VLAN entre ces deux points "
                    f"-> normal si un routage inter-VLAN est attendu ici, sinon a verifier"
                )
            flip = r.vlan_tag_flip.get((a, b), {})
            if flip.get("tagged_to_untagged"):
                print(
                    f"  {a} -> {b} : {flip['tagged_to_untagged']} flux tagges en {a} et "
                    f"untagged en {b} (normal si {b} est un port acces, sinon trunk mal configure)"
                )
            if flip.get("untagged_to_tagged"):
                print(
                    f"  {a} -> {b} : {flip['untagged_to_tagged']} flux untagged en {a} et "
                    f"tagges en {b} (normal si {a} est un port acces, sinon a verifier)"
                )
            pn = r.pcp_change.get((a, b), 0)
            if pn:
                print(
                    f"  {a} -> {b} : {pn} flux avec priorite 802.1p (PCP) modifiee "
                    f"-> equivalent L2 du remarquage DSCP, verifier la coherence de la "
                    f"politique QoS L2/L3"
                )
    else:
        print("  aucun tag VLAN 802.1Q detecte dans les captures")

    print("\n-- Encapsulation / tunnels (MPLS, GRE, VXLAN, GTP-U, ERSPAN) --")
    any_encap = any(r.encap_seen.values())
    if any_encap:
        for p in r.points:
            stacks = sorted(r.encap_seen[p])
            if stacks:
                print(f"  {p:15s} : pile(s) observee(s) = {stacks}")
        for a, b in r.pairs:
            n = r.encap_change.get((a, b), 0)
            if n:
                print(
                    f"  {a} -> {b} : {n} flux changent de pile d'encapsulation entre ces "
                    f"deux points -> normal si {a} ou {b} est justement une extremite de "
                    f"tunnel (entree/sortie), sinon a verifier"
                )
                for ex in r.encap_change_examples.get((a, b), []):
                    print(f"      ex: {ex}")
                if r.encap_frag_correlated.get((a, b), 0):
                    print(
                        "      -> coincide avec de la fragmentation sur ce meme segment "
                        "(voir section suivante) : le tunnel ajoute probablement plus "
                        "d'octets d'en-tete que le MTU disponible ne le permet"
                    )
    else:
        print("  aucun tunnel MPLS/GRE/VXLAN/GTP-U/ERSPAN/CAPWAP detecte")

    print("\n-- Fragmentation / MTU --")
    any_frag = False
    for p in r.points:
        if r.frag_count[p]:
            any_frag = True
            print(f"  {p:15s} : {r.frag_count[p]} paquets fragmentes vus")
    for a, b in r.pairs:
        n = r.frag_new.get((a, b), 0)
        if n:
            any_frag = True
            print(
                f"  {a} -> {b} : {n} datagrammes NON fragmentes en {a} mais "
                f"fragmentes en {b} -> un equipement de ce segment reduit le MTU"
            )
    for p in r.points:
        if r.icmp_frag_needed[p]:
            any_frag = True
            print(
                f"  {p:15s} : {r.icmp_frag_needed[p]} messages ICMP "
                f"'Fragmentation Needed' observes (voir la section PMTUD "
                f"ci-dessous pour la detection automatique de noir)"
            )
    # Equivalent IPv6 (Session 22) -- voir r.icmpv6_too_big.
    for p in r.points:
        if r.icmpv6_too_big[p]:
            any_frag = True
            print(
                f"  {p:15s} : {r.icmpv6_too_big[p]} messages ICMPv6 "
                f"'Packet Too Big' observes (voir la section PMTUD "
                f"ci-dessous pour la detection automatique de noir)"
            )
    if not any_frag:
        print("  aucune fragmentation ni message ICMP(v6) de MTU insuffisant detecte")

    print("\n-- PMTUD (Path MTU Discovery) : noirs detectes --")
    if any(r.pmtud_blackhole.values()):
        for a, b in r.pairs:
            n = r.pmtud_blackhole.get((a, b), 0)
            if not n:
                continue
            print(
                f"  {a} -> {b} : {n} segment(s) TCP retransmis plusieurs fois en {a} sans "
                f"jamais atteindre {b}, aucun signal ICMP(v6) de MTU insuffisant observe en "
                f"{a} -> noir PMTUD probable (RFC 1191 IPv4 / RFC 8201 IPv6)"
            )
            for ex in r.pmtud_blackhole_examples.get((a, b), []):
                print(f"      ex: {ex}")
    else:
        print(
            "  aucun noir detecte (segment retransmis + jamais vu au point aval + aucun "
            "signal ICMP(v6) de MTU insuffisant observe au point amont -- DF actif requis "
            "cote IPv4 uniquement, voir README)"
        )

    print("\n-- Timeout d'inactivite / coupure NAT-FW silencieuse --")
    if any(r.idle_timeout_dropped.values()):
        for a, b in r.pairs:
            n = r.idle_timeout_dropped.get((a, b), 0)
            if not n:
                continue
            print(
                f"  {a} -> {b} : {n} flux TCP deja etabli(s) ne reprennent jamais en {b} apres "
                f"un long silence en {a} -> coupure NAT/pare-feu silencieuse probable (table "
                f"d'etat expiree, aucun RST observe)"
            )
            for ex in r.idle_timeout_examples.get((a, b), []):
                print(f"      ex: {ex}")
    else:
        print(
            "  aucune coupure detectee (flux etabli des deux cotes + silence prolonge en amont "
            "+ trafic repris jamais revu en aval)"
        )

    print("\n-- Conflits d'adresse IP (ARP) --")
    if any(r.arp_ip_conflict.values()):
        for p in r.points:
            n = r.arp_ip_conflict.get(p, 0)
            if not n:
                continue
            print(
                f"  {p:15s} : {n} adresse(s) IP revendiquee(s) par plusieurs MAC differentes "
                f"-> conflit d'adresse IP probable"
            )
            for ex in r.arp_ip_conflict_examples.get(p, []):
                print(f"      ex: {ex}")
    else:
        print("  aucun conflit d'adresse IP detecte (trafic ARP observe ou non)")

    print("\n-- Instabilite STP --")
    if any(r.stp_topology_change.values()) or any(r.stp_root_change.values()):
        for p in r.points:
            tc = r.stp_topology_change.get(p, 0)
            rc = r.stp_root_change.get(p, 0)
            if not tc and not rc:
                continue
            print(f"  {p:15s} : {tc} changement(s) de topologie, {rc} reelection(s) de racine")
            for ex in r.stp_root_change_examples.get(p, []):
                print(f"      ex: {ex}")
    else:
        print("  aucune instabilite STP detectee (trafic STP observe ou non)")

    print("\n-- Certificats TLS --")
    if any(r.tls_cert_invalid_dates.values()) or any(r.tls_cert_mismatch.values()):
        for p in r.points:
            n = r.tls_cert_invalid_dates.get(p, 0)
            if not n:
                continue
            print(f"  {p:15s} : {n} certificat(s) hors de leur fenetre de validite")
            for ex in r.tls_cert_invalid_dates_examples.get(p, []):
                print(f"      ex: {ex}")
        for a, b in r.pairs:
            n = r.tls_cert_mismatch.get((a, b), 0)
            if not n:
                continue
            print(
                f"  {a} -> {b} : {n} connexion(s) presentent un certificat different entre les "
                f"deux points -> interception/substitution TLS possible"
            )
            for ex in r.tls_cert_mismatch_examples.get((a, b), []):
                print(f"      ex: {ex}")
    else:
        print("  aucune anomalie de certificat detectee (trafic TLS observe ou non)")

    print("\n-- Negociations TLS incompletes --")
    if any(r.tls_handshake_no_reply.values()) or any(r.tls_handshake_incomplete.values()):
        for p in r.points:
            no_reply = r.tls_handshake_no_reply.get(p, 0)
            incomplete = r.tls_handshake_incomplete.get(p, 0)
            if not no_reply and not incomplete:
                continue
            print(f"  {p:15s} : {no_reply} negociation(s) sans reponse, {incomplete} negociation(s) interrompue(s)")
            for ex in r.tls_handshake_no_reply_examples.get(p, []):
                print(f"      ex: {ex}")
            for ex in r.tls_handshake_incomplete_examples.get(p, []):
                print(f"      ex: {ex}")
    else:
        print("  aucune negociation TLS incomplete detectee (trafic TLS observe ou non)")

    print(f"\n-- Debit observe par point (fenetres de {r.bucket_seconds * 1000:.0f} ms) --")
    for p in r.points:
        vals = list(r.throughput.get(p, {}).values())
        if not vals:
            continue
        avg_kbps = statistics.mean(vals) * 8 / 1000 / r.bucket_seconds
        max_kbps = max(vals) * 8 / 1000 / r.bucket_seconds
        print(f"  {p:15s} : moy={avg_kbps:.1f} kbps  max={max_kbps:.1f} kbps")

    print("\n-- Correlation debit / pertes (saturation, policing, ou sans lien) --")
    if r.saturation_verdict:
        for (a, b), verdict in r.saturation_verdict.items():
            print(f"  {a} -> {b} : {verdict}")
    else:
        print("  aucune perte a corréler avec le debit (ou --order non fourni)")

    print("\n-- Indice de bufferbloat (latence qui augmente avec la charge) --")
    if r.bufferbloat_hint:
        for (a, b), (low_lat, high_lat) in r.bufferbloat_hint.items():
            print(
                f"  {a} -> {b} : latence moyenne {low_lat:.1f}ms en charge faible vs "
                f"{high_lat:.1f}ms en charge forte -> la file d'attente absorbe la charge "
                f"avant de perdre (bufferbloat possible)"
            )
    else:
        print("  aucun indice de bufferbloat detecte")

    print("\n-- Fenetre TCP a zero (recepteur/equipement sature) --")
    if any(r.zero_window.values()):
        for p in r.points:
            if r.zero_window[p]:
                print(f"  {p:15s} : {r.zero_window[p]} paquets avec fenetre TCP=0")
    else:
        print("  aucune fenetre a zero observee")

    print("\n-- ACK dupliques (indice de perte/reordonnancement en aval) --")
    if any(r.dup_ack.values()):
        for p in r.points:
            if r.dup_ack[p]:
                print(f"  {p:15s} : {r.dup_ack[p]} ACK dupliques")
    else:
        print("  aucun ACK duplique detecte")

    print("\n-- Retransmissions TCP par cause (classification native tshark) --")
    if any(r.retrans_fast.values()) or any(r.retrans_rto.values()) or any(r.retrans_spurious.values()):
        for p in r.points:
            fast, rto, spur = r.retrans_fast[p], r.retrans_rto[p], r.retrans_spurious[p]
            if not (fast or rto or spur):
                continue
            print(
                f"  {p:15s} : {fast} rapide(s) (3 ACK dupliques, recuperation normale), "
                f"{rto} par timeout/RTO (recuperation lente), "
                f"{spur} inutile(s)/deja acquittee(s) (minuteur mal calibre ou retour ACK "
                f"asymetrique)"
            )
    else:
        print("  aucune retransmission classifiee par tshark sur cette capture")

    print("\n-- Signaux d'expertise TCP natifs (tcp.analysis.*) --")
    print("  (issue #21) distingue perte reelle / reordonnancement / RTO")
    any_tcp_sig = any(r.out_of_order.values()) or any(r.lost_segment.values()) or any(r.window_update.values())
    if any_tcp_sig:
        for p in r.points:
            ooo, lost, wup = r.out_of_order[p], r.lost_segment[p], r.window_update[p]
            if not (ooo or lost or wup):
                continue
            print(
                f"  {p:15s} : {ooo} hors-ordre(s) (reordonnancement, pas perte), "
                f"{lost} segment(s) perdu(s) (perte reelle inferee), "
                f"{wup} maj(s) de fenetre (recepteur limitant le debit)"
            )
    else:
        print("  aucun signal d'expertise TCP supplementaire detecte")

    print("\n-- Options TCP negociees au handshake (MSS/Window Scale/SACK) --")
    any_tcp_opts = any(r.mss_clamped.values()) or any(r.wscale_stripped.values()) or any(r.sack_stripped.values())
    if any_tcp_opts:
        for a, b in r.pairs:
            mss_n = r.mss_clamped.get((a, b), 0)
            wscale_n = r.wscale_stripped.get((a, b), 0)
            sack_n = r.sack_stripped.get((a, b), 0)
            if not (mss_n or wscale_n or sack_n):
                continue
            if mss_n:
                print(f"  {a} -> {b} : MSS reduit sur {mss_n} handshake(s) (adaptation d'un equipement intermediaire)")
                for ex in r.mss_clamped_examples.get((a, b), []):
                    print(f"      ex: {ex}")
            if wscale_n:
                print(
                    f"  {a} -> {b} : Window Scale retire sur {wscale_n} handshake(s) -- "
                    f"fenetre TCP plafonnee a 65535 octets"
                )
            if sack_n:
                print(
                    f"  {a} -> {b} : SACK Permitted retire sur {sack_n} handshake(s) -- "
                    f"recuperation de perte moins efficace"
                )
    else:
        print("  aucune modification d'option detectee entre les points de capture")

    print("\n-- RST TCP --")
    if any(r.rst_count.values()):
        for p in r.points:
            if r.rst_count[p]:
                note = ""
                if r.rst_localized[p]:
                    note = (
                        f" (dont {r.rst_localized[p]} vus a ce seul point parmi "
                        f"{len(r.points)} -> RST probablement injecte localement, "
                        f"ex. firewall/IPS, plutot que provenant du vrai correspondant)"
                    )
                print(f"  {p:15s} : {r.rst_count[p]} RST{note}")
    else:
        print("  aucun RST detecte")

    print("\n-- Handshakes TCP (SYN sans reponse = filtrage actif probable) --")
    if r.syn_no_synack or r.syn_reply_missing:
        for p in r.points:
            if r.syn_no_synack[p]:
                print(
                    f"  {p:15s} : {r.syn_no_synack[p]} SYN vus (jusqu'a ce point) sans "
                    f"aucun SYN-ACK observe nulle part -> connexion bloquee, probablement "
                    f"ACL/firewall/service down"
                )
            if r.syn_reply_missing[p]:
                print(
                    f"  {p:15s} : {r.syn_reply_missing[p]} SYN vus a ce point dont la "
                    f"reponse SYN-ACK n'est jamais remontee jusqu'ici -> blocage/perte "
                    f"entre ce point et la destination"
                )
    else:
        print("  aucune anomalie de handshake detectee (necessite --order et exclut --nat-tolerant)")

    print("\n-- Retransmissions TCP detectees par point --")
    any_retrans = False
    for p in r.points:
        if r.retrans[p]:
            any_retrans = True
            print(f"  {p:15s} : {r.retrans[p]} retransmissions")
    if not any_retrans:
        print("  aucune detectee")

    print("\n-- Integrite de capture : trous de sequence TCP --")
    if r.sequence_gaps:
        print_sequence_gaps(r)
    else:
        print("  aucun trou de sequence TCP detecte")

    print("\n-- Integrite de capture : checksums IP/TCP/UDP --")
    if r.checksum_errors:
        print_checksum_errors(r)
    else:
        print("  aucun checksum IP/TCP/UDP invalide detecte")

    print(f"\n-- Flux RTP detectes voix/visio (cadence supposee {r.rtp_clock_rate}Hz) --")
    if r.rtp_streams:
        shown = r.rtp_streams[:50]
        for s in shown:
            print(f"  {s['label']}")
            for p in r.points:
                if p in s["loss_pct"]:
                    print(f"      {p:15s} : perte={s['loss_pct'][p]:.2f}%  gigue={s['jitter_ms'].get(p, 0):.2f}ms")
            for a, b in r.pairs:
                if a in s["loss_pct"] and b in s["loss_pct"]:
                    delta = s["loss_pct"][b] - s["loss_pct"][a]
                    if delta > 0.5:
                        print(f"      -> perte RTP supplementaire de {delta:.2f} points entre {a} et {b}")
            if s["delay_ms"] is not None:
                print(f"      delai {r.points[0]}->{r.points[-1]} (proxy bout-en-bout) = {s['delay_ms']:.1f}ms")
            if s["mos"] is not None:
                print(f"      R-factor={s['r_factor']:.1f}  MOS estime={s['mos']:.2f} (estimation simplifiee)")
        if len(r.rtp_streams) > 50:
            print(
                f"  ... {len(r.rtp_streams) - 50} flux RTP supplementaires non affiches "
                f"(voir le CSV de detail pour l'analyse complete)"
            )
    else:
        print(
            "  aucun flux RTP detecte (detection heuristique par en-tete : version RTP=2, "
            "peut manquer des flux ou, plus rarement, se declencher sur du trafic UDP non-RTP)"
        )

    print(f"\n-- Decomposition reseau vs serveur (mesuree cote {r.points[-1] if r.points else '?'}) --")
    if r.server_think_time:
        items = list(r.server_think_time.items())[:50]
        for label, turns in items:
            avg = statistics.mean(turns)
            print(
                f"  {label} : {len(turns)} echange(s), temps de traitement serveur "
                f"moyen={avg:.1f}ms  max={max(turns):.1f}ms"
            )
        if len(r.server_think_time) > 50:
            print(
                f"  ... {len(r.server_think_time) - 50} connexions supplementaires non "
                f"affichees (voir le CSV de detail)"
            )
        overall = [t for turns in r.server_think_time.values() for t in turns]
        print(f"  ensemble : moyenne {statistics.mean(overall):.1f}ms sur {len(overall)} echanges")
        net_pair = (r.points[0], r.points[-1])
        net_lat = r.latency.get(net_pair)
        if net_lat and len(r.points) >= 2:
            print(
                f"  a comparer au temps reseau {net_pair[0]}->{net_pair[1]} : "
                f"moyenne {statistics.mean(net_lat):.1f}ms -> si le temps serveur domine "
                f"largement le temps reseau, le ralentissement est applicatif, pas reseau"
            )
    else:
        print(
            "  aucune donnee (necessite --order, et le SYN de chaque connexion capture "
            "pour identifier avec certitude qui est le client)"
        )

    print("\n-- DHCP (attribution d'adresses IP) --")
    if r.dhcp_msg_count:
        for p in r.points:
            counts = r.dhcp_msg_count.get(p, {})
            if counts:
                summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
                print(f"  {p:15s} : {summary}")
        for p in r.points:
            if r.dhcp_nak_count[p]:
                print(
                    f"  {p:15s} : {r.dhcp_nak_count[p]} DHCPNAK "
                    f"(demande rejetee par le serveur : conflit d'adresse, mauvais "
                    f"sous-reseau, ou pool epuise)"
                )
        for p in r.points:
            servers = sorted(r.dhcp_server_seen.get(p, []))
            if servers:
                print(
                    f"  {p:15s} : serveur(s)/vendor-class annonce(s) = {servers} "
                    f"(tel que fourni par le serveur dans le paquet, pas une empreinte "
                    f"logicielle garantie -- de nombreux serveurs ISC/Kea/Windows ne "
                    f"renseignent pas ces champs de facon distinctive)"
                )
        for (a, b), missing_list in r.dhcp_missing.items():
            for m in missing_list[:20]:
                print(f"  {a} -> {b} : {m}")
            if len(missing_list) > 20:
                print(f"  {a} -> {b} : ... {len(missing_list) - 20} autres messages manquants")
        if r.dhcp_duration_ms:
            avg = statistics.mean(r.dhcp_duration_ms)
            print(f"  duree moyenne DISCOVER->ACK : {avg:.0f}ms sur {len(r.dhcp_duration_ms)} attribution(s) completes")
    else:
        print("  aucun trafic DHCP detecte dans les captures")

    print("\n-- SIP (signalisation voix/visio) --")
    if r.sip_msg_count:
        for p in r.points:
            counts = r.sip_msg_count.get(p, {})
            if counts:
                summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
                print(f"  {p:15s} : {summary}")
        for p in r.points:
            agents = sorted(r.sip_agents_seen.get(p, []))
            if agents:
                print(f"  {p:15s} : {agents} (tel que fourni dans les en-tetes SIP, pas une empreinte garantie)")
        for (a, b), missing_list in r.sip_missing.items():
            for m in missing_list[:20]:
                print(f"  {a} -> {b} : {m}")
            if len(missing_list) > 20:
                print(f"  {a} -> {b} : ... {len(missing_list) - 20} autres messages manquants")
        if r.sip_setup_duration_ms:
            avg = statistics.mean(r.sip_setup_duration_ms)
            print(
                f"  duree moyenne d'etablissement d'appel (INVITE->200) : {avg:.0f}ms "
                f"sur {len(r.sip_setup_duration_ms)} appel(s)"
            )
        if r.sip_failed_calls:
            for f in r.sip_failed_calls[:20]:
                print(f"  {f}")
            if len(r.sip_failed_calls) > 20:
                print(f"  ... {len(r.sip_failed_calls) - 20} autres echecs")
    else:
        print("  aucun trafic SIP detecte dans les captures")

    print("\n-- VoIP orientee appel (SIP + RTP) --")
    if r.voip_calls:
        for call in r.voip_calls[:50]:
            print(
                f"  {call['call_id'][:40]} : "
                f"participants={', '.join(call['participants']) or '?'} ; "
                f"RTP={len(call['rtp_streams'])} ; qualite={call['quality']} ; "
                f"etablissement={call['setup_duration_ms'] if call['setup_duration_ms'] is not None else 'n/a'}ms ; "
                f"duree={call['duration_ms'] if call['duration_ms'] is not None else 'n/a'}ms"
            )
            for event in call["events"]:
                print(f"      {event['type']} @ {event['ts']:.3f}s")
        print(f"  distribution qualite : {dict(r.voip_quality_distribution)}")
    else:
        print("  aucun appel SIP consolide")

    print("\n-- DNS (resolution de noms) --")
    if r.dns_query_count or r.dns_response_count:
        for p in r.points:
            q = r.dns_query_count.get(p, 0)
            resp = r.dns_response_count.get(p, 0)
            if q or resp:
                print(f"  {p:15s} : {q} requete(s), {resp} reponse(s)")
        for p in r.points:
            if r.dns_nxdomain_count[p]:
                print(f"  {p:15s} : {r.dns_nxdomain_count[p]} NXDOMAIN (domaine inexistant)")
            if r.dns_servfail_count[p]:
                print(f"  {p:15s} : {r.dns_servfail_count[p]} SERVFAIL (echec de resolution cote serveur/resolveur)")
        for p in r.points:
            timeouts = r.dns_timeout.get(p, [])
            for t in timeouts[:20]:
                print(f"  {p:15s} : {t}")
            if len(timeouts) > 20:
                print(f"  {p:15s} : ... {len(timeouts) - 20} autres requetes sans reponse")
        for (a, b), missing_list in r.dns_missing.items():
            for m in missing_list[:20]:
                print(f"  {a} -> {b} : {m}")
            if len(missing_list) > 20:
                print(f"  {a} -> {b} : ... {len(missing_list) - 20} autres messages manquants")
        if r.dns_duration_ms:
            avg = statistics.mean(r.dns_duration_ms)
            print(
                f"  duree moyenne de resolution (requete->reponse) : {avg:.0f}ms "
                f"sur {len(r.dns_duration_ms)} transaction(s)"
            )
    else:
        print("  aucun trafic DNS detecte dans les captures")

    print("\n-- HTTP (codes de statut, HTTP/1.x uniquement) --")
    if r.http_request_count or r.http_response_count:
        for p in r.points:
            q = r.http_request_count.get(p, 0)
            resp = r.http_response_count.get(p, 0)
            if q or resp:
                print(f"  {p:15s} : {q} requete(s), {resp} reponse(s)")
        for p in r.points:
            counts = r.http_status_count.get(p, {})
            if counts:
                summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
                print(f"  {p:15s} : {summary}")
        for p in r.points:
            for e in r.http_error_examples.get(p, []):
                print(f"  {p:15s} : {e}")
        for p in r.points:
            timeouts = r.http_timeout.get(p, [])
            for t in timeouts[:20]:
                print(f"  {p:15s} : {t}")
            if len(timeouts) > 20:
                print(f"  {p:15s} : ... {len(timeouts) - 20} autres requetes sans reponse")
        for (a, b), missing_list in r.http_missing.items():
            for m in missing_list[:20]:
                print(f"  {a} -> {b} : {m}")
            if len(missing_list) > 20:
                print(f"  {a} -> {b} : ... {len(missing_list) - 20} autres messages manquants")
        if r.http_response_time_ms:
            avg = statistics.mean(r.http_response_time_ms)
            print(
                f"  duree moyenne de reponse (requete->reponse, calculee nativement par "
                f"tshark) : {avg:.0f}ms sur {len(r.http_response_time_ms)} transaction(s)"
            )
    else:
        print("  aucun trafic HTTP detecte dans les captures")

    print("\n-- Objets HTTP transferes (metadonnees, sans corps) --")
    if r.http_objects:
        for obj in r.http_objects[:50]:
            print(
                f"  {obj.get('status_code') or '?'} {obj.get('method') or '?'} "
                f"{obj.get('uri') or '?'} : "
                f"{obj.get('content_type') or 'type inconnu'}, "
                f"{obj.get('content_length') if obj.get('content_length') is not None else '?'} octets, "
                f"{obj.get('response_time_ms') if obj.get('response_time_ms') is not None else '?'}ms"
            )
        if len(r.http_objects) > 50:
            print(f"  ... {len(r.http_objects) - 50} objets supplementaires non affiches")
    else:
        print("  aucun objet HTTP reponse exploitable")

    print("\n-- Fichiers extraits (SCENARIO-4) --")
    # Issue #349 : r.extracted_files est rempli depuis #150 (analyse), mais
    # aucun rendu ne l'exposait -- un executable PE telecharge en HTTP etait
    # invisible du rapport. Meme seuil de 50 lignes que les objets HTTP, pour
    # la meme raison (eviter de noyer la lecture sans tronquer en silence).
    extracted = getattr(r, "extracted_files", []) or []
    if extracted:
        for f in extracted[:50]:
            h = f.get("hash_sha256") or f.get("hash_md5") or "sans empreinte"
            print(
                f"  [{f.get('point', '?')}] {f.get('type_detected') or 'inconnu'} "
                f"{f.get('uri') or f.get('content_type') or '?'} "
                f"({f.get('size', '?')} octets) -- {h[:16]}"
            )
        if len(extracted) > 50:
            print(f"  ... {len(extracted) - 50} fichier(s) supplementaire(s) non affiche(s)")
    else:
        print("  aucun fichier extrait")
    logger.debug("print_report: fin")


# Nombre maximal de trous detailles par point dans le rapport texte (les
# compteurs, eux, portent toujours sur la totalite).
_MAX_SEQ_GAP_EXAMPLES = 5

_SEQ_GAP_LABELS = {
    SEQ_GAP_CAPTURE_DROP: "trou de capture",
    SEQ_GAP_NETWORK_LOSS: "perte reseau",
    SEQ_GAP_INDETERMINATE: "cause indeterminee",
}


def print_sequence_gaps(r: Report):
    """Detail de la section "Integrite de capture" : trous de sequence TCP par
    point, avec leur cause (capture / reseau / indeterminee)."""
    logger.debug("print_sequence_gaps: r={}", summarize(r, "r"))
    print(
        "  (octets jamais vus a ce point alors que des octets posterieurs l'ont ete, sans retransmission ulterieure ;"
    )
    print('   "de capture" = acquittes par le recepteur mais non captures, "perte reseau" = non acquittes)')
    by_point: dict[str, list[SequenceGap]] = defaultdict(list)
    for gap in r.sequence_gaps:
        by_point[gap.point].append(gap)
    for p in [*r.points, *sorted(set(by_point) - set(r.points))]:
        gaps = by_point.get(p)
        if not gaps:
            continue
        causes = Counter(g.cause for g in gaps)
        print(
            f"  {p:15s} : {len(gaps)} trou(s), {sum(g.missing_bytes for g in gaps)} octet(s) manquant(s) "
            f"({causes[SEQ_GAP_CAPTURE_DROP]} de capture, {causes[SEQ_GAP_NETWORK_LOSS]} perte(s) reseau, "
            f"{causes[SEQ_GAP_INDETERMINATE]} indetermine(s))"
        )
        for g in gaps[:_MAX_SEQ_GAP_EXAMPLES]:
            frame = f", trame {g.frame_number}" if g.frame_number is not None else ""
            print(
                f"      ex: {g.src}:{g.sport} -> {g.dst}:{g.dport} seq {g.start_seq}..{g.end_seq} "
                f"({g.missing_bytes} octets{frame}) -- {_SEQ_GAP_LABELS.get(g.cause, g.cause)} : {g.evidence}"
            )
        if len(gaps) > _MAX_SEQ_GAP_EXAMPLES:
            print(f"      ... et {len(gaps) - _MAX_SEQ_GAP_EXAMPLES} autre(s) trou(s)")
    logger.debug("print_sequence_gaps: fin")


# Meme plafond que _MAX_SEQ_GAP_EXAMPLES ci-dessus (Job 43/issue #163) --
# coherence d'affichage entre les deux sections "Integrite de capture".
_MAX_CHECKSUM_ERROR_EXAMPLES = 50


def print_checksum_errors(r: Report):
    """Detail de la section "Integrite de capture" : checksums IP/TCP/UDP
    invalides, un paquet par ligne (frame_number, protocole, valeur brute
    recue) -- voir netcross_core.forensic.validate_checksums pour ce qui
    est exclu (offload materiel a 0x0000, statut non verifie)."""
    by_point: dict[str, list[ChecksumError]] = defaultdict(list)
    for err in r.checksum_errors:
        by_point[err.point].append(err)
    for p in [*r.points, *sorted(set(by_point) - set(r.points))]:
        errors = by_point.get(p)
        if not errors:
            continue
        print(f"  {p:15s} : {len(errors)} checksum(s) invalide(s)")
        for e in errors[:_MAX_CHECKSUM_ERROR_EXAMPLES]:
            frame = f"trame {e.frame_number}" if e.frame_number is not None else "trame ?"
            print(f"      ex: checksum {e.protocol} invalide ({frame}, recu {e.checksum})")
        if len(errors) > _MAX_CHECKSUM_ERROR_EXAMPLES:
            print(f"      ... et {len(errors) - _MAX_CHECKSUM_ERROR_EXAMPLES} autre(s) checksum(s) invalide(s)")
    logger.debug("print_checksum_errors: fin")


def print_annotations(annotations: list[PacketAnnotation]):
    """Affiche la section annotations (Job 40/issue #160) : etiquettes et
    signets poses par l'analyste sur des paquets individuels.

    Prend une liste de `PacketAnnotation` en parametre plutot qu'un champ
    du `Report` -- une annotation vient du sidecar JSON associe a une
    capture (voir `netcross_core.forensic.read_annotations`), pas du
    calcul d'analyse : l'appelant (CLI/GUI) est responsable de la lire et
    de la passer ici, symetrique de `write_detail_csv` ci-dessous qui
    prend `flows`/`points` directement plutot que de deduire un chemin
    de capture."""
    logger.debug("print_annotations: annotations={}", summarize(annotations, "annotations"))
    print("\n-- Annotations (etiquettes et signets sur paquets) --")
    if not annotations:
        print("  aucune annotation (pas de sidecar, ou sidecar vide)")
        logger.debug("print_annotations: si not annotations -> retour")
        return
    by_tag = annotations_by_tag(annotations)
    for tag in sorted(by_tag):
        print(f"  [{tag}] {len(by_tag[tag])} paquet(s)")
        for ann in sorted(by_tag[tag], key=lambda a: a.frame_number):
            suffix = f" -- {ann.comment}" if ann.comment else ""
            print(f"    trame #{ann.frame_number}{suffix}")
    logger.debug("print_annotations: fin")


def write_detail_csv(path, flows, points, names=None):
    """Ecrit le detail par flux en CSV. Si ``names`` (une
    ``netcross_core.naming.NameTable``) est fourni, les colonnes src/dst
    affichent les noms logiques resolus a la place des adresses brutes."""

    logger.debug(
        "write_detail_csv: path={} flows={} points={} names={}",
        summarize(path, "path"),
        summarize(flows, "flows"),
        summarize(points, "points"),
        summarize(names, "names"),
    )

    def _label(addr) -> str:
        if names is None:
            logger.debug("write_detail_csv._label: si names is None -> retour str(…)")
            return str(addr)
        logger.debug("write_detail_csv._label: retour names.display(str(addr)) if addr is not None else…")
        return names.display(str(addr)) if addr is not None else ""

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            ["proto", "src", "sport", "dst", "dport", "key_id"]
            + [f"{p}_ts" for p in points]
            + [f"{p}_dscp" for p in points]
            + [f"{p}_ttl" for p in points]
        )
        for key, per_point in flows.items():
            row = list(key)
            # src (indice 1) et dst (indice 3) du key de flux strict
            # resolus en noms logiques si une NameTable est fournie.
            if len(row) > 3:
                row[1] = _label(row[1])
                row[3] = _label(row[3])
            row.extend(min(pkt.ts for pkt in per_point[p]) if p in per_point else "" for p in points)
            row.extend(per_point[p][0].dscp if p in per_point else "" for p in points)
            row.extend(per_point[p][0].ttl if p in per_point else "" for p in points)
            w.writerow(row)
    logger.debug("write_detail_csv: fin")
