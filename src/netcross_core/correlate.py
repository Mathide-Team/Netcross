"""
netcross_core.correlate -- correlation des paquets entre points de
capture (par 5-tuple strict ou par hash de payload en mode NAT-tolerant)
et calcul du debit par fenetre temporelle.
"""

from collections import defaultdict

from netcross_core.expert_model import Conversation, Flow
from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt

logger = get_logger(__name__)


def flow_key(pk: Pkt, nat_tolerant=False, nat_window_ms=200):
    """
    Cle de correlation entre points de capture.

    Mode strict (par defaut) : suppose IP/port source et destination
    identiques a chaque point -> ne fonctionne pas si un NAT/PAT est
    traverse entre deux points.

    Mode --nat-tolerant : correlation par hash du payload + fenetre
    temporelle (ignore IP/port). Limites : inutile sans payload (SYN/ACK
    purs), et inefficace si un ALG reecrit le contenu (FTP actif, SIP).
    """
    if nat_tolerant and pk.payload_hash:
        bucket = int(pk.ts / (nat_window_ms / 1000.0))
        return ("NAT", pk.proto, pk.payload_hash, bucket)
    return (pk.proto, pk.src, pk.sport, pk.dst, pk.dport, pk.key_id)


def correlate(all_packets, nat_tolerant=False, nat_window_ms=200, exclude_duplicates=False):
    """Groupe les paquets par cle de flux puis par point.

    exclude_duplicates (Job 41/issue #161, defaut False -> comportement
    historique inchange) : ignore les paquets marques `Pkt.is_duplicate`
    par netcross_core.forensic.detect_cross_capture_duplicates() -- qui
    doit donc avoir ete appelee AVANT. ATTENTION : un doublon exclu n'est
    plus compte comme une presence de son flux a SON point. Si le point du
    doublon n'a vu ce flux QUE via ce paquet, le flux y apparait comme
    absent (et une perte sera rapportee en aval avec --order) : c'est le
    prix de ne plus doubler les compteurs de paquets/octets.
    """
    flows = defaultdict(dict)  # cle -> {point: [Pkt, ...]}
    for pk in all_packets:
        if exclude_duplicates and pk.is_duplicate:
            continue
        if pk.proto in ("ARP", "STP"):
            # ARP (Session 24) et STP (Session 25) sont tous les deux
            # diffuses/locaux par nature (RFC 826 pour ARP ; IEEE 802.1D,
            # adresse de groupe 01:80:c2:00:00:00, pour STP) -- ni l'un
            # ni l'autre n'est structurellement JAMAIS relaye par un
            # routeur au point suivant. Aucun des deux n'a la semantique
            # requete/reponse-PAR-FLUX que cette correlation (et tout ce
            # qui en depend juste apres dans analyse() : pertes, latence,
            # QoS/hop TTL, inference de topologie par recouvrement de
            # flux) suppose implicitement pour chaque cle. Les inclure
            # ferait par exemple compter comme "perte" une trame ARP/STP
            # qui ne franchit jamais un routeur -- comportement normal,
            # pas une anomalie reseau -- et fausserait l'inference de
            # topologie (une meme trame diffusee vue a tous les points
            # ressemble a un recouvrement de flux parfait entre points
            # qui ne sont pas forcement adjacents). Restent disponibles
            # via all_packets pour les detecteurs qui les veulent
            # explicitement (_analyse_arp_ip_conflict,
            # _analyse_stp_instability) -- meme principe que DNS/SIP/
            # DHCP/RTP, deja tous analyses depuis all_packets plutot que
            # flows.
            continue
        flows[flow_key(pk, nat_tolerant, nat_window_ms)].setdefault(pk.point, []).append(pk)
    logger.debug(
        "correlate: {} paquet(s) -> {} flux (nat_tolerant={}, doublons exclus={})",
        len(all_packets),
        len(flows),
        nat_tolerant,
        exclude_duplicates,
    )
    return flows


def build_flows(flows: dict) -> list[Flow]:
    """Restructure le dict `flows` (produit par correlate() ci-dessus, cle
    -> {point: [Pkt, ...]}) en une liste de `Flow` (netcross_core.
    expert_model) -- troisieme objet de contrat de la Session 0 (FEATURES.md
    section 13.3). Ne recalcule rien : une seule passe supplementaire sur
    les memes Pkt deja groupes par correlate(), aucune nouvelle
    correlation ni nouvelle lecture de capture."""
    out = []
    for key, per_point in flows.items():
        f = Flow(key=key)
        for point, pkts in per_point.items():
            if not pkts:
                continue  # garde defensive, correlate() ne produit jamais de liste vide en pratique
            f.points.append(point)
            f.packet_count[point] = len(pkts)
            f.byte_count[point] = sum(pk.length for pk in pkts)
            f.first_ts[point] = min(pk.ts for pk in pkts)
            f.last_ts[point] = max(pk.ts for pk in pkts)
            if f.endpoints is None:
                f.endpoints = tuple(sorted((pkts[0].src, pkts[0].dst)))
        out.append(f)
    logger.debug("build_flows: {} flux construits", len(out))
    return out


def build_conversations(flow_list: list[Flow]) -> list[Conversation]:
    """Regroupe une liste de `Flow` (voir build_flows() ci-dessus) par
    paire d'adresses -- quatrieme objet de contrat de la Session 0. Un
    `Flow.endpoints` deja ordonne (min, max) suffit a regrouper un flux
    src->dst et son retour dst->src sous la MEME Conversation, sans
    relire les paquets bruts."""
    by_endpoints: dict[tuple[str, str], Conversation] = {}
    for f in flow_list:
        if f.endpoints is None:
            continue  # flux sans aucun paquet -- garde defensive, voir Flow.endpoints
        conv = by_endpoints.setdefault(f.endpoints, Conversation(endpoints=f.endpoints))
        conv.flow_keys.append(f.key)
        conv.packet_count += sum(f.packet_count.values())
        conv.byte_count += sum(f.byte_count.values())
    logger.debug("build_conversations: {} flux -> {} conversation(s)", len(flow_list), len(by_endpoints))
    return list(by_endpoints.values())


def compute_throughput(all_packets, bucket_seconds):
    """point -> {bucket_index: octets cumules dans cette fenetre}"""
    tp = defaultdict(lambda: defaultdict(int))
    for pk in all_packets:
        bucket = int(pk.ts // bucket_seconds)
        tp[pk.point][bucket] += pk.length
    logger.debug("compute_throughput: {} point(s), buckets de {} s", len(tp), bucket_seconds)
    return tp


def _topn_category_label(pk, dimension):
    """Etiquette de categorie pour un paquet, selon la dimension demandee.

    - "protocol" : protocole transport tel que decode par tshark (TCP/UDP/
      ICMP/ICMPv6...).
    - "port" : port de DESTINATION prefixe du protocole (ex: "TCP/443"),
      approximation du service accede -- un choix delibere plutot que le
      port source ou une paire src/dst : sur la voie client->serveur, le
      port de destination identifie le service ; sur la voie retour
      serveur->client, il redevient un port ephemere qui se disperse dans
      la longue traine et ne remonte jamais dans le "top N" (comportement
      recherche, pas un defaut a corriger). Paquets sans port (ICMP...) :
      "PROTO (sans port)".
    - "ip" : IP de DESTINATION, meme raisonnement que "port" ("vers qui"
      plutot que "depuis qui" -- une paire src/dst aurait double le volume
      total compte par categorie, cassant la propriete "somme des
      categories == debit total du point").
    - "dscp" : marquage QoS de couche 3. 0 (best effort) est une valeur
      DSCP a part entiere et est distingue explicitement de "non marque"
      (absence du champ, ex: paquet non-IP) -- piege classique de tester
      "if pk.dscp" au lieu de "is not None".
    """
    if dimension == "protocol":
        return pk.proto
    if dimension == "port":
        return f"{pk.proto}/{pk.dport}" if pk.dport is not None else f"{pk.proto} (sans port)"
    if dimension == "ip":
        return pk.dst
    if dimension == "dscp":
        return f"DSCP {pk.dscp}" if pk.dscp is not None else "non marque"
    raise ValueError(f"dimension inconnue pour compute_topn_series: {dimension!r}")


TOPN_DIMENSIONS = ("protocol", "port", "ip", "dscp")
TOPN_OTHER_LABEL = "autres"


def compute_topn_series(all_packets, bucket_seconds, dimension, top_n=5):
    """point -> {categorie: {bucket_index: octets}}, limite aux `top_n`
    categories les plus volumineuses (en octets cumules sur toute la
    capture) PAR POINT -- le reste est agrege sous la categorie
    TOPN_OTHER_LABEL. Le classement top-N et la sommation "autres" sont
    faits independamment pour chaque point (les points n'ont pas
    forcement les memes categories dominantes).

    Voir _topn_category_label() pour le detail des 4 dimensions
    supportees (TOPN_DIMENSIONS). Complement temporel de
    compute_throughput() ci-dessus : meme decoupage en buckets, mais
    ventile le debit par categorie plutot qu'agrege.
    """
    totals = defaultdict(lambda: defaultdict(int))  # point -> categorie -> octets (pour le classement)
    raw = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))  # point -> categorie -> bucket -> octets
    for pk in all_packets:
        cat = _topn_category_label(pk, dimension)
        bucket = int(pk.ts // bucket_seconds)
        totals[pk.point][cat] += pk.length
        raw[pk.point][cat][bucket] += pk.length

    result = {}
    for point, cats in raw.items():
        top_labels = {cat for cat, _total in sorted(totals[point].items(), key=lambda kv: kv[1], reverse=True)[:top_n]}
        merged = defaultdict(lambda: defaultdict(int))
        for cat, buckets in cats.items():
            target = cat if cat in top_labels else TOPN_OTHER_LABEL
            for bucket, nbytes in buckets.items():
                merged[target][bucket] += nbytes
        result[point] = {cat: dict(buckets) for cat, buckets in merged.items()}
    logger.debug("compute_topn_series: dimension {} top {} sur {} point(s)", dimension, top_n, len(result))
    return result
