"""
pcap_parser.tunnels -- couche 3 : detection de la pile d'encapsulation
(VLAN/MPLS/GRE/VXLAN/GTP-U/ERSPAN/CAPWAP) et selection de la couche
IP/TCP/UDP/ICMP la plus interne a utiliser pour l'analyse.

Difference notable avec l'ancienne version : CAPWAP est
maintenant disseque nativement par tshark (dissecteur capwap standard
sur udp/5246-5247), y compris la decapsulation de la trame Ethernet
interne -- on n'a plus besoin du decodage manuel d'octets de
parse_capwap_data() dans l'ancien parsing.py. On se contente de lire ce
que tshark a deja fait, ce qui est a la fois plus simple et plus fiable
(dissecteur maintenu par le projet Wireshark, pas une implementation
maison verifiee "au mieux" contre la RFC).
"""

from __future__ import annotations

from loguru import logger as _loguru_logger

from pcap_parser.ek_fields import all_occurrences, g, hex_or_dec_to_int, innermost, layer

# pcap_parser reste independant de netcross_core (contrat import-linter) :
# loguru directement, lie au nom du module.
logger = _loguru_logger.bind(name=__name__)

# Cles de couches EK qui signalent un vrai tunnel (l'IP/TCP/UDP le plus
# interne doit etre utilise pour l'analyse, pas le premier trouve).
# MPLS et VLAN ne sont PAS ici : ils ne re-encapsulent pas une nouvelle
# paire IP, contrairement a GRE/VXLAN/GTP-U/ERSPAN/CAPWAP -- meme
# distinction que TUNNEL_CLASSES dans l'ancien parsing.py.
TUNNEL_LAYER_KEYS: tuple[str, ...] = ("gre", "vxlan", "gtp", "erspan", "capwap_data")


def is_tunnel(layers: dict) -> bool:
    return any(key in layers for key in TUNNEL_LAYER_KEYS)


def detect_encapsulation(layers: dict) -> tuple[str, ...]:
    """Renvoie les tags decrivant la pile d'encapsulation detectee, dans
    le meme format textuel que l'ancienne version (VLAN100,
    MPLS[100,200], GRE, VXLAN(vni=...), GTP-U(teid=...), ERSPAN,
    CAPWAP(...)) pour rester compatible avec les rapports/baselines
    existants qui comparent ces chaines."""
    tags = []

    for vlan in all_occurrences(layers, "vlan"):
        vid = g(vlan, "vlan_vlan_id")
        if vid is not None:
            tags.append(f"VLAN{vid}")

    mpls_layers = all_occurrences(layers, "mpls")
    if mpls_layers:
        labels = [g(m, "mpls_mpls_label") for m in mpls_layers]
        tags.append("MPLS[" + ",".join(str(label) for label in labels if label is not None) + "]")

    if "gre" in layers:
        tags.append("GRE")

    if "vxlan" in layers:
        vni = g(innermost(layers, "vxlan"), "vxlan_vxlan_vni")
        tags.append(f"VXLAN(vni={vni})")

    if "gtp" in layers:
        teid = hex_or_dec_to_int(g(innermost(layers, "gtp"), "gtp_gtp_teid"))
        tags.append(f"GTP-U(teid={teid})")

    if "erspan" in layers:
        tags.append("ERSPAN")

    tags.extend(_capwap_tags(layers))

    if tags:
        logger.trace("detect_encapsulation: {}", ",".join(tags))
    return tuple(tags)


def _capwap_tags(layers: dict) -> list:
    """CAPWAP a deux canaux distincts (RFC 5415) : controle (5246,
    toujours DTLS en usage reel) et donnees (5247, DTLS optionnel selon
    le preambule). tshark expose la trame decapsulee sous "capwap_data"
    quand il a pu decoder ; si le canal est chiffre DTLS, il n'y a que
    "dtls" au-dessus de udp -- rien a decapsuler.

    Extensions Fortinet : le post-dissecteur Lua (netcross_capwap_fortinet.lua)
    ajoute une couche "fortinet_capwap" avec les champs vendor-specific.
    Si presente, on ajoute le tag Fortinet pour signaler que le trafic
    provient d'un equipement Fortinet (FortiAP/FortiGate)."""
    tags = []
    if "capwap_control" in layers:
        tags.append("CAPWAP(controle)")

    if "capwap_data" in layers:
        capwap = innermost(layers, "capwap_data")
        ptype = g(capwap, "capwap_capwap_preamble_type")
        if ptype == "1":
            tags.append("CAPWAP(chiffre DTLS)")
        else:
            # tshark a decode l'en-tete CAPWAP data ; a-t-il reussi a
            # poursuivre la dissection de la trame interne (Ethernet/IP) ?
            protocols = g(layers.get("frame"), "frame_frame_protocols", "") or ""
            after = protocols.split("capwap.data:", 1)
            decoded_further = len(after) == 2 and after[1] != ""
            tags.append("CAPWAP(decapsule)" if decoded_further else "CAPWAP?(non decode)")
    elif "dtls" in layers:
        udp = innermost(layers, "udp")
        ports = (g(udp, "udp_udp_srcport"), g(udp, "udp_udp_dstport"))
        if "5246" in ports or "5247" in ports:
            tags.append("CAPWAP(chiffre DTLS)")

    # Detection Fortinet via post-dissecteur Lua
    # (seulement si une couche CAPWAP est deja presente)
    if "fortinet_capwap" in layers and tags:
        tags.append("CAPWAP(Fortinet)")

    return tags


def select_innermost_layers(layers: dict) -> dict:
    """Renvoie un dict {"ip4": ..., "ip6": ..., "tcp": ..., "udp": ...,
    "icmp": ..., "icmpv6": ..., "arp": ..., "stp": ...} pointant chacun
    vers la couche EK la plus interne pertinente (en tenant compte des
    tunnels), ou None si absente.

    "stp" (Session 25) suit le meme traitement generique que "arp" :
    picker() generique, aucune logique specifique. STP, comme ARP,
    n'est en pratique jamais rencontre a l'interieur d'un tunnel gere
    ici (diffusion/multicast local au segment LAN par construction,
    IEEE 802.1D, jamais relaye au-dela d'un pont/switch, a fortiori pas
    a travers un tunnel qui re-encapsule du IP).

    "arp" (Session 24) suit le meme traitement generique que "icmp"/
    "icmpv6" : picker() generique, aucune logique specifique. ARP n'est
    en pratique jamais rencontre a l'interieur d'un des tunnels geres ici
    (GRE/VXLAN/GTP-U/ERSPAN/CAPWAP re-encapsulent du IP, pas des trames
    ARP brutes) -- garde le meme picker par coherence/simplicite plutot
    que d'introduire une exception.

    "icmpv6" (Session 22) suit exactement le meme traitement que "icmp" :
    picker() generique, aucune logique specifique a la famille d'adresse
    ici -- la seule chose propre a ICMPv6 est le nom de la couche EK a
    lire. Note sur les messages d'erreur ICMPv6 (Packet Too Big, Dest
    Unreach, Time Exceeded...) : tshark imbrique le datagramme original
    QU'ILS EMBARQUENT (donc ses propres couches "ipv6"/"udp"/"tcp") SOUS
    la cle "icmpv6" elle-meme -- verifie empiriquement (tshark 4.2.2, pcap
    scapy synthetique, voir claude.md Session 22) -- pas au meme niveau
    que les couches de l'enveloppe externe. layer()/innermost() ne lisent
    que le niveau superieur de `layers` (pas de recursion), donc ceci ne
    risque PAS d'ecraser ou de confondre le "ip4"/"ip6"/"tcp"/"udp" de
    l'enveloppe externe deja selectionnes juste au-dessus -- verifie
    explicitement par test (voir test_packet.py).

    Miroir direct de la logique if is_tunnel(...): innermost_layer(...)
    else p[IP] de l'ancien parse_capture()."""
    tunnel = is_tunnel(layers)
    if tunnel:
        logger.trace("select_innermost_layers: tunnel, couches internes retenues")
    picker = innermost if tunnel else layer
    return {
        "ip4": picker(layers, "ip"),
        "ip6": picker(layers, "ipv6"),
        "tcp": picker(layers, "tcp"),
        "udp": picker(layers, "udp"),
        "icmp": picker(layers, "icmp"),
        "icmpv6": picker(layers, "icmpv6"),
        "arp": picker(layers, "arp"),
        "stp": picker(layers, "stp"),
        "is_tunnel": tunnel,
    }
