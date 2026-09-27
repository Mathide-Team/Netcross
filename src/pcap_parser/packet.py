"""
pcap_parser.packet -- couche 5 : assemblage d'un RawPacket normalise a
partir des couches EK d'un paquet, une fois l'encapsulation detectee
(tunnels.py) et les protocoles applicatifs extraits (protocols.py).

RawPacket est le seul objet que ce package expose vers l'exterieur : il
ne depend d'aucun modele d'un projet appelant (pas d'import de
netcross_core.models ici) -- c'est a l'appelant (voir l'adaptateur
netcross_core/parsing.py) d'ajouter ce qui lui est propre (le label du
point de capture, par exemple) et de convertir vers son propre modele
si besoin.
"""

from __future__ import annotations

import hashlib
import math
import sys
from dataclasses import dataclass

from loguru import logger as _loguru_logger

from pcap_parser.ek_fields import (
    all_occurrences,
    as_bool,
    as_bytes_from_hex_dump,
    checksum_is_bad,
    expert_flag_details,
    expert_flag_names,
    g,
    has_expert_flag,
    hex_or_dec_to_int,
    layer,
)
from pcap_parser.protocols import (
    extract_dhcp,
    extract_dns,
    extract_http,
    extract_rtp,
    extract_sip,
    extract_tls_certificate,
    extract_tls_handshake,
)
from pcap_parser.tunnels import detect_encapsulation, select_innermost_layers

# pcap_parser reste independant de netcross_core (contrat import-linter) :
# loguru directement, lie au nom du module.
logger = _loguru_logger.bind(name=__name__)


def _intern(value: str | None) -> str | None:
    """sys.intern() tolerant a None -- chaque ligne NDJSON `tshark -T ek`
    est parsee independamment (un objet json.loads() par paquet), donc
    deux paquets qui portent la MEME valeur textuelle (la meme IP source,
    le meme User-Agent SIP, la meme URI HTTP...) obtiennent chacun leur
    propre objet str distinct -- verifie empiriquement (voir
    FEATURES.md/claude.md, piste "gestion memoire des grosses captures") :
    ~57 octets par chaine dupliquee de ce type sur ce projet, entierement
    evitables des qu'un meme client/serveur/URI revient sur des milliers
    de paquets, le cas courant vise par cette piste. Applique uniquement
    aux champs categoriels (adresses, protocole, methode HTTP...) -- PAS
    a payload_hash/dns_qry_name-valeurs-rares/sip_call_id, ou chaque
    valeur est generalement unique et l'interning n'apporterait rien
    (juste le cout d'une recherche dans la table globale d'interning)."""
    logger.debug("_intern: retour value if value is None else sys.intern(value)")
    return value if value is None else sys.intern(value)


def _byte_entropy(data: bytes) -> float:
    """Issue #351 : entropie de Shannon sur les octets d'un payload.

    Retourne 0.0 pour un payload vide, jusqu'a 8.0 pour des octets
    uniformement distribues (trafic chiffre/compresse). Le calcul se fait
    pendant le parsing car Pkt ne conserve pas le payload brut.
    """
    if not data:
        logger.debug("_byte_entropy: si not data -> retour 0.0")
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    logger.debug("_byte_entropy: retour entropy")
    return entropy


@dataclass(slots=True)
class RawPacket:
    ts: float
    # frame.number -- numero de trame 1-indexe attribue par tshark au sein
    # de CE fichier/flux de capture (pas un identifiant global inter-
    # fichiers). Premiere donnee manquante identifiee pour construire
    # PacketEvidence (netcross_core.expert_model, Session 32/33) : jusque
    # la, aucun champ de RawPacket ne permettait de designer UN paquet
    # precis dans sa capture d'origine (voir docstring de expert_model.py).
    # None si absent du layer EK (jamais observe en pratique avec un
    # vrai tshark, mais reste tolerant comme le reste de ce module).
    frame_number: int | None
    proto: str
    src: str
    dst: str
    sport: int | None
    dport: int | None
    length: int
    ttl: int | None
    dscp: int | None
    ecn: int | None
    seq: int | None
    ack: int | None
    window: int | None
    flags: str | None
    key_id: int | None
    payload_hash: str | None
    # charge utile brute de la couche transport (TCP/UDP), b"" sinon --
    # consommee par des modules qui ont besoin des octets sur le fil
    # (ex: netcross_core.tls_diagnostics/quic_diagnostics), pas par le
    # coeur de netcross_core (Pkt ne garde que payload_hash, plus leger
    # pour les gros volumes de paquets).
    payload: bytes
    ip_id: int | None
    is_fragment: bool
    df: bool  # bit IPv4 Don't Fragment -- toujours False cote IPv6 (pas d'equivalent direct)
    # classification tshark natif d'une retransmission -- verifie
    # empiriquement (claude.md Session 10) : is_retransmission reste actif
    # MEME quand is_fast_retransmission ou is_spurious_retransmission le
    # sont aussi (c'est le indicateur general, les deux autres sont des
    # raffinements poses EN PLUS dessus, pas des remplacements -- la doc
    # Wireshark parle de "Supersedes" mais ca ne concerne que le message
    # d'expertise affiche a l'utilisateur, pas les champs eux-memes).
    # Toujours False si le paquet n'est pas une retransmission au sens de
    # tshark. Voir _analyse_retransmission_types pour la logique de
    # priorite (spurious > fast > simple) qui evite le double comptage.
    is_retransmission: bool
    is_fast_retransmission: bool
    is_spurious_retransmission: bool
    # options TCP negociees au handshake (SYN/SYN-ACK uniquement, None/False
    # ailleurs) -- voir _analyse_tcp_options
    mss_val: int | None
    wscale_shift: int | None
    sack_permitted: bool
    icmp_type: int | None
    icmp_code: int | None
    # ICMPv6 (Session 22) -- champs distincts de icmp_type/icmp_code
    # plutot que reutilises tels quels : les espaces de valeurs ICMPv4 et
    # ICMPv6 ne se recouvrent PAS numeriquement (type 3 = Destination
    # Unreachable cote v4, Time Exceeded cote v6 ; type 2 = message
    # Redirect cote v4, Packet Too Big -- l'analogue PMTUD -- cote v6),
    # donc un code appelant qui ferait `pk.icmp_type == 2` sans verifier
    # `pk.proto` risquerait de meler les deux protocoles. proto == "ICMPv6"
    # (nouvelle valeur, symetrique de "ICMP") est deja le discriminant
    # utilise partout dans ce projet (voir "TCP"/"UDP"/"ICMP" existants) ;
    # des champs separes rendent cette confusion structurellement
    # impossible plutot que de compter sur la discipline de chaque site
    # d'appel a verifier proto en plus du type. Voir FEATURES.md/claude.md
    # "Decodage ICMPv6" pour la discussion complete de cette decision.
    icmpv6_type: int | None
    icmpv6_code: int | None
    # ARP (Session 24) -- src/dst portent deja les adresses IP ARP
    # (arp.src.proto_ipv4/arp.dst.proto_ipv4, reutilisation coherente avec
    # le reste du pipeline qui traite src/dst comme des adresses IP
    # generiques quel que soit le protocole). Champs propres a ARP :
    # l'adresse MAC de l'emetteur (necessaire pour detecter un conflit
    # d'adresse IP -- deux MAC differentes revendiquant la meme IP,
    # `arp.src.hw_mac`), le code d'operation (1=who-has/requete,
    # 2=is-at/reponse, `arp.opcode`), et le marqueur natif tshark d'ARP
    # gratuit (`arp.isgratuitous`, sender == target -- annonce/soit
    # failover soit sonde de conflit d'adresse volontaire, RFC 5227 --
    # classification NATIVE tshark lue telle quelle, meme discipline que
    # tcp.analysis.retransmission en Session 10, pas une comparaison
    # sender==target reimplementee ici).
    arp_opcode: int | None
    arp_sender_mac: str | None
    arp_is_gratuitous: bool
    # STP (Session 25) -- src/dst reutilises pour porter l'adresse MAC
    # Ethernet EMETTRICE (eth.src, le pont qui a genere ce BPDU) et
    # l'adresse MAC de destination (toujours l'adresse de groupe STP
    # bien connue 01:80:c2:00:00:00, IEEE 802.1D) -- pas d'adresse IP
    # portee par STP lui-meme (contrairement a ARP), donc pas de sens a
    # y mettre autre chose que l'identifiant Ethernet disponible, par
    # coherence avec le reste du pipeline qui garantit src/dst toujours
    # peuples (jamais None) quel que soit le protocole. bpdu_type :
    # 0x00 = Configuration BPDU, 0x80 = Topology Change Notification
    # (TCN, trame minimale de 4 octets utiles, SANS les champs
    # root/bridge ci-dessous -- verifie empiriquement, absents du layer
    # EK dans ce cas), 0x02 = RST BPDU (RSTP). flags_tc : classification
    # NATIVE tshark (bit 0 du champ flags d'une Configuration BPDU) --
    # UNIQUEMENT presente sur une Configuration BPDU, PAS sur une TCN
    # (qui n'a structurellement pas de champ flags) -- la detection de
    # "cet evenement signale un changement de topologie" doit donc
    # combiner bpdu_type==0x80 OU flags_tc, jamais l'un sans l'autre
    # (voir _analyse_stp_instability, netcross_core.analysis). root_id :
    # identifiant du pont racine (priorite/MAC concatenes en une chaine,
    # `stp.root.prio`/`stp.root.hw`), absent lui aussi sur une TCN.
    stp_bpdu_type: int | None
    stp_flags_tc: bool
    stp_root_id: str | None
    # TLS (Session 26) -- certificat FEUILLE presente lors du handshake
    # (voir extract_tls_certificate pour le detail complet des choix de
    # perimetre : pas de Subject/Issuer, pas au-dela du 1er certificat
    # de la chaine, invisible en TLS 1.3 sans SSLKEYLOGFILE). Les dates
    # de validite restent des CHAINES telles que rendues par tshark
    # ("YYYY-MM-DD HH:MM:SS (UTC)") -- le parsing/la comparaison
    # temporelle vivent dans netcross_core.analysis._analyse_tls_
    # certificate, pas ici (ce module ne fait que lire ce que tshark a
    # deja dissèque, meme discipline que les autres champs de ce fichier).
    tls_cert_not_before: str | None
    tls_cert_not_after: str | None
    tls_cert_san: tuple[str, ...] | None
    tls_cert_serial: str | None
    # -- certificat TLS (SCENARIO-7, issue #153) -- champs étendus pour
    # l'audit des certificats (émetteur, sujet, algorithme de signature,
    # type/taille de clé, SAN IP, longueur de chaîne).
    tls_cert_issuer: str | None
    tls_cert_subject: str | None
    tls_cert_sig_hash: str | None
    tls_cert_key_type: str | None
    tls_cert_key_bits: int | None
    tls_cert_san_ip: tuple[str, ...] | None
    tls_cert_chain_len: int | None
    # TLS (Session 54) -- PROGRESSION du handshake, concept different du
    # certificat ci-dessus (voir extract_tls_handshake pour le detail
    # complet) : simples booleens NATIFS -- ce paquet porte-t-il (au
    # moins) un ClientHello / un ServerHello / un enregistrement
    # application_data -- jamais interpretes ici (l'agregation par
    # connexion et par point vit dans netcross_core.analysis.
    # _analyse_tls_handshake, meme discipline que le reste de ce
    # fichier). tls_application_data reste vrai que le paquet soit un
    # VRAI echange applicatif ou un message de handshake TLS 1.3
    # deguise en application_data pour compatibilite des intermediaires
    # (voir la docstring d'extract_tls_handshake et celle de
    # _analyse_tls_handshake pour cette limite assumee).
    tls_client_hello: bool
    tls_server_hello: bool
    tls_application_data: bool
    vlan_id: int | None
    vlan_prio: int | None
    is_rtp: bool
    rtp_seq: int | None
    rtp_ts: int | None
    rtp_ssrc: int | None
    encap_tags: tuple[str, ...]
    dhcp_xid: int | None
    dhcp_msg_type: str | None
    dhcp_server_id: str | None
    dhcp_vendor_class: str | None
    sip_call_id: str | None
    sip_msg_type: str | None
    sip_cseq: str | None
    sip_user_agent: str | None
    sip_server: str | None
    # DNS -- present sur TCP comme UDP (voir extract_dns), absents
    # (None/False) sur tout paquet qui n'est pas du DNS
    dns_txn_id: int | None
    dns_is_response: bool
    dns_qry_name: str | None
    dns_rcode: int | None
    # HTTP/1.x -- present sur TCP uniquement (voir extract_http), absents
    # (None/False) sur tout paquet qui n'est pas du HTTP/1.x (HTTP/2/3
    # hors perimetre, dissecteurs tshark distincts, voir extract_http)
    http_is_request: bool
    http_is_response: bool
    http_method: str | None
    http_uri: str | None
    http_status_code: int | None
    http_response_time_ms: float | None
    # Signaux d'expertise BRUTS tshark (Session 1 de FEATURES.md section
    # 13.3, "exploitation de l'expertise Wireshark/TShark") -- generalise
    # ek_fields.has_expert_flag()/is_retransmission ci-dessus, qui ne
    # testait que trois noms de flags TCP connus un par un : ce champ
    # porte TOUS les noms de condition _ws_expert presents sur CE paquet,
    # toutes couches confondues (tuple vide si aucun, cas le plus
    # frequent). Sert de matiere premiere a netcross_core.wireshark_expert
    # -- ce projet ne decode aucun autre nom de flag en champ RawPacket
    # dedie que les trois retransmissions ci-dessus, mais ce champ capte
    # deja tout le reste (perte de segment, ACK duplique, fenetre
    # nulle...) sans attendre qu'un futur champ dedie soit ajoute pour
    # chacun. Union des couches L3 (ip4/ip6/arp/stp -- une seule active a
    # la fois pour un paquet donne) ET L4 (tcp/udp/icmp/icmpv6 -- idem) :
    # plus limite a la seule couche TCP depuis cette session (voir le
    # calcul de expert_flags/expert_details plus bas dans build_packet,
    # apres determination de toutes les couches).
    expert_flags: tuple[str, ...]
    # Vue enrichie de expert_flags ci-dessus (severite/groupe/message
    # NATIFS tshark plutot que le seul nom) -- voir ek_fields.
    # expert_flag_details pour le detail du 4-uplet (name, severity,
    # group, message) et de la table de traduction des codes numeriques
    # severite/groupe. Meme union multi-couches et meme tuple vide par
    # defaut que expert_flags -- les deux champs sont toujours calcules
    # ensemble, a partir des memes couches.
    expert_details: tuple[tuple[str, str | None, str | None, str | None], ...]
    # Issue #351 : entropie de Shannon sur les octets du payload
    payload_entropy: float = 0.0
    http_content_type: str | None = None
    http_content_length: int | None = None
    tcp_len: int | None = None
    # Adresses A/AAAA de la reponse DNS (issue #344) : tuple vide hors
    # reponse DNS. Voir protocols._dns_answers.
    dns_answers: tuple[str, ...] = ()
    # Commentaire de paquet pcapng (Enhanced Packet Block, option
    # opt_comment -- Job 39, issue #159). None sur un pcap classique (le
    # format ne porte aucune notion de commentaire) ou sur un paquet
    # pcapng qui n'en a simplement pas -- voir build_packet() pour
    # l'emplacement exact (INATTENDU) de ce champ dans les couches EK.
    comment: str | None = None
    # -- Checksum IP/TCP/UDP (Job 43/issue #163, "Integrite et qualite de
    # capture") -- valeur brute (chaine hex, ex: "0x66cd") + verdict
    # tri-etat (True=invalide, False=valide, None=non determine -- voir
    # pcap_parser.ek_fields.checksum_is_bad). ip_checksum reste None cote
    # IPv6 (pas de checksum d'en-tete). Necessite ip.check_checksum/
    # tcp.check_checksum/udp.check_checksum actives (voir
    # pcap_parser.ek_source.DEFAULT_PREFS) pour que *_bad soit exploitable
    # -- sinon toujours None (statut "Unverified" cote tshark).
    ip_checksum: str | None = None
    ip_checksum_bad: bool | None = None
    tcp_checksum: str | None = None
    tcp_checksum_bad: bool | None = None
    udp_checksum: str | None = None
    udp_checksum_bad: bool | None = None


# Cles de couches EK dont le "_ws_expert" est collecte en plus des couches
# L3/L4 (issue #137) : applicatives (http/dns/tls/smb/smb2) et la couche de
# premier niveau "_ws_malformed" que tshark ajoute a un paquet dont un
# dissecteur a leve une exception.
_APP_EXPERT_LAYER_KEYS: tuple[str, ...] = ("http", "dns", "tls", "smb", "smb2", "_ws_malformed")
# Severites natives tshark (libelles de ek_fields._SEVERITY_LABELS) sans
# valeur de detection, ecartees de la collecte applicative.
_INFORMATIVE_SEVERITIES: tuple[str, ...] = ("Chat", "Comment")


def build_packet(ts_seconds: float, layers: dict) -> RawPacket | None:
    """Construit un RawPacket a partir des couches EK d'un paquet, ou
    None si le paquet n'a ni IPv4, ni IPv6, ni ARP, ni STP (LLDP, CDP...
    hors perimetre de cette analyse). ARP (Session 24) et STP (Session
    25) sont traites malgre l'absence d'en-tete IP -- voir les branches
    `elif arp is not None`/`elif stp is not None` ci-dessous."""
    frame = layers.get("frame") or {}
    length = hex_or_dec_to_int(g(frame, "frame_frame_len")) or 0
    frame_number = hex_or_dec_to_int(g(frame, "frame_frame_number"))
    # Commentaire de paquet pcapng (Job 39, issue #159). Verifie
    # empiriquement (tshark 4.2.2, pcapng synthetique commente via
    # editcap -a) : PAS niche sous la couche "frame" comme le reste des
    # champs frame.* ci-dessus (frame_frame_len/frame_frame_number)
    # malgre le nom du champ Wireshark lui-meme (frame.comment) --
    # `tshark -T ek` le place dans une pseudo-couche TOP-LEVEL dediee et
    # separee, "pkt_comment" (absente des `layers` d'un paquet sans
    # commentaire -- pcap classique ou pcapng non commente sur CE
    # paquet), elle-meme contenant un seul champ "frame_frame_comment"
    # (meme convention de doublement de prefixe que "tcp_tcp_srcport"
    # pour "tcp.srcport" ailleurs dans ce module, voir ek_fields.py).
    # Coexiste avec un signal d'expertise natif tshark (severite/groupe
    # "Comment", _SEVERITY_LABELS/_GROUP_LABELS de ek_fields.py) sous ce
    # meme "pkt_comment" -- non exploite ici : "pkt_comment" reste
    # volontairement absent de _expert_layers plus bas, ce champ dedie
    # est la seule voie d'acces au texte du commentaire, pas de doublon
    # via expert_flags/expert_details.
    comment = g(layer(layers, "pkt_comment"), "frame_frame_comment")

    encap_tags = detect_encapsulation(layers)
    innermost = select_innermost_layers(layers)

    # -- VLAN : le tag EXTERNE (premiere occurrence), pas le plus
    # interne -- c'est ce que verra un switch/routeur intermediaire qui
    # ne depile pas le tunnel, meme comportement que l'ancien p[Dot1Q].
    vlan0 = layer(layers, "vlan")
    vlan_id = hex_or_dec_to_int(g(vlan0, "vlan_vlan_id"))
    vlan_prio = hex_or_dec_to_int(g(vlan0, "vlan_vlan_priority"))

    ip4, ip6 = innermost["ip4"], innermost["ip6"]
    arp = innermost["arp"]
    stp = innermost["stp"]
    ip_id = is_fragment = None
    df = False
    arp_opcode = arp_sender_mac = None
    arp_is_gratuitous = False
    stp_bpdu_type = stp_root_id = None
    stp_flags_tc = False
    # Checksum IP/TCP/UDP (Job 43/issue #163) -- ip_checksum reste None
    # sur IPv6 (pas de checksum d'en-tete, RFC 8200 -- seul le
    # pseudo-en-tete TCP/UDP en depend, deja couvert par tcp_checksum/
    # udp_checksum ci-dessous, calcules quelle que soit la version IP).
    ip_checksum = ip_checksum_bad = None
    if ip4 is not None:
        src, dst = _intern(g(ip4, "ip_ip_src")), _intern(g(ip4, "ip_ip_dst"))
        ttl = hex_or_dec_to_int(g(ip4, "ip_ip_ttl"))
        dscp = hex_or_dec_to_int(g(ip4, "ip_ip_dsfield_dscp"))
        ecn = hex_or_dec_to_int(g(ip4, "ip_ip_dsfield_ecn"))
        ip_id = hex_or_dec_to_int(g(ip4, "ip_ip_id"))
        # as_bool (pas bool() nu) : ip.flags.mf/df sont des sous-champs
        # booleens de l'octet de flags IP -- bool("0") vaudrait True a tort
        # si jamais rendus en chaine plutot qu'en booleen JSON natif (voir
        # as_bool, corrige au passage ici pour is_fragment, bug de la meme
        # famille que celui trouve en ecrivant le test du nouveau champ df,
        # claude.md Session 9).
        is_fragment = as_bool(g(ip4, "ip_ip_flags_mf")) or (hex_or_dec_to_int(g(ip4, "ip_ip_frag_offset")) or 0) != 0
        df = as_bool(g(ip4, "ip_ip_flags_df"))
        # ip.checksum : valeur brute recue sur le fil (chaine hex, ex:
        # "0x66cd"), jamais convertie en entier -- conservee telle quelle
        # pour la validation/affichage amont (cote netcross_core, voir
        # l'issue #163), comparer des entiers n'apporterait rien ici.
        # ip.checksum.status
        # n'existe QUE si ip.check_checksum:TRUE (voir ek_source.
        # DEFAULT_PREFS) -- absent sinon, donc checksum_is_bad(None) ->
        # None, jamais suppose invalide.
        ip_checksum = g(ip4, "ip_ip_checksum")
        ip_checksum_bad = checksum_is_bad(g(ip4, "ip_ip_checksum_status"))
    elif ip6 is not None:
        src, dst = _intern(g(ip6, "ipv6_ipv6_src")), _intern(g(ip6, "ipv6_ipv6_dst"))
        ttl = hex_or_dec_to_int(g(ip6, "ipv6_ipv6_hlim"))
        dscp = hex_or_dec_to_int(g(ip6, "ipv6_ipv6_tclass_dscp"))
        ecn = hex_or_dec_to_int(g(ip6, "ipv6_ipv6_tclass_ecn"))
        # Fragmentation IPv6 (RFC 8200 S4.5) -- contrairement a IPv4, ou
        # l'Identification est un champ ORDINAIRE de l'en-tete present sur
        # TOUT paquet (fragmente ou non), IPv6 ne porte cette information
        # que si l'en-tete d'extension Fragment est lui-meme present : un
        # datagramme IPv6 jamais fragmente n'a simplement AUCUN
        # identifiant a exposer ici (ip_id reste None dans ce cas, comme
        # avant l'ajout de ce bloc). Verifie empiriquement contre un vrai
        # tshark 4.2.2 (pcap scapy synthetique fragmente via fragment6(),
        # voir claude.md/FEATURES.md "Fragmentation IPv6") : la couche EK
        # correspondante est nichee sous ip6["ipv6_fraghdr"] (meme style
        # d'imbrication que les champs d'expertise TCP sous "_ws_expert",
        # voir ek_fields.has_expert_flag) -- normalisee liste/dict par
        # prudence comme layer()/innermost(), bien que jamais observee en
        # liste sur les captures de test (un seul en-tete Fragment
        # possible par datagramme IPv6, RFC 8200 n'en autorise pas deux).
        frag6 = g(ip6, "ipv6_fraghdr")
        if isinstance(frag6, list):
            frag6 = frag6[0] if frag6 else None
        if frag6 is not None:
            is_fragment = True
            # ipv6.fragment.id : identifiant 32 bits du datagramme
            # original -- equivalent IPv6 de ip.id, present sur CHAQUE
            # fragment (premier compris, verifie empiriquement), ce qui
            # permet la meme correlation inter-points par (src, dst,
            # ip_id) que pour IPv4 dans netcross_core.analysis, mais
            # SEULEMENT entre deux points ou le datagramme est DEJA
            # fragmente aux deux : un datagramme non fragmente au point
            # amont n'a par construction aucun ip_id disponible pour
            # l'appariement, donc frag_new ne peut pas detecter une
            # fragmentation qui apparaitrait nouvellement sur ce segment
            # cote IPv6 -- limite assumee, documentee dans FEATURES.md,
            # differente d'un oubli (le protocole ne fournit tout
            # simplement pas cette information avant fragmentation).
            ip_id = hex_or_dec_to_int(g(frag6, "ipv6_fraghdr_ipv6_fraghdr_ident"))
        else:
            is_fragment = False
        # df reste False : pas de bit DF cote IPv6, la fragmentation n'y est
        # jamais faite par un routeur intermediaire (uniquement par la
        # source) -- detection PMTUD IPv6 (ICMPv6 Packet Too Big, type 2)
        # hors perimetre de cette passe, voir FEATURES.md.
    elif arp is not None:
        # Trame ARP pure -- pas d'en-tete IP du tout (ARP est un
        # protocole de couche 2, RFC 826), donc ttl/dscp/ecn/ip_id/
        # is_fragment/df n'ont structurellement aucun sens ici : laisses
        # a leurs valeurs par defaut (None/None/None/None/None/False,
        # deja initialisees plus haut) -- meme situation que n'importe
        # quel autre paquet ICMP(v6) qui n'a pas non plus de DF/fragment
        # applicable. src/dst reutilisent les adresses IP PORTEES PAR LE
        # PROTOCOLE ARP LUI-MEME (arp.src.proto_ipv4/arp.dst.proto_ipv4)
        # -- coherent avec le reste du pipeline, qui traite deja src/dst
        # comme des adresses IP generiques quel que soit le protocole
        # (TCP/UDP/ICMP/ICMPv6), pas seulement TCP/UDP. Note : pour une
        # requete ARP (\"who-has\", opcode 1) le champ dst (arp.dst.
        # proto_ipv4) est renseigne (l'IP RECHERCHEE) mais arp.dst.hw_mac
        # vaut 00:00:00:00:00:00 (inconnue par construction, c'est
        # justement ce que la requete cherche a apprendre) -- non lu ici,
        # seul le cote EMETTEUR (src/arp_sender_mac) nous interesse pour
        # la detection de conflit d'adresse (voir _analyse_arp_ip_
        # conflict, netcross_core.analysis) : un conflit se voit deja
        # rien qu'en observant deux emetteurs differents revendiquer la
        # meme IP source, que le paquet observe soit une requete ou une
        # reponse.
        ttl = dscp = ecn = None
        src, dst = _intern(g(arp, "arp_arp_src_proto_ipv4")), _intern(g(arp, "arp_arp_dst_proto_ipv4"))
        arp_opcode = hex_or_dec_to_int(g(arp, "arp_arp_opcode"))
        arp_sender_mac = _intern(g(arp, "arp_arp_src_hw_mac"))
        # arp.isgratuitous : classification NATIVE tshark (sender IP ==
        # target IP) -- verifie empiriquement absente du layer (donc
        # False via as_bool(None)) sur un ARP ordinaire, presente et
        # valant true uniquement sur une annonce/sonde RFC 5227 (tshark
        # 4.2.2, pcap scapy synthetique, voir claude.md Session 24) --
        # meme discipline que tcp.analysis.retransmission en Session 10 :
        # le dissecteur fait deja ce travail, pas une comparaison
        # sender==target reimplementee ici.
        arp_is_gratuitous = as_bool(g(arp, "arp_arp_isgratuitous"))
    elif stp is not None:
        # Trame STP (BPDU, IEEE 802.1D/w/s) -- comme ARP, pas d'en-tete
        # IP du tout. src/dst reutilisent l'adresse MAC Ethernet de la
        # trame (eth.src/eth.dst, PAS un champ du protocole STP
        # lui-meme -- contrairement a ARP, qui porte ses propres
        # adresses IP, STP ne porte que des adresses MAC, deja dans
        # l'en-tete Ethernet) -- couche recuperee directement (jamais
        # tunnelee dans ce projet, meme raisonnement que ARP), pas via
        # `innermost` qui ne connait pas la cle "eth".
        ttl = dscp = ecn = None
        eth = layer(layers, "eth")
        src, dst = _intern(g(eth, "eth_eth_src")), _intern(g(eth, "eth_eth_dst"))
        stp_bpdu_type = hex_or_dec_to_int(g(stp, "stp_stp_type"))
        # stp.flags.tc : classification NATIVE tshark, presente
        # UNIQUEMENT sur une Configuration BPDU (absente -- pas juste
        # false -- sur une TCN, verifiee empiriquement, voir claude.md
        # Session 25) -- as_bool(None) -> False, coherent avec le reste
        # du module pour ce type de champ optionnel.
        stp_flags_tc = as_bool(g(stp, "stp_stp_flags_tc"))
        root_prio = g(stp, "stp_stp_root_prio")
        root_hw = g(stp, "stp_stp_root_hw")
        stp_root_id = f"{root_prio}/{root_hw}" if root_prio is not None and root_hw is not None else None
    else:
        # ni IP, ni ARP, ni STP : LLDP, CDP, etc. -- toujours hors perimetre
        logger.trace("build_packet: trame hors perimetre ({}) ignoree", g(frame, "frame_frame_protocols"))
        logger.debug("build_packet: sinon (stp is not None) -> retour None")
        return None

    tcp, udp, icmp = innermost["tcp"], innermost["udp"], innermost["icmp"]
    icmpv6 = innermost["icmpv6"]

    sport = dport = seq = ack = window = None
    flags = None
    proto = "IP"
    icmp_type = icmp_code = None
    icmpv6_type = icmpv6_code = None
    is_retransmission = is_fast_retransmission = is_spurious_retransmission = False
    mss_val = wscale_shift = None
    sack_permitted = False
    tcp_len = None
    is_rtp = False
    rtp_seq = rtp_ts = rtp_ssrc = None
    dhcp_xid = dhcp_msg_type = dhcp_server_id = dhcp_vendor_class = None
    sip_call_id = sip_msg_type = sip_cseq = sip_user_agent = sip_server = None
    dns_txn_id = dns_qry_name = dns_rcode = None
    dns_is_response = False
    dns_answers: tuple[str, ...] = ()
    http_method = http_uri = None
    http_status_code = None
    http_response_time_ms = None
    http_content_type = None
    http_content_length = None
    http_is_request = http_is_response = False
    tls_cert_not_before = tls_cert_not_after = tls_cert_san = tls_cert_serial = None
    tls_cert_issuer = tls_cert_subject = None
    tls_cert_sig_hash = tls_cert_key_type = None
    tls_cert_key_bits = tls_cert_san_ip = tls_cert_chain_len = None
    tls_client_hello = tls_server_hello = tls_application_data = False
    payload = b""
    expert_flags: tuple[str, ...] = ()
    expert_details: tuple[tuple[str, str | None, str | None, str | None], ...] = ()
    # Checksum TCP/UDP (Job 43/issue #163) -- voir ip_checksum ci-dessus
    # pour la convention (valeur brute en chaine hex + statut tri-etat).
    tcp_checksum = tcp_checksum_bad = None
    udp_checksum = udp_checksum_bad = None

    if tcp is not None:
        proto = "TCP"
        sport = hex_or_dec_to_int(g(tcp, "tcp_tcp_srcport"))
        dport = hex_or_dec_to_int(g(tcp, "tcp_tcp_dstport"))
        # IMPORTANT : tcp.seq / tcp.ack sont RELATIFS au premier paquet vu
        # de ce flux dans CE fichier de capture (numerotation a partir de
        # 0 par tshark) -- inutilisables tels quels des qu'on compare
        # plusieurs points de capture issus de processus tshark
        # independants (matching SYN/SYN-ACK entre points dans
        # analysis.py._analyse_handshake, estimation de decalage
        # d'horloge...). tcp.seq_raw / tcp.ack_raw sont les vraies
        # valeurs sur le fil, seules comparables entre fichiers -- c'est
        # ce que renvoyait deja l'ancien decodeur.
        seq = hex_or_dec_to_int(g(tcp, "tcp_tcp_seq_raw"))
        ack = hex_or_dec_to_int(g(tcp, "tcp_tcp_ack_raw"))
        window = hex_or_dec_to_int(g(tcp, "tcp_tcp_window_size_value"))
        # tcp.flags.str : chaine positionnelle "·······S·" (un caractere
        # par flag, lettre si actif sinon point median) -- verifie
        # empiriquement toujours presente aux cotes de tcp.flags (le
        # champ hex "0x0002") sur tshark 4.2 ; on ne se rabat pas sur ce
        # dernier, le "in" substring de l'ancien code (ex: "R" in flags
        # pour RST) ne fonctionnerait pas sur une chaine hex.
        flags = _intern(g(tcp, "tcp_tcp_flags_str"))
        tcp_len = hex_or_dec_to_int(g(tcp, "tcp_tcp_len"))
        # tcp.analysis.retransmission/.fast_retransmission/.spurious_
        # retransmission : classification NATIVE tshark (moteur d'etat
        # complet -- dup-acks recents, fenetre, ACK deja vu en sens
        # inverse...), pas une heuristique maison -- voir has_expert_flag.
        # PAS mutuellement exclusifs au niveau des champs eux-memes :
        # verifie empiriquement (claude.md Session 10) que
        # tcp.analysis.retransmission reste actif MEME quand fast/spurious
        # le sont aussi (c'est l'indicateur general, les deux autres sont
        # des raffinements poses en plus, pas des remplacements -- la doc
        # Wireshark parle de "Supersedes" mais ca ne concerne que le
        # message d'expertise affiche a l'utilisateur). Voir
        # _analyse_retransmission_types pour la priorite appliquee cote
        # netcross (spurious > fast > simple) qui evite le double comptage.
        is_retransmission = has_expert_flag(tcp, "tcp_tcp_analysis_retransmission")
        is_fast_retransmission = has_expert_flag(tcp, "tcp_tcp_analysis_fast_retransmission")
        is_spurious_retransmission = has_expert_flag(tcp, "tcp_tcp_analysis_spurious_retransmission")
        # expert_flags/expert_details (Session 1) : calcules plus bas,
        # UNE FOIS pour toutes les couches de ce paquet (pas seulement
        # TCP) -- voir le commentaire juste avant "key_id = ..." ci-dessous.
        # Options TCP negociees au handshake (SYN/SYN-ACK uniquement --
        # absentes, donc None/False, sur tout autre paquet). Champs de
        # protocole ORDINAIRES (pas des champs d'expertise -- contrairement
        # a is_retransmission ci-dessus), verifie empiriquement (tshark
        # 4.2.2, claude.md Session 11) : absents purement et simplement du
        # layer quand l'option correspondante n'est pas dans le paquet, pas
        # de valeur "vide" a filtrer. tcp.options.sack_perm n'a pas de
        # "valeur" utile (option a longueur fixe, sans champ numerique
        # associe comme mss_val/wscale.shift) -- seule sa presence compte.
        mss_val = hex_or_dec_to_int(g(tcp, "tcp_tcp_options_mss_val"))
        wscale_shift = hex_or_dec_to_int(g(tcp, "tcp_tcp_options_wscale_shift"))
        sack_permitted = g(tcp, "tcp_options_sack_perm") is not None
        payload = as_bytes_from_hex_dump(g(tcp, "tcp_tcp_payload"))
        tcp_checksum = g(tcp, "tcp_tcp_checksum")
        tcp_checksum_bad = checksum_is_bad(g(tcp, "tcp_tcp_checksum_status"))
    elif udp is not None:
        proto = "UDP"
        sport = hex_or_dec_to_int(g(udp, "udp_udp_srcport"))
        dport = hex_or_dec_to_int(g(udp, "udp_udp_dstport"))
        payload = as_bytes_from_hex_dump(g(udp, "udp_udp_payload"))
        udp_checksum = g(udp, "udp_udp_checksum")
        udp_checksum_bad = checksum_is_bad(g(udp, "udp_udp_checksum_status"))

        rtp = extract_rtp(layers, payload)
        if rtp:
            is_rtp = True
            rtp_seq, rtp_ts, rtp_ssrc = rtp["seq"], rtp["ts"], rtp["ssrc"]

        dhcp = extract_dhcp(layers)
        if dhcp:
            dhcp_xid = dhcp["xid"]
            dhcp_msg_type = _intern(dhcp["msg_type"])
            dhcp_server_id = _intern(dhcp["server_id"])
            dhcp_vendor_class = _intern(dhcp["vendor_class"])
    elif icmp is not None:
        proto = "ICMP"
        icmp_type = hex_or_dec_to_int(g(icmp, "icmp_icmp_type"))
        icmp_code = hex_or_dec_to_int(g(icmp, "icmp_icmp_code"))
        sport = hex_or_dec_to_int(g(icmp, "icmp_icmp_ident"))
        dport = hex_or_dec_to_int(g(icmp, "icmp_icmp_seq"))
    elif icmpv6 is not None:
        # Miroir direct de la branche ICMP ci-dessus -- voir RawPacket
        # pour la justification de champs separes (icmpv6_type/code)
        # plutot que la reutilisation de icmp_type/icmp_code.
        proto = "ICMPv6"
        icmpv6_type = hex_or_dec_to_int(g(icmpv6, "icmpv6_icmpv6_type"))
        icmpv6_code = hex_or_dec_to_int(g(icmpv6, "icmpv6_icmpv6_code"))
        # icmpv6.echo.identifier/.sequence_number : presents UNIQUEMENT
        # sur Echo Request/Reply (type 128/129) -- absents purement et
        # simplement du layer sur tout autre type de message ICMPv6
        # (Packet Too Big, Neighbor Discovery...), verifie empiriquement
        # (tshark 4.2.2, claude.md Session 22) -- meme comportement que
        # icmp.ident/icmp.seq cote ICMPv4 ci-dessus (g() renvoie None sans
        # lever d'exception, pas de valeur "vide" a filtrer).
        sport = hex_or_dec_to_int(g(icmpv6, "icmpv6_icmpv6_echo_identifier"))
        dport = hex_or_dec_to_int(g(icmpv6, "icmpv6_icmpv6_echo_sequence_number"))
    elif arp is not None:
        proto = "ARP"
    elif stp is not None:
        proto = "STP"

    if payload and proto in ("TCP", "UDP"):
        sip = extract_sip(layers, payload)
        if sip:
            # sip_call_id/sip_cseq : generalement uniques par appel/message,
            # pas de gain a interner -- voir _intern() pour le critere.
            sip_call_id = sip["call_id"]
            sip_msg_type = _intern(sip["msg_type"])
            sip_cseq = sip["cseq"]
            sip_user_agent = _intern(sip["user_agent"])
            sip_server = _intern(sip["server"])

    if proto in ("TCP", "UDP"):
        # Contrairement a extract_sip ci-dessus, extract_dns ne lit que la
        # dissection tshark native (pas de repli heuristique sur le
        # payload) -- pas besoin de garder cette extraction sous la
        # condition "if payload".
        dns = extract_dns(layers)
        if dns:
            dns_txn_id = dns["txn_id"]
            dns_is_response = dns["is_response"]
            dns_qry_name = _intern(dns["qry_name"])
            dns_rcode = dns["rcode"]
            dns_answers = dns["answers"]

    if proto == "TCP":
        # HTTP/1.x uniquement -- TCP est necessaire mais pas suffisant
        # (extract_http renvoie None sur du trafic TCP ordinaire non-HTTP,
        # meme condition d'entree que DNS ci-dessus mais pas UDP : HTTP/3
        # est QUIC/UDP, deja couvert separement, voir extract_http).
        http = extract_http(layers)
        if http:
            http_is_request = http["is_request"]
            http_is_response = http["is_response"]
            http_method = _intern(http["method"])
            # URI interne : forte duplication attendue en pratique (polling
            # d'un meme endpoint, requetes repetees sur la meme ressource).
            http_uri = _intern(http["uri"])
            http_status_code = http["status_code"]
            http_response_time_ms = http["response_time_ms"]
            http_content_type = _intern(http.get("content_type"))
            http_content_length = http.get("content_length")

        # TLS -- pas de garde "if payload" (comme extract_dns) : lit
        # uniquement la dissection X.509 native de tshark au sein du
        # message Certificate, jamais le payload brut.
        tls_cert = extract_tls_certificate(layers)
        if tls_cert:
            tls_cert_not_before = tls_cert["not_before"]
            tls_cert_not_after = tls_cert["not_after"]
            tls_cert_san = tls_cert["san"]
            tls_cert_serial = _intern(tls_cert["serial"])
            tls_cert_issuer = _intern(tls_cert.get("issuer"))
            tls_cert_subject = _intern(tls_cert.get("subject"))
            tls_cert_sig_hash = _intern(tls_cert.get("sig_hash"))
            tls_cert_key_type = _intern(tls_cert.get("key_type"))
            tls_cert_key_bits = tls_cert.get("key_bits")
            tls_cert_san_ip = tls_cert.get("san_ip")
            tls_cert_chain_len = tls_cert.get("chain_len")

        # Session 54 -- fonction separee (voir sa docstring), meme garde
        # d'entree (TCP requis mais pas suffisant, extract_tls_handshake
        # renvoie None sur du TCP ordinaire non-TLS).
        tls_hs = extract_tls_handshake(layers)
        if tls_hs:
            tls_client_hello = tls_hs["client_hello"]
            tls_server_hello = tls_hs["server_hello"]
            tls_application_data = tls_hs["application_data"]

    # expert_flags/expert_details (Session 1 de FEATURES.md section 13.3)
    # -- union des signaux "_ws_expert" sur TOUTES les couches presentes
    # pour ce paquet : L3 (ip4/ip6/arp/stp -- une seule active a la fois)
    # ET L4 (tcp/udp/icmp/icmpv6 -- une seule active a la fois egalement),
    # pas seulement TCP comme le premier lot de cette session (Session
    # 38). expert_flag_names()/expert_flag_details() renvoient deja un
    # resultat vide sur une couche absente (None) ou sans signal, donc
    # les couches non actives/sans expertise pour un paquet donne ne
    # coutent qu'un appel sans effet -- pas besoin de reproduire la
    # structure if/elif ci-dessus. Cle de tri tolerante a None (severity/
    # group/message peuvent manquer independamment, voir ek_fields.
    # expert_flag_details) plutot que le tri nu de expert_flag_names, qui
    # leverait sur une comparaison None/str.
    _expert_layers = (ip4, ip6, arp, stp, tcp, udp, icmp, icmpv6)
    # Couches APPLICATIVES (issue #137, exploitation des alertes Expert Info
    # pour la detection d'attaques) : http/dns/tls/smb/smb2 portent leur
    # PROPRE sous-cle "_ws_expert" (nom de condition prefixe par la cle de
    # couche, ex: "dns_dns_extraneous"), et un paquet malforme (dissecteur
    # en exception : DNS tronque, enregistrement TLS invalide...) expose en
    # plus une couche EK de premier niveau "_ws_malformed" dont le
    # "_ws_expert" porte la condition "_ws_malformed__ws_malformed_expert"
    # -- structure verifiee empiriquement avec tshark 4.2.2 (pcap scapy
    # synthetique, voir tests/test_expert_correlation.py). Les couches http/dns/tls
    # peuvent etre empilees (plusieurs messages par paquet) : on parcourt
    # toutes les occurrences. Les occurrences de severite native Chat/
    # Comment (ex: "http_http_chat", emise sur CHAQUE message HTTP) sont
    # ecartees : purement informatives, elles noieraient les vrais signaux
    # (et feraient s'allumer comm_map sur tout le trafic HTTP).
    _app_expert_layers = [occ for key in _APP_EXPERT_LAYER_KEYS for occ in all_occurrences(layers, key)]
    _app_expert_details = [
        detail
        for candidate in _app_expert_layers
        for detail in expert_flag_details(candidate)
        if detail[1] not in _INFORMATIVE_SEVERITIES
    ]
    expert_flags = tuple(
        sorted(
            {name for candidate in _expert_layers for name in expert_flag_names(candidate)}
            | {detail[0] for detail in _app_expert_details}
        )
    )
    expert_details = tuple(
        sorted(
            {detail for candidate in _expert_layers for detail in expert_flag_details(candidate)}
            | set(_app_expert_details),
            key=lambda d: (d[0], d[1] or "", d[2] or "", d[3] or ""),
        )
    )

    key_id = seq if proto == "TCP" else ip_id
    phash = hashlib.md5(payload).hexdigest() if payload else None
    # Issue #351 : entropie de Shannon sur les octets du payload
    pentropy = _byte_entropy(payload) if payload else 0.0

    logger.debug("build_packet: retour RawPacket(…)")
    return RawPacket(
        ts=ts_seconds,
        frame_number=frame_number,
        proto=proto,
        src=src or "",
        dst=dst or "",
        sport=sport,
        dport=dport,
        length=length,
        ttl=ttl,
        dscp=dscp,
        ecn=ecn,
        seq=seq,
        ack=ack,
        window=window,
        flags=flags,
        key_id=key_id,
        payload_hash=phash,
        payload=payload,
        payload_entropy=pentropy,
        ip_id=ip_id,
        is_fragment=bool(is_fragment),
        df=df,
        is_retransmission=is_retransmission,
        is_fast_retransmission=is_fast_retransmission,
        is_spurious_retransmission=is_spurious_retransmission,
        mss_val=mss_val,
        wscale_shift=wscale_shift,
        sack_permitted=sack_permitted,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        icmpv6_type=icmpv6_type,
        icmpv6_code=icmpv6_code,
        arp_opcode=arp_opcode,
        arp_sender_mac=arp_sender_mac,
        arp_is_gratuitous=arp_is_gratuitous,
        stp_bpdu_type=stp_bpdu_type,
        stp_flags_tc=stp_flags_tc,
        stp_root_id=stp_root_id,
        tls_cert_not_before=tls_cert_not_before,
        tls_cert_not_after=tls_cert_not_after,
        tls_cert_san=tls_cert_san,
        tls_cert_serial=tls_cert_serial,
        tls_cert_issuer=tls_cert_issuer,
        tls_cert_subject=tls_cert_subject,
        tls_cert_sig_hash=tls_cert_sig_hash,
        tls_cert_key_type=tls_cert_key_type,
        tls_cert_key_bits=tls_cert_key_bits,
        tls_cert_san_ip=tls_cert_san_ip,
        tls_cert_chain_len=tls_cert_chain_len,
        tls_client_hello=tls_client_hello,
        tls_server_hello=tls_server_hello,
        tls_application_data=tls_application_data,
        vlan_id=vlan_id,
        vlan_prio=vlan_prio,
        is_rtp=is_rtp,
        rtp_seq=rtp_seq,
        rtp_ts=rtp_ts,
        rtp_ssrc=rtp_ssrc,
        encap_tags=encap_tags,
        dhcp_xid=dhcp_xid,
        dhcp_msg_type=dhcp_msg_type,
        dhcp_server_id=dhcp_server_id,
        dhcp_vendor_class=dhcp_vendor_class,
        sip_call_id=sip_call_id,
        sip_msg_type=sip_msg_type,
        sip_cseq=sip_cseq,
        sip_user_agent=sip_user_agent,
        sip_server=sip_server,
        dns_txn_id=dns_txn_id,
        dns_is_response=dns_is_response,
        dns_qry_name=dns_qry_name,
        dns_rcode=dns_rcode,
        http_is_request=http_is_request,
        http_is_response=http_is_response,
        http_method=http_method,
        http_uri=http_uri,
        http_status_code=http_status_code,
        http_response_time_ms=http_response_time_ms,
        http_content_type=http_content_type,
        http_content_length=http_content_length,
        comment=comment,
        expert_flags=expert_flags,
        expert_details=expert_details,
        tcp_len=tcp_len,
        dns_answers=dns_answers,
        ip_checksum=ip_checksum,
        ip_checksum_bad=ip_checksum_bad,
        tcp_checksum=tcp_checksum,
        tcp_checksum_bad=tcp_checksum_bad,
        udp_checksum=udp_checksum,
        udp_checksum_bad=udp_checksum_bad,
    )
