"""
netcross_core.models -- structures de donnees partagees : un paquet
normalise (Pkt) et le resultat d'analyse consolide (Report).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

ROLE_SERVER = "server"
ROLE_CLIENT = "client"


@dataclass(frozen=True, slots=True)
class Banner:
    """Un logiciel identifie par sa banniere dans la charge utile d'un
    paquet (CVE-1, issue #135) -- voir netcross_core.application.banners.

    `protocol` : http, ssh, dns, smb, smtp, ftp, imap ou pop3.
    `service`  : nom du logiciel tel que le service l'annonce ("Apache",
                 "OpenSSH", "vsftpd", "BIND", "Samba"...).
    `version`  : version annoncee, None si le service n'en donne pas.
    `raw`      : texte source (en-tete, salutation) pour l'analyste.
    `role`     : ROLE_SERVER (le logiciel tourne sur l'emetteur du paquet,
                 cas normal) ou ROLE_CLIENT (User-Agent HTTP, banniere SSH
                 cliente : logiciel client de l'emetteur).
    """

    protocol: str
    service: str
    version: str | None
    raw: str
    role: str = ROLE_SERVER

    @property
    def banner(self) -> str:
        """Forme "produit/version" (ou "produit" seul), lisible par
        `netcross_core.security.cpe_match.parse_banner`."""
        logger.debug("Banner.banner: retour f'(self.service)/(self.version)' if self.version …")
        return f"{self.service}/{self.version}" if self.version else self.service


@dataclass(slots=True)
class Pkt:
    point: str
    ts: float
    # frame.number tshark -- voir pcap_parser.packet.RawPacket.frame_number
    # pour la justification complete (premiere brique de PacketEvidence).
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
    key_id: int | None  # IP ID (UDP/ICMP) ou seq TCP, utilise pour la correlation
    payload_hash: str | None
    # Identifiant de datagramme, utilise pour le suivi de fragmentation :
    # IPv4 (ip.id, toujours present) OU IPv6 (ipv6.fragment.id, present
    # UNIQUEMENT si l'en-tete d'extension Fragment existe -- None sur un
    # datagramme IPv6 jamais fragmente, l'information n'existe alors tout
    # simplement pas cote protocole. Voir pcap_parser.packet pour le
    # detail et les limites assumees de la correlation inter-points qui
    # en decoulent (frag_new/encap_frag_correlated cote IPv6).
    ip_id: int | None
    is_fragment: bool  # IPv4 : MF actif ou offset != 0 -- IPv6 : en-tete Fragment present
    df: bool  # bit IPv4 Don't Fragment -- toujours False cote IPv6
    # classification tshark natif d'une retransmission (mutuellement
    # exclusifs en pratique, voir pcap_parser.packet.RawPacket)
    is_retransmission: bool
    is_fast_retransmission: bool
    is_spurious_retransmission: bool
    mss_val: int | None
    wscale_shift: int | None
    sack_permitted: bool
    icmp_type: int | None
    icmp_code: int | None
    # ICMPv6 (Session 22) -- champs separes de icmp_type/icmp_code,
    # meme raisonnement que pcap_parser.packet.RawPacket (espaces de
    # valeurs ICMPv4/ICMPv6 non comparables numeriquement) ; proto
    # vaut "ICMPv6" (nouvelle valeur, symetrique de "ICMP") sur ce type
    # de paquet.
    icmpv6_type: int | None
    icmpv6_code: int | None
    arp_opcode: int | None
    arp_sender_mac: str | None
    arp_is_gratuitous: bool
    stp_bpdu_type: int | None
    stp_flags_tc: bool
    stp_root_id: str | None
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
    # TLS (Session 54) -- voir pcap_parser.packet.RawPacket pour le detail
    # complet (meme trois champs, meme discipline booleenne).
    tls_client_hello: bool
    tls_server_hello: bool
    tls_application_data: bool
    vlan_id: int | None
    vlan_prio: int | None
    is_rtp: bool
    rtp_seq: int | None
    rtp_ts: int | None
    rtp_ssrc: int | None
    encap_tags: tuple[str, ...]  # pile d'encapsulation detectee (VLAN, MPLS, GRE, VXLAN...)
    dhcp_xid: int | None
    dhcp_msg_type: str | None
    dhcp_server_id: str | None
    dhcp_vendor_class: str | None
    sip_call_id: str | None
    sip_msg_type: str | None
    sip_cseq: str | None
    sip_user_agent: str | None
    sip_server: str | None
    dns_txn_id: int | None
    dns_is_response: bool
    dns_qry_name: str | None
    dns_rcode: int | None
    http_is_request: bool
    http_is_response: bool
    http_method: str | None
    http_uri: str | None
    http_status_code: int | None
    http_response_time_ms: float | None
    # Signaux d'expertise bruts tshark (Session 1, voir pcap_parser.packet
    # RawPacket.expert_flags pour le detail complet) -- report a l'identique,
    # aucune transformation.
    expert_flags: tuple[str, ...]
    # Vue enrichie de expert_flags (severite/groupe/message NATIFS tshark
    # -- voir pcap_parser.packet.RawPacket.expert_details/pcap_parser.
    # ek_fields.expert_flag_details pour le detail complet) -- report a
    # l'identique, aucune transformation.
    expert_details: tuple[tuple[str, str | None, str | None, str | None], ...]
    # HTTP object metadata (Job 25), optional to preserve the historical
    # Pkt constructor/API.
    http_content_type: str | None = None
    http_content_length: int | None = None
    # Doublon inter-captures (Job 41/issue #161) : renseigne UNIQUEMENT par
    # netcross_core.forensic.detect_cross_capture_duplicates() -- un paquet
    # deja vu a un AUTRE point avec le meme payload_hash a moins de
    # `threshold_ms` (port miroir qui renvoie le trafic, par exemple).
    # False par defaut : aucun constructeur existant n'a a le passer.
    is_duplicate: bool = False
    # Issue #351 : entropie de Shannon sur les octets de la charge utile,
    # calculee pendant le parsing (Pkt ne garde pas le payload brut).
    # 0.0 = pas de payload, 8.0 = octets uniformement distribues (chiffre/
    # compresse). Plus fiable que l'entropie sur les tailles de paquets.
    payload_entropy: float = 0.0
    # Issue #351 : nombre d'octets de charge utile sur lesquels
    # payload_entropy a ete calculee (0 = pas de payload). Sert a ponderer
    # et normaliser l'entropie par flux (security.flow_stats) : l'entropie
    # de n octets est bornee par log2(min(n, 256)).
    payload_len: int = 0
    # Commentaire de paquet pcapng (Enhanced Packet Block, option
    # opt_comment -- Job 39, issue #159). Reporte a l'identique depuis
    # pcap_parser.packet.RawPacket.comment (voir sa docstring pour
    # l'emplacement -- inattendu -- de ce champ dans les couches EK) ;
    # None sur un pcap classique ou sur un paquet pcapng sans
    # commentaire (cas le plus frequent).
    comment: str | None = None
    # Logiciels identifies par banniere (CVE-1, issue #135) -- calcule par
    # netcross_core.parsing depuis RawPacket.payload (les octets ne sont
    # plus disponibles ensuite) ; sert a construire
    # Report.service_fingerprints (application.banners.build_service_fingerprints).
    service_banners: tuple[Banner, ...] = ()
    # tcp.len : longueur de la charge utile TCP du segment (voir
    # RawPacket.tcp_len pour la justification complete), None hors TCP ou quand
    # l'information n'existe pas (paquets synthetiques de l'adaptateur NetFlow...).
    tcp_len: int | None = None
    # Adresses A/AAAA d'une reponse DNS (issue #344, fast flux), reportees
    # depuis RawPacket.dns_answers ; tuple vide hors reponse DNS.
    dns_answers: tuple[str, ...] = ()
    # -- Checksums IP/TCP/UDP (Job 43/issue #163) : valeurs brutes (chaine
    # hex) et verdicts tri-etats (True=invalide, False=valide, None=non
    # determine) reportes tels quels depuis RawPacket. Pas encore consommes
    # par l'analyse (le rapport/forensic amont reste a ecrire, voir #163) :
    # Pkt ne perd volontairement AUCUN champ de RawPacket (hors payload, par
    # design -- invariant verifie par test_parsing_adapter) pour que la
    # validation de checksums dispose deja de la donnee.
    ip_checksum: str | None = None
    ip_checksum_bad: bool | None = None
    tcp_checksum: str | None = None
    tcp_checksum_bad: bool | None = None
    udp_checksum: str | None = None
    udp_checksum_bad: bool | None = None
    # -- empreintes JA4/HASSH (FLOW-2, issue #143, parent #141) : calculees
    # par netcross_core.fingerprint.report.compute_pkt_fingerprints depuis
    # RawPacket.payload (les octets ne sont plus disponibles ensuite --
    # meme contrainte que service_banners ci-dessus). None quand ce
    # paquet ne porte ni ClientHello TLS ni SSH_MSG_KEXINIT decodable.
    # `tls_ja4_readable`/`ssh_hassh_readable` : forme lisible pour
    # l'analyste (ciphers/extensions ou algorithmes en clair), le hash
    # opaque seul ne l'est pas. `ssh_hassh_role` : ROLE_CLIENT ou
    # ROLE_SERVER selon quel cote a emis ce SSH_MSG_KEXINIT (HASSH et
    # HASSHServer different -- voir netcross_core.fingerprint.ssh_hassh).
    tls_ja4: str | None = None
    tls_ja4_readable: str | None = None
    ssh_hassh: str | None = None
    ssh_hassh_role: str | None = None
    ssh_hassh_readable: str | None = None


# Cause d'un trou de sequence TCP (SequenceGap.cause) -- criteres de
# classification dans netcross_core.forensic.detect_sequence_gaps.
SEQ_GAP_CAPTURE_DROP = "capture_drop"
SEQ_GAP_NETWORK_LOSS = "network_loss"
SEQ_GAP_INDETERMINATE = "indeterminate"


@dataclass(slots=True)
class SequenceGap:
    """Trou dans la numerotation TCP d'un sens de connexion, vu a un point de
    capture : les octets [start_seq, end_seq) n'ont jamais ete observes alors
    que des octets posterieurs l'ont ete, et aucune retransmission ni paquet
    hors-ordre ne les a combles avant la fin de la capture.

    Les numeros de sequence sont les valeurs brutes du fil (32 bits, non
    relatives). `ts` et `frame_number` designent le premier segment recu APRES
    le trou (celui qui le revele). `cause` vaut SEQ_GAP_CAPTURE_DROP (octets
    acquittes par le recepteur mais absents de la capture), SEQ_GAP_NETWORK_LOSS
    (octets non acquittes, sans retransmission visible) ou SEQ_GAP_INDETERMINATE
    (pas de retour exploitable du recepteur a ce point) ; `evidence` en donne la
    justification lisible. Voir netcross_core.forensic.detect_sequence_gaps."""

    point: str
    src: str
    sport: int
    dst: str
    dport: int
    start_seq: int
    end_seq: int
    missing_bytes: int
    ts: float
    frame_number: int | None
    cause: str
    evidence: str


@dataclass(slots=True)
class ChecksumError:
    """Paquet dont le checksum IP/TCP/UDP est invalide (Job 43/issue
    #163, categorie "Integrite et qualite de capture").

    Produit par `netcross_core.forensic.validate_checksums()` a partir
    des champs de checksum bruts deja portes par `Pkt` (voir
    `pcap_parser.packet.RawPacket` pour le detail de l'extraction) --
    ce dataclass ne recalcule aucun checksum, il reflete le verdict deja
    rendu par tshark (`-o ip.check_checksum:TRUE` et equivalents TCP/UDP,
    actives par defaut, voir `pcap_parser.ek_source.DEFAULT_PREFS`).

    Un checksum a `0x0000` (offload materiel -- la carte reseau calcule
    le checksum a l'emission, tshark capture donc un paquet ou le champ
    n'a jamais ete rempli) n'est JAMAIS remonte comme ChecksumError,
    meme si tshark le rend "Bad" (0x0000 ne correspond presque jamais a
    la valeur recalculee) : voir `validate_checksums` pour la
    distinction, second critere explicite de l'issue."""

    point: str
    frame_number: int | None
    protocol: str  # "IP" | "TCP" | "UDP"
    checksum: str  # valeur brute recue sur le fil, ex: "0x1111"


@dataclass
class Report:
    points: list[str] = field(default_factory=list)
    pairs: list[tuple[str, str]] = field(default_factory=list)
    bucket_seconds: float = 1.0
    rtp_clock_rate: int = 8000
    seen_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    loss_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # issue #352 : paquets vus en amont dont le couple d'hotes n'echange
    # jamais rien a ce point (ni aller ni retour) -- trafic hors chemin
    # (scan local, flux qui sort ailleurs), a ne pas confondre avec une perte.
    off_path_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    latency: dict[tuple[str, str], list[float]] = field(default_factory=lambda: defaultdict(list))
    qos_change: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    retrans: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # -- classification tshark native des retransmissions (voir
    # _analyse_retransmission_types) : complementaire de retrans
    # ci-dessus (heuristique maison "meme flux vu plusieurs fois a ce
    # point"), plus precise (moteur d'etat TCP complet de tshark), mais
    # ne remplace pas retrans -- champ different, garde pour compatibilite
    # avec l'existant (baseline_diff notamment).
    retrans_fast: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    retrans_rto: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    retrans_spurious: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # -- negociation options TCP au handshake (voir _analyse_tcp_options) --
    mss_clamped: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    mss_clamped_examples: dict[tuple[str, str], list[str]] = field(default_factory=lambda: defaultdict(list))
    # Numeros de trame (Pkt.frame_number) du paquet cote POINT A (amont)
    # de chaque exemple ci-dessus, meme index/plafond -- PacketEvidence
    # (Session 37, extension du pilote PMTUD de la Session 35).
    mss_clamped_frames: dict[tuple[str, str], list[int | None]] = field(default_factory=lambda: defaultdict(list))
    wscale_stripped: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    sack_stripped: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    # -- TTL / topologie --
    hop_delta: dict[tuple[str, str], list[int]] = field(default_factory=lambda: defaultdict(list))
    hop_delta_outliers: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    ttl_unstable: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # -- correlation QoS x TTL --
    qos_l2_remark: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    qos_l3_remark: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    # -- fragmentation / MTU --
    frag_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    frag_new: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    icmp_frag_needed: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # Equivalent IPv6 (Session 22) de icmp_frag_needed ci-dessus : ICMPv6
    # "Packet Too Big" (type 2, RFC 4443 S3.2) -- emis par un routeur
    # intermediaire qui ne peut PAS fragmenter (seule la source le peut
    # en IPv6, voir pcap_parser.packet), le signal fonctionnel joue
    # exactement le meme role que "ICMP Fragmentation Needed" cote IPv4
    # pour _analyse_pmtud ci-dessous -- compteur separe plutot que
    # reutilisation du meme dict, meme raisonnement que icmpv6_type/code
    # sur Pkt (les deux mecanismes ICMP/ICMPv6 restent distincts, un seul
    # compteur commun aurait mele deux protocoles sous un seul nom).
    icmpv6_too_big: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # -- PMTUD (noir) : segment retransmis en amont, jamais vu en aval,
    # sans signal ICMP(v6) de MTU insuffisant observe en amont -- IPv4 :
    # bit DF actif + ICMP Fragmentation Needed ; IPv6 : pas de bit DF
    # (la semantique "ne pas fragmenter" est implicite pour tout paquet,
    # seule la source peut fragmenter) + ICMPv6 Packet Too Big. Voir
    # _analyse_pmtud pour le detail des deux branches.
    pmtud_blackhole: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    pmtud_blackhole_examples: dict[tuple[str, str], list[str]] = field(default_factory=lambda: defaultdict(list))
    # Numeros de trame (Pkt.frame_number) du paquet representatif de
    # chaque exemple ci-dessus, un par entree, meme index/meme plafond a
    # 5 -- premier champ de Report a alimenter PacketEvidence
    # (netcross_core.expert_model, Session 35), voir _analyse_pmtud et
    # netcross_report.synthesis. `None` si frame_number etait absent sur
    # le paquet source (tolerance, jamais observe en pratique avec un
    # vrai tshark -- voir pcap_parser.packet.RawPacket.frame_number).
    pmtud_blackhole_frames: dict[tuple[str, str], list[int | None]] = field(default_factory=lambda: defaultdict(list))
    # -- timeout d'inactivite / coupure NAT-FW silencieuse (voir
    # _analyse_idle_timeout) : un flux TCP deja etabli aux DEUX points,
    # dont le plus grand ecart entre deux paquets consecutifs au point
    # amont depasse le seuil (_IDLE_TIMEOUT_SECONDS), et dont le trafic
    # qui reprend en amont apres ce silence n'atteint plus jamais le
    # point aval -- signature typique d'une table d'etat NAT/pare-feu qui
    # a expire l'entree pendant l'inactivite et bloque desormais le
    # trafic repris sans emettre le moindre RST.
    idle_timeout_dropped: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    idle_timeout_examples: dict[tuple[str, str], list[str]] = field(default_factory=lambda: defaultdict(list))
    # Numero de trame (Pkt.frame_number) du paquet qui reprend le trafic en
    # amont apres le silence (meme paquet que celui qui determine gap_end
    # dans _analyse_idle_timeout), meme index/plafond -- PacketEvidence
    # (Session 37).
    idle_timeout_frames: dict[tuple[str, str], list[int | None]] = field(default_factory=lambda: defaultdict(list))
    # -- conflit d'adresse IP (ARP) -- voir _analyse_arp_ip_conflict.
    # Par POINT (pas par paire de points, contrairement a la plupart des
    # detecteurs ci-dessus) : un conflit d'adresse se voit deja au sein
    # d'un seul point de capture (deux MAC differentes qui revendiquent
    # la meme IP sur le meme segment de diffusion), une correlation
    # inter-points n'apporte rien de plus ici -- meme granularite que
    # retrans_fast/retrans_rto/retrans_spurious ci-dessus.
    arp_ip_conflict: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    arp_ip_conflict_examples: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    # Numero de trame (Pkt.frame_number) du dernier paquet ARP observe pour
    # l'IP en conflit, meme index/plafond -- PacketEvidence (Session 37).
    arp_ip_conflict_frames: dict[str, list[int | None]] = field(default_factory=lambda: defaultdict(list))
    # -- instabilite STP (Session 25) -- voir _analyse_stp_instability.
    # Par POINT, meme granularite que arp_ip_conflict ci-dessus : une
    # tempete de changements de topologie ou une reelection de pont
    # racine se voit deja au sein d'un seul point de capture.
    # stp_topology_change : nombre d'evenements de changement de
    # topologie observes (BPDU de type TCN OU Configuration BPDU avec le
    # bit TC actif -- les deux sont des signaux equivalents du meme
    # phenomene, voir docstring du detecteur). Un reseau STP stable n'en
    # emet quasiment jamais ; une boucle ou un port qui flappe en genere
    # en rafale.
    stp_topology_change: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # stp_root_change : nombre de fois ou l'identifiant du pont racine
    # (priorite/MAC) change de valeur d'une Configuration BPDU a la
    # suivante, au meme point -- une reelection repetee du pont racine
    # est un signe classique d'instabilite (boucle, lien qui flappe).
    stp_root_change: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    stp_root_change_examples: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    # Numero de trame (Pkt.frame_number) de la BPDU qui porte la nouvelle
    # racine, meme index/plafond -- PacketEvidence (Session 37).
    stp_root_change_frames: dict[str, list[int | None]] = field(default_factory=lambda: defaultdict(list))
    # -- certificat TLS (Session 26) -- voir _analyse_tls_certificate.
    # tls_cert_invalid_dates : par POINT (comme ARP/STP ci-dessus) -- un
    # certificat presente HORS de sa fenetre de validite (deja expire,
    # OU pas encore valide) au moment du handshake se voit deja au sein
    # d'un seul point de capture. Les deux cas partagent le meme
    # compteur (comme stp_topology_change regroupe TCN et bit TC) --
    # le message d'exemple precise lequel des deux s'est produit.
    tls_cert_invalid_dates: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    tls_cert_invalid_dates_examples: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    # Numero de trame (Pkt.frame_number) du paquet portant le certificat hors
    # fenetre de validite, meme index/plafond -- PacketEvidence (Session 37).
    tls_cert_invalid_dates_frames: dict[str, list[int | None]] = field(default_factory=lambda: defaultdict(list))
    # tls_cert_mismatch : PAR PAIRE de points (a, b), comme pmtud_
    # blackhole/idle_timeout_dropped -- ici la comparaison EXIGE deux
    # points : le numero de serie du certificat presente pour une meme
    # connexion differe entre l'amont et l'aval, signature possible d'une
    # interception/substitution TLS en cours de chemin (proxy
    # d'inspection, MITM) plutot qu'un forward transparent du meme
    # certificat.
    tls_cert_mismatch: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    tls_cert_mismatch_examples: dict[tuple[str, str], list[str]] = field(default_factory=lambda: defaultdict(list))
    # Numero de trame (Pkt.frame_number) du paquet cote POINT A (amont)
    # portant le numero de serie de reference, meme index/plafond --
    # PacketEvidence (Session 37).
    tls_cert_mismatch_frames: dict[tuple[str, str], list[int | None]] = field(default_factory=lambda: defaultdict(list))
    # -- negociations TLS incompletes (Session 54) -- voir
    # _analyse_tls_handshake. Concept DIFFERENT du certificat ci-dessus
    # (voir docstring de _analyse_tls_handshake pour la distinction
    # complete) : PAR POINT uniquement, comme tls_cert_invalid_dates --
    # aucune correlation entre points necessaire, une negociation qui ne
    # va pas a son terme se voit deja au sein d'un seul point de
    # capture (le point qui verrait un ClientHello amont mais capture
    # en aval de l'endroit ou la negociation s'est arretee ne verrait
    # simplement rien du tout -- absence de signal, pas un signal en
    # soi, meme limite que tout le reste de ce module PAR POINT).
    # tls_handshake_no_reply : un ClientHello est vu pour une connexion,
    # mais AUCUN ServerHello n'est jamais observe pour cette meme
    # connexion a ce meme point -- silence total apres l'ouverture de la
    # negociation (filtrage, service injoignable, ou timeout de
    # capture).
    tls_handshake_no_reply: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    tls_handshake_no_reply_examples: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    tls_handshake_no_reply_frames: dict[str, list[int | None]] = field(default_factory=lambda: defaultdict(list))
    # tls_handshake_incomplete : un ServerHello EST vu (la negociation a
    # bien commence des deux cotes), mais aucun enregistrement
    # application_data n'est jamais observe ensuite pour cette meme
    # connexion a ce meme point -- la negociation demarre puis
    # s'interrompt avant son terme (abandon client, certificat refuse,
    # middlebox qui coupe en cours de handshake).
    tls_handshake_incomplete: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    tls_handshake_incomplete_examples: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    tls_handshake_incomplete_frames: dict[str, list[int | None]] = field(default_factory=lambda: defaultdict(list))
    # -- debit / saturation / bufferbloat --
    throughput: dict[str, dict[int, int]] = field(default_factory=dict)
    # -- graphiques temporels top-N (voir netcross_core.correlate.compute_topn_series) :
    # dimension ("protocol"/"port"/"ip"/"dscp") -> point -> categorie -> bucket -> octets
    topn_timeseries: dict[str, dict[str, dict[str, dict[int, int]]]] = field(default_factory=dict)
    loss_event_buckets: dict[tuple[str, str], list[int]] = field(default_factory=lambda: defaultdict(list))
    latency_by_bucket: dict[tuple[str, str], dict[int, list[float]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(list))
    )
    saturation_verdict: dict[tuple[str, str], str] = field(default_factory=dict)
    bufferbloat_hint: dict[tuple[str, str], tuple[float, float]] = field(default_factory=dict)
    # -- fenetre TCP / ACK dupliques / RST / handshake --
    zero_window: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    dup_ack: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # -- signaux d'expertise TCP natifs tshark (tcp.analysis.*, issue #21) --
    # Compteurs par point, distincts des heuristiques retrans/dup_ack/
    # zero_window ci-dessus : exploitation directe de la classification
    # native de tshark (moteur d'etat TCP complet) pour mieux distinguer
    # perte reelle, reordonnancement, retransmission rapide et RTO. Source :
    # RawPacket.expert_flags (noms EK tcp_tcp_analysis_*). Complementaire et
    # non exclusif : un paquet hors-ordre (out_of_order) n'est PAS une
    # retransmission (conditions mutuellement exclusives cote tshark) --
    # ce compteur isole le reordonnancement des vraies pertes.
    out_of_order: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    lost_segment: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    window_update: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    rst_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    rst_localized: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    syn_no_synack: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    syn_reply_missing: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # Trous de sequence TCP (Job 42/issue #162) : octets jamais vus a un point de
    # capture alors que des octets posterieurs l'ont ete, sans retransmission
    # ulterieure -- alimente par netcross_core.forensic.detect_sequence_gaps.
    sequence_gaps: list[SequenceGap] = field(default_factory=list)
    # -- exploitation des alertes Expert Info pour la detection d'attaques
    # (issue #137, voir netcross_core.security.expert_correlation) --
    # expert_malformed : paquets malformes (dissecteur tshark en exception ou
    # condition du groupe natif Malformed), PAR POINT puis PAR PROTOCOLE
    # ("HTTP", "DNS", "TLS", "SMB", "OTHER"). expert_malformed_flows : meme information PAR
    # FLUX (liste de dicts triee, un par flux bidirectionnel portant au moins
    # un paquet malforme, avec numeros de trame en preuve).
    expert_malformed: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    expert_malformed_flows: list[dict] = field(default_factory=list)
    # exploit_suspicion : nombre de suspicions levees (un flux, ou un couple
    # source -> destination pour "dos"), PAR POINT puis PAR CLASSIFICATION
    # ("fuzzing", "overflow", "dos").
    # exploit_suspicion_flows : le detail (flux, classification, compteur,
    # preuve) de chaque suspicion levee. Une suspicion est un INDICE a
    # confirmer, jamais un diagnostic definitif -- voir la docstring du module.
    exploit_suspicion: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    exploit_suspicion_flows: list[dict] = field(default_factory=list)
    # -- decalage d'horloge (via handshakes TCP, hypothese de chemin symetrique) --
    clock_offset_samples: dict[tuple[str, str], list[float]] = field(default_factory=lambda: defaultdict(list))
    clock_offset_estimate: dict[tuple[str, str], tuple[float, float, int]] = field(default_factory=dict)
    # -- VLAN 802.1Q --
    vlan_seen: dict[str, set[int]] = field(default_factory=lambda: defaultdict(set))
    vlan_change: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    vlan_tag_flip: dict[tuple[str, str], dict[str, int]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(int))
    )
    pcp_change: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    # -- encapsulation / tunnels --
    encap_seen: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    encap_change: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    encap_change_examples: dict[tuple[str, str], list[str]] = field(default_factory=lambda: defaultdict(list))
    encap_frag_correlated: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    # -- RTP (voix/visio) --
    rtp_streams: list[dict] = field(default_factory=list)
    # -- VoIP orientee appel (Job 24 / §6.12) --
    voip_calls: list[dict] = field(default_factory=list)
    voip_quality_distribution: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # -- decomposition reseau vs serveur --
    server_think_time: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    # -- DHCP --
    dhcp_msg_count: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    dhcp_nak_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    dhcp_server_seen: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    dhcp_missing: dict[tuple[str, str], list[str]] = field(default_factory=lambda: defaultdict(list))
    dhcp_duration_ms: list[float] = field(default_factory=list)
    # -- SIP --
    sip_msg_count: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    sip_agents_seen: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    sip_missing: dict[tuple[str, str], list[str]] = field(default_factory=lambda: defaultdict(list))
    sip_setup_duration_ms: list[float] = field(default_factory=list)
    sip_failed_calls: list[str] = field(default_factory=list)
    # -- DNS (voir _analyse_dns) --
    dns_query_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    dns_response_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    dns_nxdomain_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    dns_servfail_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    dns_missing: dict[tuple[str, str], list[str]] = field(default_factory=lambda: defaultdict(list))
    dns_timeout: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    # Numero de trame (Pkt.frame_number) de la requete DNS jamais suivie de
    # reponse, meme index/plafond -- PacketEvidence (Session 37).
    dns_timeout_frames: dict[str, list[int | None]] = field(default_factory=lambda: defaultdict(list))
    dns_duration_ms: list[float] = field(default_factory=list)
    # -- HTTP/1.x (voir _analyse_http) --
    http_request_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    http_response_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    http_status_count: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    http_client_error_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))  # 4xx
    http_server_error_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))  # 5xx
    http_error_examples: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    # Numero de trame (Pkt.frame_number) de la reponse d'erreur, meme
    # index/plafond que http_error_examples -- PacketEvidence (Session 37).
    # Filtre 4xx/5xx applique au meme moment que _http_error_evidence (voir
    # synthesis.py/baseline_diff.py), sur cet index partage.
    http_error_frames: dict[str, list[int | None]] = field(default_factory=lambda: defaultdict(list))
    http_missing: dict[tuple[str, str], list[str]] = field(default_factory=lambda: defaultdict(list))
    http_timeout: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    # Numero de trame (Pkt.frame_number) de la requete jamais suivie de
    # reponse, meme index/plafond -- PacketEvidence (Session 37).
    http_timeout_frames: dict[str, list[int | None]] = field(default_factory=lambda: defaultdict(list))
    # calcule nativement par tshark (http.time), pas recompose a la main
    # comme dns_duration_ms -- voir _analyse_http
    http_response_time_ms: list[float] = field(default_factory=list)
    # -- doublons inter-captures (Job 41/issue #161, voir
    # netcross_core.forensic.detect_cross_capture_duplicates) : nombre de
    # paquets marques is_duplicate par paire de points NON ORDONNEE (tuple
    # trie alphabetiquement -- meme paire quel que soit le point qui a vu le
    # paquet en premier, sinon un port miroir dont l'ordre d'arrivee varie
    # eclaterait le compte sur (A, B) et (B, A)). Vide si la detection n'a
    # pas ete demandee.
    duplicate_count: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    # True si analyse() a ete appelee avec exclude_duplicates=True : les
    # doublons ci-dessus sont alors ABSENTS de tous les autres compteurs de
    # ce Report (debit, flux, pertes...) ; False -> ils y sont comptes.
    duplicates_excluded: bool = False
    # -- gestion memoire sur gros PCAP (issue #283, Etape 3) : renseignes par
    # l'appelant (CLI, voir cross_capture_analyzer_cli.py) AVANT correlate()/
    # analyse(), jamais par analyse() elle-meme -- meme discipline que
    # capture_comments/capture_infos ci-dessus (metadonnee sur la PORTEE de
    # l'analyse, pas sur son contenu). `truncated` est True si --max-packets
    # ou --sample a reellement limite le nombre de paquets analyses (jamais
    # True si le fichier avait de toute facon moins de paquets que la
    # limite demandee) ; `truncation_note` porte alors le texte a
    # destination du lecteur du rapport, ex: "analyse limitee aux 2 000 000
    # premiers paquets sur 18 300 000 -- les constats ne couvrent que les 4
    # premieres minutes de la capture." Une troncature silencieuse
    # produirait un rapport FAUX (l'analyste croirait couvrir toute la
    # capture) : plus grave qu'un simple echec, voir le constat de l'issue.
    truncated: bool = False
    truncation_note: str = ""
    # -- objets applicatifs HTTP (Job 25), metadonnees uniquement
    http_objects: list[dict] = field(default_factory=list)
    # -- fichiers extraits (SCENARIO-4, issue #150) : métadonnées des fichiers
    # transmis dans les flux réseau (HTTP, email, SMB, FTP). Un dict par
    # fichier, cles `point`, `proto_source`, `src`, `dst`, `ts`, `uri`,
    # `content_type`, `size`, `hash_md5`, `hash_sha256`, `type_detected`,
    # `frame_number`. Rempli par `extract.carver.detect_extracted_files`.
    extracted_files: list[dict] = field(default_factory=list)
    # -- transactions applicatives (Job 23, §6.9/§6.10)
    application_transactions: list[dict] = field(default_factory=list)
    # -- securite / detection passive de vulnerabilites (CVE-5, issue #139,
    # parent #133). Deux listes de dicts a plat, sur le modele de
    # http_objects/application_transactions ci-dessus, alimentees par les
    # modules CVE-1 a CVE-4 (fingerprinting de versions, signatures
    # d'exploits, alertes Expert Info, correlation CVE) et consommees par
    # netcross_report.security_report -- le rapport consolide ne detecte
    # rien lui-meme, il ne fait que regrouper et classer. Vides par defaut :
    # tant qu'aucun module amont ne les renseigne, le rapport de securite
    # est vide (jamais de constat invente).
    #
    # service_fingerprints : un dict par service detecte, cles `service`
    # (obligatoire), `version`, `host`, `port`, `point`.
    service_fingerprints: list[dict] = field(default_factory=list)
    # security_findings : un dict par constat, cles `severity`
    # (critique/elevee/moyenne/faible), `category` (exploit/anomalie/cve),
    # `detail` ; pour une CVE, egalement `cve_id` et `cvss` ; `service`,
    # `version`, `host`, `port`, `point` quand ils sont connus (ils
    # servent a rattacher une CVE a un service detecte).
    security_findings: list[dict] = field(default_factory=list)
    # -- exfiltration (SCENARIO-2, issue #148) : un dict par flux sortant
    # suspect, cles `point`, `src`, `dst`, `signals`, `upload_bytes`,
    # `download_bytes`, `volume_bytes`, `ratio` (None si aucun retour),
    # `score` (0-100), `severity`, `first_ts`, `last_ts`, `frames`. Rempli par
    # `security.findings.apply_security_findings` via
    # `security.exfiltration.detect_exfiltration` puis
    # `correlate_exfiltration` (beaconing #147, tunneling DNS #144).
    exfiltration_alerts: list[dict] = field(default_factory=list)
    # -- mismatches de protocole/flux (FLOW-1, issue #142) : un protocole
    # applicatif detecte sur un port non standard (SSH sur 443, HTTP sur 22,
    # DNS sur 443, tunneling ICMP). `protocol_mismatches` : compteur par
    # protocole detecte puis par description ; `protocol_mismatch_details` :
    # liste des occurrences individuelles (frame, ports, proto).
    protocol_mismatches: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(dict))
    protocol_mismatch_details: list[dict] = field(default_factory=list)
    # -- DGA et fast flux (SCENARIO-6, issue #152) : alertes de domaines
    # malveillants generes algorithmiquement (DGA) et d'infrastructures
    # a flux rapide (fast flux). `dga_alerts` : un dict par domaine suspect,
    # cles `domain`, `score`, `reason`, `entropy`, `consonant_ratio`,
    # `rare_bigram_ratio`, `length`, `nxdomain_ratio`, `point`.
    # `fast_flux_alerts` : un dict par domaine suspect, cles `domain`,
    # `alert_type`, `score`, `reason`, `ips`, `nxdomain_ratio`, `point`.
    # Remplis par `security.findings.apply_security_findings` via
    # `security.dga.detect_dga` et `security.fast_flux.detect_fast_flux`.
    dga_alerts: list[dict] = field(default_factory=list)
    fast_flux_alerts: list[dict] = field(default_factory=list)
    # -- mouvements lateraux (SCENARIO-3, issue #149) : un dict par evenement
    # detecte, cles `point`, `source`, `type` (port_scan | host_scan |
    # brute_force | unusual_protocol | new_connection), `details`, `score`,
    # `targets`. Rempli par `security.findings.apply_security_findings` via
    # `security.lateral_movement.detect_lateral_movement`.
    lateral_movement_events: list[dict] = field(default_factory=list)
    # -- plugins (issue #284) : une ligne de tracabilite par plugin demande
    # (detecteur/exporteur ; ok, aucun constat, erreur, refuse...), cles
    # `plugin`, `kind`, `status`, `reason`, `line`. Rempli par
    # `plugins.runner.run_detectors` / `run_exporters`.
    plugin_runs: list[dict] = field(default_factory=list)
    # -- statistiques de flux (FLOW-4, issue #145) : un dict par flux
    # analyse, cles `src`, `dst`, `packet_count`, `byte_count`, `splt`,
    # `classification` (interactif/transfert/obfusque/normal), `entropy`,
    # `median_size`, `upload_ratio`, `regularity_cv`. Rempli par
    # `security.findings.apply_security_findings` via
    # `security.flow_stats.analyze_flow_stats`.
    flow_anomalies: list[dict] = field(default_factory=list)
    # -- inventaire d'actifs (issue #350) : un dict par hote detecte,
    # cles `ip`, `mac`, `ports`, `os_guess`, `is_new`... Rempli par
    # `security.findings.apply_security_findings` via
    # `discovery.assets.build_asset_inventory`.
    asset_inventory: list[dict] = field(default_factory=list)
    # Issue #350 : taille de la baseline d'hotes connus passee a
    # l'inventaire (--known-hosts) ; 0 = pas de baseline, donc aucun hote
    # n'est marque nouveau (`is_new` toujours False).
    asset_baseline_size: int = 0
    # -- topologie deduite (ordre + chemins multiples) --
    topology_edges: list[tuple[str, str, dict]] = field(default_factory=list)
    topology_ambiguous: list[tuple[str, str, str]] = field(default_factory=list)
    topology_isolated: list[str] = field(default_factory=list)
    topology_branch_points: list[str] = field(default_factory=list)
    topology_merge_points: list[str] = field(default_factory=list)
    topology_order_conflicts: list[str] = field(default_factory=list)
    topology_used_for_order: bool = False
    # -- commentaires pcapng (Job 39, issue #159) -- annotations operateur
    # facultatives portees par le format pcapng, absentes par construction
    # du pcap classique. Deux champs distincts, deux origines distinctes :
    # capture_comments : commentaire de SECTION (Section Header Block, un
    #   par fichier source qui en porte un, prefixe "label : texte") --
    #   metadonnee du FICHIER, pas d'un paquet, donc PAS remplie par
    #   analyse() ci-dessous (qui ne recoit jamais les chemins de fichiers,
    #   seulement des Pkt deja construits) -- remplie par l'appelant (CLI,
    #   voir cross_capture_analyzer_cli.py) via netcross_core.parsing.
    #   read_capture_comments(captures), AVANT print_report().
    # packet_comments : commentaire de PAQUET (Enhanced Packet Block,
    #   Pkt.comment, prefixe "point — trame N : texte") -- celui-la EST
    #   rempli par analyse() a partir de all_packets, deja pre-formate
    #   pour l'affichage : contrairement a capture_comments, aucun fichier
    #   a relire, l'information est deja portee par chaque Pkt.
    capture_comments: list[str] = field(default_factory=list)
    packet_comments: list[str] = field(default_factory=list)
    # -- Metadonnees de capture (Job 38/issue #158) -- qualite de la
    # capture elle-meme (format, snaplen, paquets perdus...), pas le
    # contenu du trafic. Meme discipline que capture_comments : metadonnee
    # de FICHIER, pas de paquet, donc remplie par l'appelant (CLI) via
    # netcross_core.parsing.read_capture_infos(captures), AVANT
    # print_report(). Vide si capinfos est absent ou si la capture ne
    # porte aucune metadonnee (cas le plus frequent).
    capture_infos: list[dict] = field(default_factory=list)
    # -- Integrite/qualite de capture (Job 43/issue #163) -- voir
    # netcross_core.forensic.validate_checksums().
    checksum_errors: list[ChecksumError] = field(default_factory=list)


@dataclass(slots=True)
class PacketAnnotation:
    """Etiquette/signet pose par l'analyste sur un paquet ou un groupe de
    paquets (Job 40/issue #160, §Metadonnees et annotation).

    Persistee dans un fichier sidecar JSON a cote de la capture (voir
    `netcross_core.forensic.read_annotations`/`write_annotations`) -- ne
    fait PAS partie du `Report` : contrairement aux champs ci-dessus,
    calcules par l'analyse, une annotation est saisie manuellement par
    l'analyste et doit survivre a une reanalyse (donc stockee a part,
    jamais recalculee).

    `frame_number` seul (pas de `point`) : le sidecar est associe a UNE
    capture d'UN point (meme convention que `RawPacket`/`Pkt.frame_number`
    cote pcap_parser) -- annoter un paquet vu depuis plusieurs points
    demande donc une annotation par point, ce qui correspond a l'usage
    (l'analyste ouvre la capture d'un point donne pour annoter).
    """

    frame_number: int
    tag: str
    comment: str = ""
    color: str | None = None


@dataclass(frozen=True)
class BPFFilter:
    """Filtre BPF (libpcap) nomme, reutilisable en capture live (Job 47).

    ``expression`` est transmise telle quelle a tshark (``-f``) : aucune
    validation de syntaxe n'est faite ici (elle exige libpcap, voir
    ``netcross_core.bpf_filters``). ``name`` identifie le filtre dans les
    listes deroulantes et le fichier de sauvegarde ; ``description`` est
    libre et optionnelle (aide contextuelle).
    """

    name: str
    expression: str
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            logger.debug("BPFFilter.__post_init__: si not self.name.strip() -> levée ValueError")
            raise ValueError("BPFFilter: 'name' est requis")
        if not self.expression.strip():
            logger.debug("BPFFilter.__post_init__: si not self.expression.strip() -> levée ValueError")
            raise ValueError("BPFFilter: 'expression' est requise")
        logger.debug("BPFFilter.__post_init__: fin")
