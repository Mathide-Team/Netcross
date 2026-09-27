"""
netcross_core.wireshark_expert -- Session 1 de FEATURES.md section 13.3
("exploitation de l'expertise Wireshark/TShark") : convertit les signaux
d'expertise BRUTS deja produits par le moteur de dissection de tshark
(champs "_ws.expert", exposes cote pcap_parser via
ek_fields.expert_flag_names/expert_flag_details -- generalisation de
has_expert_flag, qui ne testait jusqu'ici que trois noms de flags TCP
connus un par un, voir Pkt.expert_flags/expert_details et
RawPacket.expert_flags/expert_details) en ExpertEvent de source
"tshark".

Principe directeur (FEATURES.md section 13.3, Session 1) : "Il ne faut
pas considerer les signaux Wireshark comme des diagnostics definitifs.
Ils constituent des preuves supplementaires pour le moteur Netcross."
Ce module ne fait donc AUCUNE correlation et AUCUNE deduction de cause/
impact (cause/impact restent toujours None, comme pour tout ExpertEvent
-- voir expert_model.py) : il se contente de regrouper et de nommer les
signaux que tshark a deja identifies pendant sa propre dissection, un
ExpertEvent par (point de capture, nom de flag) distinct.

Volontairement independant des detecteurs Netcross existants
(_analyse_retransmission_types, etc.) : un flag tshark deja exploite par
un detecteur Netcross dedie (ex: tcp.analysis.retransmission, deja
classifie fast/RTO/spurious par _analyse_retransmission_types) continue
d'apparaitre ICI AUSSI, sous sa forme brute -- ce n'est pas une
duplication a eliminer mais precisement la distinction visee par la
Session 1 : le Finding Netcross ("retrans_fast") est un diagnostic deja
categorise et priorise ; l'ExpertEvent tshark brut ("tcp.analysis.
retransmission vu N fois a ce point") est la preuve source, moins
interpretee mais plus proche de ce qu'afficherait le panneau Expert
Info de Wireshark lui-meme. Les deux sont exposes separement (cles JSON
distinctes cote netcross_report.json_report), jamais fondus dans la
meme liste -- un consommateur ne doit jamais confondre un diagnostic
deja priorise avec un signal brut moins interprete.

Severite/groupe/message NATIFS tshark (second lot de cette Session 1,
voir claude.md Session 39) : ce module lit desormais aussi la severite
et le message natifs de chaque occurrence (Pkt.expert_details, voir
_lookup_native_detail ci-dessous) -- limite initiale levee (le premier
lot de cette session, Session 38, ne demandait/lisait pas encore ces
deux champs). La severite NATIVE (traduite en vocabulaire Netcross via
_NATIVE_TO_NETCROSS_SEVERITY) est PRIORITAIRE sur la table `_KNOWN_FLAGS`
ci-dessous des qu'elle est disponible ; `_KNOWN_FLAGS` reste le repli
pour les paquets sans expert_details (ancien format anterieur a cette
session, ou -- cas jamais rencontre en pratique -- une occurrence sans
son champ severite). Le message natif, potentiellement PARAMETRE par
paquet (ex: "Bad checksum [should be 0x8cfa]", la valeur attendue
variant d'un paquet a l'autre) plutot que fixe par flag, est ajoute a
l'EVIDENCE de chaque exemple (pas au message agrege de l'ExpertEvent,
qui reste construit a partir du seul nom de flag comme avant) -- une
severite/un groupe sont en revanche des proprietes constantes du type de
condition (definies une fois pour toutes cote dissecteur tshark, jamais
au niveau du paquet), sans ce risque de non-representativite.

Plus limite a la couche TCP (leve dans cette meme session, voir
pcap_parser.packet : expert_flags/expert_details sont desormais une
union sur toutes les couches du paquet).

Confiance / premiere-derniere occurrence (Session 40, premier lot de la
Session 2 de la section 13.3 -- "moteur d'evenements d'expertise") : ce
module est desormais la SEULE implementation concrete de
`ExpertEvent.confidence`/`first_seen`/`last_seen` (voir expert_model.py
pour le contrat complet et pourquoi ils restent `None` cote source
"netcross"). `confidence` reflete la nature de la donnee source, pas une
probabilite calibree -- trois niveaux discrets (voir `_confidence_for`
ci-dessous) : 1.0 quand la severite NATIVE tshark est disponible pour ce
(point, flag) (classification faite par le dissecteur lui-meme), 0.7
quand le flag est seulement connu de `_KNOWN_FLAGS` (table maintenue a la
main par ce projet, jamais verifiee par tshark), 0.4 sinon (nom de champ
EK jamais vu, severite de repli `_DEFAULT_SEVERITY`). `first_seen`/
`last_seen` sont le min/max de `pk.ts` sur TOUTES les occurrences d'un
(point, flag), pas seulement les `_MAX_EXAMPLES` exemples conserves dans
`evidence` -- calcules dans la meme boucle que `counts` ci-dessous
(deja parcourue en integralite pour le compteur d'occurrences, aucun
cout de parcours supplementaire).

Couche reseau / protocole (Session 41, deuxieme lot de la Session 2 de la
section 13.3) : ce module est egalement la SEULE implementation concrete
de `ExpertEvent.layer`/`protocol` (voir expert_model.py pour le contrat
complet et pourquoi ils restent `None` cote source "netcross"). Un nom de
flag EK brut est TOUJOURS construit comme "{cle_couche}_{nom_de_champ}"
(voir pcap_parser.ek_fields et l'exemple "tcp_tcp_srcport" pour "tcp.
srcport" plus haut) ; `cle_couche` est l'une des huit cles EK reellement
lues par `pcap_parser.packet` pour construire `Pkt.expert_flags`/
`expert_details` ("ip", "ipv6", "arp", "stp", "tcp", "udp", "icmp",
"icmpv6" -- voir pcap_parser.tunnels.select_innermost_layers), et aucune
de ces huit cles ne contient elle-meme de underscore : `flag_name.
split("_", 1)[0]` isole donc TOUJOURS `cle_couche` exactement, une
propriete STRUCTURELLE de la convention EK deja documentee plus haut dans
ce module, jamais une supposition. `_LAYER_AND_PROTOCOL` traduit cette
cle en (couche OSI, nom de protocole) -- voir `_layer_and_protocol_for`
ci-dessous. Une cle absente de la table (aucune des huit ne devrait
jamais l'etre en pratique, `_expert_layers` dans pcap_parser.packet etant
un ensemble ferme) retombe sur `(None, None)`, jamais une supposition --
meme discipline defensive que `_flag_label`/`_flag_severity` pour un nom
de flag inconnu de `_KNOWN_FLAGS`.

Flux concernes (Session 43, troisieme lot de la Session 2 de la section
13.3) : ce module est egalement la SEULE implementation concrete
d'`ExpertEvent.flow_keys` (voir expert_model.py pour le contrat complet
et pourquoi il reste `[]` cote source "netcross"). Reutilise directement
`netcross_core.correlate.flow_key()` -- aucune nouvelle notion d'identite
de flux -- applique a CHAQUE paquet porteur du signal, pas seulement aux
exemples plafonnes conserves dans `evidence` (meme discipline que
`first_seen`/`last_seen`, Session 40). Dedoublonne dans l'ordre de
premiere rencontre (voir docstring d'`ExpertEvent.flow_keys` pour la
raison de ne PAS trier : `key_id`/`sport`/`dport` melangent `int` et
`None` selon le protocole du paquet).

Points/paquets concernes (Session 44, quatrieme lot de la Session 2 de
la section 13.3) : ce module est egalement la SEULE implementation
concrete d'`ExpertEvent.packet_evidence` (voir expert_model.py pour le
contrat complet et pourquoi il reste `[]` cote source "netcross"). Un
`PacketEvidence(point, frame_number)` par occurrence dont `pk.
frame_number` est disponible, sur CHAQUE paquet porteur du signal --
pas seulement les exemples plafonnes conserves dans `evidence` (meme
discipline que `first_seen`/`last_seen`/`flow_keys` ci-dessus). Aucune
deduplication necessaire : `pk.expert_flags` ne repete jamais le meme
nom de flag pour un meme paquet (voir pcap_parser.packet), donc chaque
(point, flag) ne visite un `pk` donne qu'une seule fois -- chaque numero
de trame n'apparait donc naturellement qu'une fois dans la liste.

Action de verification/remediation (Session 45, cinquieme et dernier lot
cote ExpertEvent de la Session 2 de la section 13.3) : ce module est
egalement la SEULE implementation concrete d'`ExpertEvent.remediation`
(voir expert_model.py pour le contrat complet et pourquoi il reste
`None` cote source "netcross"). Contrairement a tout ce qui precede
(confidence/layer/protocol/flow_keys/packet_evidence -- tous LUS depuis
une donnee deja disponible), `remediation` est un texte REDIGE par ce
projet, voir `_REMEDIATION` ci-dessous : une piste de verification
technique courte par flag deja connu de `_KNOWN_FLAGS`, jamais une
supposition pour un flag absent de cette table (`_remediation_for`
retourne alors `None`, meme discipline defensive que `_flag_label`/
`_flag_severity`). Constant pour un flag donne (propriete du TYPE de
signal, pas d'une occurrence individuelle) : calcule une seule fois par
(point, flag), comme `layer`/`protocol`.

Sur le libelle lisible (`label` dans `_KNOWN_FLAGS`) : une premiere
version de ce module tentait de le RECONSTRUIRE algorithmiquement depuis
le nom de champ EK brut ("tcp_tcp_analysis_fast_retransmission" ->
retirer le premier segment, rejoindre le reste par des points). Ce
raisonnement est FAUX en general : la convention EK remplace les points
du nom de champ tshark par des underscores, mais plusieurs noms de
champ tshark contiennent eux-memes un underscore dans leur DERNIER
segment ("tcp.analysis.fast_retransmission", "tcp.analysis.
zero_window"...) -- rien dans le nom EK ne distingue un underscore qui
etait un point de celui qui appartenait deja au nom. Reconstruire
"tcp.analysis.fast.retransmission" (FAUX, un point en trop) etait donc
un bug, pas juste une approximation ratée -- decouvert par
test_wireshark_expert.py, voir claude.md. La seule reconstruction
fiable est une table explicite, flag connu par flag connu (comme la
severite ci-dessus) : `_KNOWN_FLAGS` porte les deux ensemble. Pour un
flag ABSENT de la table (nouveau nom introduit par une version future
de tshark), le nom EK brut est affiche tel quel plutot qu'une
reconstruction devinee qui pourrait a nouveau etre fausse -- moins
lisible, jamais trompeur (la severite NATIVE, quand disponible, reste
elle correcte meme pour un flag absent de cette table -- voir plus
haut).
"""

from __future__ import annotations

from netcross_core.correlate import flow_key
from netcross_core.expert_model import EvidenceLink, ExpertEvent, PacketEvidence
from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

# Flags tshark deja identifies par ce projet : (libelle lisible exact,
# severite Netcross de REPLI -- vocabulaire Finding.severity, utilisee
# seulement quand aucune severite NATIVE tshark n'est disponible pour ce
# flag, voir _NATIVE_TO_NETCROSS_SEVERITY/_lookup_native_detail plus bas
# et la docstring de module). Un flag absent de cette table (tshark en
# introduit regulierement de nouveaux au fil de ses versions) n'a pas de
# libelle fiable ni, EN L'ABSENCE de severite native, de severite fiable
# non plus : voir _flag_label()/_DEFAULT_SEVERITY ci-dessous, jamais une
# supposition.
_KNOWN_FLAGS: dict[str, tuple[str, str]] = {
    "tcp_tcp_analysis_retransmission": ("tcp.analysis.retransmission", "info"),
    "tcp_tcp_analysis_fast_retransmission": ("tcp.analysis.fast_retransmission", "info"),
    "tcp_tcp_analysis_spurious_retransmission": ("tcp.analysis.spurious_retransmission", "a_surveiller"),
    "tcp_tcp_analysis_lost_segment": ("tcp.analysis.lost_segment", "anomalie"),
    "tcp_tcp_analysis_ack_lost_segment": ("tcp.analysis.ack_lost_segment", "anomalie"),
    "tcp_tcp_analysis_duplicate_ack": ("tcp.analysis.duplicate_ack", "info"),
    "tcp_tcp_analysis_zero_window": ("tcp.analysis.zero_window", "anomalie"),
    "tcp_tcp_analysis_window_full": ("tcp.analysis.window_full", "a_surveiller"),
    "tcp_tcp_analysis_keep_alive": ("tcp.analysis.keep_alive", "info"),
    "tcp_tcp_analysis_out_of_order": ("tcp.analysis.out_of_order", "a_surveiller"),
    "tcp_tcp_analysis_reused_ports": ("tcp.analysis.reused_ports", "info"),
}
_DEFAULT_SEVERITY = "info"  # flag inconnu de la table -- jamais surestime

# Meme plafond que les champs Report.*_examples ailleurs dans ce projet
# (pmtud_blackhole_examples, arp_ip_conflict_examples...) : assez
# d'exemples pour illustrer sans faire exploser la taille du JSON sur un
# flux tres bavard.
_MAX_EXAMPLES = 5


def _flag_label(flag_name: str) -> str:
    """Libelle lisible pour un nom de champ EK brut. Flag connu de
    `_KNOWN_FLAGS` -> libelle exact de la table. Flag inconnu -> le nom
    EK brut, INCHANGE (voir docstring de module : une reconstruction
    algorithmique generique s'est averee fausse dans le cas general,
    mieux vaut un nom brut moins lisible qu'un nom invente incorrect)."""
    known = _KNOWN_FLAGS.get(flag_name)
    logger.debug("_flag_label: retour conditionnel")
    return known[0] if known else flag_name


def _flag_severity(flag_name: str) -> str:
    """Severite Netcross estimee pour ce nom de champ EK brut -- voir
    `_KNOWN_FLAGS`/`_DEFAULT_SEVERITY` ci-dessus pour le detail des deux
    limites (pas la severite native tshark, jamais surestimee si le flag
    est inconnu de la table)."""
    known = _KNOWN_FLAGS.get(flag_name)
    logger.debug("_flag_severity: retour conditionnel")
    return known[1] if known else _DEFAULT_SEVERITY


# Piste de verification/remediation par flag deja connu de _KNOWN_FLAGS --
# Session 45, cinquieme et dernier lot cote ExpertEvent de la Session 2 de
# la section 13.3 (voir expert_model.ExpertEvent.remediation et la
# docstring de module ci-dessus pour la justification complete). Texte
# REDIGE, volontairement court (une a deux phrases) : une piste de
# verification technique pour un analyste humain, jamais une affirmation
# de cause/impact definitive (ceux-ci restent la matiere de la Session 3,
# absente aujourd'hui). Volontairement restreint aux onze flags deja
# repertories ci-dessus -- un flag absent de cette table n'a PAS de
# remediation par defaut (voir _remediation_for), a la difference de
# _flag_severity qui retombe sur _DEFAULT_SEVERITY : il n'existe pas
# d'equivalent "prudent" pour un conseil de verification, seulement
# "aucun conseil" quand la nature exacte du signal n'est pas etablie.
_REMEDIATION: dict[str, str] = {
    "tcp_tcp_analysis_retransmission": (
        "Retransmission isolee generalement benigne. Si le taux depasse "
        "quelques pourcents sur ce flux, comparer les points de capture "
        "pour localiser le segment de chemin responsable (perte reseau, "
        "congestion) et verifier le RTT et la taille de fenetre."
    ),
    "tcp_tcp_analysis_fast_retransmission": (
        "Recuperation TCP normale declenchee par trois ACK dupliques, pas "
        "une anomalie en soi. Une recurrence elevee indique des pertes "
        "regulieres sur le chemin -- correler avec tcp.analysis."
        "duplicate_ack sur le meme flux."
    ),
    "tcp_tcp_analysis_spurious_retransmission": (
        "Le segment retransmis s'est revele inutile (l'original est "
        "finalement arrive) -- souvent une estimation de RTO trop "
        "agressive ou une forte variance de latence (gigue) sur le "
        "chemin. Verifier la stabilite du RTT entre les points de "
        "capture avant de conclure a un dysfonctionnement applicatif."
    ),
    "tcp_tcp_analysis_lost_segment": (
        "Segment attendu jamais vu a ce point de capture. Comparer avec "
        "les points en amont/aval pour localiser le segment de chemin qui "
        "perd le paquet (lien sature, filtrage, probleme de MTU/"
        "fragmentation) plutot que d'incriminer directement l'hote final."
    ),
    "tcp_tcp_analysis_ack_lost_segment": (
        "L'ACK confirmant un segment perdu n'a pas ete observe -- signal "
        "de perte cote retour, a traiter comme tcp.analysis.lost_segment "
        "mais dans le sens inverse du flux. Verifier en priorite le "
        "segment de chemin du sens retour."
    ),
    "tcp_tcp_analysis_duplicate_ack": (
        "Indicateur normal de reordonnancement ou de perte en cours de "
        "detection cote TCP ; un ACK duplique isole n'appelle aucune "
        "action. Une accumulation rapide (>= 3) precede typiquement une "
        "retransmission rapide deja visible separement."
    ),
    "tcp_tcp_analysis_zero_window": (
        "Le recepteur annonce une fenetre nulle : il ne peut plus "
        "accepter de donnees, generalement parce que l'application cote "
        "recepteur ne consomme pas assez vite le tampon socket. Verifier "
        "la charge CPU/IO de l'hote recepteur et la taille du tampon de "
        "reception avant d'incriminer le reseau."
    ),
    "tcp_tcp_analysis_window_full": (
        "La fenetre d'envoi annoncee par le recepteur est desormais "
        "pleine cote emetteur -- souvent un prelude a une fenetre nulle "
        "si la tendance se confirme. Surveiller l'evolution et verifier "
        "le debit d'ecoulement cote application receptrice."
    ),
    "tcp_tcp_analysis_keep_alive": (
        "Segment de maintien de connexion, comportement normal d'une "
        "connexion inactive. Aucune action requise sauf frequence "
        "anormalement elevee, qui indiquerait un intervalle mal "
        "configure cote application ou une middlebox NAT/pare-feu "
        "agressive sur les timeouts."
    ),
    "tcp_tcp_analysis_out_of_order": (
        "Paquet recu hors sequence. Isole, effet courant d'un leger "
        "reordonnancement reseau sans impact applicatif notable (buffer "
        "de reassemblage TCP). Une recurrence elevee doit faire "
        "suspecter un ECMP/repartition de charge asymetrique ou un lien "
        "sature introduisant un reordonnancement systematique."
    ),
    "tcp_tcp_analysis_reused_ports": (
        "Reutilisation rapide d'un couple adresse/port par une nouvelle "
        "connexion TCP (TIME_WAIT recycle), normale sous forte charge de "
        "connexions courtes. Verifier le parametrage de reutilisation de "
        "socket cote application si le volume de connexions est tres "
        "eleve et que TIME_WAIT devient un facteur limitant."
    ),
}


def _remediation_for(flag_name: str) -> str | None:
    """Piste de verification/remediation pour ce nom de champ EK brut --
    `None` si le flag est absent de `_REMEDIATION` (voir la table
    ci-dessus pour la justification : pas d'equivalent "prudent" a un
    conseil de verification, contrairement a `_flag_severity`)."""
    logger.debug("_remediation_for: retour get(...)")
    return _REMEDIATION.get(flag_name)


# Couche OSI / nom de protocole pour chacune des HUIT cles EK reellement
# lues par pcap_parser.packet pour construire Pkt.expert_flags/
# expert_details (voir pcap_parser.tunnels.select_innermost_layers) --
# Session 41, deuxieme lot de la Session 2 de la section 13.3 (voir
# docstring de module pour la justification complete : ces huit cles
# sont un ensemble FERME, et aucune ne contient elle-meme de underscore,
# donc flag_name.split("_", 1)[0] isole toujours exactement l'une
# d'elles). "liaison"/"reseau"/"transport" : les trois seules couches OSI
# que ce module peut aujourd'hui distinguer sans ambiguite -- pas les
# sept couches completes du modele OSI.
_LAYER_AND_PROTOCOL: dict[str, tuple[str, str]] = {
    "arp": ("liaison", "ARP"),
    "stp": ("liaison", "STP"),
    "ip": ("reseau", "IPv4"),
    "ipv6": ("reseau", "IPv6"),
    "icmp": ("reseau", "ICMP"),
    "icmpv6": ("reseau", "ICMPv6"),
    "tcp": ("transport", "TCP"),
    "udp": ("transport", "UDP"),
}


def _layer_and_protocol_for(flag_name: str) -> tuple[str | None, str | None]:
    """(couche, protocole) pour ce nom de champ EK brut, lus depuis son
    prefixe de couche (voir `_LAYER_AND_PROTOCOL`/docstring de module).
    `(None, None)` si le prefixe ne correspond a aucune des huit cles
    connues -- ne devrait jamais arriver en pratique (`_expert_layers`
    dans pcap_parser.packet est le meme ensemble ferme), mais un repli
    honnete plutot qu'un KeyError ou une supposition, meme discipline que
    `_flag_label`/`_flag_severity` pour un flag inconnu de `_KNOWN_FLAGS`."""
    prefix = flag_name.split("_", 1)[0]
    found = _LAYER_AND_PROTOCOL.get(prefix)
    logger.debug("_layer_and_protocol_for: retour conditionnel")
    return found if found is not None else (None, None)


# Traduction severite NATIVE tshark (voir ek_fields._SEVERITY_LABELS,
# valeurs authentiques "tshark -G values" 4.2.2) -> vocabulaire Netcross
# (Finding.severity). Error est sans ambiguite le niveau le plus grave
# de Wireshark -> anomalie ; Warning, intermediaire -> a_surveiller ;
# Note/Chat/Comment, les trois niveaux purement informatifs de Wireshark
# (aucune anomalie impliquee -- ex: Chat couvre le suivi de conversation
# TCP lui-meme, SYN/SYN-ACK observes lors de la validation empirique de
# cette session, voir claude.md Session 39) -> info, la aussi sans
# ambiguite. Une valeur absente de cette table (native_severity=None,
# champ non present sur ce paquet, ou -- jamais rencontre en pratique --
# un libelle non reconnu par _SEVERITY_LABELS) declenche le repli sur
# _flag_severity()/_KNOWN_FLAGS ci-dessus, jamais une valeur devinee ici.
_NATIVE_TO_NETCROSS_SEVERITY: dict[str, str] = {
    "Error": "anomalie",
    "Warning": "a_surveiller",
    "Note": "info",
    "Chat": "info",
    "Comment": "info",
}


def _confidence_for(flag_name: str, has_native_severity: bool) -> float:
    """Score de confiance (voir docstring de module) pour ce nom de champ
    EK brut : 1.0 des qu'une severite NATIVE tshark a ete trouvee pour ce
    (point, flag) (peu importe le flag -- la donnee native prime, meme
    raisonnement de priorite que _NATIVE_TO_NETCROSS_SEVERITY plus haut),
    0.7 si le flag est seulement connu de `_KNOWN_FLAGS`, 0.4 sinon
    (nom EK jamais vu par ce projet, aucune confirmation tshark non
    plus)."""
    if has_native_severity:
        logger.debug("_confidence_for: retour 1.0")
        return 1.0
    logger.debug("_confidence_for: retour conditionnel")
    return 0.7 if flag_name in _KNOWN_FLAGS else 0.4


def _lookup_native_detail(pk, flag_name: str) -> tuple[str | None, str | None, str | None]:
    """Cherche, dans pk.expert_details (voir ek_fields.expert_flag_details
    pour la provenance du 4-uplet), l'occurrence correspondant a
    flag_name -- (severite, groupe, message) NATIFS tshark si trouves,
    (None, None, None) sinon. "Sinon" couvre deux cas indistinguables ici
    et traites de la meme facon (repli) : un Pkt d'avant cette session
    (expert_details vide, ancien format) et -- jamais rencontre en
    pratique -- un flag present dans expert_flags mais absent de
    expert_details (les deux sont toujours calcules ensemble a partir
    des memes couches, voir pcap_parser.packet, donc structurellement
    synchronises)."""
    for name, severity, group, message in pk.expert_details:
        if name == flag_name:
            logger.debug("_lookup_native_detail: retour tuple")
            return severity, group, message
    logger.debug("_lookup_native_detail: retour tuple")
    return None, None, None


def build_wireshark_expert_events(all_packets) -> list[ExpertEvent]:
    """Un ExpertEvent par (point, flag) distinct rencontre dans
    all_packets -- jamais un par paquet individuel : un flux avec des
    centaines de retransmissions produirait sinon des centaines
    d'evenements quasi identiques, peu exploitables (meme raisonnement
    que le plafonnement des *_examples de Report ailleurs dans ce
    projet). `evidence` porte jusqu'a `_MAX_EXAMPLES` exemples, chacun
    rattache a un `PacketEvidence` quand `frame_number` est disponible
    (systematique avec un vrai tshark, voir pcap_parser.packet -- `None`
    reste tolere plutot que suppose).

    Liste vide si aucun paquet ne porte de signal d'expertise (cas le
    plus frequent en pratique) -- jamais `None`, meme convention que
    `build_flows`/`build_conversations` (netcross_core.correlate).

    Severite (voir _NATIVE_TO_NETCROSS_SEVERITY) : NATIVE tshark des
    qu'un exemple de ce (point, flag) la porte (constante par flag,
    definie une fois pour toutes cote dissecteur tshark -- le premier
    exemple qui la porte suffit, inutile de tous les parcourir), repli
    sur `_flag_severity`/`_KNOWN_FLAGS` sinon. Message natif -- lui
    potentiellement PARAMETRE par paquet, voir docstring de module --
    ajoute a l'evidence de CHAQUE exemple individuellement plutot qu'au
    message agrege ci-dessus, qui reste construit a partir du seul nom
    de flag comme avant cette session.

    Confiance (voir _confidence_for) et premiere/derniere occurrence
    (Session 40) : calculees sur la TOTALITE des occurrences de chaque
    (point, flag), pas seulement les exemples plafonnes conserves dans
    `evidence` -- voir docstring de module.

    Couche/protocole (voir _layer_and_protocol_for, Session 41) : lus une
    seule fois par (point, flag) depuis le prefixe du nom de flag lui-meme
    -- constants pour un flag donne, pas besoin de les recalculer par
    exemple.

    Flux concernes (Session 43) : `flow_key(pk)` (netcross_core.correlate)
    applique a TOUTES les occurrences d'un (point, flag), pas seulement
    les exemples plafonnes -- dedoublonne dans l'ordre de premiere
    rencontre, jamais trie (voir docstring de module).

    Points/paquets concernes (Session 44) : un `PacketEvidence(point, pk.
    frame_number)` par occurrence dont `pk.frame_number` est disponible,
    sur TOUTES les occurrences d'un (point, flag) -- pas seulement les
    exemples plafonnes conserves dans `evidence` (voir docstring de
    module).

    Remediation (Session 45, voir _remediation_for) : lue une seule fois
    par (point, flag) depuis `_REMEDIATION` -- constante pour un flag
    donne, comme layer/protocol, `None` pour tout flag absent de cette
    table."""
    # (point, flag) -> liste de Pkt exemples (plafonnee), compteur total,
    # min/max de pk.ts sur TOUTES les occurrences (Session 40), flux
    # concernes dedoublonnes dans l'ordre de premiere rencontre (Session 43),
    # PacketEvidence de TOUTES les occurrences avec frame_number (Session 44).
    logger.debug("build_wireshark_expert_events: all_packets={}", summarize(all_packets, "all_packets"))
    groups: dict[tuple[str, str], list] = {}
    counts: dict[tuple[str, str], int] = {}
    first_seen: dict[tuple[str, str], float] = {}
    last_seen: dict[tuple[str, str], float] = {}
    flow_keys: dict[tuple[str, str], list] = {}
    seen_flow_keys: dict[tuple[str, str], set] = {}
    packet_evidence: dict[tuple[str, str], list] = {}
    for pk in all_packets:
        for flag in pk.expert_flags:
            key = (pk.point, flag)
            counts[key] = counts.get(key, 0) + 1
            examples = groups.setdefault(key, [])
            if len(examples) < _MAX_EXAMPLES:
                examples.append(pk)
            if key not in first_seen or pk.ts < first_seen[key]:
                first_seen[key] = pk.ts
            if key not in last_seen or pk.ts > last_seen[key]:
                last_seen[key] = pk.ts
            fk = flow_key(pk)
            already_seen = seen_flow_keys.setdefault(key, set())
            if fk not in already_seen:
                already_seen.add(fk)
                flow_keys.setdefault(key, []).append(fk)
            if pk.frame_number is not None:
                packet_evidence.setdefault(key, []).append(PacketEvidence(point=pk.point, frame_number=pk.frame_number))

    events = []
    for (point, flag), examples in groups.items():
        label = _flag_label(flag)
        count = counts[(point, flag)]

        native_severity = None
        native_group = None
        for pk in examples:
            native_severity, native_group, _ = _lookup_native_detail(pk, flag)
            if native_severity is not None:
                break
        if native_severity in _NATIVE_TO_NETCROSS_SEVERITY:
            severity = _NATIVE_TO_NETCROSS_SEVERITY[native_severity]
        else:
            severity = _flag_severity(flag)
        confidence = _confidence_for(flag, has_native_severity=native_severity is not None)
        layer, protocol = _layer_and_protocol_for(flag)
        remediation = _remediation_for(flag)

        evidence = []
        for pk in examples:
            _, _, native_message = _lookup_native_detail(pk, flag)
            text = f"{pk.src}:{pk.sport} -> {pk.dst}:{pk.dport} ({label})"
            if native_message:
                text += f" -- {native_message}"
            evidence.append(
                EvidenceLink(
                    point=point,
                    text=text,
                    packet=(
                        PacketEvidence(point=point, frame_number=pk.frame_number)
                        if pk.frame_number is not None
                        else None
                    ),
                )
            )

        message = f"{label} : {count} occurrence(s) (signal brut tshark, pas un diagnostic Netcross)"
        if native_group:
            message += f" [groupe tshark : {native_group}]"

        events.append(
            ExpertEvent(
                category="Wireshark/TShark",
                severity=severity,
                segment=point,
                message=message,
                evidence=evidence,
                source="tshark",
                confidence=confidence,
                first_seen=first_seen[(point, flag)],
                last_seen=last_seen[(point, flag)],
                layer=layer,
                protocol=protocol,
                flow_keys=list(flow_keys.get((point, flag), [])),
                packet_evidence=list(packet_evidence.get((point, flag), [])),
                remediation=remediation,
            )
        )
    logger.debug("build_wireshark_expert_events: retour events")
    return events
