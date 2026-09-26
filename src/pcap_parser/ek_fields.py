"""
pcap_parser.ek_fields -- couche 2 : acces bas niveau aux champs d'un
paquet EK. Aucune connaissance protocolaire ici, juste les mecanismes
communs a tous les champs tshark -T ek :

- une couche presente plusieurs fois dans un paquet (double IP en GRE,
  double VLAN en QinQ, labels MPLS empiles...) est rendue comme une
  LISTE de dicts au lieu d'un seul dict -- outer(), innermost() et
  all_occurrences() gerent cette normalisation une bonne fois pour
  toutes.
- les valeurs numeriques arrivent en chaines, parfois en decimal
  ("64"), parfois en hexadecimal prefixe ("0x0800") selon le champ --
  as_int()/hex_or_dec_to_int() couvrent les deux.
"""

from __future__ import annotations

from typing import Any

from loguru import logger as _loguru_logger

# pcap_parser reste independant de netcross_core (contrat import-linter) :
# loguru directement, lie au nom du module.
logger = _loguru_logger.bind(name=__name__)


def layer(layers: dict, key: str) -> dict | None:
    """Couche unique (premiere/seule occurrence). None si absente."""
    val = layers.get(key)
    if val is None:
        return None
    return val[0] if isinstance(val, list) else val


def innermost(layers: dict, key: str) -> dict | None:
    """Derniere occurrence d'une couche empilee -- la plus interne, donc
    la plus proche des vraies donnees applicatives (ex: le vrai IP client
    derriere un GRE/VXLAN/ERSPAN, pas l'IP du tunnel)."""
    val = layers.get(key)
    if val is None:
        return None
    return val[-1] if isinstance(val, list) else val


def all_occurrences(layers: dict, key: str) -> list[dict]:
    """Toutes les occurrences d'une couche, dans l'ordre outer -> inner."""
    val = layers.get(key)
    if val is None:
        return []
    return val if isinstance(val, list) else [val]


def g(d: dict | None, name: str, default: Any = None) -> Any:
    if d is None:
        return default
    return d.get(name, default)


def as_int(value: Any, base: int = 10) -> int | None:
    if value is None:
        return None
    try:
        return int(value, base) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        # appele pour chaque champ de chaque paquet : TRACE, pas de traceback
        logger.trace("as_int: valeur non entière {!r} (base {})", value, base)
        return None


def hex_or_dec_to_int(value: Any) -> int | None:
    """Beaucoup de champs tshark (ip.id, gtp.teid, dhcp.id...) sont rendus
    en hexadecimal prefixe "0x...". D'autres non. On accepte les deux."""
    if value is None:
        return None
    if isinstance(value, str) and value.lower().startswith("0x"):
        return as_int(value, 16)
    return as_int(value, 10)


def checksum_is_bad(status_value: Any) -> bool | None:
    """Interprete un champ de statut de checksum tshark (ip.checksum.
    status/tcp.checksum.status/udp.checksum.status), rendu en EK comme
    un CODE ENTIER en chaine decimale -- verifie empiriquement (tshark
    4.2.2, `-o ip.check_checksum:TRUE -o tcp.check_checksum:TRUE -o
    udp.check_checksum:TRUE`, pcap scapy synthetique avec checksum
    volontairement invalide) : "0" = Bad, "1" = Good, "2" = Unverified
    (validation desactivee -- c'est la valeur systematique SANS ces
    trois preferences, voir pcap_parser.ek_source.DEFAULT_PREFS).

    Trois etats possibles en sortie, jamais deux (contrairement a
    as_bool ci-dessus, pour un champ tshark reellement binaire) :
    True si invalide (0), False si valide (1), None si non verifie (2)
    OU si le champ est absent (couche sans checksum -- IPv6 n'a pas de
    checksum d'en-tete, par exemple) -- jamais suppose invalide/valide
    par defaut, un statut inconnu n'est ni l'un ni l'autre."""
    code = hex_or_dec_to_int(status_value)
    if code == 0:
        return True
    if code == 1:
        return False
    return None


def as_float(value: Any) -> float | None:
    """Symetrique a as_int/hex_or_dec_to_int, pour les champs tshark non
    entiers (ex: http.time -- ecart requete->reponse calcule nativement
    par le dissecteur HTTP, rendu en chaine flottante de secondes comme
    "0.000467410"). Verifie empiriquement (tshark 4.2.2, claude.md
    Session 17) : toujours une chaine, jamais un flottant JSON natif --
    contrairement a ip.flags.df/mf (booleens, voir as_bool). On reste
    neanmoins tolerant a un flottant deja natif par symetrie avec le
    reste de ce module, au cas ou une autre version de tshark differe."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        logger.trace("as_float: valeur non numérique {!r}", value)
        return None


def as_bool(value: Any) -> bool:
    """Interprete un champ booleen EK (ip.flags.df, ip.flags.mf...).

    Verifie empiriquement (tshark 4.2.2, sous-champs d'un octet de flags
    IP genere via un pcap scapy synthetique, voir claude.md Session 9) :
    ces champs sont rendus en booleen JSON natif (True/False), pas en
    chaine "0"/"1" comme les champs numeriques -- contrairement a ce que
    hex_or_dec_to_int gere. On reste neanmoins tolerant a une
    representation en chaine (autre version de tshark, ou un generateur
    EK different) plutot que de supposer un seul format, par symetrie
    avec hex_or_dec_to_int qui fait la meme chose pour les nombres.
    Absent (champ non emis) -> False, comme le reste du module."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() not in ("", "0", "false")
    return bool(value)


def has_expert_flag(layer: dict | None, name: str) -> bool:
    """Un champ genere par le systeme d'expertise de tshark (tcp.analysis.
    retransmission, .fast_retransmission, .spurious_retransmission...)
    n'existe que si la condition correspondante est remplie -- toujours
    rendu avec une valeur None, seule sa PRESENCE compte (contrairement a
    ip.flags.df/mf, qui sont des champs de protocole ORDINAIRES, toujours
    presents, avec une vraie valeur booleenne -- voir as_bool ci-dessus).

    Verifie empiriquement (tshark 4.2.2, pcap scapy synthetique avec un
    vrai scenario de retransmission, voir claude.md Session 10) : ces
    champs d'expertise ne sont PAS au meme niveau que le reste du layer,
    mais niches sous une sous-cle "_ws_expert". "_ws_expert" peut lui-meme
    etre une liste si plusieurs conditions d'expertise s'appliquent au
    meme paquet -- meme normalisation liste/dict que layer()/innermost()
    ci-dessus, par prudence (non confirme necessaire par la capture de
    test, qui n'a jamais produit qu'une seule condition a la fois, mais
    pas exclu non plus et le cout de le gerer est nul)."""
    if layer is None:
        return False
    expert = layer.get("_ws_expert")
    if expert is None:
        return False
    candidates = expert if isinstance(expert, list) else [expert]
    return any(name in c for c in candidates if isinstance(c, dict))


def expert_flag_names(layer: dict | None) -> tuple[str, ...]:
    """Generalise has_expert_flag() ci-dessus : au lieu de tester la
    presence d'UN nom de champ d'expertise connu a la fois, renvoie TOUS
    les noms de CONDITION presents sous "_ws_expert" pour cette couche,
    tries.

    Sert de brique generique pour la Session 1 de FEATURES.md section
    13.3 ("exploitation de l'expertise Wireshark/TShark") : capte tout
    signal d'expertise que le dissecteur tshark ajoute a un paquet,
    y compris ceux que ce projet ne decode pas encore explicitement en
    champ RawPacket dedie (voir netcross_core.wireshark_expert), sans
    devoir ajouter un nouveau champ/une nouvelle constante par nouveau
    type de signal observe. has_expert_flag() reste utile tel quel pour
    les trois flags de retransmission deja decodes individuellement en
    booleens RawPacket (is_retransmission/is_fast_retransmission/
    is_spurious_retransmission) -- cette fonction ne les remplace pas,
    elle complete par une vue brute exhaustive.

    Exclut volontairement _META_KEYS (severite/groupe/message natifs,
    voir expert_flag_details ci-dessous) : ces trois champs DESCRIPTIFS
    accompagnent TOUJOURS le(s) nom(s) de condition d'une occurrence
    _ws_expert (verifie empiriquement avec un vrai tshark 4.2.2, voir
    claude.md Session 39), ce ne sont pas des noms de condition a leur
    tour. BUG CORRIGE dans cette meme session : la version precedente
    (Session 38) ne les excluait pas -- seul le champ message avait ete
    anticipe dans une fixture de test (jamais son effet UNE FOIS COMBINE
    a severite/groupe, tous deux alors inconnus de ce projet), jamais
    remarque faute de tshark reel pour verifier la structure complete
    d'une occurrence. Avec un vrai tshark, tout signal d'expertise reel
    aurait donc fait remonter TROIS entrees parasites en plus du vrai nom
    de condition (un "evenement" par (point, "_ws_expert__ws_expert_
    message") par exemple dans netcross_core.wireshark_expert.
    build_wireshark_expert_events(), qui iterait RawPacket.expert_flags
    sans distinction) -- voir test_expert_flag_names_exclut_les_champs_
    meta pour la regression.

    Vide si la couche est absente ou ne porte aucun signal d'expertise
    (cas le plus frequent : la grande majorite des paquets n'ont aucune
    condition d'expertise tshark active)."""
    if layer is None:
        return ()
    expert = layer.get("_ws_expert")
    if expert is None:
        return ()
    candidates = expert if isinstance(expert, list) else [expert]
    names: set[str] = set()
    for c in candidates:
        if isinstance(c, dict):
            names.update(k for k in c if k not in _META_KEYS)
    return tuple(sorted(names))


# Les trois champs descriptifs GENERIQUES que porte toute occurrence
# _ws_expert aux cotes du/des nom(s) de condition (verifie empiriquement
# avec un vrai tshark 4.2.2 -- voir claude.md Session 39) : severite et
# groupe NATIFS tshark (entiers, rendus en chaine decimale en sortie EK,
# ex: "4194304"), et message natif (texte libre, parfois parametre par
# paquet -- ex: "Bad checksum [should be 0x8cfa]"). "_ws_expert__ws_
# expert_severite" (double prefixe) et non "_ws_expert_severity" (simple)
# -- meme convention de doublement de prefixe que "tcp_tcp_srcport" pour
# "tcp.srcport" ailleurs dans ce module, appliquee ici au nom PROPRE du
# champ generique "_ws.expert.severity" (dont le "groupe" au sens de ce
# doublement est lui-meme "_ws.expert"), pas au nom de la couche qui
# l'englobe.
_SEVERITY_KEY = "_ws_expert__ws_expert_severity"
_GROUP_KEY = "_ws_expert__ws_expert_group"
_MESSAGE_KEY = "_ws_expert__ws_expert_message"
_META_KEYS = (_SEVERITY_KEY, _GROUP_KEY, _MESSAGE_KEY)

# Tables de correspondance code numerique -> libelle humain pour
# severite/groupe, generees depuis "tshark -G values" (tshark 4.2.2,
# sortie authentique du binaire, pas une supposition -- voir claude.md
# Session 39). Ce sont les memes constantes internes Wireshark (PI_*/
# GROUP_*) que celles utilisees pour l'affichage dans l'IHM graphique ;
# l'export EK ne rend que le code numerique brut, jamais le libelle.
# Un code absent de ces tables (nouvelle valeur d'une future version de
# tshark) n'a pas de libelle fiable -- voir _expert_label ci-dessous,
# meme discipline que _KNOWN_FLAGS/_flag_label dans wireshark_expert.py
# pour les noms de condition : la chaine brute plutot qu'une supposition.
_SEVERITY_LABELS: dict[int, str] = {
    8388608: "Error",
    6291456: "Warning",
    4194304: "Note",
    2097152: "Chat",
    1048576: "Comment",
}
_GROUP_LABELS: dict[int, str] = {
    16777216: "Checksum",
    33554432: "Sequence",
    50331648: "Response",
    67108864: "Request",
    83886080: "Undecoded",
    100663296: "Reassemble",
    117440512: "Malformed",
    134217728: "Debug",
    150994944: "Protocol",
    167772160: "Security",
    184549376: "Comment",
    201326592: "Decryption",
    218103808: "Assumption",
    234881024: "Deprecated",
}


def _expert_label(raw: Any, table: dict[int, str]) -> str | None:
    """Traduit un code numerique brut (chaine decimale ou hex, voir
    hex_or_dec_to_int) en libelle humain via `table`. `raw` absent ->
    None (occurrence sans ce champ). Code non reconnu (ni convertible en
    entier, ni present dans `table`) -> sa representation brute en
    chaine, jamais une supposition -- meme discipline que _flag_label
    dans wireshark_expert.py pour les noms de condition inconnus."""
    if raw is None:
        return None
    code = hex_or_dec_to_int(raw)
    if code is None:
        return str(raw)
    return table.get(code, str(raw))


def expert_flag_details(layer: dict | None) -> tuple[tuple[str, str | None, str | None, str | None], ...]:
    """Vue enrichie, complementaire a expert_flag_names() ci-dessus :
    pour chaque nom de CONDITION trouve sous "_ws_expert", renvoie aussi
    la severite et le groupe NATIFS tshark (traduits en libelle humain
    via _SEVERITY_LABELS/_GROUP_LABELS quand le code est reconnu, en
    chaine brute sinon) et le message natif -- au lieu du seul nom, sans
    ce contexte. Chaque element du tuple renvoye est un 4-uplet (name,
    severity, group, message) ; severity/group/message valent None si le
    champ correspondant est absent de cette occurrence (jamais leve).

    Une occurrence _ws_expert porte en pratique EXACTEMENT un nom de
    condition (verifie empiriquement avec un vrai tshark 4.2.2, y
    compris avec deux conditions SIMULTANEES sur le meme paquet -- voir
    claude.md Session 39 : "_ws_expert" devient alors une LISTE de deux
    occurrences INDEPENDANTES, chacune avec son propre nom, sa propre
    severite/groupe/message -- jamais un melange ambigu). Une occurrence
    sans nom de condition (jamais observee, mais le cout de le tolerer
    est nul) ne produit simplement aucune entree ; par symetrie, une
    occurrence avec plusieurs noms simultanes (jamais observee non plus)
    produirait un 4-uplet par nom, tous partageant la meme severite/
    groupe/message de cette occurrence -- coherent avec le fait que ces
    trois champs decrivent l'occurrence, pas un nom en particulier.

    Vide si la couche est absente ou ne porte aucun signal d'expertise --
    meme convention que expert_flag_names()."""
    if layer is None:
        return ()
    expert = layer.get("_ws_expert")
    if expert is None:
        return ()
    candidates = expert if isinstance(expert, list) else [expert]
    details: set[tuple[str, str | None, str | None, str | None]] = set()
    for c in candidates:
        if not isinstance(c, dict):
            continue
        severity = _expert_label(c.get(_SEVERITY_KEY), _SEVERITY_LABELS)
        group = _expert_label(c.get(_GROUP_KEY), _GROUP_LABELS)
        message = c.get(_MESSAGE_KEY)
        for name in c:
            if name not in _META_KEYS:
                details.add((name, severity, group, message))
    return tuple(sorted(details, key=lambda d: (d[0], d[1] or "", d[2] or "", d[3] or "")))


def as_bytes_from_hex_dump(value: Any) -> bytes:
    """tshark rend un buffer binaire (ex: udp.payload) comme une chaine
    "aa:bb:cc:..." octets separes par ':'. Vide/absent -> b""."""
    if not value:
        return b""
    try:
        return bytes.fromhex(value.replace(":", ""))
    except ValueError:
        logger.trace("as_bytes_from_hex_dump: dump hexadécimal invalide ({} car.)", len(str(value)))
        return b""
