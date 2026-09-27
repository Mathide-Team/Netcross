"""
netcross_core.redact -- anonymisation des adresses (IP/MAC) d'une liste
de paquets deja chargee, en vue d'un partage externe (ticket support
vendeur, rapport transmis a un tiers) sans exposer l'adressage reel du
reseau du client.

Perimetre assume, volontairement etroit (nom du flag CLI : --redact,
"adresses" au sens strict, voir FEATURES.md section 5.2) :

- adresses IP (Pkt.src/dst -- SAUF sur un paquet STP, ou ces deux champs
  portent en realite une adresse MAC Ethernet, pas une IP, voir
  pcap_parser.packet ; et Pkt.dhcp_server_id) -> plage de documentation
  RFC 5737 (IPv4, TEST-NET-1/2/3) ou RFC 3849 (IPv6, 2001:db8::/32) --
  jamais routable sur le vrai Internet, signal univoque que la donnee a
  ete anonymisee (convention deja largement utilisee par les outils de
  redaction de captures) ;
- adresses MAC (Pkt.arp_sender_mac, la partie MAC de Pkt.stp_root_id
  "prio/mac", et Pkt.src/dst sur un paquet STP) -> OUI localement
  administre 02:00:00:00:00:00 + compteur (bit "locally administered"
  actif, RFC/IEEE 802 -- jamais une vraie adresse assignee par un
  constructeur).

Explicitement HORS PERIMETRE de cette passe (voir FEATURES.md section
5.2, ligne "Anonymisation") -- ce sont des NOMS, pas des ADRESSES, et
laisses tels quels : noms DNS (dns_qry_name), URI/host HTTP (http_uri),
SAN de certificat TLS (tls_cert_san, tls_cert_san_ip) et sujet/emetteur
(tls_cert_subject/tls_cert_issuer), identifiants SIP (sip_call_id/
sip_user_agent/sip_server). Une capture "redigee" avec ce module reste
donc potentiellement identifiante via ces canaux -- limite assumee et
documentee (README.md, "Limites connues"), pas un oubli.

Egalement HORS PERIMETRE, par construction architecturale plutot que
par choix : les diagnostics TLS/QUIC (netcross_core.tls_diagnostics/
quic_diagnostics) et la comparaison client vs client
(netcross_core.client_diff) operent chacun sur leur PROPRE reparse
independant des fichiers (voir leurs docstrings respectives) ou sur des
adresses IP fournies explicitement par l'operateur sur la ligne de
commande (--client-group) -- aucun des deux ne passe par la liste
`all_packets` redigee ici. Combiner --redact avec --tls/--quic/
--client-group laisserait donc filtrer des adresses reelles par ces
canaux : les deux CLI refusent explicitement cette combinaison plutot
que de produire un rapport partiellement redige sans le signaler (voir
cross_capture_analyzer_cli.py/cross_capture_diff_cli.py, meme discipline
que le refus deja existant de --tls/--quic/--parallel avec --live).

Mapping deterministe et partage : une meme adresse d'origine produit
toujours le meme pseudonyme, sur tout l'appel a AddressRedactor.redact()
-- y compris a travers plusieurs appels successifs sur le MEME
AddressRedactor (necessaire pour cross_capture_diff_cli.py : baseline et
courant doivent partager un mapping identique, sans quoi le diff entre
les deux perdrait tout son sens). L'ordre d'attribution suit l'ordre de
premiere apparition dans la ou les listes de paquets fournies --
deterministe pour un meme jeu de paquets, mais PAS reproductible d'une
capture a l'autre (pas un besoin identifie ici : le mapping n'a de sens
que le temps d'un run, voir --redact-map pour le conserver).

Mutation EN PLACE des objets Pkt/RawPacket fournis (pas de copie) :
coherent avec l'esprit "reecrit des adresses dans des paquets deja
charges" de cette fonctionnalite, et evite de doubler transitoirement
la memoire d'une grosse capture (voir la piste "gestion memoire des
grosses captures", Session 19). Fonctionne indifferemment sur une liste
de Pkt (netcross_core.models) ou de RawPacket (pcap_parser.packet) :
les deux dataclasses partagent exactement les memes noms de champs pour
src/dst/proto/arp_sender_mac/stp_root_id/dhcp_server_id -- aucun
isinstance ici, uniquement de l'acces par attribut.
"""

from __future__ import annotations

import csv
import ipaddress
import re

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

_IPV4_DOC_BLOCKS = (
    (192, 0, 2),  # RFC 5737 TEST-NET-1
    (198, 51, 100),  # RFC 5737 TEST-NET-2
    (203, 0, 113),  # RFC 5737 TEST-NET-3
)
_IPV4_BLOCK_SIZE = 254  # .1 a .254 par bloc -- .0/.255 evites (reseau/diffusion)
_IPV4_DOC_CAPACITY = len(_IPV4_DOC_BLOCKS) * _IPV4_BLOCK_SIZE  # 762

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


def _ipv4_pseudonym(index: int) -> str:
    """192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737) d'abord --
    762 adresses distinctes, tres largement suffisant pour une capture de
    depannage reseau (2, 4, 9... points, pas un releve d'annuaire
    Internet). Au-dela (jamais atteint par aucune capture de ce projet a
    ce jour), bascule sur 240.0.0.0/4 (RFC 1112, "reserved for future
    use", jamais assigne ni routable) -- ~268M adresses, marge large."""
    if index < _IPV4_DOC_CAPACITY:
        block = _IPV4_DOC_BLOCKS[index // _IPV4_BLOCK_SIZE]
        octet = 1 + (index % _IPV4_BLOCK_SIZE)
        return f"{block[0]}.{block[1]}.{block[2]}.{octet}"
    overflow = index - _IPV4_DOC_CAPACITY
    return f"240.{(overflow >> 16) & 0xFF}.{(overflow >> 8) & 0xFF}.{overflow & 0xFF}"


def _ipv6_pseudonym(index: int) -> str:
    """2001:db8::/32 (RFC 3849, documentation) -- ~2**96 adresses, aucun
    overflow realiste pour une capture reseau. index+1 (pas index) pour
    ne jamais produire l'adresse "2001:db8::" toute seule (suffixe nul),
    lisible mais inutilement ambigue avec le prefixe lui-meme."""
    return f"2001:db8::{index + 1:x}"


def _mac_pseudonym(index: int) -> str:
    """02:00:00:00:00:00 + compteur -- premier octet 0x02 = bit
    "locally administered" actif / bit multicast inactif (IEEE 802) :
    convention standard pour une MAC synthetique, jamais une vraie
    adresse issue d'un OUI constructeur."""
    return f"02:00:00:{(index >> 16) & 0xFF:02x}:{(index >> 8) & 0xFF:02x}:{index & 0xFF:02x}"


_GENERATORS = {"ipv4": _ipv4_pseudonym, "ipv6": _ipv6_pseudonym, "mac": _mac_pseudonym}


def _ip_kind(value: str) -> str | None:
    """ "ipv4"/"ipv6" si `value` est une adresse IP syntaxiquement valide,
    None sinon (champ deja vide/malforme -- laisse tel quel par
    l'appelant plutot que de lever une exception sur une capture reelle
    imparfaite, meme discipline defensive que le reste du projet)."""
    try:
        return "ipv6" if ipaddress.ip_address(value).version == 6 else "ipv4"
    except ValueError:
        logger.exception("échec dans _ip_kind")
        return None


def _is_mac(value: str) -> bool:
    return bool(_MAC_RE.match(value))


class AddressRedactor:
    """Etat partage pour anonymiser une ou plusieurs listes de paquets
    avec un mapping coherent. Un mapping neuf = un nouveau pseudonyme
    pour chaque adresse encore jamais vue par CET objet ; reappeler
    .redact() sur une autre liste avec le MEME objet reutilise les
    pseudonymes deja attribues pour toute adresse deja rencontree."""

    def __init__(self) -> None:
        self._map: dict[str, tuple[str, str]] = {}  # adresse reelle -> (pseudonyme, type)
        self._counters = {"ipv4": 0, "ipv6": 0, "mac": 0}

    def _pseudonym(self, addr: str, kind: str) -> str:
        entry = self._map.get(addr)
        if entry is not None:
            return entry[0]
        idx = self._counters[kind]
        self._counters[kind] += 1
        pseudo = _GENERATORS[kind](idx)
        self._map[addr] = (pseudo, kind)
        return pseudo

    def redact(self, packets) -> None:
        """Mutation en place de chaque paquet de `packets` (Pkt ou
        RawPacket, voir docstring de module)."""
        for pk in packets:
            self._redact_one(pk)

    def _redact_one(self, pk) -> None:
        if pk.proto == "STP":
            # src/dst portent ici une adresse MAC Ethernet (eth.src/
            # eth.dst), pas une IP -- voir pcap_parser.packet.build_packet.
            if pk.src is not None and _is_mac(pk.src):
                pk.src = self._pseudonym(pk.src, "mac")
            if pk.dst is not None and _is_mac(pk.dst):
                pk.dst = self._pseudonym(pk.dst, "mac")
        else:
            if pk.src is not None:
                kind = _ip_kind(pk.src)
                if kind is not None:
                    pk.src = self._pseudonym(pk.src, kind)
            if pk.dst is not None:
                kind = _ip_kind(pk.dst)
                if kind is not None:
                    pk.dst = self._pseudonym(pk.dst, kind)

        if pk.arp_sender_mac is not None and _is_mac(pk.arp_sender_mac):
            pk.arp_sender_mac = self._pseudonym(pk.arp_sender_mac, "mac")

        if pk.dhcp_server_id is not None:
            kind = _ip_kind(pk.dhcp_server_id)
            if kind is not None:
                pk.dhcp_server_id = self._pseudonym(pk.dhcp_server_id, kind)

        if pk.stp_root_id is not None and "/" in pk.stp_root_id:
            prio, _sep, mac = pk.stp_root_id.partition("/")
            if _is_mac(mac):
                pk.stp_root_id = f"{prio}/{self._pseudonym(mac, 'mac')}"

    def entries(self):
        """Tuples (adresse_reelle, pseudonyme, type), tries par type puis
        par pseudonyme -- ordre stable pour un export reproductible
        (--redact-map, tests)."""
        logger.debug("AddressRedactor.entries()")
        return sorted(
            ((addr, pseudo, kind) for addr, (pseudo, kind) in self._map.items()),
            key=lambda t: (t[2], t[1]),
        )

    def __len__(self) -> int:
        return len(self._map)

    @property
    def mapping(self) -> dict[str, str]:
        """Vue simplifiee adresse_reelle -> pseudonyme (sans le type),
        pour un usage programmatique simple (tests notamment)."""
        return {addr: pseudo for addr, (pseudo, _kind) in self._map.items()}


def redact_packets(packets) -> AddressRedactor:
    """Raccourci pour le cas simple (un seul appel, un seul jeu de
    paquets) : construit un AddressRedactor neuf, redige `packets`,
    renvoie le redacteur (mapping/entries() consultables ensuite,
    notamment pour --redact-map)."""
    logger.debug("redact_packets: packets={}", summarize(packets, "packets"))
    redactor = AddressRedactor()
    redactor.redact(packets)
    return redactor


def write_redaction_map_csv(redactor: AddressRedactor, path: str) -> None:
    """Ecrit le mapping adresse reelle -> pseudonyme dans un CSV LOCAL
    (adresse_reelle, pseudonyme, type) -- a conserver uniquement par
    l'operateur, jamais transmis avec la capture/le rapport reidiges :
    permet de retrouver plus tard a quelle adresse reelle correspond un
    pseudonyme mentionne par un tiers (ex: un support vendeur qui cite
    192.0.2.4 dans sa reponse)."""
    logger.debug(
        "write_redaction_map_csv: redactor={} path={}",
        summarize(redactor, "redactor"),
        summarize(path, "path"),
    )
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["adresse_reelle", "pseudonyme", "type"])
        for addr, pseudo, kind in redactor.entries():
            writer.writerow([addr, pseudo, kind])
