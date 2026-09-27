"""
netcross_core.bpf_filters -- catalogue de filtres BPF predefinis et filtres
sauvegardes par l'utilisateur (Job 47 / issue #167).

Les filtres BPF de la capture live (``--live LABEL:INTERFACE[:BPF]``, GUI
"Capture en direct") etaient saisis a la main a chaque session. Ce module
fournit :

- ``PREDEFINED_BPF_FILTERS`` : catalogue de filtres courants (HTTP, HTTPS,
  DNS, ARP...), fige dans le code ;
- une persistance JSON dans un fichier "sidecar" de l'utilisateur
  (``~/.netcross/bpf_filters.json`` par defaut), relisible a la main et
  partageable tel quel : copier le fichier, ou passer un autre ``path`` aux
  fonctions ci-dessous (export/import d'un fichier d'equipe, par exemple) ;
- ``available_bpf_filters()`` : la liste proposee a l'utilisateur (catalogue
  puis filtres sauvegardes), que la GUI affiche dans son menu deroulant.

Regles de nommage : les noms sont compares sans tenir compte de la casse ni
des espaces de bordure. Les noms du catalogue sont RESERVES : on ne peut pas
sauvegarder un filtre qui porte l'un d'eux (``upsert_bpf_filter`` refuse), et
une entree de meme nom trouvee dans un fichier edite a la main est ignoree
par ``available_bpf_filters`` plutot que d'apparaitre en double.

Limite assumee : ce module ne VALIDE PAS la syntaxe BPF. Compiler une
expression exige libpcap ; l'expression est transmise telle quelle a tshark
(``-f``), qui la rejette avec son propre message si elle est invalide.

Le module est un CONSOMMATEUR pur de ``netcross_core.models`` : il ne depend
ni de la GUI, ni du CLI, ni de tshark.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import asdict
from pathlib import Path

from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import BPFFilter

logger = get_logger(__name__)

#: Version du format du fichier de sauvegarde (cle ``version``). Incrementee
#: si la structure change de facon incompatible ; le chargeur actuel ignore
#: la valeur (un fichier sans ``version``, ou une simple liste, est accepte).
_FORMAT_VERSION = 1

#: Catalogue de filtres predefinis. Tuple (immuable) : les filtres de
#: l'utilisateur vivent dans le fichier sidecar, jamais ici.
PREDEFINED_BPF_FILTERS: tuple[BPFFilter, ...] = (
    BPFFilter("HTTP", "tcp port 80", "Trafic HTTP/1.x en clair (TCP/80)."),
    BPFFilter(
        "HTTPS",
        "tcp port 443",
        "Trafic TLS/HTTPS (TCP/443). Le contenu est chiffre : seuls les segments TCP et le handshake TLS "
        "sont analysables.",
    ),
    BPFFilter("DNS", "port 53", "Requetes et reponses DNS (UDP et TCP, port 53)."),
    BPFFilter(
        "TCP (retransmissions)",
        "tcp",
        "BPF est sans etat : il ne sait pas isoler une retransmission. Ce filtre capture tout le TCP ; "
        "les retransmissions (rapides, RTO, parasites) sont detectees ensuite, a l'analyse.",
    ),
    BPFFilter(
        "TCP SYN/RST",
        "tcp[tcpflags] & (tcp-syn|tcp-rst) != 0",
        "Uniquement les segments SYN (dont SYN-ACK) et RST : ouvertures et resets de connexion, "
        "tres leger sur un lien charge.",
    ),
    BPFFilter("ARP", "arp", "Resolution d'adresses ARP (IPv4) -- utile pour detecter un conflit d'adresse IP."),
    BPFFilter("ICMP", "icmp or icmp6", "Messages de controle ICMP et ICMPv6 (PMTUD, TTL exceeded, Packet Too Big)."),
    BPFFilter("DHCP", "udp port 67 or udp port 68", "Echanges DHCPv4 (ports serveur 67 et client 68)."),
    BPFFilter(
        "SIP",
        "port 5060 or port 5061",
        "Signalisation SIP (5060, TLS 5061). Le flux RTP associe utilise des ports dynamiques : "
        "il n'est pas capture par ce filtre.",
    ),
    BPFFilter("QUIC", "udp port 443", "QUIC / HTTP/3 (UDP/443)."),
    BPFFilter("Fragments IPv4", "(ip[6:2] & 0x3fff) != 0", "Fragments IPv4 (bit MF actif ou offset non nul)."),
)


def _name_key(name: str) -> str:
    logger.debug("_name_key: retour name.strip().casefold(…)")
    return name.strip().casefold()


_PREDEFINED_KEYS = frozenset(_name_key(f.name) for f in PREDEFINED_BPF_FILTERS)


def default_bpf_filters_path() -> Path:
    """Chemin par defaut du fichier de sauvegarde : ``~/.netcross/bpf_filters.json``."""
    logger.debug("default_bpf_filters_path()")
    return Path.home() / ".netcross" / "bpf_filters.json"


def _resolve(path: str | Path | None) -> Path:
    logger.debug("_resolve: retour Path(path).expanduser() if path is not None else …")
    return Path(path).expanduser() if path is not None else default_bpf_filters_path()


def save_bpf_filters(filters: Iterable[BPFFilter], path: str | Path | None = None) -> Path:
    """Ecrit ``filters`` (liste complete, remplace le contenu) en JSON.

    Cree le dossier parent au besoin. L'ecriture est atomique (fichier
    temporaire puis ``os.replace``) : un plantage en cours d'ecriture laisse
    l'ancien fichier intact au lieu d'en produire un tronque. Renvoie le
    chemin ecrit.
    """
    target = _resolve(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    doc = {"version": _FORMAT_VERSION, "filters": [asdict(f) for f in filters]}
    payload = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    tmp = target.with_name(target.name + ".tmp")
    try:
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, target)
    except BaseException:
        logger.exception("erreur: BaseException")
        tmp.unlink(missing_ok=True)
        logger.debug("save_bpf_filters: except BaseException -> relance de l'exception en cours")
        raise
    logger.debug("save_bpf_filters: retour target={}", summarize(target, "target"))
    return target


def _filter_from_item(item: object, index: int) -> BPFFilter:
    if not isinstance(item, dict):
        logger.trace("_filter_from_item: refus, ValueError")
        logger.debug("_filter_from_item: si not isinstance(item, dict) -> levée ValueError")
        raise ValueError(f"entree #{index}: objet JSON attendu, pas {type(item).__name__}")
    for key in ("name", "expression"):
        value = item.get(key)
        if not isinstance(value, str) or not value.strip():
            logger.trace("_filter_from_item: refus, ValueError")
            logger.debug("_filter_from_item: si not isinstance(value, str) or not value.strip() -> levée ValueError")
            raise ValueError(f"entree #{index}: '{key}' est requis (chaine non vide)")
    description = item.get("description")
    if description is None:
        description = ""
    if not isinstance(description, str):
        logger.trace("_filter_from_item: refus, ValueError")
        logger.debug("_filter_from_item: si not isinstance(description, str) -> levée ValueError")
        raise ValueError(f"entree #{index}: 'description' doit etre une chaine")
    logger.debug("_filter_from_item: retour BPFFilter(…)")
    return BPFFilter(item["name"].strip(), item["expression"].strip(), description.strip())


def load_bpf_filters(path: str | Path | None = None) -> list[BPFFilter]:
    """Charge les filtres sauvegardes.

    Fichier absent : liste vide (premier lancement, cas normal). Fichier
    present mais illisible ou mal forme : ``ValueError`` avec le chemin et la
    cause -- jamais de repli silencieux, pour qu'un fichier corrompu ne soit
    pas ecrase par la sauvegarde suivante. Autres erreurs d'E/S (droits...) :
    ``OSError`` telle quelle.

    Formats acceptes : ``{"version": 1, "filters": [...]}`` (celui de
    ``save_bpf_filters``) ou une simple liste d'objets. Un meme nom present
    plusieurs fois ne donne qu'une entree : la derniere valeur, a la
    position de la premiere.
    """
    source = _resolve(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError:
        # premier lancement : aucun filtre sauvegarde, ce n'est pas une erreur (#468)
        logger.debug("load_bpf_filters: {} absent, aucun filtre utilisateur", source)
        return []
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.exception(f"échec dans load_bpf_filters: {exc}")
        raise ValueError(f"filtres BPF: fichier illisible {source}: {exc}") from exc
    if isinstance(data, dict):
        if "filters" not in data:
            logger.debug("load_bpf_filters: si 'filters' not in data -> levée ValueError")
            raise ValueError(f"filtres BPF: cle 'filters' absente dans {source}")
        data = data["filters"]
    if not isinstance(data, list):
        logger.debug("load_bpf_filters: si not isinstance(data, list) -> levée ValueError")
        raise ValueError(f"filtres BPF: une liste est attendue dans {source}, pas {type(data).__name__}")
    by_name: dict[str, BPFFilter] = {}
    for index, item in enumerate(data):
        flt = _filter_from_item(item, index)
        by_name[_name_key(flt.name)] = flt
    logger.debug("load_bpf_filters: retour list(…)")
    return list(by_name.values())


def available_bpf_filters(path: str | Path | None = None) -> list[BPFFilter]:
    """Filtres proposes a l'utilisateur : catalogue predefini, puis filtres
    sauvegardes (ceux dont le nom collisionne avec le catalogue sont ignores,
    voir l'en-tete du module). Meme contrat d'erreur que ``load_bpf_filters``.
    """
    user = [f for f in load_bpf_filters(path) if _name_key(f.name) not in _PREDEFINED_KEYS]
    logger.debug("available_bpf_filters: retour liste")
    return [*PREDEFINED_BPF_FILTERS, *user]


def upsert_bpf_filter(new: BPFFilter, path: str | Path | None = None) -> list[BPFFilter]:
    """Sauvegarde ``new`` (ajout, ou remplacement du filtre de meme nom) et
    renvoie la liste ``available_bpf_filters`` mise a jour.

    ``ValueError`` si le nom est reserve au catalogue, ou si le fichier
    existant est illisible (il n'est alors pas modifie). ``OSError`` si
    l'ecriture echoue.
    """
    clean = BPFFilter(new.name.strip(), new.expression.strip(), new.description.strip())
    key = _name_key(clean.name)
    if key in _PREDEFINED_KEYS:
        logger.trace("upsert_bpf_filter: refus, ValueError")
        logger.debug("upsert_bpf_filter: si key in _PREDEFINED_KEYS -> levée ValueError")
        raise ValueError(f"le nom '{clean.name}' est reserve au catalogue predefini : choisir un autre nom")
    saved = load_bpf_filters(path)
    for index, existing in enumerate(saved):
        if _name_key(existing.name) == key:
            saved[index] = clean
            break
    else:
        saved.append(clean)
    save_bpf_filters(saved, path)
    logger.debug("upsert_bpf_filter: retour available_bpf_filters(…)")
    return available_bpf_filters(path)
