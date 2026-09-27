"""
netcross_core.discovery.assets -- inventaire passif des actifs reseau
(SCENARIO-5, issue #151, parent #141).

Objectif de l'issue : produire un INVENTAIRE STRUCTURE (un hote = IP +
MAC + premiere/derniere vue + ports exposes), complementaire de la
topologie deja deduite par netcross_core.analysis
(Report.topology_edges) -- difference explicitee par l'issue elle-meme :
"Netcross a deja une topologie deduite et des compteurs par point. Ce
module produit un inventaire structure (asset inventory) avec details
par hote."

100% passif comme le reste du projet : AUCUNE sonde n'est emise, tout
provient des Pkt deja construits par netcross_core.parsing (memes
objets que netcross_core.analysis.analyse()). Module independant, meme
discipline que client_diff.py/baseline_diff.py : fichier neuf, ne
modifie ni parsing.py, ni analysis.py, ni models.py, ni correlate.py.

Un hote est identifie par IP (une IP = un hote dans ce modele) -- le
roaming DHCP d'une meme machine sur plusieurs IP n'est PAS fusionne
ici ; meme limite assumee, pour la meme raison, que
client_diff.group_packets_by_client (le regroupement explicite reste a
l'appelant qui connait la topologie de son reseau).

Detection de port "expose" : UNIQUEMENT confirmee par une reponse
positive deja observee sur le fil (SYN-ACK TCP, ou banniere applicative
cote serveur) -- jamais par une simple tentative de connexion (un SYN
seul, ou un datagramme UDP isole) qui pourrait tout aussi bien avoir
ete rejetee hors de la capture. Cette regle est au coeur de la
discipline "100% passif" de l'issue : aucun port n'est signale ouvert
sur la seule foi d'un trafic emis vers lui.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from netcross_core.discovery.os_detect import OsGuess, guess_os_from_ttl, refine_with_tcp_options
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import ROLE_SERVER, Pkt

logger = get_logger(__name__)

PROTO_TCP = "tcp"
PROTO_UDP = "udp"


@dataclass
class ExposedService:
    """Un service expose sur un hote, vu soit par port (SYN-ACK TCP
    observe = port confirme ouvert), soit par banniere applicative
    (service_banners cote serveur, voir netcross_core.application.
    banners) -- les deux sources alimentent la meme entree quand elles
    portent sur le meme (port, transport)."""

    port: int
    transport: str  # PROTO_TCP ou PROTO_UDP
    service: str | None = None
    version: str | None = None


@dataclass
class HostAsset:
    """Un hote de l'inventaire -- voir docstring du module pour la
    convention "une IP = un hote"."""

    ip: str
    mac: str | None = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    packet_count: int = 0
    points: set[str] = field(default_factory=set)
    vlan_ids: set[int] = field(default_factory=set)
    # cle (port, transport) -- un seul ExposedService par port/transport,
    # comme un inventaire reel (le port est le meme quelle que soit la
    # source qui l'a revele en premier).
    ports: dict[tuple[int, str], ExposedService] = field(default_factory=dict)
    os_guess: OsGuess | None = None

    def sorted_ports(self) -> list[ExposedService]:
        """Ports exposes, tries (port, transport) -- ordre stable pour
        l'affichage et les exports (voir to_records)."""
        logger.debug("sorted_ports: retour liste")
        return [self.ports[key] for key in sorted(self.ports)]


@dataclass
class AssetInventory:
    """Resultat de `build_asset_inventory` -- un hote par IP vue dans la
    capture, plus la liste des nouveaux hotes si une baseline a ete
    fournie."""

    hosts: dict[str, HostAsset] = field(default_factory=dict)
    # Hotes absents de la baseline fournie -- toujours vide si aucune
    # baseline n'a ete passee (voir build_asset_inventory : pas de
    # baseline signifie "rien a comparer", jamais "tout est nouveau").
    new_hosts: tuple[str, ...] = ()
    baseline_size: int = 0

    def sorted_hosts(self) -> list[HostAsset]:
        """Hotes tries par IP -- ordre stable pour l'affichage et les
        exports (voir to_records)."""
        logger.debug("sorted_hosts: retour liste")
        return [self.hosts[ip] for ip in sorted(self.hosts)]

    def to_records(self) -> list[dict]:
        """Inventaire a plat, un dict par hote -- meme convention que
        Report.service_fingerprints/security_findings (netcross_core.
        models) : une liste de dicts consommable directement par un
        exporteur JSON, sans dependre de netcross_report (contrat de
        couches : netcross_core n'importe jamais netcross_report).
        Sert de base a une integration SIEM (critere d'acceptation de
        l'issue #151)."""
        logger.debug("AssetInventory.to_records()")
        records = []
        for host in self.sorted_hosts():
            os_guess = host.os_guess
            records.append(
                {
                    "ip": host.ip,
                    "mac": host.mac,
                    "first_seen": host.first_seen,
                    "last_seen": host.last_seen,
                    "packet_count": host.packet_count,
                    "points": sorted(host.points),
                    "vlan_ids": sorted(host.vlan_ids),
                    "ports": [
                        {"port": svc.port, "transport": svc.transport, "service": svc.service, "version": svc.version}
                        for svc in host.sorted_ports()
                    ],
                    "os_guess": None
                    if os_guess is None
                    else {
                        "family": os_guess.family,
                        "confidence": os_guess.confidence,
                        "guessed_initial_ttl": os_guess.guessed_initial_ttl,
                        "hop_estimate": os_guess.hop_estimate,
                        "evidence": os_guess.evidence,
                    },
                    "is_new": host.ip in self.new_hosts,
                }
            )
        logger.debug("to_records: retour records")
        return records


def load_baseline_hosts(path: str | Path) -> set[str]:
    """Charge une baseline d'hotes connus depuis un fichier JSON --
    soit une liste plate d'IP (``["10.0.0.1", "10.0.0.2"]``), soit un
    objet avec une cle ``hosts`` de meme forme. Meme discipline de
    tolerance que netcross_core.fingerprint.known.
    load_known_fingerprints : un fichier absent ou illisible ne fait
    JAMAIS echouer l'appelant, il renvoie simplement un ensemble vide
    -- voir build_asset_inventory pour la consequence (pas de baseline
    = pas de comparaison, jamais "tout est nouveau" par defaut)."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        logger.exception("échec dans load_baseline_hosts")
        return set()
    if isinstance(data, list):
        logger.debug("load_baseline_hosts: retour valeur")
        return {str(ip) for ip in data}
    if isinstance(data, dict) and isinstance(data.get("hosts"), list):
        logger.debug("load_baseline_hosts: retour valeur")
        return {str(ip) for ip in data["hosts"]}
    logger.debug("load_baseline_hosts: retour set(...)")
    return set()


def _get_or_create(hosts: dict[str, HostAsset], ip: str) -> HostAsset:
    host = hosts.get(ip)
    if host is None:
        host = HostAsset(ip=ip)
        hosts[ip] = host
    logger.debug("_get_or_create: retour host")
    return host


def _touch(host: HostAsset, pkt: Pkt) -> None:
    if host.packet_count == 0 or pkt.ts < host.first_seen:
        host.first_seen = pkt.ts
    if host.packet_count == 0 or pkt.ts > host.last_seen:
        host.last_seen = pkt.ts
    host.packet_count += 1
    host.points.add(pkt.point)
    if pkt.vlan_id is not None:
        host.vlan_ids.add(pkt.vlan_id)


def _record_banner_service(host: HostAsset, pkt: Pkt) -> None:
    """Associe les bannieres cote serveur (Banner.role == ROLE_SERVER,
    voir netcross_core.models) au port emetteur du paquet qui les
    porte -- le logiciel annonce tourne sur pkt.src, sur le port par
    lequel il vient de repondre."""
    if not pkt.service_banners:
        logger.debug("_record_banner_service: retour (None implicite)")
        return
    target_port = pkt.sport if pkt.sport is not None else pkt.dport
    if target_port is None:
        logger.debug("_record_banner_service: retour (None implicite)")
        return
    transport = PROTO_TCP if pkt.proto == "TCP" else PROTO_UDP
    key = (target_port, transport)
    for banner in pkt.service_banners:
        if banner.role != ROLE_SERVER:
            continue
        existing = host.ports.get(key)
        if existing is None:
            host.ports[key] = ExposedService(
                port=target_port, transport=transport, service=banner.service, version=banner.version
            )
        elif existing.service is None:
            existing.service = banner.service
            existing.version = banner.version


def build_asset_inventory(all_packets: list[Pkt], baseline_hosts: set[str] | None = None) -> AssetInventory:
    """Point d'entree principal.

    `all_packets` : meme liste plate de Pkt (tous points confondus) que
    netcross_core.analysis.analyse() -- l'inventaire est PAR CAPTURE,
    pas par point : un hote deja vu a un point est le meme hote vu a un
    autre (Pkt.point est agrege dans HostAsset.points, pas utilise pour
    scinder l'hote).

    `baseline_hosts` : ensemble optionnel d'IP deja connues (baseline
    configurable, critere d'acceptation de l'issue #151 -- voir
    `load_baseline_hosts` pour la charger depuis un fichier JSON). Tout
    hote de l'inventaire absent de cet ensemble est remonte dans
    AssetInventory.new_hosts. None ou vide : aucune comparaison
    effectuee, new_hosts reste vide -- une baseline absente signifie
    "rien a comparer", jamais "tout est nouveau" par defaut (piege
    classique d'une baseline mal initialisee qui noierait l'analyste
    sous de faux positifs des le premier lancement).
    """
    logger.debug(
        "build_asset_inventory: all_packets={} baseline_hosts={}",
        summarize(all_packets, "all_packets"),
        summarize(baseline_hosts, "baseline_hosts"),
    )
    hosts: dict[str, HostAsset] = {}
    ttl_samples: dict[str, list[int]] = {}
    handshake_samples: dict[str, Pkt] = {}

    for pkt in all_packets:
        if not pkt.src or not pkt.dst:
            continue
        src_host = _get_or_create(hosts, pkt.src)
        _touch(src_host, pkt)
        dst_host = _get_or_create(hosts, pkt.dst)
        _touch(dst_host, pkt)

        if pkt.arp_sender_mac:
            # L'emetteur ARP ne revendique que sa PROPRE MAC -- jamais
            # celle du destinataire (meme prudence que arp_ip_conflict
            # cote netcross_core.analysis : ne jamais deduire une MAC
            # depuis le mauvais cote de l'echange).
            src_host.mac = pkt.arp_sender_mac

        flags = pkt.flags or ""
        is_syn = pkt.proto == "TCP" and "S" in flags
        is_synack = is_syn and "A" in flags

        if is_synack and pkt.sport is not None:
            # SYN-ACK : l'EMETTEUR (pkt.src) confirme un service ouvert
            # sur pkt.sport -- seul signal TCP retenu comme port
            # "expose" (voir docstring du module).
            key = (pkt.sport, PROTO_TCP)
            if key not in src_host.ports:
                src_host.ports[key] = ExposedService(port=pkt.sport, transport=PROTO_TCP)
            if pkt.ttl is not None:
                ttl_samples.setdefault(pkt.src, []).append(pkt.ttl)
            handshake_samples.setdefault(pkt.src, pkt)
        elif is_syn and not is_synack:
            # SYN seul : indice de TTL/options cote CLIENT (pkt.src) --
            # jamais transforme en port "expose" cote pkt.dst, un SYN
            # sans reponse positive observee ne prouve rien (voir
            # docstring du module).
            if pkt.ttl is not None:
                ttl_samples.setdefault(pkt.src, []).append(pkt.ttl)
            handshake_samples.setdefault(pkt.src, pkt)

        _record_banner_service(src_host, pkt)

    for ip, host in hosts.items():
        samples = ttl_samples.get(ip)
        if not samples:
            continue
        # TTL le plus frequent observe depuis cet hote -- une route
        # asymetrique ou un equipement NAT peut faire varier le TTL
        # d'un paquet a l'autre (voir Report.ttl_unstable cote
        # netcross_core.analysis) ; le mode reduit ce bruit sans
        # l'ignorer completement.
        most_common_ttl = max(set(samples), key=samples.count)
        guess = guess_os_from_ttl(most_common_ttl)
        handshake = handshake_samples.get(ip)
        if handshake is not None:
            guess = refine_with_tcp_options(
                guess,
                wscale_shift=handshake.wscale_shift,
                sack_permitted=handshake.sack_permitted,
                mss_val=handshake.mss_val,
            )
        host.os_guess = guess

    baseline = baseline_hosts or set()
    new_hosts = tuple(sorted(ip for ip in hosts if baseline and ip not in baseline))

    logger.debug("build_asset_inventory: retour AssetInventory(...)")
    return AssetInventory(hosts=hosts, new_hosts=new_hosts, baseline_size=len(baseline))
