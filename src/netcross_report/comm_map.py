"""
netcross_report.comm_map -- cartographie des communications observees
(Job 15/issue #15, FEATURES.md section 6.6).

La GUI savait afficher le rapport texte et des graphiques par metrique.
Elle ne savait pas montrer QUI PARLE A QUI : un graphe hotes/echanges, avec
les volumes, les protocoles et les anomalies, filtrable par protocole,
top-N et presence d'anomalie. C'est la vue exploratoire qu'on ouvre en
premier quand on ne sait pas encore quoi chercher.

Module de calcul pur, sans GTK ni matplotlib : la GUI (netcross_gtk4) et le
rendu (netcross_report.charts) s'appuient dessus, ce qui rend la logique de
filtrage testable sans interface graphique -- GTK 4 n'est pas installable
partout, et une regle de filtrage non testee est une regle qui derive.

Deux choix de comptage a connaitre avant de lire les chiffres :

1. Un paquet physique vu a plusieurs points de capture ne doit pas compter
   plusieurs fois dans un VOLUME (contrairement au diagramme de sequence,
   ou chaque observation est une ligne -- voir sequence_view). Pour chaque
   flux, le comptage retient donc le point qui a vu le PLUS de paquets :
   le plus complet des points d'observation, sans jamais additionner deux
   observations du meme paquet.
2. Les aretes sont ORIENTEES (src -> dst). Un echange TCP produit donc
   deux aretes, une par sens : c'est precisement ce qui permet de voir
   qu'un sens passe et que l'autre ne repond pas.

Couche : `netcross_report` peut importer `netcross_core`, jamais l'inverse.
"""

from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

DEFAULT_TOP_N = 15
"""Aretes conservees par defaut quand un top-N est demande. Un graphe
au-dela d'une quinzaine d'aretes cesse d'etre lisible a l'ecran, et la GUI
laisse de toute facon l'utilisateur relever ce plafond."""


@dataclass
class CommNode:
    """Un hote (adresse) du graphe.

    `packets`/`bytes` : volumes cumules, emis ET recus -- la taille du
    noeud repond a "qui parle beaucoup", pas a "qui emet beaucoup" (le sens
    est porte par les aretes).
    """

    host: str
    packets: int = 0
    bytes: int = 0
    protocols: set = field(default_factory=set)
    anomalies: int = 0


@dataclass
class CommEdge:
    """Un sens de communication entre deux hotes.

    `anomalies` : paquets porteurs d'un signal d'expertise tshark
    (`Pkt.expert_flags`) ou marques retransmission. C'est un COMPTAGE de
    signaux bruts, pas une severite : la severite appartient aux
    Finding/ExpertEvent, qui raisonnent par segment de capture et non par
    couple d'hotes.
    """

    src: str
    dst: str
    packets: int = 0
    bytes: int = 0
    protocols: set = field(default_factory=set)
    anomalies: int = 0
    flows: int = 0

    @property
    def label(self) -> str:
        logger.debug("CommEdge.label: retour chaîne formatée")
        return f"{self.src} -> {self.dst}"


@dataclass
class CommMap:
    """Graphe complet, deja filtre.

    `total_edges` : nombre d'aretes AVANT filtrage, pour que la GUI puisse
    afficher "15 aretes sur 132" plutot que laisser croire que le graphe
    est complet.
    """

    nodes: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    protocols: list = field(default_factory=list)
    total_edges: int = 0
    total_hosts: int = 0


def available_protocols(flows) -> list[str]:
    """Protocoles presents dans le dict `flows` de `correlate()`, tries --
    sert a remplir la liste deroulante de filtrage de la GUI sans que
    celle-ci ait a parcourir les paquets elle-meme."""
    logger.debug("available_protocols: flows={}", summarize(flows, "flows"))
    protos = set()
    for per_point in (flows or {}).values():
        for pkts in (per_point or {}).values():
            for pk in pkts or []:
                if pk.proto:
                    protos.add(pk.proto)
    logger.debug("available_protocols: retour sorted(…)")
    return sorted(protos)


def _representative_packets(per_point):
    """Paquets du point qui a vu le plus de paquets de ce flux (voir le
    choix de comptage 1 en tete de module). Liste vide si le flux n'a aucun
    paquet."""
    best = []
    for pkts in (per_point or {}).values():
        if len(pkts or []) > len(best):
            best = pkts
    logger.debug("_representative_packets: retour best or []")
    return best or []


def build_comm_map(flows, protocols=None, top_n=None, only_anomalies=False) -> CommMap:
    """Construit la cartographie a partir du dict `flows` de `correlate()`
    (`{cle: {point: [Pkt, ...]}}`).

    `protocols` : ensemble/liste de protocoles a conserver (None ou vide =
    tous). Filtre applique AU NIVEAU DU PAQUET, pas du flux : un flux
    tunnelise peut porter plusieurs protocoles.

    `top_n` : nombre d'aretes conservees, les plus volumineuses en octets
    (None ou <= 0 = toutes). Le tri secondaire est le libelle, pour que
    deux executions sur la meme capture donnent le meme graphe.

    `only_anomalies` : ne conserve que les aretes portant au moins un
    signal (retransmission ou `expert_flags`).

    Les noeuds sont recalcules APRES filtrage des aretes : un graphe qui
    afficherait des hotes sans arete laisserait croire a une communication
    filtree alors qu'il s'agit d'un residu du filtre.
    """
    logger.debug(
        "build_comm_map: flows={} protocols={} top_n={} only_anomalies={}",
        summarize(flows, "flows"),
        summarize(protocols, "protocols"),
        summarize(top_n, "top_n"),
        summarize(only_anomalies, "only_anomalies"),
    )
    wanted = {p for p in (protocols or []) if p}
    edges: dict[tuple[str, str], CommEdge] = {}
    protos_seen = set()

    for per_point in (flows or {}).values():
        packets = _representative_packets(per_point)
        touched = set()
        for pk in packets:
            if pk.proto:
                protos_seen.add(pk.proto)
            if wanted and pk.proto not in wanted:
                continue
            key = (pk.src, pk.dst)
            edge = edges.get(key)
            if edge is None:
                edge = edges[key] = CommEdge(src=pk.src, dst=pk.dst)
            edge.packets += 1
            edge.bytes += pk.length
            if pk.proto:
                edge.protocols.add(pk.proto)
            if pk.is_retransmission or pk.expert_flags:
                edge.anomalies += 1
            touched.add(key)
        for key in touched:
            edges[key].flows += 1

    all_edges = sorted(edges.values(), key=lambda e: (-e.bytes, e.label))
    total_hosts = len({host for e in all_edges for host in (e.src, e.dst)})
    kept = [e for e in all_edges if e.anomalies] if only_anomalies else list(all_edges)
    if top_n and top_n > 0:
        kept = kept[:top_n]

    nodes: dict[str, CommNode] = {}
    for edge in kept:
        for host in (edge.src, edge.dst):
            node = nodes.get(host)
            if node is None:
                node = nodes[host] = CommNode(host=host)
            node.packets += edge.packets
            node.bytes += edge.bytes
            node.protocols |= edge.protocols
            node.anomalies += edge.anomalies

    logger.debug("build_comm_map: retour CommMap(…)")
    return CommMap(
        nodes=sorted(nodes.values(), key=lambda n: (-n.bytes, n.host)),
        edges=kept,
        protocols=sorted(protos_seen),
        total_edges=len(all_edges),
        total_hosts=total_hosts,
    )


def format_comm_map(cmap, top_n=DEFAULT_TOP_N) -> str:
    """Rendu texte de la cartographie -- utilise par la GUI pour legender
    le graphe (et lisible sans interface graphique, ce qui rend la vue
    verifiable en console pendant le developpement)."""
    logger.debug("format_comm_map: cmap={} top_n={}", summarize(cmap, "cmap"), summarize(top_n, "top_n"))
    if not cmap.edges:
        logger.debug("format_comm_map: si not cmap.edges -> retour 'Aucune communication a afficher avec c…")
        return "Aucune communication a afficher avec ces filtres."
    lignes = [f"{len(cmap.edges)} arete(s) affichee(s) sur {cmap.total_edges}, {len(cmap.nodes)} hote(s)."]
    for edge in cmap.edges[:top_n]:
        protos = ",".join(sorted(edge.protocols)) or "?"
        anomalies = f"  anomalies={edge.anomalies}" if edge.anomalies else ""
        lignes.append(
            f"  {edge.label:45s} {edge.packets:7d} pq  {edge.bytes:10d} o  {protos:12s}  flux={edge.flows}{anomalies}"
        )
    if len(cmap.edges) > top_n:
        lignes.append(f"  ... {len(cmap.edges) - top_n} arete(s) supplementaire(s) non detaillee(s)")
    logger.debug("format_comm_map: retour '\\n'.join(…)")
    return "\n".join(lignes)
