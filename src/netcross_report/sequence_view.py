"""
netcross_report.sequence_view -- diagramme de sequence multi-hotes
(Job 14/issue #11, FEATURES.md section 6.5).

Le rapport savait deja dire "ce flux a perdu des paquets entre le point A
et le point B". Il ne savait pas montrer l'ECHANGE : qui parle a qui, dans
quel ordre, avec quel delai, et a quel point de capture chaque message a
ete vu. C'est exactement ce que dessine un diagramme de sequence, et c'est
la forme sous laquelle un operateur lit un handshake qui echoue ou une
requete qui reste sans reponse.

Une ligne = UN paquet vu a UN point. Le meme paquet physique traversant
deux points de capture produit donc DEUX lignes, et c'est voulu : le
decalage entre ces deux lignes est la mesure du temps de transit, c'est-a-
dire l'information que la capture multi-points est la seule a pouvoir
donner. Les fondre en une ligne unique reviendrait a jeter la seule
mesure qui justifie l'outil.

Ce module ne recalcule rien : il reordonne les `Pkt` deja groupes par
`correlate()` (dict `{point: [Pkt, ...]}` d'un seul flux, voir
`netcross_core.correlate.build_flows`). Aucun seuil, aucun verdict.

Couche : `netcross_report` peut importer `netcross_core`, jamais l'inverse.
"""

from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

DEFAULT_MAX_STEPS = 30
"""Nombre de lignes rendues par defaut. Un diagramme de sequence cesse
d'etre lisible bien avant la centaine de lignes, et un flux TCP soutenu en
compte des milliers : au-dela, la troncature est plus honnete qu'une image
illisible -- meme raisonnement que le plafonnement des exemples dans
Report (voir models.Report.*_examples)."""


@dataclass
class SequenceStep:
    """Un paquet, vu a un point de capture.

    `rel_ms` : date relative au premier paquet du flux, en ms -- un
    timestamp absolu n'a aucun interet de lecture ici, l'oeil suit des
    ecarts.

    `delta_ms` : ecart avec la ligne precedente du diagramme (toutes
    lignes confondues, tous points confondus), meme convention que
    `netcross_core.flow_timeline.PacketTiming.delta_ms`.

    `frame_number` : numero de trame tshark, ou `None` si la capture ne le
    portait pas -- c'est lui qui relie la ligne du diagramme au paquet dans
    Wireshark, et c'est la raison d'etre du critere d'acceptation "chaque
    ligne reliee a un paquet et un point".
    """

    ts: float
    rel_ms: float
    delta_ms: float
    src: str
    dst: str
    point: str
    length: int
    proto: str = ""
    sport: int | None = None
    dport: int | None = None
    flags: str = ""
    frame_number: int | None = None
    is_retransmission: bool = False

    @property
    def label(self) -> str:
        """Libelle court de la fleche : protocole + ports quand ils
        existent (UDP/TCP), drapeaux TCP s'ils sont connus, et la mention
        "retr." pour une retransmission -- c'est le detail qui explique un
        aller-retour apparemment duplique."""
        parts = [self.proto or "?"]
        if self.sport is not None and self.dport is not None:
            parts.append(f"{self.sport}->{self.dport}")
        if self.flags:
            parts.append(f"[{self.flags}]")
        if self.is_retransmission:
            parts.append("retr.")
        logger.debug("label: retour join(...)")
        return " ".join(parts)


@dataclass
class SequenceView:
    """Diagramme de sequence d'un flux : les hotes en colonnes, les
    paquets en lignes.

    `hosts` : adresses dans l'ordre d'apparition -- pas triees
    alphabetiquement : l'initiateur de l'echange doit rester a gauche,
    c'est ce qui rend le dessin lisible.

    `truncated` : nombre de paquets non rendus. Expose plutot que devine
    par l'appelant, pour que le PDF puisse l'ecrire noir sur blanc.
    """

    title: str = ""
    steps: list[SequenceStep] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    points: list[str] = field(default_factory=list)
    truncated: int = 0
    total_steps: int = 0


def build_sequence_view(packets_by_point, title="", max_steps=DEFAULT_MAX_STEPS) -> SequenceView:
    """Construit la vue de sequence d'UN flux a partir du dict
    `{point: [Pkt, ...]}` que `correlate()` produit deja pour ce flux.

    Les lignes sont triees par timestamp, puis par point a timestamp egal
    (deterministe : deux points peuvent horodater le meme paquet a la
    microseconde pres, et un diagramme qui change d'ordre d'une execution
    a l'autre n'est pas verifiable).

    Troncature : les `max_steps` PREMIERES lignes sont conservees, pas les
    plus grosses ni un echantillon reparti -- le debut d'un echange est ce
    qui porte le diagnostic (handshake, negociation, premiere requete), la
    suite est de la repetition.
    """
    logger.debug(
        "build_sequence_view: packets_by_point={} title={} max_steps={}",
        summarize(packets_by_point, "packets_by_point"),
        summarize(title, "title"),
        summarize(max_steps, "max_steps"),
    )
    packets = [pk for pkts in (packets_by_point or {}).values() for pk in (pkts or [])]
    view = SequenceView(title=title)
    if not packets:
        logger.debug("build_sequence_view: retour view")
        return view

    packets.sort(key=lambda pk: (pk.ts, pk.point, pk.frame_number or 0))
    view.total_steps = len(packets)
    origin = packets[0].ts
    kept = packets[: max_steps if max_steps and max_steps > 0 else len(packets)]
    view.truncated = len(packets) - len(kept)

    prev_ts = None
    for pk in kept:
        view.steps.append(
            SequenceStep(
                ts=pk.ts,
                rel_ms=(pk.ts - origin) * 1000.0,
                delta_ms=0.0 if prev_ts is None else (pk.ts - prev_ts) * 1000.0,
                src=pk.src,
                dst=pk.dst,
                point=pk.point,
                length=pk.length,
                proto=pk.proto or "",
                sport=pk.sport,
                dport=pk.dport,
                flags=pk.flags or "",
                frame_number=pk.frame_number,
                is_retransmission=bool(pk.is_retransmission),
            )
        )
        prev_ts = pk.ts

    for step in view.steps:
        for host in (step.src, step.dst):
            if host not in view.hosts:
                view.hosts.append(host)
        if step.point not in view.points:
            view.points.append(step.point)
    logger.debug("build_sequence_view: retour view")
    return view


def flow_title(flow) -> str:
    """Titre lisible d'un `Flow` (netcross_core.expert_model) : ses
    extremites et son protocole quand la cle les porte. La cle de flux est
    un tuple technique (voir `correlate.flow_key`), y compris la variante
    `("NAT", ...)` du mode --nat-tolerant : on ne suppose donc jamais sa
    forme, on lit ce qui est lisible et on retombe sur `str(key)`.
    """
    endpoints = getattr(flow, "endpoints", None)
    key = getattr(flow, "key", ())
    proto = key[0] if key and isinstance(key[0], str) and key[0] != "NAT" else ""
    if endpoints:
        base = f"{endpoints[0]} <-> {endpoints[1]}"
        logger.debug("flow_title: retour strip(...)")
        return f"{proto} {base}".strip()
    logger.debug("flow_title: retour str(...)")
    return str(key)


def top_flow_views(flows, flow_objects=None, max_flows=1, max_steps=DEFAULT_MAX_STEPS):
    """Vues de sequence des flux les plus volumineux du dict `flows`
    (`{cle: {point: [Pkt, ...]}}` de `correlate()`).

    Tri par nombre de paquets decroissant, cle en second critere pour un
    ordre stable. Le flux le plus volumineux n'est pas forcement le plus
    interessant -- mais c'est le seul critere disponible sans introduire
    ici un jugement de gravite, qui appartient aux Finding/ExpertEvent.
    L'appelant qui veut un autre flux appelle `build_sequence_view()`
    directement.

    `flow_objects` : liste de `Flow` optionnelle, seulement utilisee pour
    intituler les diagrammes (voir `flow_title`).
    """
    logger.debug(
        "top_flow_views: flows={} flow_objects={} max_flows={} max_steps={}",
        summarize(flows, "flows"),
        summarize(flow_objects, "flow_objects"),
        summarize(max_flows, "max_flows"),
        summarize(max_steps, "max_steps"),
    )
    titles = {getattr(f, "key", None): flow_title(f) for f in flow_objects or []}
    ranked = sorted(
        (flows or {}).items(),
        key=lambda item: (-sum(len(p or []) for p in item[1].values()), str(item[0])),
    )
    views = []
    for key, per_point in ranked[: max(max_flows, 0)]:
        views.append(build_sequence_view(per_point, title=titles.get(key) or str(key), max_steps=max_steps))
    logger.debug("top_flow_views: retour views")
    return views
