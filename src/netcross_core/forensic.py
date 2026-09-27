"""
netcross_core.forensic -- index de correlation bidirectionnel evenement ↔
flow ↔ paquet (Job 8/issue #5, §6.3 et §6.14 de FEATURES.md).

Construit une couche d'indexation permettant de naviguer dans les deux
sens :

- **Evenement → flows → paquets** : partant d'un `ExpertEvent`, retrouver
  les flux puis les paquets qui le justifient.
- **Paquet → flow → evenement** : partant d'un paquet (point + numero de
  trame), retrouver le flux auquel il appartient, puis les evenements qui
  concernent ce flux ou ce segment.

L'index est construit a partir de trois sources deja disponibles :
1. `all_packets` (liste de `Pkt`) -- pour l'index paquet → flow
2. `flows` (dict produit par `correlate()`) -- pour l'index flow → paquets
3. `events` (liste d'`ExpertEvent`) -- pour l'index event → flows/paquets

Strategie de mapping event → flow (par ordre de priorite) :
1. Si `ExpertEvent.flow_keys` est non vide (source "tshark"), matching
   direct par cle de flux.
2. Sinon, si `ExpertEvent.evidence` contient des `EvidenceLink.packet`
   (`PacketEvidence`), matching par paquet → flow_key.
3. Sinon, matching par segment : les flows qui passent par le point
   nomme dans `event.segment` (ex: "A", "B") ou par la paire "A -> B".

Ce module est un CONSOMMATEUR des donnees deja calculees (Pkt, Flow,
ExpertEvent) -- il ne recalcule rien, ne reparse aucune capture, et ne
modifie pas les objets sources. L'index est construit en UNE passe sur
chaque source a l'initialisation.

Seule exception, definie juste avant la classe : detect_cross_capture_duplicates()
(Job 41/issue #161) MARQUE `Pkt.is_duplicate` en place -- c'est son role,
et elle est appelee AVANT correlate()/analyse(), pas sur leurs sorties.
"""

from __future__ import annotations

import json
import os
from bisect import bisect_left
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from netcross_core.correlate import flow_key
from netcross_core.expert_model import ExpertEvent, Flow, PacketEvidence
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import (
    SEQ_GAP_CAPTURE_DROP,
    SEQ_GAP_INDETERMINATE,
    SEQ_GAP_NETWORK_LOSS,
    ChecksumError,
    PacketAnnotation,
    Pkt,
    SequenceGap,
)

logger = get_logger(__name__)

# -- Detection de doublons inter-captures (Job 41/issue #161) ---------------

# Delta maximal (ms) entre deux observations du meme payload a deux points
# differents pour les considerer comme UN doublon plutot que comme le meme
# paquet vu successivement le long du chemin. Valeur volontairement basse :
# une capture multi-points sert justement a voir le meme paquet a plusieurs
# points, avec la latence qui les separe -- un seuil trop large marquerait
# ce trafic normal comme doublon. A regler sous la plus petite latence
# attendue entre deux points (voir detect_cross_capture_duplicates).
DEFAULT_DUPLICATE_THRESHOLD_MS = 1.0


def detect_cross_capture_duplicates(
    packets: list[Pkt],
    threshold_ms: float = DEFAULT_DUPLICATE_THRESHOLD_MS,
) -> dict[tuple[str, str], int]:
    """Detecte et marque les paquets dupliques entre points de capture.

    Cas vise : un port miroir (SPAN) qui renvoie le meme trafic a deux
    sondes, si bien que le meme paquet est capture deux fois presque
    simultanement -- les compteurs de paquets/octets sont alors doubles.

    Critere de doublon (Job 41) : meme `payload_hash` ET `ts` a moins de
    `threshold_ms` d'un paquet DEJA vu a un AUTRE point. Le plus ancien
    paquet du groupe est l'« original » ; le ou les suivants (a un autre
    point, dans la fenetre) recoivent `is_duplicate = True`. A egalite
    stricte de `ts`, l'ordre de la liste `packets` departage (tri stable).
    Un doublon n'est compare qu'aux ORIGINAUX, jamais a un autre doublon :
    pas de derive en chaine (A -> B a 0,9 ms -> C a 1,8 ms de A n'est pas
    un doublon de C).

    Ne compte jamais deux paquets d'un MEME point (c'est le domaine de la
    detection de retransmissions, deja couverte ailleurs) ni les paquets
    sans `payload_hash` (ACK purs, SYN...) -- sans contenu, rien ne permet
    d'affirmer que deux paquets sont le meme.

    LIMITE ASSUMEE : la seule difference entre un doublon et le meme paquet
    vu en deux points successifs du chemin est le delai entre les deux
    observations. Si la latence reelle entre deux points est inferieure a
    `threshold_ms`, le trafic normal de ce segment sera marque doublon :
    ajuster le seuil (et/ou ne pas activer la detection) en connaissance
    de la topologie.

    Effets de bord : REINITIALISE `is_duplicate` a False sur tous les
    paquets de `packets` avant de recalculer (rappeler avec un autre seuil
    ne laisse aucune marque perimee), puis marque les doublons en place --
    contrairement a ForensicIndex, ce n'est pas un consommateur passif.

    Retourne le nombre de doublons par paire de points NON ORDONNEE
    (tuple trie alphabetiquement), forme attendue par
    `Report.duplicate_count`. Dict vide si aucun doublon.

    Raises ValueError si `threshold_ms` est negatif (0 est accepte et ne
    detecte rien : le critere est un delta STRICTEMENT inferieur).
    """
    if threshold_ms < 0:
        logger.debug("detect_cross_capture_duplicates: seuil negatif {} refuse", threshold_ms)
        raise ValueError(f"threshold_ms doit etre >= 0, recu {threshold_ms!r}")

    by_hash: dict[str, list[Pkt]] = defaultdict(list)
    for pk in packets:
        pk.is_duplicate = False
        if pk.payload_hash is not None:
            by_hash[pk.payload_hash].append(pk)

    threshold_s = threshold_ms / 1000.0
    counts: dict[tuple[str, str], int] = defaultdict(int)

    for group in by_hash.values():
        if len(group) < 2:
            continue
        group.sort(key=lambda pk: pk.ts)
        # originaux encore dans la fenetre : trie par ts croissant, donc tout
        # original trop ancien pour le paquet courant l'est aussi pour tous
        # les suivants -- `start` ne fait qu'avancer (O(n) par groupe au
        # lieu de O(n^2) sur un payload tres repete, ex: keepalive).
        window: list[Pkt] = []
        start = 0  # index du plus ancien original encore dans la fenetre
        for pk in group:
            while start < len(window) and pk.ts - window[start].ts >= threshold_s:
                start += 1
            original = next((o for o in window[start:] if o.point != pk.point), None)
            if original is None:
                window.append(pk)
                continue
            pk.is_duplicate = True
            pair = (original.point, pk.point) if original.point <= pk.point else (pk.point, original.point)
            counts[pair] += 1

    logger.debug(
        "detect_cross_capture_duplicates: {} empreinte(s), seuil {} ms, {} doublon(s) sur {} paire(s) de points",
        len(by_hash),
        threshold_ms,
        sum(counts.values()),
        len(counts),
    )
    return dict(counts)


class ForensicIndex:
    """Index bidirectionnel evenement ↔ flow ↔ paquet.

    Construit en une passe a l'initialisation. Toutes les methodes de
    recherche sont en O(1) ou O(k) ou k est le nombre de resultats.
    """

    def __init__(
        self,
        all_packets: list[Pkt],
        flows: dict[tuple, dict[str, list[Pkt]]],
        events: list[ExpertEvent],
        nat_tolerant: bool = False,
        nat_window_ms: int = 200,
    ):
        # Index paquet → flow_key : (point, frame_number) -> flow_key
        self._packet_to_key: dict[tuple[str, int], tuple] = {}
        for pk in all_packets:
            if pk.frame_number is not None:
                k = flow_key(pk, nat_tolerant, nat_window_ms)
                self._packet_to_key[(pk.point, pk.frame_number)] = k

        # Index flow_key → Flow (objet type)
        self._flow_by_key: dict[tuple, Flow] = {}
        # Index flow_key → paquets par point
        self._packets_by_key: dict[tuple, dict[str, list[Pkt]]] = {}
        for fkey, per_point in flows.items():
            self._packets_by_key[fkey] = per_point
            f = Flow(key=fkey)
            for point, pkts in per_point.items():
                if not pkts:
                    continue
                f.points.append(point)
                f.packet_count[point] = len(pkts)
                f.byte_count[point] = sum(pk.length for pk in pkts)
                f.first_ts[point] = min(pk.ts for pk in pkts)
                f.last_ts[point] = max(pk.ts for pk in pkts)
                if f.endpoints is None:
                    f.endpoints = (min(pkts[0].src, pkts[0].dst), max(pkts[0].src, pkts[0].dst))
            self._flow_by_key[fkey] = f

        # Index segment → events
        self._events_by_segment: dict[str, list[ExpertEvent]] = defaultdict(list)
        # Index flow_key → events (quand flow_keys est peuple)
        self._events_by_flow_key: dict[tuple, list[ExpertEvent]] = defaultdict(list)
        for ev in events:
            self._events_by_segment[ev.segment].append(ev)
            for fk in ev.flow_keys:
                self._events_by_flow_key[fk].append(ev)
        logger.debug(
            "ForensicIndex: {} paquet(s) indexe(s), {} flux, {} segment(s) d'evenements",
            len(self._packet_to_key),
            len(self._flow_by_key),
            len(self._events_by_segment),
        )

    # -- Evenement → flows ------------------------------------------------

    def event_to_flows(self, event: ExpertEvent) -> list[Flow]:
        """Retourne les flux lies a un ExpertEvent, par priorite :
        1. flow_keys de l'evenement (source "tshark")
        2. paquets d'evidence → flow_key
        3. flows passant par le segment (point ou paire "A -> B")
        """
        flows: list[Flow] = []
        seen_keys: set[tuple] = set()

        # 1. flow_keys direct (tshark)
        for fk in event.flow_keys:
            if fk in self._flow_by_key and fk not in seen_keys:
                flows.append(self._flow_by_key[fk])
                seen_keys.add(fk)

        # 2. evidence → PacketEvidence → flow_key
        if not flows:
            logger.trace("event_to_flows: aucun flow_key direct, repli sur les preuves paquet")
            for link in event.evidence:
                if link.packet and link.packet.point and link.packet.frame_number is not None:
                    pk_key = (link.packet.point, link.packet.frame_number)
                    found_key: tuple | None = self._packet_to_key.get(pk_key)
                    if found_key and found_key not in seen_keys:
                        flows.append(self._flow_by_key[found_key])
                        seen_keys.add(found_key)

        # 3. matching par segment (point ou paire "A -> B")
        if not flows:
            logger.debug("event_to_flows: repli sur le segment {!r}", event.segment)
            segment = event.segment
            points: list[str] = []
            if " -> " in segment:
                parts = segment.split(" -> ")
                points = [p.strip() for p in parts if p.strip()]
            else:
                points = [segment]

            for fk, flow in self._flow_by_key.items():
                if any(p in flow.points for p in points) and fk not in seen_keys:
                    flows.append(flow)
                    seen_keys.add(fk)

        logger.trace("event_to_flows: {} flux lie(s)", len(flows))
        logger.debug("ForensicIndex.event_to_flows: retour flows={}", summarize(flows, "flows"))
        return flows

    # -- Evenement → paquets -----------------------------------------------

    def event_to_packets(self, event: ExpertEvent) -> list[PacketEvidence]:
        """Retourne les paquets qui justifient un ExpertEvent : d'abord
        ceux references dans evidence/packet_evidence, puis les paquets
        des flows lies (complement)."""
        pkts: list[PacketEvidence] = []
        seen: set[tuple[str, int]] = set()

        # 1. packet_evidence (tshark, liste complete)
        for pe in event.packet_evidence:
            key = (pe.point, pe.frame_number)
            if key not in seen:
                pkts.append(pe)
                seen.add(key)

        # 2. evidence → EvidenceLink.packet
        for link in event.evidence:
            if link.packet:
                key = (link.packet.point, link.packet.frame_number)
                if key not in seen:
                    pkts.append(link.packet)
                    seen.add(key)

        # 3. complement : paquets des flows lies
        for flow in self.event_to_flows(event):
            per_point = self._packets_by_key.get(flow.key, {})
            for point, pk_list in per_point.items():
                for pk in pk_list:
                    if pk.frame_number is not None:
                        key = (point, pk.frame_number)
                        if key not in seen:
                            pkts.append(PacketEvidence(point=point, frame_number=pk.frame_number))
                            seen.add(key)

        logger.trace("event_to_packets: {} paquet(s) de preuve", len(pkts))
        logger.debug("ForensicIndex.event_to_packets: retour pkts={}", summarize(pkts, "pkts"))
        return pkts

    # -- Paquet → flow ------------------------------------------------------

    def packet_to_flow(self, point: str, frame_number: int) -> Flow | None:
        """Retourne le flow auquel appartient un paquet (point + numero
        de trame), ou None si le paquet n'est pas indexe."""
        pk_key = (point, frame_number)
        fk = self._packet_to_key.get(pk_key)
        if fk is None:
            logger.debug("packet_to_flow: trame {} du point {} hors index", frame_number, point)
            return None
        logger.debug("ForensicIndex.packet_to_flow: retour self._flow_by_key.get(…)")
        return self._flow_by_key.get(fk)

    # -- Flow → evenements --------------------------------------------------

    def flow_to_events(self, flow: Flow) -> list[ExpertEvent]:
        """Retourne les evenements lies a un flow : d'abord par flow_keys
        direct (tshark), puis par segment (les points du flow)."""
        events: list[ExpertEvent] = []
        seen: set[int] = set()

        # 1. flow_key direct (tshark)
        for ev in self._events_by_flow_key.get(flow.key, []):
            if id(ev) not in seen:
                events.append(ev)
                seen.add(id(ev))

        # 2. matching par segment : les points du flow
        if not events:
            logger.trace("flow_to_events: aucun evenement par flow_key, repli sur les points {}", flow.points)
            for point in flow.points:
                for ev in self._events_by_segment.get(point, []):
                    if id(ev) not in seen:
                        events.append(ev)
                        seen.add(id(ev))

        logger.debug("ForensicIndex.flow_to_events: retour events={}", summarize(events, "events"))
        return events

    # -- Flow → paquets -----------------------------------------------------

    def flow_to_packets(self, flow: Flow) -> list[Pkt]:
        """Retourne tous les paquets d'un flow, tous points confondus,
        dans l'ordre de point puis d'arrivee."""
        per_point = self._packets_by_key.get(flow.key, {})
        result: list[Pkt] = []
        for point in flow.points:
            result.extend(per_point.get(point, []))
        logger.trace("flow_to_packets: {} paquet(s) sur {} point(s)", len(result), len(flow.points))
        logger.debug("ForensicIndex.flow_to_packets: retour result={}", summarize(result, "result"))
        return result


# -- Etiquetage et signets sur paquets (Job 40/issue #160) -------------------
#
# Sidecar JSON : par convention `<capture>.annotations.json` a cote du
# fichier de capture (meme repertoire, meme radical + suffixe dedie -- pas
# d'extension `.pcap*.json` ambigue avec un eventuel --json-report). Le
# sidecar est TOUJOURS optionnel : son absence n'est pas une erreur, elle
# signifie simplement "aucune annotation" (voir read_annotations).
#
# Format sur disque : liste de dicts a plat (un par PacketAnnotation),
# volontairement PAS un objet englobant versionne -- symetrique du choix
# deja fait par json_report.py pour --json-report (pas de sur-ingenierie
# tant qu'un second format n'est pas requis).


def annotations_sidecar_path(capture_path: str) -> str:
    """Chemin du sidecar JSON associe a une capture (`<capture>.annotations.json`).

    Ne verifie PAS l'existence du fichier -- utiliser `read_annotations`
    pour une lecture tolerante a l'absence."""
    logger.debug("annotations_sidecar_path: retour chaîne formatée")
    return f"{capture_path}.annotations.json"


def read_annotations(capture_path: str) -> list[PacketAnnotation]:
    """Lit les annotations du sidecar associe a `capture_path`.

    Retourne une liste VIDE (pas d'exception) si le sidecar n'existe pas
    -- une capture sans annotation est le cas courant, pas une erreur.
    Un sidecar present mais illisible (JSON invalide) est en revanche une
    erreur reelle (fichier corrompu) et remonte l'exception."""
    path = annotations_sidecar_path(capture_path)
    if not os.path.exists(path):
        logger.debug("read_annotations: aucun fichier d'annotations {}", path)
        return []
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    logger.debug("read_annotations: {} annotation(s) lue(s) depuis {}", len(raw), path)
    return [
        PacketAnnotation(
            frame_number=item["frame_number"],
            tag=item["tag"],
            comment=item.get("comment", ""),
            color=item.get("color"),
        )
        for item in raw
    ]


def write_annotations(capture_path: str, annotations: list[PacketAnnotation]) -> None:
    """Ecrit (remplace) le sidecar d'annotations associe a `capture_path`.

    Ecriture integrale (pas de fusion avec un sidecar preexistant) --
    l'appelant est responsable de relire puis de composer la liste
    complete avant d'ecrire, meme discipline que les autres sidecars/
    exports de ce projet (pas d'etat cache cote disque)."""
    path = annotations_sidecar_path(capture_path)
    payload = [
        {
            "frame_number": ann.frame_number,
            "tag": ann.tag,
            "comment": ann.comment,
            "color": ann.color,
        }
        for ann in annotations
    ]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    logger.debug("write_annotations: {} annotation(s) ecrite(s) dans {}", len(payload), path)


def annotations_by_tag(annotations: list[PacketAnnotation]) -> dict[str, list[PacketAnnotation]]:
    """Regroupe des annotations par etiquette, pour la vue GUI filtrable
    par tag (voir netcross_gtk4.annotations_view) et pour la section
    annotations du rapport texte."""
    grouped: dict[str, list[PacketAnnotation]] = defaultdict(list)
    for ann in annotations:
        grouped[ann.tag].append(ann)
    logger.debug("annotations_by_tag: {} annotation(s) en {} etiquette(s)", len(annotations), len(grouped))
    return dict(grouped)


# -- Trous de sequence TCP (Job 42/issue #162) --------------------------------
#
# Un trou de sequence est un intervalle d'octets TCP jamais vu a un point de
# capture alors que des octets POSTERIEURS l'ont ete, sans qu'aucun segment
# (retransmission, paquet arrive hors-ordre) ne le comble plus tard dans la
# capture. Le point de capture seul ne dit pas POURQUOI ces octets manquent ;
# l'ACK cumulatif du recepteur, vu au meme point, departage :
#
# - trou de CAPTURE : le recepteur a acquitte ces octets (ACK >= fin du trou)
#   sans qu'aucune retransmission ait ete necessaire -> ils ont traverse le
#   reseau, c'est la capture qui les a rates (tampon noyau/carte sature, port
#   SPAN sature, visibilite partielle...) ;
# - perte RESEAU : le recepteur continue d'acquitter mais reste bloque a/dans
#   le trou (ACK dupliques) et aucune retransmission n'est visible -> ces
#   octets ne lui sont pas parvenus (perte non recuperee avant la fin de la
#   capture) ;
# - INDETERMINE : pas de retour exploitable du recepteur a ce point apres le
#   trou (sens retour non capture, fin de capture...) -> on ne tranche pas.

_SEQ_MODULO = 1 << 32
_SEQ_HALF = 1 << 31

# Plus grand trou plausible : la fenetre TCP est bornee a 2**30 octets (RFC
# 7323, Window Scale <= 14). Un ecart superieur entre deux segments successifs
# n'est pas une perte au sein d'une fenetre (capture reprise en cours de route,
# autre connexion sur le meme 5-uplet...) : on resynchronise au lieu de
# signaler un trou geant.
_MAX_PLAUSIBLE_GAP_BYTES = 1 << 30

# (point, src, sport, dst, dport) : un sens d'une connexion TCP a un point.
_StreamKey = tuple[str, str, int, str, int]


def _seq_delta(a: int, b: int) -> int:
    """a - b en arithmetique modulo 2**32, ramene dans [-2**31, 2**31[ : positif
    si a est "apres" b sur le cercle des numeros de sequence (gere le retour a
    zero du compteur de 32 bits)."""
    logger.debug("_seq_delta: retour (a - b + _SEQ_HALF) % _SEQ_MODULO - _SEQ_HALF")
    return ((a - b + _SEQ_HALF) % _SEQ_MODULO) - _SEQ_HALF


def _has_flag(pk: Pkt, letter: str) -> bool:
    """Drapeau TCP leve ? `Pkt.flags` est la chaine positionnelle de tshark
    (tcp.flags.str) : une lettre (S, F, A, R...) par drapeau actif."""
    logger.debug("_has_flag: retour pk.flags is not None and letter in pk.flags")
    return pk.flags is not None and letter in pk.flags


@dataclass(slots=True)
class _OpenGap:
    """Trou en cours de suivi dans _track_stream : octets [start, start+length)."""

    start: int
    length: int
    prev_ts: float  # horodatage du segment qui precede le trou
    reveal_frame: int | None  # trame du premier segment recu apres le trou...
    reveal_ts: float  # ... et son horodatage
    epoch_end_ts: float = float("inf")  # fin de la connexion suivie (nouveau SYN), sinon +inf


def _fill_gaps(gaps: list[_OpenGap], start: int, span: int) -> list[_OpenGap]:
    """Retire des trous ouverts les octets [start, start+span) qu'un segment
    (retransmission, paquet hors-ordre) vient de couvrir : un trou peut
    disparaitre, rester intact, retrecir ou se scinder en deux."""
    remaining: list[_OpenGap] = []
    for gap in gaps:
        offset = _seq_delta(start, gap.start)
        lo = max(offset, 0)
        hi = min(offset + span, gap.length)
        if lo >= hi:
            remaining.append(gap)
            continue
        logger.trace("_fill_gaps: trou {}+{} comble sur [{}, {}[", gap.start, gap.length, lo, hi)
        if lo > 0:
            remaining.append(_OpenGap(gap.start, lo, gap.prev_ts, gap.reveal_frame, gap.reveal_ts))
        if hi < gap.length:
            tail_start = (gap.start + hi) % _SEQ_MODULO
            remaining.append(_OpenGap(tail_start, gap.length - hi, gap.prev_ts, gap.reveal_frame, gap.reveal_ts))
    logger.debug("_fill_gaps: retour remaining={}", summarize(remaining, "remaining"))
    return remaining


def _track_stream(ordered: list[Pkt]) -> list[_OpenGap]:
    """Suit UN sens d'une connexion TCP a UN point de capture (paquets deja
    tries par ordre de capture) et renvoie les trous jamais combles.

    `next_seq` est le premier numero de sequence pas encore couvert :
    - segment a next_seq : le flux avance normalement ;
    - segment au-dela : les octets [next_seq, seq) manquent -> trou ouvert ;
    - segment en-deca (retransmission, hors-ordre, recouvrement) : il comble
      tout ou partie des trous ouverts.
    Un segment sans octet de donnees ni SYN/FIN (ACK pur, RST, keep-alive
    vide...) ne consomme aucun numero de sequence : il est ignore, son seq ne
    prouve aucun trou. Un nouveau SYN (nouvelle connexion sur le meme 5-uplet)
    ou un ecart implausible clot la connexion suivie et repart de zero ; un SYN
    retransmis (meme numero de sequence initial) ne remet rien a zero."""
    finished: list[_OpenGap] = []
    open_gaps: list[_OpenGap] = []
    next_seq: int | None = None
    isn: int | None = None
    last_ts = 0.0

    def close_epoch(ts: float) -> None:
        if open_gaps:
            logger.trace("_track_stream: fin d'epoque a {}, {} trou(s) cloture(s)", ts, len(open_gaps))
        for gap in open_gaps:
            gap.epoch_end_ts = ts
        finished.extend(open_gaps)
        open_gaps.clear()
        logger.debug("_track_stream.close_epoch: fin")

    for pk in ordered:
        if pk.tcp_len is None or pk.seq is None:
            # longueur inconnue : la borne suivante n'est plus calculable, on
            # repart de zero plutot que de fabriquer un faux trou
            logger.trace("_track_stream: trame {} sans longueur/sequence TCP, suivi reinitialise", pk.frame_number)
            finished.extend(open_gaps)
            open_gaps.clear()
            next_seq = None
            continue
        syn = _has_flag(pk, "S")
        span = pk.tcp_len + (1 if syn else 0) + (1 if _has_flag(pk, "F") else 0)
        if span == 0:
            continue
        seq = pk.seq
        end = (seq + span) % _SEQ_MODULO
        if syn and seq != isn:
            close_epoch(pk.ts)
            isn = seq
            next_seq, last_ts = end, pk.ts
            continue
        if next_seq is None:
            next_seq, last_ts = end, pk.ts
            continue
        delta = _seq_delta(seq, next_seq)
        if delta > 0:
            if delta > _MAX_PLAUSIBLE_GAP_BYTES:
                logger.trace("_track_stream: saut de {} octets invraisemblable, nouvelle epoque", delta)
                close_epoch(pk.ts)
            else:
                open_gaps.append(_OpenGap(next_seq, delta, last_ts, pk.frame_number, pk.ts))
            next_seq, last_ts = end, pk.ts
        elif delta == 0:
            next_seq, last_ts = end, pk.ts
        else:
            if open_gaps:
                open_gaps[:] = _fill_gaps(open_gaps, seq, span)
            if _seq_delta(end, next_seq) > 0:
                next_seq, last_ts = end, pk.ts
    finished.extend(open_gaps)
    if finished:
        logger.trace("_track_stream: {} paquet(s), {} trou(s) de sequence", len(ordered), len(finished))
    logger.debug("_track_stream: retour finished={}", summarize(finished, "finished"))
    return finished


def _classify_gap(gap: _OpenGap, ack_ts: list[float], ack_nums: list[int]) -> tuple[str, str]:
    """Cause d'un trou (SEQ_GAP_*) et sa justification, d'apres les ACK du
    recepteur vus au meme point (`ack_ts` trie, `ack_nums` parallele). Seuls
    comptent les ACK posterieurs au segment qui precede le trou et anterieurs a
    la fin de la connexion suivie (un ACK d'une connexion ulterieure sur le
    meme 5-uplet n'a aucun sens ici)."""
    end = (gap.start + gap.length) % _SEQ_MODULO
    logger.trace("_classify_gap: trou {}..{} ({} octets), {} ACK(s)", gap.start, end, gap.length, len(ack_ts))
    first = bisect_left(ack_ts, gap.prev_ts)
    last = bisect_left(ack_ts, gap.epoch_end_ts)
    for i in range(first, last):
        if _seq_delta(ack_nums[i], end) >= 0:
            logger.debug("_classify_gap: si _seq_delta(ack_nums[i], end) >= 0 -> retour tuple de 2")
            return (
                SEQ_GAP_CAPTURE_DROP,
                f"ACK {ack_nums[i]} >= fin du trou ({end}) : octets acquittes par le recepteur "
                "sans retransmission, mais absents de la capture",
            )
    after = bisect_left(ack_ts, gap.reveal_ts)
    if after < last:
        stuck = max(ack_nums[after:last], key=lambda a: _seq_delta(a, gap.start))
        if _seq_delta(stuck, gap.start) >= 0:
            logger.debug("_classify_gap: si _seq_delta(stuck, gap.start) >= 0 -> retour tuple de 2")
            return (
                SEQ_GAP_NETWORK_LOSS,
                f"ACK bloque a {stuck} (< fin du trou {end}) : octets non acquittes, "
                "aucune retransmission dans la capture",
            )
        logger.debug("_classify_gap: si after < last -> retour tuple de 2")
        return (
            SEQ_GAP_INDETERMINATE,
            f"ACK du recepteur en retard sur le trou ({stuck} < debut du trou {gap.start}) : impossible de conclure",
        )
    logger.debug("_classify_gap: retour tuple de 2")
    return (SEQ_GAP_INDETERMINATE, "aucun ACK du recepteur observe a ce point apres le trou : impossible de conclure")


def detect_sequence_gaps(packets: Iterable[Pkt]) -> list[SequenceGap]:
    """Trous de sequence TCP des connexions presentes dans `packets`.

    `packets` : les paquets d'un ou plusieurs flux (typiquement `all_packets`
    d'analyse()). Ils sont regroupes par point de capture et par SENS de
    connexion (5-uplet oriente) -- les "flows" de correlate() ne conviennent pas
    comme unite de suivi : leur cle contient le numero de sequence (key_id), un
    "flow" est donc un unique segment vu a plusieurs points, pas une connexion.

    Ne sont rapportes que les octets jamais combles avant la fin de la capture :
    un paquet hors-ordre ou une retransmission qui remplit le trou l'annule.
    Chaque trou est ensuite classe (capture / reseau / indetermine) grace aux
    ACK inverses du meme point, voir l'en-tete de section. TCP uniquement : UDP
    n'a pas de numerotation de transport (la perte RTP par numero de sequence
    est deja traitee par l'analyse RTP).

    Liste triee par (point, horodatage du segment qui revele le trou)."""
    streams: dict[_StreamKey, list[Pkt]] = defaultdict(list)
    for pk in packets:
        if pk.proto == "TCP" and pk.seq is not None and pk.sport is not None and pk.dport is not None:
            streams[(pk.point, pk.src, pk.sport, pk.dst, pk.dport)].append(pk)

    found: list[tuple[_StreamKey, _OpenGap]] = []
    for key, pkts in streams.items():
        pkts.sort(key=lambda pk: pk.ts)  # tri stable : l'ordre du fichier departage les ex aequo
        found.extend((key, gap) for gap in _track_stream(pkts))
    if not found:
        logger.debug("detect_sequence_gaps: {} flux TCP, aucun trou de sequence", len(streams))
        return []

    acks_by_stream: dict[_StreamKey, tuple[list[float], list[int]]] = {}
    gaps: list[SequenceGap] = []
    for key, gap in found:
        point, src, sport, dst, dport = key
        reverse = (point, dst, dport, src, sport)
        if reverse not in acks_by_stream:
            acks = sorted(
                ((pk.ts, pk.ack) for pk in streams.get(reverse, ()) if pk.ack is not None and _has_flag(pk, "A")),
                key=lambda entry: entry[0],
            )
            acks_by_stream[reverse] = ([ts for ts, _ in acks], [ack for _, ack in acks])
        cause, evidence = _classify_gap(gap, *acks_by_stream[reverse])
        gaps.append(
            SequenceGap(
                point=point,
                src=src,
                sport=sport,
                dst=dst,
                dport=dport,
                start_seq=gap.start,
                end_seq=(gap.start + gap.length) % _SEQ_MODULO,
                missing_bytes=gap.length,
                ts=gap.reveal_ts,
                frame_number=gap.reveal_frame,
                cause=cause,
                evidence=evidence,
            )
        )
    gaps.sort(key=lambda g: (g.point, g.ts, g.start_seq))
    causes: dict[str, int] = defaultdict(int)
    for g in gaps:
        causes[g.cause] += 1
    logger.debug("detect_sequence_gaps: {} flux TCP, {} trou(s), causes {}", len(streams), len(gaps), dict(causes))
    return gaps


# -- Integrite/qualite de capture : validation des checksums IP/TCP/UDP -----
# (Job 43/issue #163)
#
# validate_checksums() est un CONSOMMATEUR pur des champs de checksum deja
# extraits par pcap_parser.packet.build_packet() (ip_checksum/tcp_checksum/
# udp_checksum + leur pendant *_checksum_bad, voir Pkt) -- comme le reste de
# ce module, aucune somme de controle n'est recalculee ici : Netcross lit le
# verdict que tshark a deja rendu (validation activee par defaut, voir
# pcap_parser.ek_source.DEFAULT_PREFS).


def validate_checksums(packets: Iterable[Pkt]) -> list[ChecksumError]:
    """Valide les checksums IP/TCP/UDP d'une liste de paquets deja parses.

    Un paquet est signale (`ChecksumError`) UNIQUEMENT si tshark a
    explicitement rendu son checksum "Bad" (`*_checksum_bad is True`) ET
    que la valeur brute recue n'est PAS `0x0000` : ce cas particulier est
    la signature de l'offload materiel (la carte reseau calcule le
    checksum a l'emission, jamais rempli dans le paquet tel que capture),
    pas une vraie corruption -- distinguer les deux etait explicitement
    le second critere de l'issue, verifie empiriquement (tshark rend
    "Bad" pour un checksum offload a 0x0000, la valeur recalculee ne
    valant quasiment jamais elle-meme 0x0000).

    Un paquet sans verdict exploitable (`*_checksum_bad is None` --
    checksum absent, ex: IP en IPv6 qui n'a pas de checksum d'en-tete, ou
    statut "Unverified" si la validation tshark est desactivee) n'est
    jamais signale : l'absence de donnee n'est pas une preuve
    d'invalidite."""
    errors: list[ChecksumError] = []
    for pk in packets:
        for protocol, checksum, is_bad in (
            ("IP", pk.ip_checksum, pk.ip_checksum_bad),
            ("TCP", pk.tcp_checksum, pk.tcp_checksum_bad),
            ("UDP", pk.udp_checksum, pk.udp_checksum_bad),
        ):
            if checksum is None or is_bad is None:
                continue
            if checksum.lower() == "0x0000":
                continue  # offload materiel -- jamais une erreur, voir docstring
            if is_bad:
                errors.append(
                    ChecksumError(
                        point=pk.point,
                        frame_number=pk.frame_number,
                        protocol=protocol,
                        checksum=checksum,
                    )
                )
    logger.debug("validate_checksums: {} checksum(s) invalide(s)", len(errors))
    return errors
