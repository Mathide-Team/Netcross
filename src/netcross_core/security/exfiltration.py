"""
netcross_core.security.exfiltration -- issue #148 (SCENARIO-2, parent #141) :
detection d'exfiltration de donnees (transferts sortants anormaux).

Detecte les transferts volumineux vers l'exterieur qui pourraient indiquer
une exfiltration de donnees. Exploite les champs deja disponibles sur `Pkt`
(`point`, `src`, `dst`, `length`, `ts`, `proto`, `sport`, `dport`,
`dns_qry_name`) : aucune nouvelle dissection.

Groupement : PAR POINT DE CAPTURE puis par couple oriente (source,
destination). Sans le point, une capture multi-points compterait deux fois
le meme transfert (vu en amont ET en aval) et doublerait le volume.

Sens evalue (`external_only`, defaut) : seulement une source NON routable
globalement (RFC 1918, ULA...) vers une destination routable globalement --
c'est la definition meme d'une donnee qui sort. Sans ce filtre, un simple
telechargement HTTP produit un flux serveur->client tres asymetrique qui
serait pris pour une exfiltration par le serveur (critere « aucun faux
positif sur un download HTTP normal »), et une sauvegarde vers un NAS
interne leverait une alerte de volume.

Signaux FORTS (au moins un requis pour lever une alerte) :
- **high_volume** : octets ENVOYES par la source > `min_volume_bytes`
  (defaut 10 Mo) -- pas la somme des deux sens, sans quoi un gros
  telechargement leverait l'alerte sur le flux client->serveur ;
- **asymmetric_ratio** : upload/download > `min_asymmetric_ratio` (defaut
  10:1) ET upload >= `min_upload_for_ratio` (defaut : un dixieme de
  `min_volume_bytes`). Le plancher evite qu'un POST de formulaire de 20 Ko
  suivi d'une reponse de 1 Ko ne passe pour une exfiltration.

Signaux FAIBLES (n'aggravent qu'une alerte deja levee) :
- **off_hours** : au moins `off_hours_min_fraction` (defaut 50 %) des
  octets envoyes hors de `business_hours_start`-`business_hours_end` (UTC --
  le fuseau du site n'est pas connu, limite assumee comme dans `beaconing`) ;
- **new_destination** : destination absente de la baseline fournie par
  l'appelant (`known_destinations`) ; sans baseline, jamais emis ;
- **unusual_protocol_volume** : gros volume sur DNS ou ICMP ;
- **correlated_beaconing** / **correlated_dns_tunnel** : ajoutes par
  `correlate_exfiltration` quand le meme hote beaconne vers la meme
  destination (#147) ou interroge un domaine suspect de tunneling (#144).

Score de risque (0-100) : somme ponderee des signaux (volume, ratio,
horaire, destination, protocole, correlations), plafonnee a 100. Severite :
`elevee` a partir de 60, `moyenne` sinon (un signal fort est toujours
present). Une alerte reste un INDICE : une sauvegarde cloud nocturne
legitime coche volume + ratio + horaire -- seul l'analyste tranche, d'ou la
baseline de destinations connues pour la faire taire.

Limites assumees :
- le volume est mesure en octets de trame (en-tetes compris) ;
- « HTTP POST vers un stockage cloud » n'est pas identifie comme tel : le
  corps HTTP et la liste des fournisseurs ne sont pas disponibles ; un tel
  transfert remonte par le volume et le ratio.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt
from netcross_core.security.address_scope import is_external

logger = get_logger(__name__)

# -- Constantes ---------------------------------------------------------------

SIGNAL_HIGH_VOLUME = "high_volume"
SIGNAL_ASYMMETRIC_RATIO = "asymmetric_ratio"
SIGNAL_OFF_HOURS = "off_hours"
SIGNAL_NEW_DESTINATION = "new_destination"
SIGNAL_UNUSUAL_PROTOCOL = "unusual_protocol_volume"
SIGNAL_CORRELATED_BEACONING = "correlated_beaconing"
SIGNAL_CORRELATED_DNS_TUNNEL = "correlated_dns_tunnel"

STRONG_SIGNALS = (SIGNAL_HIGH_VOLUME, SIGNAL_ASYMMETRIC_RATIO)
WEAK_SIGNALS = (
    SIGNAL_OFF_HOURS,
    SIGNAL_NEW_DESTINATION,
    SIGNAL_UNUSUAL_PROTOCOL,
    SIGNAL_CORRELATED_BEACONING,
    SIGNAL_CORRELATED_DNS_TUNNEL,
)

SIGNAL_WEIGHTS = {
    SIGNAL_HIGH_VOLUME: 35,
    SIGNAL_ASYMMETRIC_RATIO: 25,
    SIGNAL_OFF_HOURS: 10,
    SIGNAL_NEW_DESTINATION: 15,
    SIGNAL_UNUSUAL_PROTOCOL: 15,
    SIGNAL_CORRELATED_BEACONING: 15,
    SIGNAL_CORRELATED_DNS_TUNNEL: 15,
}
HIGH_SEVERITY_SCORE = 60

# Familles de protocoles inhabituelles pour un gros volume sortant.
_UNUSUAL_VOLUME_PROTOCOLS = {"DNS", "ICMP"}

_MAX_FRAMES = 10


@dataclass(frozen=True)
class ExfiltrationThresholds:
    """Seuils des signaux (voir la docstring du module). Tous parametrables."""

    min_volume_bytes: int = 10_000_000  # 10 Mo
    min_asymmetric_ratio: float = 10.0  # 10:1 upload/download
    business_hours_start: int = 8  # 8h UTC
    business_hours_end: int = 18  # 18h UTC
    min_packets_for_volume: int = 5  # minimum pour lever high_volume
    min_bytes_for_protocol: int = 1_000_000  # 1 Mo sur protocole inhabituel
    # None : un dixieme de min_volume_bytes.
    min_upload_for_ratio: int | None = None
    off_hours_min_fraction: float = 0.5
    external_only: bool = True
    # Issue #365 : plages TEST-NET (RFC 5737) traitees comme externes
    # (demonstrations) ; par defaut internes, comme pour ipaddress.
    treat_test_net_as_external: bool = False

    @property
    def ratio_floor(self) -> int:
        if self.min_upload_for_ratio is not None:
            return self.min_upload_for_ratio
        return self.min_volume_bytes // 10


DEFAULT_THRESHOLDS = ExfiltrationThresholds()


def compute_score(signals: Iterable[str]) -> int:
    return min(100, sum(SIGNAL_WEIGHTS.get(s, 0) for s in set(signals)))


def severity_for(score: int) -> str:
    return "elevee" if score >= HIGH_SEVERITY_SCORE else "moyenne"


@dataclass
class ExfiltrationAlert:
    """Une suspicion d'exfiltration sur un flux (point, src -> dst)."""

    src: str
    dst: str
    point: str = ""
    signals: list[str] = field(default_factory=list)
    volume_bytes: int = 0
    upload_bytes: int = 0
    download_bytes: int = 0
    ratio: float = 0.0
    protocols: set[str] = field(default_factory=set)
    frames: list[int | None] = field(default_factory=list)
    first_ts: float | None = None
    last_ts: float | None = None
    off_hours_fraction: float = 0.0

    @property
    def is_strong(self) -> bool:
        return any(s in STRONG_SIGNALS for s in self.signals)

    @property
    def score(self) -> int:
        return compute_score(self.signals)

    def to_dict(self) -> dict:
        score = self.score
        return {
            "point": self.point,
            "src": self.src,
            "dst": self.dst,
            "signals": list(self.signals),
            "volume_bytes": self.volume_bytes,
            "upload_bytes": self.upload_bytes,
            "download_bytes": self.download_bytes,
            # inf n'est pas du JSON valide : un upload sans aucun retour est
            # signale par ratio=None et download_bytes=0.
            "ratio": None if self.ratio == float("inf") else round(self.ratio, 2),
            "protocols": sorted(self.protocols),
            "frames": [f for f in self.frames if f is not None][:_MAX_FRAMES],
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "off_hours_fraction": round(self.off_hours_fraction, 3),
            "strong": self.is_strong,
            "score": score,
            "severity": severity_for(score),
        }


@dataclass
class ExfiltrationResult:
    """Sortie de `detect_exfiltration`, meme forme que les autres detecteurs."""

    alerts: list[dict] = field(default_factory=list)
    flow_stats: list[dict] = field(default_factory=list)


def _is_off_hours(ts: float, thresholds: ExfiltrationThresholds) -> bool:
    """Verifie si le timestamp tombe hors des heures ouvrables (UTC)."""
    hour = datetime.fromtimestamp(ts, tz=timezone.utc).hour
    return hour < thresholds.business_hours_start or hour >= thresholds.business_hours_end


def _is_outbound(src: str, dst: str, thresholds: ExfiltrationThresholds = DEFAULT_THRESHOLDS) -> bool:
    treat = thresholds.treat_test_net_as_external
    return not is_external(src, treat_test_net_as_external=treat) and is_external(dst, treat_test_net_as_external=treat)


def _proto_family(pk: Pkt) -> str:
    proto = (pk.proto or "").upper()
    if proto.startswith("ICMP"):
        return "ICMP"
    if proto == "DNS" or pk.sport == 53 or pk.dport == 53 or getattr(pk, "dns_qry_name", None):
        return "DNS"
    return proto


def _ratio(upload: int, download: int) -> float:
    if download > 0:
        return upload / download
    return float("inf") if upload > 0 else 0.0


def detect_exfiltration(
    packets: Iterable[Pkt],
    thresholds: ExfiltrationThresholds = DEFAULT_THRESHOLDS,
    known_destinations: frozenset[str] | None = None,
) -> ExfiltrationResult:
    """
    Detecte les transferts sortants anormaux pouvant indiquer une
    exfiltration de donnees.

    `known_destinations` : ensemble d'IPs de destinations connues
    (baseline). Si fourni, les destinations non listees declenchent le
    signal faible `new_destination`.
    """
    flow_data: dict[tuple[str, str, str], dict] = defaultdict(
        lambda: {
            "bytes": 0,
            "off_hours_bytes": 0,
            "protocols": set(),
            "frames": [],
            "first_ts": None,
            "last_ts": None,
            "proto_bytes": defaultdict(int),
        }
    )

    for pk in packets:
        data = flow_data[(pk.point, pk.src, pk.dst)]
        data["bytes"] += pk.length
        if _is_off_hours(pk.ts, thresholds):
            data["off_hours_bytes"] += pk.length
        data["protocols"].add(pk.proto)
        data["frames"].append(pk.frame_number)
        data["first_ts"] = pk.ts if data["first_ts"] is None else min(data["first_ts"], pk.ts)
        data["last_ts"] = pk.ts if data["last_ts"] is None else max(data["last_ts"], pk.ts)
        data["proto_bytes"][_proto_family(pk)] += pk.length

    def download_of(point: str, src: str, dst: str) -> int:
        rev = flow_data.get((point, dst, src))
        return rev["bytes"] if rev else 0

    alerts: list[ExfiltrationAlert] = []
    flow_stats: list[dict] = []

    for (point, src, dst), data in flow_data.items():
        upload = data["bytes"]
        download = download_of(point, src, dst)
        volume = upload + download
        ratio = _ratio(upload, download)
        packet_count = len(data["frames"])
        flow_stats.append(
            {
                "point": point,
                "src": src,
                "dst": dst,
                "upload_bytes": upload,
                "download_bytes": download,
                "volume_bytes": volume,
                "ratio": None if ratio == float("inf") else round(ratio, 2),
                "packet_count": packet_count,
                "protocols": sorted(data["protocols"]),
                "outbound": _is_outbound(src, dst, thresholds),
            }
        )

        if thresholds.external_only and not _is_outbound(src, dst, thresholds):
            continue

        signals: list[str] = []
        # -- Signaux forts --
        # le volume ENVOYE, pas la somme des deux sens : sinon un gros
        # telechargement leverait high_volume sur le flux client->serveur.
        if upload > thresholds.min_volume_bytes and packet_count >= thresholds.min_packets_for_volume:
            signals.append(SIGNAL_HIGH_VOLUME)
        if upload >= thresholds.ratio_floor and ratio > thresholds.min_asymmetric_ratio:
            signals.append(SIGNAL_ASYMMETRIC_RATIO)
        if not signals:
            continue

        # -- Signaux faibles (uniquement si au moins un signal fort) --
        off_fraction = data["off_hours_bytes"] / upload if upload else 0.0
        if upload and off_fraction >= thresholds.off_hours_min_fraction:
            signals.append(SIGNAL_OFF_HOURS)
        if known_destinations is not None and dst not in known_destinations:
            signals.append(SIGNAL_NEW_DESTINATION)
        if any(
            fam in _UNUSUAL_VOLUME_PROTOCOLS and b > thresholds.min_bytes_for_protocol
            for fam, b in data["proto_bytes"].items()
        ):
            signals.append(SIGNAL_UNUSUAL_PROTOCOL)

        alerts.append(
            ExfiltrationAlert(
                src=src,
                dst=dst,
                point=point,
                signals=signals,
                volume_bytes=volume,
                upload_bytes=upload,
                download_bytes=download,
                ratio=ratio,
                protocols=data["protocols"],
                frames=data["frames"],
                first_ts=data["first_ts"],
                last_ts=data["last_ts"],
                off_hours_fraction=off_fraction,
            )
        )

    alerts.sort(key=lambda a: (-a.score, -a.upload_bytes, a.point, a.src, a.dst))
    flow_stats.sort(key=lambda s: (-s["volume_bytes"], s["point"], s["src"], s["dst"]))
    logger.debug("detect_exfiltration: {} alerte(s)", len(alerts))
    return ExfiltrationResult(alerts=[a.to_dict() for a in alerts], flow_stats=flow_stats)


def dns_tunnel_sources(packets: Iterable[Pkt], dns_suspicions: Iterable[dict]) -> set[tuple[str, str]]:
    """(point, IP source) des hotes ayant interroge un domaine suspect de
    tunneling DNS (sorties `dns_tunnel.detect_dns_tunneling`)."""
    domains: dict[str, set[str]] = defaultdict(set)
    for s in dns_suspicions:
        if s.get("domain"):
            domains[str(s.get("point") or "")].add(str(s["domain"]).lower().rstrip("."))
    if not domains:
        return set()
    sources: set[tuple[str, str]] = set()
    for pk in packets:
        name = getattr(pk, "dns_qry_name", None)
        if not name or getattr(pk, "dns_is_response", False):
            continue
        name = name.lower().rstrip(".")
        for dom in domains.get(pk.point, ()):
            if name == dom or name.endswith("." + dom):
                sources.add((pk.point, pk.src))
                break
    logger.debug("dns_tunnel_sources: {} source(s) de tunnel DNS", len(sources))
    return sources


def correlate_exfiltration(
    alerts: list[dict],
    beacon_suspicions: Iterable[dict] = (),
    dns_sources: set[tuple[str, str]] | None = None,
) -> list[dict]:
    """Ajoute les signaux de correlation (#144, #147) aux alertes et
    recalcule score et severite. Renvoie une NOUVELLE liste, triee par
    score decroissant.

    - `correlated_beaconing` : le meme hote beaconne vers la meme
      destination, sur le meme point (canal de commande + canal de sortie) ;
    - `correlated_dns_tunnel` : le meme hote interroge un domaine suspect de
      tunneling DNS sur le meme point.
    """
    beacons = {(str(s.get("point") or ""), s.get("src"), s.get("dst")) for s in beacon_suspicions}
    dns_sources = dns_sources or set()
    out = []
    for alert in alerts:
        a = dict(alert)
        signals = list(a.get("signals") or [])
        key = (a.get("point") or "", a.get("src"), a.get("dst"))
        if key in beacons and SIGNAL_CORRELATED_BEACONING not in signals:
            signals.append(SIGNAL_CORRELATED_BEACONING)
        if (key[0], key[1]) in dns_sources and SIGNAL_CORRELATED_DNS_TUNNEL not in signals:
            signals.append(SIGNAL_CORRELATED_DNS_TUNNEL)
        a["signals"] = signals
        a["score"] = compute_score(signals)
        a["severity"] = severity_for(a["score"])
        out.append(a)
    out.sort(key=lambda d: (-d["score"], -int(d.get("upload_bytes") or 0)))
    logger.debug("correlate_exfiltration: {} alerte(s), {} source(s) DNS", len(out), len(dns_sources))
    return out
