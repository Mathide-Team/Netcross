"""
pcap_parser.ek_source -- couche 1 : execution de tshark -T ek et lecture
du flux NDJSON qui en resulte, fichier pcap ou interface live.

Cette couche ne connait rien aux protocoles applicatifs : elle expose
uniquement des dicts "layers" bruts (un par paquet), tels que tshark les
produit. Toute la semantique reseau vit dans les couches au-dessus
(tunnels.py, protocols.py, packet.py).

Pourquoi tshark -T ek :
- decodage en C dans tshark (dissecteurs Wireshark), pas en Python pur
  paquet par paquet -> gain de vitesse important sur de grosses captures
- -T ek (Elastic/Kafka bulk NDJSON) produit un objet JSON par paquet sur
  une seule ligne, ce qui permet un vrai streaming ligne par ligne (utile
  pour parse_capture comme pour la capture live), contrairement a
  une lecture qui chargerait tout le fichier en memoire avant de rendre
  la main
- les tunnels (GRE/VXLAN/GTP-U/ERSPAN/CAPWAP) et les protocoles
  applicatifs (RTP/DHCP/SIP) sont deja disseques nativement par
  Wireshark -- on n'a plus besoin de reimplementer leur decodage a la
  main comme le faisait l'ancien decodeur (cf. parse_capwap_data() dans
  l'ancienne version, remplace par le dissecteur capwap natif, cf.
  tunnels.py)
"""

from __future__ import annotations

import calendar
import contextlib
import datetime
import json
import re
import shutil
import subprocess
import threading
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import IO

from loguru import logger

# frame_frame_time_epoch : "2026-08-20T20:19:51.632525000Z" (nanosecondes).
# Nettement plus precis que le "timestamp" racine du bulk EK (millisecondes
# seulement) -- important pour des mesures de latence inter-points fines.
_FRAME_TIME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d+)Z?$")


def _parse_frame_time_epoch(value: str | None) -> float | None:
    if not value:
        return None
    m = _FRAME_TIME_RE.match(value)
    if not m:
        return None
    y, mo, d, h, mi, se, frac = m.groups()
    dt = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(se), tzinfo=datetime.timezone.utc)
    frac_seconds = int(frac[:9].ljust(9, "0")) / 1e9
    return calendar.timegm(dt.timetuple()) + frac_seconds


class TsharkNotFoundError(RuntimeError):
    """tshark n'est pas installe / pas dans le PATH."""


class TsharkError(RuntimeError):
    """tshark a demarre mais a echoue (fichier illisible, interface
    inconnue, permissions insuffisantes...). Porte le code de retour et
    stderr pour que l'appelant puisse construire un message utile."""

    def __init__(self, message: str, returncode: int | None = None, stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


# Preferences tshark activees par defaut. rtp.heuristic_rtp est le point
# important : sans elle, tshark ne reconnait le RTP que sur les ports
# annonces via SDP (SIP/H.323...) -- exactement le meme angle mort que
# l'ancienne detection heuristique par octets dans parsing.py, donc on
# la garde active pour au moins egaler le comportement precedent.
#
# ip.check_checksum/tcp.check_checksum/udp.check_checksum (Job 43/issue
# #163) : DESACTIVEES par defaut cote tshark (cout de recalcul, bruit
# historique avec l'offload materiel) -- sans elles, le champ EK
# "*.checksum.status" reste TOUJOURS a "2" (Unverified), quelle que soit
# la validite reelle du checksum (verifie empiriquement, pcap scapy
# synthetique avec checksum TCP/IP volontairement invalide, tshark
# 4.2.2 : statut "2" dans les deux cas sans cette preference). Activees
# ici pour que netcross_core.forensic.validate_checksums() ait une
# donnee exploitable -- voir pcap_parser.packet pour l'extraction du
# statut et netcross_core.forensic pour la distinction offload (0x0000)
# vs invalide.
DEFAULT_PREFS: Sequence[str] = (
    "rtp.heuristic_rtp:TRUE",
    "ip.check_checksum:TRUE",
    "tcp.check_checksum:TRUE",
    "udp.check_checksum:TRUE",
)


def _tshark_path() -> str:
    path = shutil.which("tshark")
    if path is None:
        logger.warning("tshark introuvable dans le PATH")
        raise TsharkNotFoundError(
            "tshark introuvable dans le PATH -- installer le paquet "
            "'tshark' (apt install tshark / dnf install wireshark-cli)."
        )
    logger.debug("_tshark_path: {}", path)
    return path


_SECRET_PREF_RE = re.compile(r"^(extcap\.[^.:]+\.[a-z]*(?:password|passphrase)):.*$")


def redact_args(args: Sequence[str]) -> list:
    """Copie de `args` sans secret, pour les journaux (issue #166) :
    valeur de `-A utilisateur:mot_de_passe` (rpcap) et preferences extcap
    de mot de passe/phrase secrete (sshdump) masquees."""
    out = []
    mask_next = False
    for arg in args:
        if mask_next:
            user = str(arg).split(":", 1)[0]
            out.append(f"{user}:***")
            mask_next = False
            continue
        match = _SECRET_PREF_RE.match(str(arg))
        out.append(f"{match.group(1)}:***" if match else arg)
        mask_next = arg == "-A"
    return out


def _build_args(
    *,
    path: str | None = None,
    interface: str | None = None,
    bpf_filter: str | None = None,
    display_filter: str | None = None,
    extra_prefs: Sequence[str] = (),
    extra_args: Sequence[str] = (),
    lua_scripts: Sequence[str] = (),
) -> list:
    if (path is None) == (interface is None):
        raise ValueError("fournir soit path= (batch), soit interface= (live), pas les deux")

    args = [_tshark_path()]
    if path is not None:
        args += ["-r", path]
    else:
        # -l : flush ligne par ligne (indispensable pour du live streaming,
        # sinon tshark bufferise sa sortie et rien n'arrive avant un bon
        # moment). -Q : reduit le bruit sur stderr (pas de compteur de
        # paquets capture).
        assert interface is not None  # garanti par le check path/interface ci-dessus
        args += ["-i", interface, "-l", "-Q"]

    if bpf_filter:
        args += ["-f", bpf_filter]
    if display_filter:
        args += ["-Y", display_filter]
    for pref in (*DEFAULT_PREFS, *extra_prefs):
        args += ["-o", pref]
    for script in lua_scripts:
        args += ["-X", f"lua_script:{script}"]
    args += ["-T", "ek"]
    args += list(extra_args)
    return args


def _iter_ndjson_records(stream: IO[str]) -> Iterator[dict]:
    """Lit le flux ligne par ligne et yield chaque objet JSON qui contient
    une cle "layers" (les lignes "index" du format bulk Elastic sont
    ignorees -- elles ne portent aucune donnee de paquet, juste un
    marqueur d'index pour un bulk insert Elasticsearch)."""
    for raw_line in stream:
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            # une ligne tronquee/corrompue ne doit pas faire tomber tout
            # le flux -- on la saute et on continue sur la suivante
            logger.warning("_iter_ndjson_records: ligne JSON invalide ignorée ({} car., {})", len(line), exc)
            continue
        if "layers" in obj:
            yield obj


@dataclass
class EkRecord:
    ts: float  # secondes depuis epoch, precision nanoseconde (frame_frame_time_epoch)
    layers: dict


def _terminate_on_event(proc: subprocess.Popen, stop_event: threading.Event) -> None:
    """Tourne dans un thread daemon dedie : dort (sans polling) jusqu'a ce
    que stop_event soit positionne, puis termine `proc` immediatement.

    Necessaire car la boucle de lecture principale est bloquee sur un
    appel systeme (lecture du pipe stdout du sous-processus) : un simple
    `if stop_event.is_set(): break` verifie APRES chaque paquet ne suffit
    pas sur une interface totalement silencieuse, ou aucun paquet ne
    declenchera jamais ce test. Terminer le processus depuis un thread
    separe debloque la lecture par EOF quel que soit le trafic (valide :
    voir test_stop_mechanism.py, arret en ~1s meme sans aucune sortie)."""
    stop_event.wait()
    if proc.poll() is None:
        logger.debug("_terminate_on_event: arrêt demandé, terminate() de tshark (pid {})", getattr(proc, "pid", None))
        proc.terminate()


def iter_ek_records(
    *,
    path: str | None = None,
    interface: str | None = None,
    bpf_filter: str | None = None,
    display_filter: str | None = None,
    extra_prefs: Sequence[str] = (),
    extra_args: Sequence[str] = (),
    lua_scripts: Sequence[str] = (),
    stop_event: threading.Event | None = None,
) -> Iterator[EkRecord]:
    """
    Lance tshark -T ek et yield un EkRecord par paquet, au fil de l'eau.

    Mode batch : path="capture.pcapng" (le processus tshark se termine
    de lui-meme une fois le fichier lu).
    Mode live : interface="eth0" (le generateur ne se termine que si
    l'appelant s'arrete d'iterer -- fermer le generateur ou lever
    GeneratorExit tue proprement le processus tshark, cf. finally).

    stop_event (mode live uniquement, optionnel) : threading.Event que
    l'appelant peut positionner depuis un AUTRE thread pour demander
    l'arret. Contrairement a fermer le generateur (qui ne prend effet
    qu'au prochain paquet recu), stop_event termine le sous-processus
    tshark directement -- reactif meme sur une interface sans trafic.
    Sans objet en mode batch (le processus se termine de lui-meme).

    Leve TsharkNotFoundError si tshark n'est pas installe, ou TsharkError
    si le processus tshark a echoue (code de retour non nul et aucun
    paquet produit).
    """
    args = _build_args(
        path=path,
        interface=interface,
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        extra_prefs=extra_prefs,
        extra_args=extra_args,
        lua_scripts=lua_scripts,
    )
    logger.debug("tshark args : {}", redact_args(args))

    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # bufsize=1 : line-buffered, necessaire pour le live
    )
    if stop_event is not None:
        threading.Thread(target=_terminate_on_event, args=(proc, stop_event), daemon=True).start()
    logger.debug("iter_ek_records: tshark lancé (pid {}, source={})", getattr(proc, "pid", None), path or interface)
    records_count = 0
    produced_any = False
    try:
        assert proc.stdout is not None
        for obj in _iter_ndjson_records(proc.stdout):
            produced_any = True
            records_count += 1
            frame = obj["layers"].get("frame") or {}
            ts = _parse_frame_time_epoch(frame.get("frame_frame_time_epoch"))
            if ts is None:
                # repli : "timestamp" racine du bulk EK, en millisecondes
                # -- moins precis, mais toujours present.
                try:
                    ts = int(float(obj.get("timestamp", 0))) / 1000.0
                except (TypeError, ValueError):
                    logger.debug("iter_ek_records: horodatage illisible, 0.0 utilisé")
                    ts = 0.0
            yield EkRecord(ts=ts, layers=obj["layers"])
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                logger.warning("iter_ek_records: tshark ne s'arrête pas après terminate(), kill")
                proc.kill()
                proc.wait()
        logger.debug(
            "iter_ek_records: tshark terminé, code {}, {} enregistrement(s)",
            proc.returncode,
            records_count,
        )
        stderr_text = ""
        if proc.stderr is not None:
            with contextlib.suppress(OSError, ValueError):
                # best-effort uniquement : ce texte n'enrichit qu'un message
                # d'erreur eventuel plus bas -- son absence ne fait perdre
                # aucune fonctionnalite, juste un message legerement moins detaille.
                stderr_text = proc.stderr.read() or ""
        if proc.returncode not in (0, None, -15) and not produced_any:
            # -15 = SIGTERM, normal quand on arrete nous-memes un live
            # capture. Un code d'echec alors qu'aucun paquet n'est sorti
            # signale un vrai probleme (fichier illisible, interface
            # inconnue, permissions) -- a faire remonter, pas a avaler.
            logger.debug("iter_ek_records: échec tshark sans aucun paquet produit")
            raise TsharkError(
                f"tshark a echoue (code {proc.returncode}) : {stderr_text.strip()}",
                returncode=proc.returncode,
                stderr=stderr_text,
            )
