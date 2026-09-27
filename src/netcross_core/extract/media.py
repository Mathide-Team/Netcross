"""
netcross_core.extract.media -- issue #278 : flux RTP audio/video.

Deux usages, volontairement separes :

- **analyse qualitative** (``--media-quality``) : pertes, doublons,
  desordre, rafales de pertes, gigue, et une **note de degradation due au
  transport** (0 = intact, 100 = inexploitable). Rien n'est ecrit sur
  disque : c'est la version sobre, a privilegier.
- **extraction** (``--extract-contents``) : ecriture du son (G.711 ->
  WAV) et de la video (H.264 -> flux Annex B lisible par ffplay/VLC).
  Les paquets perdus sont remplaces par du silence (audio) ou omis
  (video) : ce que l'on entend/voit est ce que le transport a livre,
  degradations comprises.

Le decodage de la couche transport reste le role de tshark (via
``pcap_parser``) ; ce module ne lit que l'en-tete RTP (RFC 3550) et le
SDP present dans la capture, puis decode les charges utiles G.711 et
depaquette H.264 (RFC 6184).

Limites (voir docs/extraction-contenus.md) : la note audio repose sur
l'E-model simplifie deja utilise par le rapport (``compute_mos``) avec un
delai *estime* (paquetisation + tampon de gigue), le delai de bout en bout
n'etant pas mesurable depuis un seul point de capture ; la note video
mesure la part d'images touchees par une perte, pas la qualite percue.
Flux chiffres (SRTP) : statistiques de transport seules, contenu non
exploitable.
"""

from __future__ import annotations

import re
import statistics
import struct
import wave
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from netcross_core.logging_config import get_logger, summarize
from pcap_parser.protocols import compute_mos

logger = get_logger(__name__)

# PT statiques (RFC 3551) : nom, horloge, nature.
_STATIC_PT: dict[int, tuple[str, int, str]] = {
    0: ("PCMU", 8000, "audio"),
    3: ("GSM", 8000, "audio"),
    4: ("G723", 8000, "audio"),
    8: ("PCMA", 8000, "audio"),
    9: ("G722", 8000, "audio"),
    18: ("G729", 8000, "audio"),
    26: ("JPEG", 90000, "video"),
    31: ("H261", 90000, "video"),
    32: ("MPV", 90000, "video"),
    34: ("H263", 90000, "video"),
}
_VIDEO_CODECS = frozenset({"H264", "H265", "VP8", "VP9", "AV1", "H263", "H263-1998", "H261", "JPEG", "MPV"})

MIN_STREAM_PACKETS = 10
_MIN_SEQUENTIAL_RATIO = 0.8
_MAX_FILL_PACKETS = 3000  # silence insere au plus par trou (evite un WAV geant sur un flux coupe)
_R_MAX = 93.2  # R-factor d'un G.711 parfait dans compute_mos

KINDS = ("audio", "video", "documents")


@dataclass
class _RtpPacket:
    arrival: float
    seq: int
    ts: int
    pt: int
    marker: bool
    payload: bytes


@dataclass
class RtpStream:
    """Flux RTP d'un point de capture, identifie par (5-uplet UDP, SSRC)."""

    point: str
    src: str
    sport: int
    dst: str
    dport: int
    ssrc: int
    pt: int
    codec: str | None = None
    clock_rate: int | None = None
    kind: str = "inconnu"
    encrypted: bool = False  # SDP RTP/SAVP(F) : SRTP, contenu inexploitable
    packets: list[_RtpPacket] = field(default_factory=list, repr=False)

    @property
    def label(self) -> str:
        logger.debug("RtpStream.label: retour chaîne formatée")
        return f"{self.point} {self.src}:{self.sport} -> {self.dst}:{self.dport} ssrc=0x{self.ssrc:08x}"

    @property
    def file_stem(self) -> str:
        raw = f"{self.point}_{self.src}_{self.sport}-{self.dst}_{self.dport}_{self.ssrc:08x}"
        logger.debug("RtpStream.file_stem: retour re.sub(…)")
        return re.sub(r"[^A-Za-z0-9_.-]", "-", raw)


@dataclass
class StreamQuality:
    """Analyse qualitative d'un flux : ce que le transport a abime."""

    label: str
    kind: str
    codec: str | None
    received: int
    expected: int
    lost: int
    loss_pct: float
    duplicates: int
    reordered: int
    max_burst: int
    jitter_ms: float | None
    duration_s: float
    mos: float | None = None
    r_factor: float | None = None
    frames: int | None = None
    damaged_frames: int | None = None
    degradation: int | None = None
    verdict: str = "non evaluee"
    exported: str | None = None
    note: str | None = None

    def to_dict(self) -> dict:
        logger.debug("StreamQuality.to_dict: retour dict(…)")
        return dict(self.__dict__)


# -- lecture ----------------------------------------------------------------


def parse_rtp_header(data: bytes) -> tuple[int, int, int, int, bool, bytes] | None:
    """(pt, seq, ts, ssrc, marker, charge utile) ou None si pas du RTP v2."""
    logger.debug("parse_rtp_header: data={}", summarize(data, "data"))
    if len(data) < 12 or data[0] >> 6 != 2:
        logger.debug("parse_rtp_header: si len(data) < 12 or data[0] >> 6 != 2 -> retour None")
        return None
    pt = data[1] & 0x7F
    if 72 <= pt <= 76:  # RTCP (SR/RR/SDES/BYE/APP) multiplexe
        logger.debug("parse_rtp_header: si 72 <= pt <= 76 -> retour None")
        return None
    hlen = 12 + (data[0] & 0x0F) * 4
    if data[0] & 0x10:  # extension d'en-tete
        if len(data) < hlen + 4:
            logger.debug("parse_rtp_header: si len(data) < hlen + 4 -> retour None")
            return None
        hlen += 4 + struct.unpack_from("!H", data, hlen + 2)[0] * 4
    end = len(data)
    if data[0] & 0x20:  # bourrage
        end -= data[-1]
    if hlen > end:
        logger.debug("parse_rtp_header: si hlen > end -> retour None")
        return None
    seq, ts, ssrc = struct.unpack_from("!HII", data, 2)
    logger.debug("parse_rtp_header: retour tuple de 6")
    return pt, seq, ts, ssrc, bool(data[1] & 0x80), data[hlen:end]


_M_LINE = re.compile(rb"^m=(\w+) (\d+) ([A-Za-z/]+)")
_C_LINE = re.compile(rb"^c=IN IP[46] ([0-9A-Fa-f.:]+)")
_RTPMAP = re.compile(rb"^a=rtpmap:(\d+) ([A-Za-z0-9._-]+)/(\d+)")


_SdpMap = dict[tuple[str | None, int | None], dict[int, tuple[str, int, str, bool]]]


def parse_sdp(payload: bytes) -> _SdpMap:
    """Table {(adresse, port) : {pt : (codec, horloge, nature, srtp)}} des SDP
    trouves dans une charge utile (SIP sur UDP/TCP). ``(None, None)``
    recoit aussi chaque correspondance : repli quand l'adresse ne colle pas
    (NAT, c= au niveau session seulement)."""
    logger.debug("parse_sdp: payload={}", summarize(payload, "payload"))
    out: _SdpMap = {}
    if b"a=rtpmap:" not in payload:
        logger.debug("parse_sdp: si b'a=rtpmap:' not in payload -> retour out={}", summarize(out, "out"))
        return out
    session_addr: str | None = None
    media: tuple[str, int, bool] | None = None
    media_addr: str | None = None
    for line in payload.replace(b"\r\n", b"\n").split(b"\n"):
        if m := _M_LINE.match(line):
            media = (m.group(1).decode(), int(m.group(2)), b"SAVP" in m.group(3))
            media_addr = None
        elif c := _C_LINE.match(line):
            if media is None:
                session_addr = c.group(1).decode()
            else:
                media_addr = c.group(1).decode()
        elif (r := _RTPMAP.match(line)) and media is not None:
            codec = r.group(2).decode().upper()
            kind = "video" if media[0] == "video" or codec in _VIDEO_CODECS else "audio"
            entry = (codec, int(r.group(3)), kind, media[2])
            for key in ((media_addr or session_addr, media[1]), (None, None)):
                out.setdefault(key, {})[int(r.group(1))] = entry
    logger.debug("parse_sdp: retour out={}", summarize(out, "out"))
    return out


def collect_streams(datagrams: Iterable[tuple]) -> list[RtpStream]:
    """Regroupe en flux RTP des datagrammes
    ``(point, arrivee, src, sport, dst, dport, charge_utile_udp)``.
    Un flux n'est retenu que s'il ressemble vraiment a du RTP : au moins
    MIN_STREAM_PACKETS paquets et des numeros de sequence majoritairement
    consecutifs (evite de prendre du DNS ou du QUIC pour de la voix)."""
    logger.debug("collect_streams: datagrams={}", summarize(datagrams, "datagrams"))
    streams: dict[tuple, RtpStream] = {}
    sdp: _SdpMap = {}
    for point, arrival, src, sport, dst, dport, payload in datagrams:
        if not payload:
            continue
        for addr_port, mapping in parse_sdp(payload).items():
            sdp.setdefault(addr_port, {}).update(mapping)
        head = parse_rtp_header(payload)
        if head is None or sport is None or dport is None:
            continue
        pt, seq, ts, ssrc, marker, body = head
        key = (point, src, sport, dst, dport, ssrc)
        st = streams.get(key)
        if st is None:
            st = streams[key] = RtpStream(point, src, sport, dst, dport, ssrc, pt)
        st.packets.append(_RtpPacket(arrival, seq, ts, pt, marker, body))

    kept = []
    for st in streams.values():
        if len(st.packets) < MIN_STREAM_PACKETS:
            continue
        deltas = [(b.seq - a.seq) & 0xFFFF for a, b in zip(st.packets, st.packets[1:])]
        if sum(1 for d in deltas if d == 1) < _MIN_SEQUENTIAL_RATIO * len(deltas):
            continue
        st.pt = statistics.mode(p.pt for p in st.packets)
        entry = (
            sdp.get((st.dst, st.dport), {}).get(st.pt)
            or sdp.get((st.src, st.sport), {}).get(st.pt)
            or (sdp.get((None, None), {}).get(st.pt) if st.pt >= 96 else None)
        )
        if entry:
            st.codec, st.clock_rate, st.kind, st.encrypted = entry
        elif static := _STATIC_PT.get(st.pt):
            st.codec, st.clock_rate, st.kind = static
        kept.append(st)
    kept.sort(key=lambda s: (s.point, s.packets[0].arrival))
    logger.debug("collect_streams: retour kept={}", summarize(kept, "kept"))
    return kept


# -- analyse ----------------------------------------------------------------


def _extended(packets: list[_RtpPacket]) -> list[int]:
    """Numeros de sequence etendus (bouclage a 65536 deroule)."""
    out: list[int] = []
    if not packets:
        logger.debug("_extended: si not packets -> retour out={}", summarize(out, "out"))
        return out
    highest = packets[0].seq
    for p in packets:
        base = highest - (highest & 0xFFFF)
        ref = highest
        ext = min((base - 0x10000 + p.seq, base + p.seq, base + 0x10000 + p.seq), key=lambda c: abs(c - ref))
        out.append(ext)
        highest = max(highest, ext)
    logger.debug("_extended: retour out={}", summarize(out, "out"))
    return out


def verdict(degradation: int | None) -> str:
    if degradation is None:
        logger.debug("verdict: si degradation is None -> retour 'non evaluee'")
        return "non evaluee"
    if degradation < 5:
        logger.debug("verdict: si degradation < 5 -> retour 'imperceptible'")
        return "imperceptible"
    if degradation < 15:
        logger.debug("verdict: si degradation < 15 -> retour 'legere'")
        return "legere"
    if degradation < 35:
        logger.debug("verdict: si degradation < 35 -> retour 'genante'")
        return "genante"
    logger.debug("verdict: retour 'severe'")
    return "severe"


def _ordered_unique(st: RtpStream) -> list[tuple[int, _RtpPacket]]:
    seen: dict[int, _RtpPacket] = {}
    for ext, p in zip(_extended(st.packets), st.packets):
        seen.setdefault(ext, p)
    logger.debug("_ordered_unique: retour sorted(…)")
    return sorted(seen.items())


def analyse_stream(st: RtpStream) -> StreamQuality:
    logger.debug("analyse_stream: st={}", summarize(st, "st"))
    exts = _extended(st.packets)
    unique = sorted(set(exts))
    expected = unique[-1] - unique[0] + 1
    lost = expected - len(unique)
    reordered, highest = 0, None
    for e in exts:
        if highest is not None and e < highest:
            reordered += 1
        highest = e if highest is None else max(highest, e)
    max_burst = max((b - a - 1 for a, b in zip(unique, unique[1:])), default=0)

    jitter_ms = None
    if st.clock_rate:
        j, prev = 0.0, None
        for p in st.packets:
            cur = (p.arrival, p.ts / st.clock_rate)
            if prev is not None:
                j += (abs((cur[0] - prev[0]) - (cur[1] - prev[1])) - j) / 16.0
            prev = cur
        jitter_ms = round(j * 1000.0, 2)

    q = StreamQuality(
        label=st.label,
        kind=st.kind,
        codec=st.codec,
        received=len(st.packets),
        expected=expected,
        lost=lost,
        loss_pct=round(lost / expected * 100.0, 2),
        duplicates=len(exts) - len(unique),
        reordered=reordered,
        max_burst=max_burst,
        jitter_ms=jitter_ms,
        duration_s=round(st.packets[-1].arrival - st.packets[0].arrival, 3),
    )
    if st.kind == "audio" and st.clock_rate:
        ordered = _ordered_unique(st)
        steps = [
            (b[1].ts - a[1].ts) / (b[0] - a[0])
            for a, b in zip(ordered, ordered[1:])
            if b[0] > a[0] and b[1].ts > a[1].ts
        ]
        ptime_ms = (statistics.median(steps) / st.clock_rate * 1000.0) if steps else 20.0
        delay_ms = ptime_ms + 2.0 * (jitter_ms or 0.0)  # paquetisation + tampon de gigue estime
        r, mos = compute_mos(delay_ms, q.loss_pct)
        q.r_factor, q.mos = round(r, 1), round(mos, 2)
        q.degradation = round(max(0.0, _R_MAX - r) / _R_MAX * 100)
        q.note = f"delai estime {delay_ms:.0f} ms (paquetisation + tampon de gigue), non mesure"
    elif st.kind == "video":
        q.frames, q.damaged_frames = _video_frames(_ordered_unique(st))
        q.degradation = round(q.damaged_frames / q.frames * 100) if q.frames else None
        q.note = "part des images touchees par une perte (pas une mesure de qualite percue)"
    else:
        q.note = f"codec non identifie (PT {st.pt}) : statistiques de transport seules"
    if st.encrypted:
        q.note = (q.note + " ; " if q.note else "") + "flux SRTP : contenu chiffre, non exportable"
    q.verdict = verdict(q.degradation)
    logger.debug("analyse_stream: retour q={}", summarize(q, "q"))
    return q


def _video_frames(ordered: list[tuple[int, _RtpPacket]]) -> tuple[int, int]:
    """(images, images endommagees). Une image = un horodatage RTP ; elle
    est endommagee si un numero de sequence manque en son sein ou juste
    avant elle (perte non attribuable, imputee a l'image qui suit)."""
    frames = damaged = 0
    prev_ext: int | None = None
    current_ts: int | None = None
    current_bad = False
    for ext, p in ordered:
        gap = prev_ext is not None and ext != prev_ext + 1
        if p.ts != current_ts:
            if current_ts is not None:
                frames += 1
                damaged += current_bad
            current_ts, current_bad = p.ts, gap
        elif gap:
            current_bad = True
        prev_ext = ext
    if current_ts is not None:
        frames += 1
        damaged += current_bad
    logger.debug("_video_frames: retour tuple de 2")
    return frames, damaged


# -- extraction -------------------------------------------------------------


def _ulaw_sample(b: int) -> int:
    b = ~b & 0xFF
    exp, mant = (b >> 4) & 0x07, b & 0x0F
    s = (((mant << 3) + 0x84) << exp) - 0x84
    logger.debug("_ulaw_sample: retour -s if b & 128 else s")
    return -s if b & 0x80 else s


def _alaw_sample(b: int) -> int:
    b ^= 0x55
    exp, mant = (b >> 4) & 0x07, b & 0x0F
    s = (mant << 4) + 8 if exp == 0 else ((mant << 4) + 0x108) << (exp - 1)
    logger.debug("_alaw_sample: retour s if b & 128 else -s")
    return s if b & 0x80 else -s


_G711 = {
    "PCMU": [struct.pack("<h", _ulaw_sample(i)) for i in range(256)],
    "PCMA": [struct.pack("<h", _alaw_sample(i)) for i in range(256)],
}


def decode_g711(codec: str, payload: bytes) -> bytes:
    """PCM 16 bits little-endian depuis une charge utile G.711."""
    table = _G711[codec]
    logger.debug("decode_g711: retour b''.join(…)")
    return b"".join(table[x] for x in payload)


def write_wav(st: RtpStream, path: Path) -> None:
    """Son du flux ; chaque paquet perdu devient un silence de meme duree."""
    if st.codec not in _G711:
        logger.trace("write_wav: refus, ValueError")
        logger.debug("write_wav: si st.codec not in _G711 -> levée ValueError")
        raise ValueError(f"codec audio {st.codec} non decode (seul G.711 PCMU/PCMA l'est)")
    ordered = _ordered_unique(st)
    frame_len = statistics.median(len(p.payload) for _, p in ordered) or 160
    silence = b"\x00\x00" * int(frame_len)
    chunks: list[bytes] = []
    prev = None
    for ext, p in ordered:
        if prev is not None:
            chunks.extend([silence] * min(ext - prev - 1, _MAX_FILL_PACKETS))
        chunks.append(decode_g711(st.codec, p.payload))
        prev = ext
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(st.clock_rate or 8000)
        w.writeframes(b"".join(chunks))
    logger.debug("write_wav: fin")


_START = b"\x00\x00\x00\x01"


def depacketize_h264(ordered: Iterable[tuple[int, bytes]]) -> bytes:
    """Flux H.264 Annex B depuis des charges utiles RTP (RFC 6184 : NAL
    simple, STAP-A, FU-A). Un fragment FU-A dont un morceau manque est
    ecarte entier : le decodeur masque l'image plutot que d'avaler un NAL
    tronque."""
    logger.debug("depacketize_h264: ordered={}", summarize(ordered, "ordered"))
    out = bytearray()
    frag: bytearray | None = None
    prev = None
    for ext, p in ordered:
        if not p:
            prev = ext
            continue
        continuous = prev is not None and ext == prev + 1
        prev = ext
        nal_type = p[0] & 0x1F
        if 1 <= nal_type <= 23:
            frag = None
            out += _START + p
        elif nal_type == 24:  # STAP-A
            frag = None
            i = 1
            while i + 2 <= len(p):
                size = struct.unpack_from("!H", p, i)[0]
                i += 2
                if size == 0 or i + size > len(p):
                    break
                out += _START + p[i : i + size]
                i += size
        elif nal_type == 28 and len(p) >= 2:  # FU-A
            fu = p[1]
            if fu & 0x80:
                frag = bytearray([(p[0] & 0xE0) | (fu & 0x1F)]) + p[2:]
            elif frag is not None and continuous:
                frag += p[2:]
            else:
                frag = None
            if frag is not None and fu & 0x40:
                out += _START + frag
                frag = None
    logger.debug("depacketize_h264: retour bytes(…)")
    return bytes(out)


def export_stream(st: RtpStream, out_dir: Path) -> Path:
    """Ecrit le contenu du flux ; ValueError si le codec n'est pas pris en charge."""
    if st.encrypted:
        logger.trace("export_stream: refus, ValueError")
        logger.debug("export_stream: si st.encrypted -> levée ValueError")
        raise ValueError("flux SRTP : contenu chiffre, non exporte")
    if st.kind == "audio":
        path = out_dir / "audio" / f"{st.file_stem}.wav"
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_wav(st, path)
    elif st.kind == "video" and st.codec == "H264":
        path = out_dir / "video" / f"{st.file_stem}.h264"
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(depacketize_h264((e, p.payload) for e, p in _ordered_unique(st)))
    else:
        logger.trace("export_stream: refus, ValueError")
        logger.debug("export_stream: sinon (st.kind == 'video' and st.codec == 'H26…) -> levée ValueError")
        raise ValueError(f"{st.kind} {st.codec or 'codec inconnu'} non exporte (pris en charge : G.711, H.264)")
    path.chmod(0o600)
    logger.debug("export_stream: retour path={}", summarize(path, "path"))
    return path
