"""
netcross_core.tls_diagnostics -- extrait l'etat des handshakes TLS
(ClientHello/ServerHello/Alert/donnees applicatives) a chaque point de
capture et localise le segment ou un handshake qui reussissait en amont
se met a echouer.

Module volontairement independant de analysis.py/models.py : il relit
les captures lui-meme via pcap_parser (meme moteur de decodage --
tshark -T ek -- que parse_capture(), mais un pipeline separe qui a
juste besoin en plus de la charge utile brute portee par
`RawPacket.payload`) et n'importe rien du reste de netcross_core au-
dela de ca. Zero risque de conflit si analysis.py/models.py sont
modifies en parallele.

Perimetre couvert :
- ClientHello : SNI (extension server_name), version TLS proposee
- ServerHello : version TLS negociee, cipher suite choisie
- Alert : niveau (warning/fatal) + description (sous-ensemble IANA le
  plus utile en depannage reseau)
- Donnees applicatives (content type 23) : utilisees comme signal que
  le handshake a abouti, PAS analysees (chiffrees, hors de portee)

Limites connues (volontairement hors perimetre pour ce module) :
- Pas de reassemblage TCP inter-segments : un ClientHello/ServerHello
  scinde sur 2 segments TCP (frequent si beaucoup d'extensions, souvent
  justement corrélé a une fragmentation IP en aval) n'est lu que
  partiellement -- l'evenement est marque `truncated=True` plutot que
  d'etre invente.
- Pas de decapsulation de tunnel (VXLAN/GRE/MPLS/CAPWAP) : le TLS a
  l'interieur d'un tunnel n'est pas vu. A croiser manuellement avec le
  module tunnel de netcross_core si besoin.
- Pas de QUIC/HTTP3 (TLS 1.3 sur UDP) : uniquement le TLS classique sur
  TCP.
- Pas d'extraction de la chaine de certificats : seul l'etat du
  handshake (reussi/bloque/en erreur) est produit, pas son contenu.
- Correlation entre points par 4-tuple strict (src, sport, dst, dport) :
  comme le mode par defaut de netcross_core.correlate, ne fonctionne
  pas si un NAT/PAT est traverse entre deux points de capture.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

import pcap_parser
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

TLS_CONTENT_TYPES = {
    20: "change_cipher_spec",
    21: "alert",
    22: "handshake",
    23: "application_data",
}
HANDSHAKE_TYPES = {
    1: "client_hello",
    2: "server_hello",
    4: "new_session_ticket",
    11: "certificate",
    12: "server_key_exchange",
    13: "certificate_request",
    14: "server_hello_done",
    15: "certificate_verify",
    16: "client_key_exchange",
    20: "finished",
}
TLS_VERSIONS = {
    (3, 1): "TLS 1.0",
    (3, 2): "TLS 1.1",
    (3, 3): "TLS 1.2",
    (3, 4): "TLS 1.3",
}
ALERT_LEVELS = {1: "warning", 2: "fatal"}
# sous-ensemble du registre IANA TLS Alert -- les codes les plus frequents
# en depannage reseau (filtrage SNI, inspection TLS, certificats, MTU)
ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    90: "user_canceled",
    109: "missing_extension",
    112: "unrecognized_name",
    116: "certificate_required",
}


def _tls_version_str(major: int, minor: int) -> str:
    return TLS_VERSIONS.get((major, minor), f"0x{major:02x}{minor:02x}")


@dataclass
class TlsEvent:
    point: str
    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    record_type: str  # "handshake" | "alert" | "change_cipher_spec" | "application_data"
    handshake_type: str | None = None
    sni: str | None = None
    tls_version: str | None = None
    cipher: str | None = None
    alert_level: str | None = None
    alert_description: str | None = None
    record_length: int | None = None
    truncated: bool = False


def _flow_id(src: str, sport: int, dst: str, dport: int) -> str:
    """Identifiant de flux independant du sens (client->serveur ou
    serveur->client voient le meme flux avec src/dst inverses)."""
    a, b = f"{src}:{sport}", f"{dst}:{dport}"
    return " <-> ".join(sorted((a, b)))


def _read_u16(b: bytes, i: int) -> int | None:
    return int.from_bytes(b[i : i + 2], "big") if i + 2 <= len(b) else None


def parse_client_hello(body: bytes) -> dict:
    """
    Extrait la version TLS proposee et le SNI (extension server_name)
    d'un corps de message ClientHello. Renvoie {} des que la structure
    ne correspond pas a ce qui est attendu -- pas de reconstruction
    approximative en cas de doute.
    """
    if len(body) < 34:
        logger.trace("parse_client_hello: corps trop court ({} octets), ignore", len(body))
        return {}
    version = _tls_version_str(body[0], body[1])
    i = 34  # client_version(2) + random(32)
    if i >= len(body):
        return {"tls_version": version}
    session_id_len = body[i]
    i += 1 + session_id_len
    cs_len = _read_u16(body, i)
    if cs_len is None:
        return {"tls_version": version}
    i += 2 + cs_len
    if i >= len(body):
        return {"tls_version": version}
    comp_len = body[i]
    i += 1 + comp_len
    ext_total_len = _read_u16(body, i)
    if ext_total_len is None:
        logger.trace("parse_client_hello: ClientHello sans extensions, SNI inconnu")
        return {"tls_version": version}
    i += 2
    ext_end = min(i + ext_total_len, len(body))
    sni = None
    while i + 4 <= ext_end:
        ext_type = _read_u16(body, i)
        ext_len = _read_u16(body, i + 2)
        if ext_type is None or ext_len is None:
            break
        ext_body = body[i + 4 : i + 4 + ext_len]
        if ext_type == 0 and len(ext_body) >= 5:  # server_name
            name_len = _read_u16(ext_body, 3)
            if name_len is not None:
                sni = ext_body[5 : 5 + name_len].decode(errors="replace")
        i += 4 + ext_len
    return {"tls_version": version, "sni": sni}


def parse_server_hello(body: bytes) -> dict:
    """Extrait la version TLS negociee et le cipher suite choisi."""
    if len(body) < 35:
        logger.trace("parse_server_hello: corps trop court ({} octets), ignore", len(body))
        return {}
    version = _tls_version_str(body[0], body[1])
    i = 34
    session_id_len = body[i]
    i += 1 + session_id_len
    cipher = _read_u16(body, i)
    if cipher is None:
        return {"tls_version": version}
    return {"tls_version": version, "cipher": f"0x{cipher:04x}"}


def parse_alert(body: bytes) -> dict:
    if len(body) < 2:
        logger.trace("parse_alert: alerte tronquee ({} octet(s))", len(body))
        return {}
    level = ALERT_LEVELS.get(body[0], f"unknown({body[0]})")
    desc = ALERT_DESCRIPTIONS.get(body[1], f"unknown({body[1]})")
    return {"level": level, "description": desc}


def _iter_tls_records(
    payload: bytes,
) -> Iterator[tuple[int, int, int, int, bytes, bool]]:
    """(content_type, major, minor, length_annoncee, body, truncated) pour
    chaque record TLS trouve dans le payload. S'arrete des que ca ne
    ressemble plus a du TLS bien forme, plutot que de deviner."""
    i, n = 0, len(payload)
    while i + 5 <= n:
        content_type, major, minor = payload[i], payload[i + 1], payload[i + 2]
        length = int.from_bytes(payload[i + 3 : i + 5], "big")
        if content_type not in TLS_CONTENT_TYPES or major != 3:
            logger.trace("_iter_tls_records: plus de TLS bien forme a l'offset {} (type {})", i, content_type)
            break
        body_start = i + 5
        body_end = body_start + length
        truncated = body_end > n
        body = payload[body_start : min(body_end, n)]
        yield content_type, major, minor, length, body, truncated
        if truncated:
            logger.trace("_iter_tls_records: record de {} octets tronque a {}", length, len(body))
            break  # le reste est dans un segment suivant, pas de reassemblage ici
        i = body_end


def _iter_handshake_messages(body: bytes) -> Iterator[tuple[int, bytes, bool]]:
    """(handshake_type, message_body, truncated) -- un record handshake
    TLS 1.2 peut contenir plusieurs messages concatenes (typiquement
    Certificate + ServerKeyExchange + ServerHelloDone dans un seul
    record)."""
    i, n = 0, len(body)
    while i + 4 <= n:
        htype = body[i]
        hlen = int.from_bytes(body[i + 1 : i + 4], "big")
        msg_start = i + 4
        msg_end = msg_start + hlen
        if msg_end > n:
            logger.trace("_iter_handshake_messages: message {} tronque ({}/{} octets)", htype, n - msg_start, hlen)
            yield htype, body[msg_start:n], True
            break
        yield htype, body[msg_start:msg_end], False
        i = msg_end


def _looks_like_tls(payload: bytes) -> bool:
    return len(payload) >= 5 and payload[0] in TLS_CONTENT_TYPES and payload[1] == 3


def parse_tls_capture(label: str, path: str) -> list[TlsEvent]:
    """Lit une capture via pcap_parser (tshark -T ek) et renvoie les
    evenements TLS trouves sur des segments TCP. Comme parse_capture(),
    avale les erreurs de lecture (message sur stderr, deja emis par
    pcap_parser lui-meme) et renvoie une liste vide plutot que de faire
    planter tout le run -- coherent avec le reste de netcross_core."""
    events: list[TlsEvent] = []
    raw_packets = pcap_parser.parse_capture(path, raise_on_error=False)
    logger.debug("parse_tls_capture: point {}, {} paquet(s) lus depuis {}", label, len(raw_packets), path)
    tls_segments = 0

    for raw in raw_packets:
        if raw.proto != "TCP" or not raw.payload:
            continue

        payload = raw.payload
        if not _looks_like_tls(payload):
            continue
        tls_segments += 1

        ts = raw.ts
        src, dst = raw.src, raw.dst
        sport, dport = raw.sport, raw.dport

        for content_type, _major, _minor, length, body, truncated in _iter_tls_records(payload):
            type_name = TLS_CONTENT_TYPES[content_type]
            base_truncated = truncated
            base_length = length

            if content_type == 22:  # handshake
                for htype, msg_body, msg_truncated in _iter_handshake_messages(body):
                    hs_name = HANDSHAKE_TYPES.get(htype, f"unknown({htype})")
                    extra = {}
                    if htype == 1 and not msg_truncated:
                        extra = parse_client_hello(msg_body)
                    elif htype == 2 and not msg_truncated:
                        extra = parse_server_hello(msg_body)
                    events.append(
                        TlsEvent(
                            point=label,
                            ts=ts,
                            src=src,
                            sport=sport or 0,
                            dst=dst,
                            dport=dport or 0,
                            record_type=type_name,
                            record_length=base_length,
                            truncated=base_truncated or msg_truncated,
                            handshake_type=hs_name,
                            sni=extra.get("sni"),
                            tls_version=extra.get("tls_version"),
                            cipher=extra.get("cipher"),
                        )
                    )
            elif content_type == 21:  # alert
                extra = parse_alert(body) if not truncated else {}
                events.append(
                    TlsEvent(
                        point=label,
                        ts=ts,
                        src=src,
                        sport=sport or 0,
                        dst=dst,
                        dport=dport or 0,
                        record_type=type_name,
                        record_length=base_length,
                        truncated=base_truncated,
                        alert_level=extra.get("level"),
                        alert_description=extra.get("description"),
                    )
                )
            else:  # change_cipher_spec, application_data : pas de champ supplementaire
                events.append(
                    TlsEvent(
                        point=label,
                        ts=ts,
                        src=src,
                        sport=sport or 0,
                        dst=dst,
                        dport=dport or 0,
                        record_type=type_name,
                        record_length=base_length,
                        truncated=base_truncated,
                    )
                )

    logger.debug(
        "parse_tls_capture: point {}, {} segment(s) TLS, {} evenement(s) dont {} tronque(s)",
        label,
        tls_segments,
        len(events),
        sum(1 for ev in events if ev.truncated),
    )
    return events


@dataclass
class HandshakeStatus:
    point: str
    flow_id: str
    client_hello_seen: bool = False
    sni: str | None = None
    server_hello_seen: bool = False
    tls_version: str | None = None
    cipher: str | None = None
    fatal_alert: str | None = None
    warning_alert: str | None = None
    application_data_seen: bool = False
    first_ts: float | None = None
    last_ts: float | None = None

    @property
    def verdict(self) -> str:
        if self.fatal_alert:
            return f"alert_fatal:{self.fatal_alert}"
        if self.application_data_seen:
            return "complete"
        if self.server_hello_seen:
            return "server_hello_no_data"
        if self.client_hello_seen:
            return "client_hello_no_reply"
        return "no_handshake_seen"


def build_handshake_status(
    events: list[TlsEvent],
) -> dict[str, dict[str, HandshakeStatus]]:
    """point -> flow_id -> HandshakeStatus, construit en rejouant les
    evenements dans l'ordre chronologique."""
    status: dict[str, dict[str, HandshakeStatus]] = {}
    for ev in sorted(events, key=lambda e: e.ts):
        fid = _flow_id(ev.src, ev.sport, ev.dst, ev.dport)
        per_point = status.setdefault(ev.point, {})
        st = per_point.setdefault(fid, HandshakeStatus(point=ev.point, flow_id=fid))

        if st.first_ts is None:
            st.first_ts = ev.ts
        st.last_ts = ev.ts

        if ev.record_type == "handshake" and ev.handshake_type == "client_hello":
            st.client_hello_seen = True
            st.sni = st.sni or ev.sni
            st.tls_version = st.tls_version or ev.tls_version
        elif ev.record_type == "handshake" and ev.handshake_type == "server_hello":
            st.server_hello_seen = True
            st.tls_version = ev.tls_version or st.tls_version
            st.cipher = ev.cipher or st.cipher
        elif ev.record_type == "alert":
            if ev.alert_level == "fatal":
                st.fatal_alert = ev.alert_description
            elif ev.alert_level == "warning":
                st.warning_alert = ev.alert_description
        elif ev.record_type == "application_data":
            st.application_data_seen = True

    logger.debug(
        "build_handshake_status: {} evenement(s) -> {} flux sur {} point(s)",
        len(events),
        sum(len(per_point) for per_point in status.values()),
        len(status),
    )
    return status


@dataclass
class TlsFinding:
    severity: str  # "anomalie" | "a_surveiller" | "info" -- meme vocabulaire que synthesis.Finding
    category: str = "TLS"
    segment: str = ""
    message: str = ""


def diagnose_tls(
    status_by_point: dict[str, dict[str, HandshakeStatus]],
    points_order: list[str] | None = None,
) -> list[TlsFinding]:
    """
    Compare l'etat des handshakes TLS entre points consecutifs et
    localise le segment ou un handshake qui reussissait en amont se met
    a echouer. Sans points_order, utilise l'ordre alphabetique des
    points -- fournir --order pour un resultat fiable (contrairement a
    analysis.py, ce module ne deduit pas la topologie lui-meme, c'est
    une limite assumee vu son perimetre).
    """
    findings: list[TlsFinding] = []
    points = points_order or sorted(status_by_point)
    logger.debug(
        "diagnose_tls: {} point(s), ordre {}", len(points), "fourni" if points_order else "alphabetique (par defaut)"
    )

    # -- alertes fatales, un constat par point --
    for point in points:
        fatal = [st for st in status_by_point.get(point, {}).values() if st.fatal_alert]
        if fatal:
            examples = ", ".join(sorted({f"{st.sni or '?'}:{st.fatal_alert}" for st in fatal})[:3])
            findings.append(
                TlsFinding(
                    "anomalie",
                    "TLS",
                    point,
                    f"{len(fatal)} handshake(s) TLS avec alert fatal a ce point (ex: {examples})",
                )
            )

    # -- degradation entre points consecutifs, flux par flux --
    # itertools.pairwise() serait plus idiomatique mais demande Python 3.10+ ;
    # zip() reste compatible avec le python3 3.9 par defaut de Rocky/RHEL 9.
    for a, b in zip(points, points[1:]):  # noqa: RUF007
        status_a, status_b = status_by_point.get(a, {}), status_by_point.get(b, {})
        broken_here = []
        for fid, st_a in status_a.items():
            st_b = status_b.get(fid)
            if st_b is None:
                # flux pas vu au point suivant -- hors perimetre de ce module
                # (voir netcross_core.analyse pour les pertes)
                logger.trace("diagnose_tls: flux {} absent en {}, ignore", fid, b)
                continue
            if st_a.verdict == "complete" and st_b.verdict != "complete":
                broken_here.append((st_a, st_b))
        if broken_here:
            examples = ", ".join(sorted({st_a.sni or st_a.flow_id for st_a, _ in broken_here})[:3])
            verdicts = sorted({st_b.verdict for _, st_b in broken_here})
            findings.append(
                TlsFinding(
                    "anomalie",
                    "TLS",
                    f"{a} -> {b}",
                    f"{len(broken_here)} handshake(s) TLS qui aboutissaient en {a} echouent en {b} "
                    f"({', '.join(verdicts)}) -- SNI concernes : {examples} -- suspects : inspection "
                    f"TLS/firewall qui coupe sur le SNI, fragmentation du ClientHello, MTU de tunnel",
                )
            )

    # -- contexte, pas un probleme en soi --
    for point in points:
        all_status = status_by_point.get(point, {})
        total = len(all_status)
        if total == 0:
            continue
        complete = sum(1 for st in all_status.values() if st.verdict == "complete")
        findings.append(
            TlsFinding(
                "info",
                "TLS",
                point,
                f"{complete}/{total} handshakes TLS aboutis a ce point",
            )
        )

    findings.sort(
        key=lambda f: (
            {"anomalie": 0, "a_surveiller": 1, "info": 2}[f.severity],
            f.segment,
        )
    )
    logger.debug(
        "diagnose_tls: {} constat(s) dont {} anomalie(s)",
        len(findings),
        sum(1 for f in findings if f.severity == "anomalie"),
    )
    return findings


def print_tls_diagnostics(findings: list[TlsFinding]) -> None:
    logger.debug("print_tls_diagnostics: {} constat(s)", len(findings))
    print("=" * 70)
    print("DIAGNOSTIC TLS -- etat des handshakes par point")
    print("=" * 70)
    if not findings:
        print(
            "\nAucun trafic TLS detecte (ou aucune capture ne contenait de segment "
            "reconnaissable comme TLS -- QUIC/HTTP3 et le TLS en tunnel ne sont pas couverts)."
        )
        return
    for f in findings:
        print(f"  [{f.severity:12s}] {f.segment:20s} : {f.message}")
