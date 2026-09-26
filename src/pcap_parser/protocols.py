"""
pcap_parser.protocols -- couche 4 : RTP / DHCP / SIP.

Contrairement a l'ancienne version qui devait tout reimplementer
a la main (parse_rtp, parse_dhcp, parse_sip operant sur les octets
bruts), tshark dissecte deja ces trois protocoles nativement quand il
les reconnait. On lit d'abord ses resultats ; seul le cas ou tshark n'a
PAS reconnu le protocole (port SIP non standard, RTP sans heuristique
activee) retombe sur un parsing heuristique du payload brut -- repli
qui reutilise le meme algorithme que l'ancienne version, sur le
payload extrait via udp.payload / tcp.payload (champ hex EK).
"""

from __future__ import annotations

from loguru import logger as _loguru_logger

from pcap_parser.ek_fields import as_bool, as_float, g, hex_or_dec_to_int, innermost

# pcap_parser reste independant de netcross_core (contrat import-linter) :
# loguru directement, lie au nom du module.
logger = _loguru_logger.bind(name=__name__)
try:  # cryptography est une dependance du projet ; son absence degrade l'extraction, ne la casse pas
    from cryptography import x509 as _x509
    from cryptography.exceptions import UnsupportedAlgorithm as _UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import dsa as _dsa
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric import ed448 as _ed448
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
except ImportError:  # pragma: no cover - exercee seulement sans cryptography
    logger.debug("dépendance optionnelle absente: ImportError")
    _x509 = None  # type: ignore[assignment]

# Table de correspondance code -> nom, cf. RFC 2132 section 9.6 (option
# 53, DHCP Message Type). Wireshark ne rend que le code numerique en EK
# (dhcp_dhcp_type), le nommage etait auparavant fait a la main.
DHCP_MESSAGE_TYPES = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}

# Table de correspondance code -> nom, RFC 1035 section 4.1.1 (RCODE, code
# de retour DNS sur 4 bits a l'origine, etendu depuis par RFC 6895). Sert
# uniquement a l'affichage lisible d'un code quelconque -- NXDOMAIN/SERVFAIL
# sont testes en dur par leur valeur numerique la ou ca compte (analysis.py),
# comme DHCP_MESSAGE_TYPES ci-dessus n'est qu'un affichage, pas une logique.
DNS_RCODES = {
    0: "NoError",
    1: "FormErr",
    2: "ServFail",
    3: "NXDomain",
    4: "NotImp",
    5: "Refused",
}

SIP_METHODS = (
    "INVITE",
    "ACK",
    "BYE",
    "CANCEL",
    "REGISTER",
    "OPTIONS",
    "PRACK",
    "SUBSCRIBE",
    "NOTIFY",
    "MESSAGE",
    "INFO",
    "UPDATE",
    "REFER",
    "PUBLISH",
)


def extract_rtp(layers: dict, udp_payload: bytes) -> dict | None:
    """Lit le resultat de la dissection RTP de tshark si presente
    (rtp.heuristic_rtp:TRUE est active par defaut dans ek_source.py,
    cf. DEFAULT_PREFS) ; sinon retombe sur l'heuristique par octets,
    identique a l'ancienne parse_rtp()."""
    rtp = innermost(layers, "rtp")
    if rtp is not None:
        seq = hex_or_dec_to_int(g(rtp, "rtp_rtp_seq"))
        ts = hex_or_dec_to_int(g(rtp, "rtp_rtp_timestamp"))
        ssrc = hex_or_dec_to_int(g(rtp, "rtp_rtp_ssrc"))
        pt = hex_or_dec_to_int(g(rtp, "rtp_rtp_p_type"))
        if seq is not None and ts is not None and ssrc is not None:
            return {"pt": pt, "seq": seq, "ts": ts, "ssrc": ssrc}

    return _parse_rtp_heuristic(udp_payload)


def _parse_rtp_heuristic(payload: bytes) -> dict | None:
    """Detection heuristique d'un en-tete RTP (version=2 + coherence de
    longueur), pour les flux que tshark n'a pas reconnus faute de
    signalisation SDP vue dans la capture. Identique a l'ancien
    parse_rtp() de parsing.py."""
    if len(payload) < 12:
        return None
    b0 = payload[0]
    if (b0 >> 6) & 0x3 != 2:
        return None
    cc = b0 & 0xF
    header_len = 12 + cc * 4
    if header_len > len(payload):
        return None
    pt = payload[1] & 0x7F
    seq = int.from_bytes(payload[2:4], "big")
    ts = int.from_bytes(payload[4:8], "big")
    ssrc = int.from_bytes(payload[8:12], "big")
    return {"pt": pt, "seq": seq, "ts": ts, "ssrc": ssrc}


def extract_dhcp(layers: dict) -> dict | None:
    """Lit la dissection DHCP/BOOTP native de tshark. Renvoie None si le
    paquet n'est pas du DHCP (dhcp.type absent)."""
    dhcp = innermost(layers, "dhcp")
    if dhcp is None:
        return None
    msg_code = hex_or_dec_to_int(g(dhcp, "dhcp_dhcp_type"))
    if msg_code is None:
        return None
    return {
        "xid": hex_or_dec_to_int(g(dhcp, "dhcp_dhcp_id")),
        "msg_type": DHCP_MESSAGE_TYPES.get(msg_code, str(msg_code)),
        "server_id": g(dhcp, "dhcp_dhcp_option_dhcp_server_id"),
        "vendor_class": g(dhcp, "dhcp_dhcp_option_vendor_class_id"),
    }


def extract_sip(layers: dict, payload: bytes) -> dict | None:
    """Lit la dissection SIP native de tshark (reconnue sur le port 5060
    et quelques autres ports enregistres) ; sinon retombe sur
    l'heuristique par premiere ligne du payload, comme l'ancien
    parse_sip() -- utile pour du SIP sur un port non standard."""
    sip = innermost(layers, "sip")
    if sip is not None:
        msg_type = g(sip, "sip_sip_Method") or g(sip, "sip_sip_Status-Line")
        if msg_type is not None:
            return {
                "msg_type": msg_type,
                "call_id": g(sip, "sip_sip_Call-ID"),
                "cseq": g(sip, "sip_sip_CSeq"),
                "user_agent": g(sip, "sip_sip_User-Agent"),
                "server": g(sip, "sip_sip_Server"),
            }

    return _parse_sip_heuristic(payload)


def _parse_sip_heuristic(payload: bytes) -> dict | None:
    """Identique a l'ancien parse_sip() : detection par premiere ligne
    (methode connue ou "SIP/2.0 <code>"), extraction litterale des
    en-tetes sans interpretation."""
    if not payload:
        return None
    try:
        text = payload.decode("utf-8", errors="replace")
    except (AttributeError, UnicodeError):
        logger.trace("_parse_sip_heuristic: charge utile non décodable ({} octets)", len(payload))
        return None
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    if not lines:
        return None
    first = lines[0].strip()

    msg_type = None
    if first.startswith("SIP/2.0 "):
        parts = first.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            msg_type = f"{parts[1]} {parts[2] if len(parts) > 2 else ''}".strip()
    else:
        token = first.split(" ", 1)[0]
        if token in SIP_METHODS:
            msg_type = token
    if msg_type is None:
        return None

    headers = {}
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    return {
        "msg_type": msg_type,
        "call_id": headers.get("call-id") or headers.get("i"),
        "cseq": headers.get("cseq"),
        "user_agent": headers.get("user-agent"),
        "server": headers.get("server"),
    }


def extract_dns(layers: dict) -> dict | None:
    """Lit la dissection DNS native de tshark (reconnue sur le port 53,
    UDP comme TCP, entre autres). Renvoie None si le paquet n'est pas du
    DNS (dns.id absent). Contrairement a RTP/SIP, pas de repli
    heuristique : DNS n'a pas de forme "sans signalisation prealable" a
    detecter par lecture d'octets bruts -- tshark le reconnait nativement
    des que le port est standard ou que la conversation complete est
    visible dans la capture, cas largement majoritaire en pratique.

    dns.qry.name peut en theorie etre une liste si le paquet contient
    plusieurs questions (dns.count.queries > 1, rarissime en pratique) --
    on ne garde que la premiere, meme simplification que layer()/
    innermost() pour les couches empilees ailleurs dans ce package."""
    dns = innermost(layers, "dns")
    if dns is None:
        return None
    txn_id = hex_or_dec_to_int(g(dns, "dns_dns_id"))
    if txn_id is None:
        return None
    qry_name = g(dns, "dns_dns_qry_name")
    if isinstance(qry_name, list):
        qry_name = qry_name[0] if qry_name else None
    return {
        "txn_id": txn_id,
        "is_response": as_bool(g(dns, "dns_dns_flags_response")),
        "qry_name": qry_name,
        "rcode": hex_or_dec_to_int(g(dns, "dns_dns_flags_rcode")),
        "answers": _dns_answers(dns),
    }


def _dns_answers(dns: dict) -> tuple[str, ...]:
    """Adresses A/AAAA de la section reponse (issue #344 : fast flux).

    Verifie avec tshark 4.2 (reponse forgee a 3 A + 1 AAAA) : ``dns.a`` et
    ``dns.aaaa`` sont une chaine quand il n'y a qu'un enregistrement, une
    liste sinon. Ordre conserve, doublons retires ; tuple vide pour une
    requete ou une reponse sans A/AAAA (NXDOMAIN, CNAME seul...)."""
    out: list[str] = []
    for key in ("dns_dns_a", "dns_dns_aaaa"):
        val = g(dns, key)
        if val is None:
            continue
        for ip in val if isinstance(val, list) else [val]:
            if ip and ip not in out:
                out.append(str(ip))
    return tuple(out)


def extract_http(layers: dict) -> dict | None:
    """Lit la dissection HTTP/1.x native de tshark (reconnue sur le port 80
    et quelques autres ports enregistres/suivis). Renvoie None si ni
    http.request ni http.response n'est present -- contrairement a
    RTP/SIP, pas de repli heuristique : meme raisonnement que pour DNS
    (extract_dns ci-dessus), tshark reconnait HTTP nativement des que le
    port est standard ou que la conversation complete est visible.

    HTTP/2 (bien que lui aussi transporte sur TCP) a un dissecteur tshark
    distinct (couche "http2", nommage de champs different) et HTTP/3 est
    QUIC/UDP (deja couvert separement par netcross_core.quic_diagnostics,
    limite au SNI, pas de code de statut) -- tous deux hors perimetre ici.

    Verifie empiriquement (tshark 4.2.2, capture HTTP/1.1 reelle generee
    sur loopback -- serveur+client locaux, voir claude.md Session 17) :
    - http.request / http.response sont rendus en booleen JSON natif
      (comme ip.flags.df, cf. Session 9) ;
    - http.response.code est une chaine decimale ("200", "404"...) ;
    - http.time (ecart requete->reponse calcule NATIVEMENT par le
      dissecteur HTTP de tshark, present uniquement sur le paquet de
      reponse quand tshark a pu apparier la transaction dans CE fichier)
      est une chaine flottante de secondes ("0.000467410") -- d'ou
      as_float, symetrique a hex_or_dec_to_int pour les champs non
      entiers ;
    - la reponse ne porte pas la methode (http.request.method est
      uniquement sur la requete), mais porte http.response.for.uri --
      l'URI complete de la requete a laquelle elle repond, deja calculee
      par tshark. On l'utilise directement plutot que de re-apparier
      requete/reponse nous-memes : cote requete on prefere l'URI complete
      (http.request.full.uri, avec schema+host) quand disponible, sinon
      le chemin seul (http.request.uri).
    """
    http = innermost(layers, "http")
    if http is None:
        return None
    is_request = as_bool(g(http, "http_http_request"))
    is_response = as_bool(g(http, "http_http_response"))
    if not is_request and not is_response:
        return None
    if is_request:
        uri = g(http, "http_http_request_full_uri") or g(http, "http_http_request_uri")
    else:
        uri = g(http, "http_http_response_for_uri")
    response_time_s = as_float(g(http, "http_http_time"))
    content_length = hex_or_dec_to_int(g(http, "http_http_content_length"))
    content_type = g(http, "http_http_content_type")
    if isinstance(content_type, list):
        content_type = content_type[0] if content_type else None
    return {
        "is_request": is_request,
        "is_response": is_response,
        "method": g(http, "http_http_request_method"),
        "uri": uri,
        "status_code": hex_or_dec_to_int(g(http, "http_http_response_code")),
        "response_time_ms": response_time_s * 1000.0 if response_time_s is not None else None,
        "content_type": content_type,
        "content_length": content_length,
    }


# OID de signature que `cryptography` ne sait pas mapper vers un hash (il leve
# UnsupportedAlgorithm) mais qui doivent quand meme etre reconnus comme faibles.
_UNMAPPED_SIGNATURE_HASHES = {
    "1.2.840.113549.1.1.2": "md2",  # md2WithRSAEncryption
    "1.2.840.113549.1.1.3": "md4",  # md4WithRSAEncryption
}


def _public_key_summary(cert) -> tuple[str | None, int | None]:
    """(type, taille en bits) de la cle publique d'un certificat : "RSA"/"EC"/
    "DSA"/"Ed25519"/"Ed448". La taille d'une courbe elliptique est celle de la
    courbe (256 pour P-256), celle d'une cle EdDSA n'est pas significative
    (None). (None, None) si la cle n'est pas decodable."""
    try:
        key = cert.public_key()
    except (ValueError, _UnsupportedAlgorithm) as exc:
        logger.debug("_public_key_summary: clé publique non décodable ({})", type(exc).__name__)
        return None, None
    if isinstance(key, _rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, _ec.EllipticCurvePublicKey):
        return "EC", key.curve.key_size
    if isinstance(key, _dsa.DSAPublicKey):
        return "DSA", key.key_size
    if isinstance(key, _ed25519.Ed25519PublicKey):
        return "Ed25519", None
    if isinstance(key, _ed448.Ed448PublicKey):
        return "Ed448", None
    return type(key).__name__, None


def _signature_hash(cert) -> str | None:
    """Nom du hash de la signature du certificat ("sha256", "sha1", "md5"...),
    None pour une signature sans hash separe (EdDSA) ou inconnue."""
    try:
        algo = cert.signature_hash_algorithm
    except _UnsupportedAlgorithm:
        logger.debug("_signature_hash: algorithme non pris en charge {}", cert.signature_algorithm_oid.dotted_string)
        return _UNMAPPED_SIGNATURE_HASHES.get(cert.signature_algorithm_oid.dotted_string)
    return algo.name if algo is not None else None


def _certificate_details(tls: dict) -> dict:
    """Details X.509 du certificat FEUILLE, lus dans le DER brut que tshark
    expose en EK (`tls.handshake.certificate`, une valeur hexadecimale par
    certificat de la chaine, feuille en premier -- RFC 5246 7.4.2).

    Complete `extract_tls_certificate` la ou le flux EK aplati est ambigu
    (Subject/Issuer, algorithmes, cle) : le DER de CHAQUE certificat est
    parse individuellement, il n'y a donc plus de tableau positionnel partage
    entre certificats. Verifie empiriquement sur des captures TLS 1.2
    reelles (tshark 4.2.2) : chaine complete, feuille seule, auto-signe.

    Renvoie un dict vide si le DER est absent ou illisible (ancienne version
    de tshark, `cryptography` absent) -- l'appelant conserve alors les champs
    historiques, jamais une valeur devinee."""
    raw = g(tls, "tls_tls_handshake_certificate")
    blobs = raw if isinstance(raw, list) else ([raw] if raw else [])
    if not blobs or _x509 is None:
        return {}
    try:
        leaf = _x509.load_der_x509_certificate(bytes.fromhex(str(blobs[0]).replace(":", "")))
    except ValueError as exc:
        logger.debug("_certificate_details: DER du certificat feuille illisible ({})", exc)
        return {}
    key_type, key_bits = _public_key_summary(leaf)
    try:
        san = leaf.extensions.get_extension_for_class(_x509.SubjectAlternativeName).value
        san_ip = tuple(str(ip) for ip in san.get_values_for_type(_x509.IPAddress))
    except (_x509.ExtensionNotFound, ValueError) as exc:
        # certificat sans SAN : cas courant, pas une erreur
        logger.trace("_certificate_details: pas de SAN IP lisible ({})", type(exc).__name__)
        san_ip = ()
    return {
        "issuer": leaf.issuer.rfc4514_string(),
        "subject": leaf.subject.rfc4514_string(),
        "sig_hash": _signature_hash(leaf),
        "key_type": key_type,
        "key_bits": key_bits,
        "san_ip": san_ip,
        "chain_len": len(blobs),
    }


def extract_tls_certificate(layers: dict) -> dict | None:
    """
    Lit la dissection X.509 native de tshark au sein d'un message TLS
    Certificate (tshark dissecte automatiquement la chaine complete, y
    compris l'imbrication ASN.1 des certificats, des qu'il reconnait du
    TLS -- port 443 et quelques autres ports enregistres, ou via
    heuristique). Renvoie None si aucun certificat n'est present dans ce
    paquet (grande majorite des paquets TLS : ClientHello, Application
    Data, etc. n'en portent pas).

    Se limite volontairement au certificat FEUILLE (le premier de la
    chaine) : la RFC 5246 §7.4.2 impose que "the sender's certificate
    MUST come first in the list" -- les indices 0/1 (dates de validite)
    et le premier element (numero de serie/SAN) correspondent donc
    TOUJOURS au certificat du serveur lui-meme, quelle que soit la
    longueur de la chaine presentee (feuille seule, ou feuille +
    intermediaire(s)). Les dates de validite et le SAN des certificats
    intermediaires/racine eventuellement presents dans la meme chaine ne
    sont PAS extraits (indices suivants du meme champ EK, ignores) --
    perimetre volontaire : diagnostiquer le certificat que le SERVEUR
    presente au CLIENT, pas verifier toute la chaine de confiance PKI
    (hors de portee d'une capture reseau passive de toute facon, qui n'a
    pas acces au magasin de confiance du client).

    Depuis l'issue #153 (audit des certificats TLS), les champs Sujet/Emetteur,
    algorithme de signature, cle publique, IP du SAN et longueur de chaine
    sont ajoutes (cles "issuer", "subject", "sig_hash", "key_type",
    "key_bits", "san_ip", "chain_len") en parsant le DER brut de chaque
    certificat plutot que les tableaux EK aplatis -- voir
    _certificate_details. Ces cles sont ABSENTES si le DER n'est pas
    disponible. La justification ci-dessous reste vraie pour les champs EK
    aplatis eux-memes, qui restent inutilises pour Subject/Issuer.

    N'extrait PAS Sujet/Emetteur (Subject/Issuer Distinguished Name) via ces
    champs EK aplatis :
    tshark les aplatit en EK dans des tableaux positionnels PARTAGES
    entre TOUTES les RDN de TOUS les certificats de la chaine
    (x509if.oid / x509sat.uTF8String / x509sat.CountryName...), sans
    moyen fiable de determiner par simple position laquelle des deux RDN
    (Issuer ou Subject, du meme certificat OU d'un autre de la chaine)
    correspond a quel attribut (CN/O/OU/C). Reconstruire cette info de
    facon fiable demanderait de parcourir l'arbre imbrique (`-T json` ou
    `-T pdml`, PAS `-T ek`) plutot que le flux EK deja aplati utilise
    partout ailleurs dans ce pipeline -- chantier a part, hors de
    perimetre ici. Verifie empiriquement (tshark 4.2.2, capture TLS 1.2
    reelle generee sur loopback -- serveur+client locaux openssl, voir
    claude.md Session 26) : SAN (x509ce.dNSName) et dates de validite
    (x509af.utcTime), elles, sont des champs a plat SANS cette
    ambiguite -- d'ou le perimetre retenu ici.

    Rappel important (verifie empiriquement, memes captures) : en TLS
    1.3, le message Certificate est chiffre (RFC 8446) et donc invisible
    en capture passive sans les cles de session -- cette fonction ne
    peut renvoyer un resultat que sur un handshake TLS 1.2 ou anterieur,
    ou sur un TLS 1.3 dont les cles ont ete fournies a tshark
    (SSLKEYLOGFILE), cas rare pour une capture passive sur le terrain.
    """
    tls = innermost(layers, "tls")
    if tls is None:
        return None
    dates = g(tls, "x509af_x509af_utcTime")
    if not isinstance(dates, list):
        dates = [dates] if dates is not None else []
    if len(dates) < 2:
        return None  # pas de certificat (dates de validite) dans ce paquet
    san = g(tls, "x509ce_x509ce_dNSName")
    if san is None:
        san = ()
    elif isinstance(san, list):
        san = tuple(san)
    else:
        san = (san,)
    serial = g(tls, "x509af_x509af_serialNumber")
    if isinstance(serial, list):
        serial = serial[0] if serial else None
    return {
        "not_before": dates[0],
        "not_after": dates[1],
        "san": san,
        "serial": serial,
        **_certificate_details(tls),
    }


def extract_tls_handshake(layers: dict) -> dict | None:
    """
    Session 54 -- lit UNIQUEMENT des champs d'en-tete TLS toujours en
    clair, jamais le contenu chiffre lui-meme : tls.record.content_type
    (type de l'ENREGISTREMENT -- 20=change_cipher_spec, 21=alert,
    22=handshake, 23=application_data) fait partie de l'en-tete de
    chaque enregistrement TLS et reste donc visible meme quand son
    contenu est chiffre (verifie empiriquement : capture TLS 1.2 reelle
    sur loopback, tshark 4.2.2, openssl s_server/curl -- le Finished
    chiffre apres ChangeCipherSpec a bien content_type=22 mais AUCUN
    tls.handshake.type decode, voir claude.md Session 54) ; et
    tls.handshake.type (sous-type -- 1=ClientHello, 2=ServerHello --
    UNIQUEMENT decodable quand ce sous-message est encore en clair).

    Sert a `_analyse_tls_handshake` (netcross_core.analysis) pour
    detecter les negociations TLS qui ne vont jamais a leur terme --
    concept different du certificat presente (extract_tls_certificate
    ci-dessus), volontairement independant : une fonction PAR signal,
    memes garanties de bas niveau (aucune interpretation ici, seulement
    la lecture de ce que tshark a deja disseque).

    Un seul paquet peut porter PLUSIEURS enregistrements TLS coalesces
    (ex : ServerHello + Certificate + ServerKeyExchange + ServerHello
    Done souvent regroupes par le serveur dans un seul segment TCP) --
    tshark rend alors content_type/handshake_type en LISTES paralleles
    plutot qu'en valeur scalaire (meme situation que x509af_x509af_
    utcTime dans extract_tls_certificate ci-dessus, meme traitement
    scalaire-ou-liste). Peu importe pour cette fonction COMBIEN de
    ClientHello/ServerHello un paquet porte ni dans quel ordre au sein
    du paquet -- seuls des booleens agreges par paquet sont renvoyes,
    les appelants n'ont besoin que de savoir CE QUI est present.

    Renvoie None si ce paquet ne porte aucune couche "tls" (evite tout
    travail inutile sur la tres grande majorite des paquets qui n'en
    ont pas -- meme garde que extract_tls_certificate).
    """
    tls = innermost(layers, "tls")
    if tls is None:
        return None

    def _as_int_set(value) -> set[int]:
        if not isinstance(value, list):
            value = [value] if value is not None else []
        return {v for v in (hex_or_dec_to_int(x) for x in value) if v is not None}

    content_types = _as_int_set(g(tls, "tls_tls_record_content_type"))
    handshake_types = _as_int_set(g(tls, "tls_tls_handshake_type"))

    return {
        "client_hello": 1 in handshake_types,
        "server_hello": 2 in handshake_types,
        "application_data": 23 in content_types,
    }


def compute_mos(delay_ms: float, loss_pct: float):
    """R-factor / MOS simplifies (modele type Cisco, codec G.711 : Ie=0,
    Bpl=4.3). Inchange par rapport a l'ancienne version -- calcul pur,
    aucune dependance a tshark."""
    d = max(0.0, delay_ms)
    # Id/Ie_eff/R : noms consacres par l'E-model simplifie (ITU-T G.107), repris tels
    # quels -- un lecteur du domaine VoIP/QoS les reconnait immediatement sous cette forme.
    Id = 0.024 * d + (0.11 * (d - 177.3) if d > 177.3 else 0.0)  # noqa: N806
    Ie_eff = 95.0 * loss_pct / (loss_pct + 4.3) if loss_pct > 0 else 0.0  # noqa: N806
    R = 93.2 - Id - Ie_eff  # noqa: N806
    R = max(0.0, min(100.0, R))  # noqa: N806
    mos = 1.0 if R <= 0 else 1 + 0.035 * R + 7e-06 * R * (R - 60) * (100 - R)
    mos = max(1.0, min(4.5, mos))
    return R, mos
