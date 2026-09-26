"""
netcross_core.security.tls_audit -- issue #153 (SCENARIO-7, parent #141) :
audit des certificats TLS presentes par les serveurs (expires, auto-signes,
algorithmes faibles, validite excessive, noms suspects, chaine incomplete).

Le module exploite uniquement les champs `tls_cert_*` de `Pkt` (voir
`pcap_parser.protocols.extract_tls_certificate`) : aucune nouvelle dissection
tshark au-dela de la lecture du DER du certificat FEUILLE deja expose par le
flux EK. Il ne verifie PAS la chaine de confiance PKI ni la revocation
(hors de portee d'une capture passive : pas de magasin de confiance, pas de
requete OCSP/CRL).

Controles, appliques a chaque certificat feuille observe (severites par
defaut dans `DEFAULT_SEVERITIES`, toutes remplacables par la politique) :

- **expired** / **not_yet_valid** : `notAfter` / `notBefore` compares a
  l'horodatage du PAQUET portant le certificat (jamais a l'heure actuelle :
  une analyse a froid d'une vieille capture reste correcte) ;
- **self_signed** : emetteur == sujet ;
- **broken_signature** (MD2/MD4/MD5) et **deprecated_signature** (SHA-1) ;
- **weak_key** : RSA/DSA < `min_rsa_bits`/`min_dsa_bits` (2048), EC <
  `min_ec_bits` (256) ;
- **long_validity** : validite > `max_validity_days` (398, plafond CA/B Forum
  depuis 2020 ; a noter que ce plafond s'applique aux seuls certificats
  publiquement approuves et qu'il baisse par etapes -- 200 jours depuis le
  15/03/2026, 100 en 2027, 47 en 2029 : le seuil reste donc configurable) ;
- **incomplete_chain** : feuille non auto-signee presentee SANS aucun
  intermediaire (chaine de longueur 1). Indice faible : une feuille emise
  directement par une racine connue du client est legitime ;
- noms (SAN DNS/IP) : **wildcard** (`*.exemple.fr`), **wildcard_broad** (`*`,
  `*.com`), **ip_in_san**, **long_name** (> `max_name_len` caracteres),
  **random_name** (premier label >= `random_min_label_len` caracteres d'entropie
  de Shannon >= `random_min_entropy_bits` -- un CDN legitime produit aussi
  des labels aleatoires, d'ou une severite faible).

Score de risque par serveur (`servers`) : un serveur est un couple
(adresse IP, port) qui EMET le certificat. Le score est la somme des points
(`SEVERITY_POINTS`) de chaque probleme distinct de chaque certificat distinct
qu'il a presente, plafonnee a 100. Un serveur sans probleme n'apparait pas
dans les constats mais reste liste avec un score de 0.

Limites assumees :
- TLS 1.3 chiffre le message Certificate, et une reprise de session n'en
  envoie pas : ces connexions sont invisibles (voir `extract_tls_certificate`) ;
- un serveur qui sert plusieurs certificats selon le SNI est evalue sur
  l'ensemble des certificats vus ;
- les constats sont des INDICES a confirmer (comme `dns_tunnel`) : un
  equipement interne auto-signe est banal, un certificat expire l'est moins.

Sortie pure (`audit_tls_certificates`) : `certificates` (un dict par
certificat distinct, avec ses problemes) et `servers` (un dict par serveur, avec
son score). `security.findings` la convertit en constats du rapport de securite.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt
from netcross_core.security.dns_tunnel import shannon_entropy

logger = get_logger(__name__)

SEVERITY_ELEVEE = "elevee"
SEVERITY_MOYENNE = "moyenne"
SEVERITY_FAIBLE = "faible"

# Points ajoutes au score de risque d'un serveur par probleme distinct.
SEVERITY_POINTS: dict[str, int] = {SEVERITY_ELEVEE: 30, SEVERITY_MOYENNE: 15, SEVERITY_FAIBLE: 5}
MAX_SCORE = 100

CODE_EXPIRED = "expired"
CODE_NOT_YET_VALID = "not_yet_valid"
CODE_SELF_SIGNED = "self_signed"
CODE_BROKEN_SIGNATURE = "broken_signature"
CODE_DEPRECATED_SIGNATURE = "deprecated_signature"
CODE_WEAK_KEY = "weak_key"
CODE_LONG_VALIDITY = "long_validity"
CODE_INCOMPLETE_CHAIN = "incomplete_chain"
CODE_WILDCARD = "wildcard"
CODE_WILDCARD_BROAD = "wildcard_broad"
CODE_IP_IN_SAN = "ip_in_san"
CODE_LONG_NAME = "long_name"
CODE_RANDOM_NAME = "random_name"

# « critique » reste reserve aux CVE confirmees (voir security.findings) :
# aucun constat TLS n'est plus grave qu'« elevee ».
DEFAULT_SEVERITIES: dict[str, str] = {
    CODE_EXPIRED: SEVERITY_ELEVEE,
    CODE_NOT_YET_VALID: SEVERITY_MOYENNE,
    CODE_SELF_SIGNED: SEVERITY_MOYENNE,
    CODE_BROKEN_SIGNATURE: SEVERITY_ELEVEE,
    CODE_DEPRECATED_SIGNATURE: SEVERITY_MOYENNE,
    CODE_WEAK_KEY: SEVERITY_ELEVEE,
    CODE_LONG_VALIDITY: SEVERITY_FAIBLE,
    CODE_INCOMPLETE_CHAIN: SEVERITY_FAIBLE,
    CODE_WILDCARD: SEVERITY_FAIBLE,
    CODE_WILDCARD_BROAD: SEVERITY_MOYENNE,
    CODE_IP_IN_SAN: SEVERITY_FAIBLE,
    CODE_LONG_NAME: SEVERITY_FAIBLE,
    CODE_RANDOM_NAME: SEVERITY_FAIBLE,
}

# Nombre maximal de noms cites dans le detail d'un constat de nom.
_MAX_NAMES_SHOWN = 3


@dataclass(frozen=True)
class TlsAuditPolicy:
    """Politique de securite de l'audit. Tout est parametrable.

    `severities` remplace, code par code, `DEFAULT_SEVERITIES` (un code absent
    garde sa severite par defaut) ; `disabled` desactive des controles par leur
    code ; `max_validity_days=None` desactive le controle de validite."""

    max_validity_days: int | None = 398
    min_rsa_bits: int = 2048
    min_dsa_bits: int = 2048
    min_ec_bits: int = 256
    broken_hashes: frozenset[str] = frozenset({"md2", "md4", "md5"})
    deprecated_hashes: frozenset[str] = frozenset({"sha1"})
    max_name_len: int = 100
    random_min_label_len: int = 16
    random_min_entropy_bits: float = 3.6
    severities: Mapping[str, str] = field(default_factory=dict)
    disabled: frozenset[str] = frozenset()

    def severity(self, code: str) -> str:
        return self.severities.get(code) or DEFAULT_SEVERITIES.get(code, SEVERITY_FAIBLE)

    def enabled(self, code: str) -> bool:
        return code not in self.disabled


DEFAULT_POLICY = TlsAuditPolicy()


@dataclass(frozen=True)
class TlsIssue:
    """Un probleme releve sur un certificat."""

    code: str
    severity: str
    detail: str


@dataclass
class TlsAuditResult:
    """Sortie de `audit_tls_certificates`, meme forme de dicts que les autres detecteurs de securite."""

    certificates: list[dict] = field(default_factory=list)
    servers: list[dict] = field(default_factory=list)


def parse_cert_date(value: str | None) -> datetime | None:
    """Date de certificat telle que rendue par tshark ("YYYY-MM-DD HH:MM:SS
    (UTC)") en datetime UTC ; None si le format est inattendu (aucune
    reconstruction approximative)."""
    if value is None:
        return None
    try:
        return datetime.strptime(value.removesuffix(" (UTC)"), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        logger.debug("parse_cert_date: format de date inattendu {!r}", value)
        return None


def _shown(names: list[str]) -> str:
    extra = len(names) - _MAX_NAMES_SHOWN
    text = ", ".join(names[:_MAX_NAMES_SHOWN])
    return text + (f" (+{extra})" if extra > 0 else "")


def _is_broad_wildcard(name: str) -> bool:
    """`*` seul ou joker directement sous un suffixe a un seul label (`*.com`)."""
    if not name.startswith("*"):
        return False
    rest = name[1:].lstrip(".")
    return not rest or "." not in rest


def _name_issues(pk: Pkt, policy: TlsAuditPolicy) -> list[tuple[str, str]]:
    names = [n for n in (pk.tls_cert_san or ()) if n]
    found: list[tuple[str, str]] = []
    wildcards = [n for n in names if n.startswith("*")]
    broad = [n for n in wildcards if _is_broad_wildcard(n)]
    if broad:
        found.append((CODE_WILDCARD_BROAD, f"joker trop large dans le SAN : {_shown(broad)}"))
    narrow = [n for n in wildcards if n not in broad]
    if narrow:
        found.append((CODE_WILDCARD, f"certificat wildcard : {_shown(narrow)}"))
    if pk.tls_cert_san_ip:
        found.append((CODE_IP_IN_SAN, f"adresse IP dans le SAN : {_shown(list(pk.tls_cert_san_ip))}"))
    long_names = [n for n in names if len(n) > policy.max_name_len]
    if long_names:
        count = len(long_names)
        found.append((CODE_LONG_NAME, f"{count} nom(s) de plus de {policy.max_name_len} caracteres dans le SAN"))
    random_names = []
    for n in names:
        label = n.lstrip("*.").split(".", 1)[0]
        if len(label) >= policy.random_min_label_len and shannon_entropy(label) >= policy.random_min_entropy_bits:
            random_names.append(n)
    if random_names:
        found.append((CODE_RANDOM_NAME, f"nom d'apparence aleatoire dans le SAN : {_shown(random_names)}"))
    return found


def audit_certificate(pk: Pkt, policy: TlsAuditPolicy = DEFAULT_POLICY) -> list[TlsIssue]:
    """Problemes releves sur le certificat feuille porte par `pk` (liste vide
    si le certificat est sain ou si `pk` n'en porte pas). L'horodatage de
    reference est celui du paquet."""
    if pk.tls_cert_serial is None:
        return []
    raw: list[tuple[str, str]] = []

    not_before = parse_cert_date(pk.tls_cert_not_before)
    not_after = parse_cert_date(pk.tls_cert_not_after)
    seen_at = datetime.fromtimestamp(pk.ts, tz=timezone.utc)
    if not_after is not None and seen_at > not_after:
        raw.append((CODE_EXPIRED, f"certificat expire depuis le {not_after:%Y-%m-%d} (presente le {seen_at:%Y-%m-%d})"))
    elif not_before is not None and seen_at < not_before:
        detail = f"certificat pas encore valide avant le {not_before:%Y-%m-%d} (presente le {seen_at:%Y-%m-%d})"
        raw.append((CODE_NOT_YET_VALID, detail))
    if policy.max_validity_days is not None and not_before is not None and not_after is not None:
        days = (not_after - not_before).days
        if days > policy.max_validity_days:
            raw.append((CODE_LONG_VALIDITY, f"validite de {days} jours (plafond retenu : {policy.max_validity_days})"))

    self_signed = pk.tls_cert_issuer is not None and pk.tls_cert_issuer == pk.tls_cert_subject
    if self_signed:
        raw.append((CODE_SELF_SIGNED, "certificat auto-signe (emetteur == sujet)"))

    sig_hash = (pk.tls_cert_sig_hash or "").lower()
    if sig_hash in policy.broken_hashes:
        raw.append((CODE_BROKEN_SIGNATURE, f"signature {sig_hash.upper()} (algorithme casse)"))
    elif sig_hash in policy.deprecated_hashes:
        raw.append((CODE_DEPRECATED_SIGNATURE, f"signature {sig_hash.upper()} (algorithme obsolete)"))

    key_type, bits = pk.tls_cert_key_type, pk.tls_cert_key_bits
    minimum = {"RSA": policy.min_rsa_bits, "DSA": policy.min_dsa_bits, "EC": policy.min_ec_bits}.get(key_type or "")
    if minimum is not None and bits is not None and bits < minimum:
        raw.append((CODE_WEAK_KEY, f"cle {key_type} de {bits} bits (minimum retenu : {minimum})"))

    if pk.tls_cert_chain_len == 1 and pk.tls_cert_issuer is not None and not self_signed:
        raw.append((CODE_INCOMPLETE_CHAIN, "chaine incomplete : certificat serveur presente sans intermediaire"))

    raw.extend(_name_issues(pk, policy))
    return [TlsIssue(code, policy.severity(code), detail) for code, detail in raw if policy.enabled(code)]


def audit_tls_certificates(packets: Iterable[Pkt], policy: TlsAuditPolicy = DEFAULT_POLICY) -> TlsAuditResult:
    """Applique les controles de la docstring du module a `packets`."""
    # (point, hote, port, serie, sujet) -> premier paquet + nombre d'occurrences
    first: dict[tuple, Pkt] = {}
    count: dict[tuple, int] = {}
    for pk in packets:
        if pk.tls_cert_serial is None:
            continue
        key = (pk.point, pk.src, pk.sport, pk.tls_cert_serial, pk.tls_cert_subject)
        count[key] = count.get(key, 0) + 1
        if key not in first or pk.ts < first[key].ts:
            first[key] = pk

    result = TlsAuditResult()
    servers: dict[tuple[str, int | None], dict] = {}
    for key in sorted(first, key=lambda k: (k[1], k[2] or 0, k[0], k[3])):
        pk = first[key]
        issues = audit_certificate(pk, policy)
        result.certificates.append(
            {
                "point": pk.point,
                "host": pk.src,
                "port": pk.sport,
                "serial": pk.tls_cert_serial,
                "subject": pk.tls_cert_subject,
                "issuer": pk.tls_cert_issuer,
                "not_before": pk.tls_cert_not_before,
                "not_after": pk.tls_cert_not_after,
                "frame": pk.frame_number,
                "occurrences": count[key],
                "issues": issues,
            }
        )
        srv = servers.setdefault(
            (pk.src, pk.sport), {"host": pk.src, "port": pk.sport, "points": set(), "_certs": set(), "_issues": set()}
        )
        srv["points"].add(pk.point)
        srv["_certs"].add((pk.tls_cert_serial, pk.tls_cert_subject))
        # un probleme distinct par certificat distinct (un meme certificat vu a
        # plusieurs points ne compte qu'une fois)
        srv["_issues"].update((pk.tls_cert_serial, pk.tls_cert_subject, i.code, i.severity) for i in issues)

    for srv in servers.values():
        found = srv.pop("_issues")
        srv["certificates"] = len(srv.pop("_certs"))
        score = sum(SEVERITY_POINTS.get(sev, 0) for _serial, _subject, _code, sev in found)
        severities = {sev for _serial, _subject, _code, sev in found}
        srv["points"] = sorted(srv["points"])
        srv["issues"] = sorted({code for _serial, _subject, code, _sev in found})
        srv["score"] = min(MAX_SCORE, score)
        ranked = (SEVERITY_ELEVEE, SEVERITY_MOYENNE, SEVERITY_FAIBLE)
        srv["severity"] = next((s for s in ranked if s in severities), None)
        result.servers.append(srv)
    result.servers.sort(key=lambda s: (-s["score"], s["host"], s["port"] or 0))
    logger.debug(
        "audit_tls_certificates: {} certificat(s), {} serveur(s)", len(result.certificates), len(result.servers)
    )
    return result
