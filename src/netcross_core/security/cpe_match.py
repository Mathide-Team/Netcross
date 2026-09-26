"""
netcross_core.security.cpe_match -- conversion d'une banniere de service
("Apache/2.4.41") en identifiant CPE 2.3 et comparaison de versions avec
les ranges NVD (versionStart/EndIncluding/Excluding).

Pas d'appel a un solveur de version externe (ex: `packaging.version`,
pensee pour PyPI, pas pour des versions de serveurs C comme "1.1.1k" ou
"8.2p1") : la comparaison ci-dessous decoupe chaque version en groupes
alternes chiffres/lettres (`_version_key`) et compare terme a terme --
suffisant pour les identifiants de version qu'on trouve dans les
bannieres de services reseau (Apache, OpenSSH, nginx, OpenSSL, ...) et
dans les champs `versionStartIncluding`/`versionEndExcluding` du flux
NVD, qui suivent la meme convention.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

# Alias banniere -> (vendor, product) CPE 2.3, alignes sur le
# dictionnaire officiel NVD (https://nvd.nist.gov/products/cpe/search).
# Volontairement une liste courte de produits reseau courants plutot
# qu'un import du dictionnaire CPE complet (des centaines de milliers
# d'entrees) : ce module ne fait que du matching, pas de la decouverte
# de produits inconnus. Etendre cette table est le seul changement
# necessaire pour reconnaitre un nouveau produit.
PRODUCT_ALIASES: dict[str, tuple[str, str]] = {
    "apache": ("apache", "http_server"),
    "nginx": ("f5", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "iis": ("microsoft", "internet_information_services"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "bind": ("isc", "bind"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "samba": ("samba", "samba"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "haproxy": ("haproxy", "haproxy"),
    "squid": ("squid-cache", "squid"),
    "php": ("php", "php"),
}

# Vendeurs CPE historiques d'un meme produit (issue #353). Le NVD
# renomme parfois le vendeur d'un produit ET republie ses anciennes CVE
# sous le nouveau nom : nginx est passe de nginx:nginx a f5:nginx apres
# le rachat par F5 (CVE-2013-2028 comprise), vsftpd de beasts:vsftpd a
# vsftpd_project:vsftpd. PRODUCT_ALIASES porte le nom ACTUEL -- celui des
# flux NVD d'aujourd'hui, donc du seed embarque -- et une base importee
# avant le renommage garde les anciens : la correlation interroge les
# deux, sans quoi aucune banniere nginx/vsftpd ne trouvait de CVE.
LEGACY_VENDORS: dict[tuple[str, str], tuple[str, ...]] = {
    ("f5", "nginx"): ("nginx", "igor_sysoev"),
    ("vsftpd_project", "vsftpd"): ("beasts", "vsftpd"),
}


def vendor_candidates(vendor: str, product: str) -> tuple[str, ...]:
    """Vendeur actuel puis vendeurs historiques du couple (vendor, product)."""
    return (vendor, *LEGACY_VENDORS.get((vendor, product), ()))


# Bannieres "Nom_version" ou "Nom-version" (ex: OpenSSH_8.2p1,
# dropbear_2020.81) en plus de la forme "Nom/version" la plus courante
# (headers HTTP Server:), avec un underscore ou tiret explicite --
# distinct du tiret qui peut apparaitre a l'interieur d'un numero de
# version (ex: "1.1.1-beta"), donc uniquement teste apres l'echec du
# separateur "/".
_BANNER_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9._-]*?)[/_]([0-9][A-Za-z0-9.+_-]*)$",
)


@dataclass(frozen=True, slots=True)
class ParsedBanner:
    """Un token de banniere reconnu comme produit catalogue + version."""

    raw: str
    product_key: str  # cle dans PRODUCT_ALIASES (nom normalise, minuscule)
    vendor: str
    product: str
    version: str

    @property
    def cpe23(self) -> str:
        return build_cpe23(self.vendor, self.product, self.version)


def build_cpe23(vendor: str, product: str, version: str) -> str:
    """Construit un identifiant CPE 2.3 (partie applicative 'a')."""
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def parse_banner(banner: str) -> ParsedBanner | None:
    """
    Reconnait le PREMIER token "produit/version" d'une banniere parmi
    les produits catalogues (PRODUCT_ALIASES). Une banniere HTTP
    complete comme "Apache/2.4.41 (Unix) OpenSSL/1.1.1k" contient
    plusieurs tokens : utiliser parse_all_banners() pour les recuperer
    tous. Renvoie None si aucun token reconnu (produit non catalogue --
    pas une erreur, juste un service que ce module ne sait pas encore
    situer dans le referentiel CPE).
    """
    for token in banner.split():
        parsed = _parse_token(token)
        if parsed is not None:
            return parsed
    logger.trace("parse_banner: aucun produit reconnu")
    return None


def parse_all_banners(banner: str) -> list[ParsedBanner]:
    """Comme parse_banner(), mais renvoie tous les tokens reconnus (pas seulement le premier)."""
    parsed = []
    for token in banner.split():
        result = _parse_token(token)
        if result is not None:
            parsed.append(result)
    return parsed


def _parse_token(token: str) -> ParsedBanner | None:
    match = _BANNER_RE.match(token.strip().strip("()"))
    if match is None:
        return None
    name, version = match.group(1), match.group(2)
    key = name.lower()
    aliases = PRODUCT_ALIASES.get(key)
    if aliases is None:
        return None
    vendor, product = aliases
    return ParsedBanner(raw=token, product_key=key, vendor=vendor, product=product, version=version)


def _version_key(version: str) -> tuple:
    """
    Decoupe une version en tuple comparable : chaque groupe de chiffres
    devient (0, int), chaque groupe de lettres devient (1, str) -- le 0/1
    de tete garantit qu'un groupe numerique est toujours compare a un
    groupe numerique (jamais un int vs un str, non ordonnable) meme si
    deux versions alternent chiffres/lettres a des positions differentes
    (rare mais pas exclu, ex: "1.1.1k" vs "1.1.1a").
    """
    return tuple((0, int(g)) if g.isdigit() else (1, g.lower()) for g in re.findall(r"\d+|[A-Za-z]+", version))


def compare_versions(a: str, b: str) -> int:
    """-1 si a < b, 0 si a == b, 1 si a > b (comparaison lexicographique par groupe, voir _version_key)."""
    ka, kb = _version_key(a), _version_key(b)
    if ka == kb:
        return 0
    return -1 if ka < kb else 1


def version_in_range(
    version: str,
    *,
    exact: str | None = None,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
) -> bool:
    """
    Teste si `version` tombe dans le range NVD decrit par les bornes
    fournies (memes noms que les champs `cpeMatch` de l'API NVD 2.0).
    Si `exact` est fourni ET qu'aucune borne de range n'est donnee (cas
    d'une entree NVD sans versionStart/End -- une seule version exacte
    est marquee vulnerable), c'est une egalite stricte qui tranche.
    Sans aucune borne ni `exact`, le produit entier est considere
    concerne (CPE "cpe:...:*" sans precision de version) : renvoie True.
    """
    has_range = any(b is not None for b in (start_including, start_excluding, end_including, end_excluding))

    if not has_range:
        if exact is None or exact == "*":
            return True
        return compare_versions(version, exact) == 0

    if start_including is not None and compare_versions(version, start_including) < 0:
        return False
    if start_excluding is not None and compare_versions(version, start_excluding) <= 0:
        return False
    if end_including is not None and compare_versions(version, end_including) > 0:
        return False
    return not (end_excluding is not None and compare_versions(version, end_excluding) >= 0)
