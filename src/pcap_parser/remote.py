"""pcap_parser.remote -- sources de capture distantes (issue #166).

Le champ « interface » d'une capture en direct accepte, en plus d'un nom
d'interface locale (``eth0``), une URL de source :

``rpcap://[utilisateur@]hote[:port]/interface``
    Demon rpcapd distant (port 2002 par defaut). tshark doit etre compile
    avec la capture distante (option ``-A`` presente dans ``tshark -h``).
    Mot de passe : variable d'environnement ``NETCROSS_RPCAP_PASSWORD``.

``sshdump://[utilisateur@]hote[:port]/interface[?key=CHEMIN&priv=sudo]``
    Extcap ``sshdump`` de Wireshark : tcpdump lance a distance via SSH, sans
    rien installer d'autre que tcpdump sur la cible. Authentification par
    cle (``key=``) ou agent SSH ; mot de passe eventuel via
    ``NETCROSS_SSH_PASSWORD``. ``ssh://`` est accepte comme alias.

``pipe://-`` (ou ``-``)
    Flux pcap lu sur l'entree standard, par exemple
    ``ssh routeur tcpdump -U -w - -i eth0 | netcross-analyze --live R:-``.

``pipe:///chemin/fifo``
    Tube nomme (``mkfifo``) alimente par un autre processus.

Les secrets ne sont jamais acceptes dans l'URL (historique du shell, liste
des processus, journaux) et n'apparaissent pas dans ``CaptureSource.display``.
Chaque valeur est validee (hote, port, interface, utilisateur) : aucune ne
peut commencer par ``-`` ni contenir d'espace, donc aucune ne peut etre
interpretee comme une option de tshark.

Module sans E/S hormis la lecture de l'environnement et un ``stat`` pour
``pipe://`` : testable sans tshark.
"""

from __future__ import annotations

import ipaddress
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote

from loguru import logger as _loguru_logger

# pcap_parser reste independant de netcross_core (contrat import-linter) :
# loguru directement, lie au nom du module.
logger = _loguru_logger.bind(name=__name__)

ENV_RPCAP_PASSWORD = "NETCROSS_RPCAP_PASSWORD"
ENV_SSH_PASSWORD = "NETCROSS_SSH_PASSWORD"
RPCAP_DEFAULT_PORT = 2002
SSH_DEFAULT_PORT = 22
REMOTE_SCHEMES = ("rpcap", "sshdump", "ssh", "pipe")

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*$")
_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")
# Noms d'interface : Linux (eth0, br-lan, wlan0.1), Windows distant
# (\Device\NPF_{GUID}), extcap/usb (usbmon1). Pas d'espace, pas de '-' initial.
_IFACE_RE = re.compile(r"^[A-Za-z0-9_\\{}][A-Za-z0-9_.:@\\{}/+-]{0,254}$")
_SSHDUMP_PRIVS = ("none", "sudo", "doas")


class CaptureSourceError(ValueError):
    """Source de capture invalide (message destine a l'utilisateur)."""


@dataclass(frozen=True)
class CaptureSource:
    """Source resolue, prete pour tshark.

    - ``kind`` : ``local``, ``rpcap``, ``sshdump`` ou ``pipe``
    - ``interface`` : valeur passee a ``tshark -i``
    - ``extra_args`` : arguments tshark supplementaires (``-o``, ``-A``) --
      peuvent contenir un secret : ne jamais les journaliser
    - ``display`` : forme lisible, sans secret
    - ``uses_stdin`` : la source consomme l'entree standard du processus
    """

    kind: str
    interface: str
    extra_args: tuple[str, ...] = ()
    display: str = ""
    uses_stdin: bool = False

    @property
    def is_remote(self) -> bool:
        return self.kind in ("rpcap", "sshdump")


def is_source_url(text: str) -> bool:
    """Vrai si ``text`` commence par un schema de source connu (``rpcap://``...)."""
    scheme, sep, _rest = text.partition("://")
    return bool(sep) and scheme.lower() in REMOTE_SCHEMES


def split_live_target(text: str) -> tuple[str, str | None]:
    """Separe ``SOURCE[:FILTRE_BPF]`` (partie de ``--live`` apres le label).

    Pour une interface locale, le premier ``:`` separe le filtre (compor-
    tement historique). Pour une URL, les ``:`` de l'hote (port, IPv6 entre
    crochets) ne comptent pas : le separateur est le premier ``:`` situe
    apres le debut du chemin (``/interface``).
    """
    if not is_source_url(text):
        iface, sep, bpf = text.partition(":")
        return iface, (bpf if sep else None)
    body_start = text.index("://") + 3
    if text.lower().startswith("pipe://-"):
        path_start = body_start + 1
    else:
        slash = text.find("/", body_start)
        path_start = len(text) if slash < 0 else slash
    colon = text.find(":", path_start)
    if colon < 0:
        return text, None
    logger.debug("split_live_target: URL de source avec filtre BPF")
    return text[:colon], text[colon + 1 :]


def _check_host(host: str) -> str:
    if host.startswith("[") and host.endswith("]"):
        try:
            return str(ipaddress.IPv6Address(host[1:-1]))
        except ValueError:
            logger.debug("_check_host: IPv6 invalide {!r}", host)
            raise CaptureSourceError(f"adresse IPv6 invalide : {host}") from None
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        # cas normal pour un nom DNS : pas une erreur
        logger.debug("_check_host: {!r} n'est pas une IPv4, vérifié comme nom DNS", host)
    if _HOSTNAME_RE.match(host):
        return host
    raise CaptureSourceError(f"hote invalide : {host!r} (nom DNS, IPv4 ou [IPv6])")


def _split_netloc(netloc: str, scheme: str, default_port: int) -> tuple[str | None, str, int]:
    user = None
    if "@" in netloc:
        userinfo, netloc = netloc.rsplit("@", 1)
        if ":" in userinfo:
            env = ENV_RPCAP_PASSWORD if scheme == "rpcap" else ENV_SSH_PASSWORD
            raise CaptureSourceError(
                f"mot de passe interdit dans l'URL {scheme}:// (visible dans l'historique et la liste "
                f"des processus) : utiliser la variable d'environnement {env}"
            )
        user = unquote(userinfo)
        if not _USER_RE.match(user):
            raise CaptureSourceError(f"nom d'utilisateur invalide : {user!r}")
    port = default_port
    if netloc.startswith("["):
        end = netloc.find("]")
        if end < 0:
            raise CaptureSourceError(f"adresse IPv6 non fermee : {netloc}")
        host, rest = netloc[: end + 1], netloc[end + 1 :]
        if rest:
            if not rest.startswith(":"):
                raise CaptureSourceError(f"hote invalide : {netloc}")
            port = _check_port(rest[1:])
    elif ":" in netloc:
        host, port_text = netloc.rsplit(":", 1)
        port = _check_port(port_text)
    else:
        host = netloc
    if not host:
        raise CaptureSourceError(f"hote manquant dans l'URL {scheme}://")
    return user, _check_host(host), port


def _check_port(text: str) -> int:
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        raise CaptureSourceError(f"port invalide : {text!r} (1-65535)")
    return int(text)


def _check_iface(iface: str, scheme: str) -> str:
    iface = unquote(iface)
    if not iface:
        raise CaptureSourceError(f"interface distante manquante : {scheme}://hote/INTERFACE")
    if not _IFACE_RE.match(iface):
        raise CaptureSourceError(f"nom d'interface invalide : {iface!r}")
    return iface


def _host_for_url(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def _parse_rpcap(body: str, env: Mapping[str, str]) -> CaptureSource:
    netloc, _, path = body.partition("/")
    if "?" in path:
        raise CaptureSourceError("rpcap:// n'accepte pas de parametres (?...)")
    user, host, port = _split_netloc(netloc, "rpcap", RPCAP_DEFAULT_PORT)
    iface = _check_iface(path, "rpcap")
    target = f"rpcap://{_host_for_url(host)}:{port}/{iface}"
    extra: tuple[str, ...] = ()
    if user is not None:
        password = env.get(ENV_RPCAP_PASSWORD)
        if not password:
            raise CaptureSourceError(
                f"rpcap:// avec utilisateur ({user}) : definir le mot de passe dans {ENV_RPCAP_PASSWORD}"
            )
        extra = ("-A", f"{user}:{password}")
    who = f"{user}@" if user else ""
    display = f"rpcap://{who}{_host_for_url(host)}:{port}/{iface}"
    logger.debug("_parse_rpcap: {} (authentification={})", display, user is not None)
    return CaptureSource("rpcap", target, extra, display)


def _parse_sshdump(body: str, env: Mapping[str, str]) -> CaptureSource:
    netloc, _, path_query = body.partition("/")
    path, _, query = path_query.partition("?")
    user, host, port = _split_netloc(netloc, "sshdump", SSH_DEFAULT_PORT)
    iface = _check_iface(path, "sshdump")
    params = parse_qs(query, keep_blank_values=True, strict_parsing=False) if query else {}
    unknown = sorted(set(params) - {"key", "priv"})
    if unknown:
        raise CaptureSourceError(f"parametre(s) sshdump inconnu(s) : {', '.join(unknown)} (attendus : key, priv)")

    def pref(name: str, value: object) -> tuple[str, str]:
        return ("-o", f"extcap.sshdump.{name}:{value}")

    extra: list[str] = []
    extra += pref("remotehost", host)
    extra += pref("remoteport", port)
    if user is not None:
        extra += pref("remoteusername", user)
    extra += pref("remoteinterface", iface)
    key_desc = ""
    if "key" in params:
        key = os.path.expanduser(params["key"][-1])
        if not key or not os.path.isfile(key):
            raise CaptureSourceError(f"cle SSH introuvable : {key!r}")
        extra += pref("sshkey", key)
        key_desc = f"?key={key}"
    if "priv" in params:
        priv = params["priv"][-1]
        if priv not in _SSHDUMP_PRIVS:
            raise CaptureSourceError(f"priv={priv!r} invalide (attendus : {', '.join(_SSHDUMP_PRIVS)})")
        extra += pref("remotepriv", priv)
        key_desc += ("&" if key_desc else "?") + f"priv={priv}"
    password = env.get(ENV_SSH_PASSWORD)
    if password:
        extra += pref("remotepassword", password)
    who = f"{user}@" if user else ""
    display = f"sshdump://{who}{_host_for_url(host)}:{port}/{iface}{key_desc}"
    logger.debug("_parse_sshdump: {} (mot de passe via env={})", display, bool(password))
    return CaptureSource("sshdump", "sshdump", tuple(extra), display)


def _parse_pipe(body: str) -> CaptureSource:
    if body == "-":
        logger.debug("_parse_pipe: entrée standard")
        return CaptureSource("pipe", "-", (), "pipe://- (entree standard)", uses_stdin=True)
    if not body.startswith("/"):
        raise CaptureSourceError("pipe:// attend '-' (entree standard) ou un chemin absolu : pipe:///chemin/fifo")
    path = unquote(body)
    try:
        mode = os.stat(path).st_mode
    except OSError:
        logger.warning("_parse_pipe: tube nommé introuvable {}", path)
        raise CaptureSourceError(f"tube nomme introuvable : {path} (le creer avec mkfifo)") from None
    if not stat.S_ISFIFO(mode):
        raise CaptureSourceError(f"{path} n'est pas un tube nomme (pour un fichier, utiliser --capture)")
    logger.debug("_parse_pipe: tube nommé {}", path)
    return CaptureSource("pipe", path, (), f"pipe://{path}")


def parse_source(text: str, env: Mapping[str, str] | None = None) -> CaptureSource:
    """Resout le champ interface d'une capture en direct (voir le module).

    Leve CaptureSourceError si l'URL est invalide ; un nom d'interface
    locale est renvoye tel quel (tshark signalera une interface inconnue).
    """
    env = os.environ if env is None else env
    text = text.strip()
    if not text:
        raise CaptureSourceError("interface manquante")
    if text == "-":
        return _parse_pipe("-")
    scheme, sep, body = text.partition("://")
    if not sep:
        if text.startswith("-"):
            raise CaptureSourceError(f"nom d'interface invalide : {text!r}")
        logger.debug("parse_source: interface locale {}", text)
        return CaptureSource("local", text, (), text)
    logger.debug("parse_source: schéma {}", scheme.lower())
    scheme = scheme.lower()
    if scheme == "rpcap":
        return _parse_rpcap(body, env)
    if scheme in ("sshdump", "ssh"):
        return _parse_sshdump(body, env)
    if scheme == "pipe":
        return _parse_pipe(body)
    raise CaptureSourceError(f"schema de source inconnu : {scheme}:// (attendus : rpcap, sshdump, ssh, pipe)")


def source_display(text: str) -> str:
    """Forme lisible et sans secret de ``text`` (ou ``text`` si invalide)."""
    try:
        return parse_source(text, env={}).display
    except CaptureSourceError as exc:
        # repli attendu : source invalide affichee telle quelle
        logger.debug("source_display: {!r} invalide ({}), affichée telle quelle", text, exc)
        return text
