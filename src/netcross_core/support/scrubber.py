"""
netcross_core.support.scrubber -- anonymisation de TEXTE LIBRE (issue #269).

Complement indispensable de netcross_core.redact, qui n'anonymise que des
CHAMPS STRUCTURES de paquets deja decodes (Pkt/RawPacket). Une remontee de
ticket transporte au contraire du texte non structure -- message
d'exception, traceback, lignes de log, chemin du fichier de capture,
ligne de commande -- ou les donnees identifiantes apparaissent noyees dans
de la prose. Aucun des deux modules ne remplace l'autre :

- redact.py       : champs typés d'un paquet (src, dst, arp_sender_mac...)
- scrubber.py     : chaines de caracteres quelconques (logs, tracebacks)

Discipline de pseudonymisation, identique a redact.AddressRedactor : un
objet TextScrubber porte un mapping ; la MEME valeur reelle rencontree
deux fois, y compris dans deux textes differents scrubbes par le meme
objet, recoit le MEME pseudonyme. C'est ce qui permet de correler un
ticket avec la trace correspondante de la campagne (voir
docs/quality/anonymization-plan.md) sans jamais exposer la valeur reelle.

Categories traitees, dans cet ORDRE (l'ordre est significatif : une regle
large placee trop tot mangerait le texte que les regles suivantes doivent
voir) :

1. ``secret``    -- ``Bearer xxx``, puis ``password=``/``token:`` et
   apparentes -> ``[SECRET-REDIGE]``. Jamais pseudonymise : un secret n'a
   aucune valeur de correlation, seulement un risque de fuite. Le schema
   ``Bearer`` passe AVANT la forme cle=valeur, sinon
   ``Authorization: Bearer <jeton>`` verrait sa valeur reduite au mot
   ``Bearer`` et laisserait le jeton en clair.
2. ``email``     -- ``nom@domaine`` -> ``user-N@example.invalid``
3. ``url``       -- schema://hote/chemin -> ``https://host-N.example.invalid/redacted``
4. ``mac``       -- ``aa:bb:cc:dd:ee:ff`` -> ``02:00:00:00:00:NN`` (OUI
   localement administre, meme convention que redact.py)
5. ``ipv6``      -- -> ``2001:db8::N`` (RFC 3849, comme redact.py)
6. ``ipv4``      -- -> ``192.0.2.N`` (RFC 5737, comme redact.py)
7. ``capture``   -- ``client_acme_site3.pcapng`` -> ``capture-N.pcapng``
   (le NOM d'un fichier de capture nomme tres souvent le client)
8. ``path``      -- ``/home/jdupont``, ``C:\\Users\\jdupont`` ->
   ``/home/user-N`` / ``C:\\Users\\user-N`` (le repertoire personnel porte
   l'identite de l'operateur ; le reste du chemin est conserve, il est
   utile au diagnostic et n'est pas identifiant)
9. ``hostname``  -- FQDN residuel ``srv-compta.acme.local`` ->
   ``host-N.example.invalid``

Substitution en DEUX PHASES, et non regle apres regle sur le texte en
cours : chaque correspondance est d'abord remplacee par un jeton interne
opaque, et les pseudonymes ne sont reinjectes qu'a la toute fin. Sans
cela, les regles se mangeraient entre elles -- la MAC pseudonymisee
``02:00:00:00:00:00`` est un IPv6 valide pour la regle suivante, et
``capture-1.pcapng`` ressemble a un FQDN dont le TLD serait ``pcapng``.
C'est aussi ce qui garantit ``scrub(scrub(t)) == scrub(t)`` : les valeurs
que le scrubber produit lui-meme sont enregistrees comme deja anonymes et
se traversent elles-memes sans etre renumerotees.

HORS PERIMETRE, limite assumee et tracee (jamais passee sous silence, cf.
docs/quality/traceability-rule.md) : un nom d'hote en un seul mot, sans
point (``SRVCOMPTA01``), est indissociable d'un mot ordinaire du message
et reste donc en clair. Le rapport de scrubbing porte cette limite dans
son champ ``limites`` a chaque appel, y compris quand rien n'a ete
redige : le lecteur du ticket sait toujours ce que l'outil NE garantit
pas, plutot que de le deduire d'un silence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

# Categories, dans l'ordre d'application (voir docstring de module).
CATEGORIES = (
    "secret",
    "email",
    "url",
    "mac",
    "ipv6",
    "ipv4",
    "capture",
    "path",
    "hostname",
)

# Marqueur unique pour les secrets : aucune correlation possible ni voulue.
SECRET_PLACEHOLDER = "[SECRET-REDIGE]"

# Limites connues du scrubbing, remontees dans CHAQUE rapport (regle de
# tracabilite : on documente ce qui n'est pas couvert au lieu de laisser
# croire a une couverture totale).
KNOWN_LIMITS = (
    "un nom d'hote sans point (ex. SRVCOMPTA01) reste en clair : indissociable d'un mot ordinaire du texte",
    "un identifiant metier libre (numero de dossier, nom de site) reste "
    "en clair : aucun motif ne permet de le reconnaitre",
)

_HEX = r"[0-9A-Fa-f]"

# 1. Secrets. Bearer/Basic d'abord (voir docstring, point 1).
_SECRET_KEYS = r"(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|authorization|auth)"
_RE_SECRET_BEARER = re.compile(r"(?i)\b(bearer|basic)(\s+)[A-Za-z0-9._~+/=-]{8,}")
_RE_SECRET_KV = re.compile(
    rf"(?i)\b({_SECRET_KEYS})(\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|\S+)",
)

# 2. Email -- avant url/hostname, sinon le domaine serait mange en premier.
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# 3. URL -- schema obligatoire, pour ne pas confondre avec un FQDN nu.
_RE_URL = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>)\]},]+")

# 4. MAC -- separateur : ou -, avant ipv6 (les deux utilisent ":").
_RE_MAC = re.compile(rf"\b(?:{_HEX}{{2}}[:-]){{5}}{_HEX}{{2}}\b")

# 5. IPv6 -- doit accepter la forme abregee "::" a n'importe quelle
# position (fe80::1, 2001:db8::a:b:c), d'ou l'alternance explicite plutot
# qu'une repetition unique de groupes "hex:".
_G = rf"{_HEX}{{1,4}}"
_RE_IPV6 = re.compile(
    r"(?<![:.\w])(?:"
    rf"(?:{_G}:){{7}}{_G}"  # forme pleine
    rf"|(?:{_G}:){{1,7}}:"  # se termine par ::
    rf"|(?:{_G}:){{1,6}}(?::{_G}){{1,6}}"  # :: au milieu
    rf"|:(?::{_G}){{1,7}}"  # commence par ::
    r"|::"
    r")(?:%[A-Za-z0-9]+)?(?![:.\w])"
)

# 6. IPv4 -- port eventuel laisse en place (utile au diagnostic, non
# identifiant) : seul le quadruplet est remplace.
_RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# 7. Fichier de capture -- nom de base seul, l'extension est conservee
# (elle renseigne le format, information de diagnostic non identifiante).
_CAPTURE_EXTS = r"(?:pcapng\.gz|pcap\.gz|pcapng|pcap|cap|erf|snoop)"
_RE_CAPTURE = re.compile(rf"(?i)\b[\w.\-]+\.({_CAPTURE_EXTS})\b")

# 8. Repertoire personnel -- seul le composant "utilisateur" est remplace.
# PAS de \b devant "/" : entre une espace et "/" il n'y a aucune frontiere
# de mot, la regle ne se declencherait jamais en milieu de phrase.
_RE_HOME_UNIX = re.compile(r"(?i)(?<![\w/])(/(?:home|Users))/([^/\\\s:\"']+)")
_RE_HOME_WIN = re.compile(r"(?i)\b([A-Za-z]:\\Users\\)([^\\/\s:\"']+)")

# 9. FQDN residuel -- au moins un point, TLD alphabetique. Applique en
# DERNIER : tout ce qui etait email/url/ipv4/capture a deja ete retire.
#
# Un nom de FICHIER a exactement la meme forme qu'un FQDN ("site.txt" vaut
# "acme.local" pour une regex) : sans garde-fou, la regle renommerait les
# fichiers cites dans les tracebacks en hotes, ce qui detruirait
# l'information de diagnostic sans rien anonymiser. D'ou (a) une liste
# d'extensions courantes exclues, (b) le refus de matcher juste apres un
# separateur de chemin.
# fmt: off
_FILE_EXTS = frozenset((
    # texte et code
    "txt", "log", "py", "pyc", "pyi", "rst", "md", "sql", "patch", "diff",
    "sh", "bash", "css", "js", "ts", "map", "min",
    # donnees et configuration
    "json", "csv", "tsv", "yaml", "yml", "xml", "html", "htm", "cfg", "ini",
    "toml", "lock", "conf", "env", "service", "socket", "target",
    # archives et paquets
    "gz", "tgz", "zip", "tar", "bz2", "xz", "deb", "rpm", "whl", "dist", "egg",
    # binaires et media
    "so", "dll", "exe", "pdf", "png", "jpg", "jpeg", "gif", "svg", "ico",
    # cles et bases : le NOM du fichier n'est pas un hote
    "key", "pem", "crt", "cer", "der", "db", "sqlite", "sqlite3",
    # bureautique et fichiers temporaires
    "xlsx", "docx", "pptx", "bak", "tmp", "swp", "out", "err",
))
# fmt: on
_RE_FQDN = re.compile(r"(?<![/\\\w.])(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+([A-Za-z]{2,})\b")

# FQDN de remplacement que le scrubber produit lui-meme.
_OWN_DOMAINS = ("example.invalid",)

# Jeton interne de la phase 1. Encadre par NUL : aucun motif de ce module
# ne peut le traverser (ni point, ni deux-points, ni caractere de mot au
# contact), donc aucune regle ulterieure ne peut le reouvrir.
_TOKEN = "\x00{}\x00"
_RE_TOKEN = re.compile(r"\x00(\d+)\x00")


@dataclass
class ScrubReport:
    """Compte-rendu d'une passe de scrubbing.

    Toujours produit, meme quand rien n'a ete redige (``total == 0``) : la
    regle de tracabilite du projet impose de remonter l'information "tout
    va bien" explicitement plutot que de ne rien dire (voir
    docs/quality/traceability-rule.md). Un ticket sans section
    d'anonymisation serait indiscernable d'un ticket dont
    l'anonymisation a silencieusement echoue.

    ``par_categorie`` ne porte QUE les categories effectivement
    rencontrees ; ``total`` est la somme des occurrences remplacees et
    ``valeurs_distinctes`` le nombre de valeurs reelles distinctes
    pseudonymisees (deux occurrences de la meme IP comptent 2 dans
    ``total`` et 1 dans ``valeurs_distinctes``).
    """

    par_categorie: dict[str, int] = field(default_factory=dict)
    total: int = 0
    valeurs_distinctes: int = 0
    limites: tuple[str, ...] = KNOWN_LIMITS

    @property
    def statut(self) -> str:
        """``"redige"`` ou ``"aucune_donnee_sensible_detectee"``.

        Le second cas est un resultat POSITIF explicite, pas une absence
        de resultat : il affirme que la passe a bien eu lieu et n'a rien
        trouve a rediger.
        """
        logger.debug("statut: retour conditionnel")
        return "redige" if self.total else "aucune_donnee_sensible_detectee"

    def to_dict(self) -> dict:
        logger.debug("to_dict: retour dict")
        return {
            "statut": self.statut,
            "total_occurrences": self.total,
            "valeurs_distinctes": self.valeurs_distinctes,
            "par_categorie": dict(sorted(self.par_categorie.items())),
            "limites": list(self.limites),
        }


class TextScrubber:
    """Anonymise du texte libre avec un mapping stable et reutilisable.

    Un seul objet doit etre utilise pour tout un ticket (voire toute une
    campagne) : c'est le partage du mapping qui rend les pseudonymes
    correlables entre le traceback, les logs et le nom de la capture.

    Le mapping reel -> pseudonyme n'est JAMAIS ecrit dans le ticket. Il
    reste disponible cote operateur via ``mapping_csv_rows()`` pour etre
    conserve localement, exactement comme ``--redact-map`` le fait pour
    les adresses de paquets.
    """

    def __init__(self) -> None:
        # valeur reelle -> pseudonyme
        logger.debug("TextScrubber.__init__()")
        self._map: dict[str, str] = {}
        # valeur reelle -> categorie (pour l'export du mapping)
        self._kind: dict[str, str] = {}
        # valeurs PRODUITES par ce scrubber : deja anonymes, se traversent
        # elles-memes (idempotence) et n'entrent pas dans le mapping.
        self._own: set[str] = set()
        self._counters: dict[str, int] = dict.fromkeys(CATEGORIES, 0)

    # -- pseudonymes ------------------------------------------------------

    def _pseudonym(self, real: str, kind: str) -> str:
        """Pseudonyme stable pour ``real``, cree a la premiere rencontre.

        Une valeur deja produite par ce scrubber est renvoyee telle quelle :
        rescrubber un texte deja anonymise ne renumerote rien.
        """
        if real in self._own:
            logger.debug("_pseudonym: retour real")
            return real
        known = self._map.get(real)
        if known is not None:
            logger.debug("_pseudonym: retour known")
            return known
        idx = self._counters[kind]
        self._counters[kind] += 1
        pseudo = _GENERATORS[kind](idx)
        self._map[real] = pseudo
        self._kind[real] = kind
        self._own.add(pseudo)
        logger.debug("_pseudonym: retour pseudo")
        return pseudo

    def mapping_csv_rows(self) -> list[tuple[str, str, str]]:
        """Lignes ``(valeur_reelle, pseudonyme, categorie)`` triees.

        Destine a un fichier conserve PAR L'OPERATEUR, jamais joint au
        ticket -- il annulerait l'anonymisation.
        """
        logger.debug("TextScrubber.mapping_csv_rows()")
        return sorted((real, pseudo, self._kind[real]) for real, pseudo in self._map.items())

    # -- scrubbing --------------------------------------------------------

    def scrub(self, text: str | None) -> tuple[str | None, ScrubReport]:
        """Renvoie ``(texte_redige, rapport)``.

        ``None`` et la chaine vide traversent inchanges, avec un rapport a
        zero : la encore, un rapport est produit -- l'appelant sait que la
        passe a eu lieu sur une entree vide, ce qui n'est pas la meme
        chose que de ne pas avoir tente de rediger.
        """
        report = ScrubReport()
        if not text:
            logger.debug("scrub: retour tuple")
            return text, report

        counts: dict[str, int] = {}
        # Phase 1 : chaque correspondance devient un jeton opaque.
        pending: list[str] = []

        def _emit(value: str, kind: str) -> str:
            counts[kind] = counts.get(kind, 0) + 1
            pending.append(value)
            logger.debug("_emit: retour format(...)")
            return _TOKEN.format(len(pending) - 1)

        out = text

        # 1. Secrets (valeur ecrasee, cle conservee : savoir QU'UN mot de
        # passe figurait la est un signal de diagnostic utile).
        out = _RE_SECRET_BEARER.sub(lambda m: f"{m.group(1)}{m.group(2)}{_emit(SECRET_PLACEHOLDER, 'secret')}", out)
        out = _RE_SECRET_KV.sub(lambda m: f"{m.group(1)}{m.group(2)}{_emit(SECRET_PLACEHOLDER, 'secret')}", out)

        # 2. Emails.
        out = _RE_EMAIL.sub(lambda m: _emit(self._pseudonym(m.group(0), "email"), "email"), out)

        # 3. URLs.
        out = _RE_URL.sub(lambda m: _emit(self._pseudonym(m.group(0), "url"), "url"), out)

        # 4. MAC (avant ipv6 : les deux contiennent des ":").
        out = _RE_MAC.sub(lambda m: _emit(self._pseudonym(m.group(0).lower(), "mac"), "mac"), out)

        # 5. IPv6.
        out = _RE_IPV6.sub(lambda m: _emit(self._pseudonym(m.group(0).lower(), "ipv6"), "ipv6"), out)

        # 6. IPv4.
        out = _RE_IPV4.sub(lambda m: _emit(self._pseudonym(m.group(0), "ipv4"), "ipv4"), out)

        # 7. Noms de fichiers de capture (extension preservee).
        def _capture(m: re.Match[str]) -> str:
            base = self._pseudonym(m.group(0), "capture")
            full = f"{base}.{m.group(1)}"
            # La forme complete est aussi "notre" valeur : un second passage
            # la reconnait et ne la renumerote pas.
            self._own.add(full)
            logger.debug("_capture: retour _emit(...)")
            return _emit(full, "capture")

        out = _RE_CAPTURE.sub(_capture, out)

        # 8. Repertoires personnels (seul le composant utilisateur change).
        out = _RE_HOME_UNIX.sub(lambda m: f"{m.group(1)}/{_emit(self._pseudonym(m.group(2), 'path'), 'path')}", out)
        out = _RE_HOME_WIN.sub(lambda m: f"{m.group(1)}{_emit(self._pseudonym(m.group(2), 'path'), 'path')}", out)

        # 9. FQDN residuels, en dernier -- en ignorant nos propres domaines
        # et tout ce qui est en realite un nom de fichier.
        def _fqdn(m: re.Match[str]) -> str:
            value = m.group(0)
            if value.endswith(_OWN_DOMAINS) or m.group(1).lower() in _FILE_EXTS:
                logger.debug("_fqdn: retour value")
                return value
            logger.debug("_fqdn: retour _emit(...)")
            return _emit(self._pseudonym(value.lower(), "hostname"), "hostname")

        out = _RE_FQDN.sub(_fqdn, out)

        # Phase 2 : reinjection des pseudonymes a la place des jetons.
        out = _RE_TOKEN.sub(lambda m: pending[int(m.group(1))], out)

        report.par_categorie = counts
        report.total = sum(counts.values())
        report.valeurs_distinctes = len(self._map)
        logger.debug("scrub: retour tuple")
        return out, report

    def scrub_lines(self, lines) -> tuple[list[str], ScrubReport]:
        """``scrub`` applique a une sequence de lignes, rapport agrege."""
        logger.debug("TextScrubber.scrub_lines: lines={}", summarize(lines, "lines"))
        out: list[str] = []
        agg = ScrubReport()
        for line in lines:
            scrubbed, rep = self.scrub(line)
            out.append(scrubbed if scrubbed is not None else "")
            for kind, n in rep.par_categorie.items():
                agg.par_categorie[kind] = agg.par_categorie.get(kind, 0) + n
        agg.total = sum(agg.par_categorie.values())
        agg.valeurs_distinctes = len(self._map)
        logger.debug("scrub_lines: retour tuple")
        return out, agg


def _ipv4_pseudonym(index: int) -> str:
    """RFC 5737 TEST-NET-1, comme redact.py : jamais routable."""
    logger.debug("_ipv4_pseudonym: retour valeur")
    return f"192.0.2.{index % 254 + 1}"


def _ipv6_pseudonym(index: int) -> str:
    """RFC 3849 : 2001:db8::/32, documentation uniquement."""
    logger.debug("_ipv6_pseudonym: retour valeur")
    return f"2001:db8::{index + 1:x}"


def _mac_pseudonym(index: int) -> str:
    """OUI localement administre, comme redact.py."""
    logger.debug("_mac_pseudonym: retour valeur")
    return f"02:00:00:00:{(index >> 8) & 0xFF:02x}:{index & 0xFF:02x}"


def _email_pseudonym(index: int) -> str:
    logger.debug("_email_pseudonym: retour valeur")
    return f"user-{index + 1}@example.invalid"


def _url_pseudonym(index: int) -> str:
    logger.debug("_url_pseudonym: retour valeur")
    return f"https://host-{index + 1}.example.invalid/redacted"


def _capture_pseudonym(index: int) -> str:
    logger.debug("_capture_pseudonym: retour valeur")
    return f"capture-{index + 1}"


def _path_pseudonym(index: int) -> str:
    logger.debug("_path_pseudonym: retour valeur")
    return f"user-{index + 1}"


def _hostname_pseudonym(index: int) -> str:
    logger.debug("_hostname_pseudonym: retour valeur")
    return f"host-{index + 1}.example.invalid"


_GENERATORS = {
    "ipv4": _ipv4_pseudonym,
    "ipv6": _ipv6_pseudonym,
    "mac": _mac_pseudonym,
    "email": _email_pseudonym,
    "url": _url_pseudonym,
    "capture": _capture_pseudonym,
    "path": _path_pseudonym,
    "hostname": _hostname_pseudonym,
    # "secret" n'a pas de generateur : valeur ecrasee, jamais pseudonymisee.
}
