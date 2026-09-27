"""netcross_core.i18n -- internationalisation par GNU gettext (issue #299).

Les chaines destinees a l'utilisateur sont ecrites en francais (langue
source) et marquees ``_("...")`` / ``ngettext(sing, plur, n)``. Les
constantes de module, evaluees avant le choix de la langue, sont marquees
``N_("...")`` (extraction seule) et traduites au moment de l'affichage par
``_(CONSTANTE)``.

Catalogues : ``lang/<locale>.po`` a la racine du depot, modele
``lang/messages.pot``, liste des langues dans ``lang/LINGUAS`` -- la seule
liste : aucune locale n'est ecrite dans le code. Les ``.mo`` compiles
(``scripts/i18n-update.sh --compile``) sont cherches, dans l'ordre :

1. ``$NETCROSS_LOCALEDIR`` ;
2. ``netcross_core/locale/`` (compile par le packaging, a cote du code) ;
3. ``<sys.prefix>/share/locale`` puis ``/usr/share/locale``.

Langue : ``$NETCROSS_LANG`` (ex. ``en``, ``pt_BR``), sinon les variables
standard ``LANGUAGE``, ``LC_ALL``, ``LC_MESSAGES``, ``LANG``. Sans catalogue
correspondant, les chaines restent en francais : l'absence de traduction ne
casse jamais l'affichage.
"""

from __future__ import annotations

import gettext
import os
import sys
from pathlib import Path

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

DOMAIN = "netcross"
ENV_LANG = "NETCROSS_LANG"
ENV_LOCALEDIR = "NETCROSS_LOCALEDIR"
PACKAGE_LOCALEDIR = Path(__file__).resolve().parent / "locale"

_translation: gettext.NullTranslations | None = None


def locale_dirs() -> list[Path]:
    """Repertoires de catalogues compiles, par priorite decroissante."""
    logger.debug("locale_dirs()")
    dirs: list[Path] = []
    env = os.environ.get(ENV_LOCALEDIR)
    if env:
        dirs.append(Path(env))
    dirs += [PACKAGE_LOCALEDIR, Path(sys.prefix) / "share" / "locale", Path("/usr/share/locale")]
    unique: list[Path] = []
    for d in dirs:
        if d not in unique:
            unique.append(d)
    logger.debug("locale_dirs: {} repertoire(s)", len(unique))
    return unique


def requested_languages(language: str | None = None) -> list[str] | None:
    """Langues demandees : argument, puis ``$NETCROSS_LANG`` ; ``None``
    laisse gettext lire LANGUAGE/LC_ALL/LC_MESSAGES/LANG."""
    value = language or os.environ.get(ENV_LANG)
    if not value:
        logger.debug("requested_languages: aucune langue demandee")
        return None
    langs = [part.strip() for part in value.split(":") if part.strip()]
    logger.debug("requested_languages: {} langue(s)", len(langs))
    return langs


def setup(language: str | None = None) -> gettext.NullTranslations:
    """Charge le catalogue de la langue demandee (ou de l'environnement) et
    l'active pour ``_``/``ngettext``. Retourne la traduction active."""
    global _translation
    languages = requested_languages(language)
    found: gettext.NullTranslations = gettext.NullTranslations()
    for localedir in locale_dirs():
        try:
            found = gettext.translation(DOMAIN, localedir=str(localedir), languages=languages)
        except OSError:
            # Absence de catalogue dans ce repertoire : cas normal (lancement
            # depuis les sources, locale francaise = langue source). #468
            logger.debug("i18n.setup: aucun catalogue {} dans {}", DOMAIN, localedir)
            continue
        logger.debug("i18n.setup: catalogue charge depuis {}", localedir)
        break
    else:
        logger.debug("i18n.setup: aucun catalogue trouve, chaines source (francais)")
    _translation = found
    logger.debug("setup: catalogue actif={}", found is not None)
    return found


def active_language() -> str | None:
    """Langue du catalogue actif (``None`` : chaines source en francais)."""
    logger.debug("active_language()")
    info = _current().info()
    lang = info.get("language") or None
    logger.debug("active_language: langue={}", lang)
    return lang


def available_languages(localedir: Path | None = None) -> list[str]:
    """Locales ayant un catalogue compile, trouvees sur disque (pas de
    liste codee en dur)."""
    logger.debug("available_languages: localedir={}", summarize(localedir, "localedir"))
    dirs = [localedir] if localedir else locale_dirs()
    langs: set[str] = set()
    for d in dirs:
        if d.is_dir():
            langs.update(p.parent.parent.name for p in d.glob(f"*/LC_MESSAGES/{DOMAIN}.mo"))
    result = sorted(langs)
    logger.debug("available_languages: {} langue(s)", len(result))
    return result


def _current() -> gettext.NullTranslations:
    return _translation if _translation is not None else setup()


def _(message: str) -> str:
    """Traduit ``message`` (francais source) dans la langue active."""
    return _current().gettext(message)


def ngettext(singular: str, plural: str, n: int) -> str:
    """Forme singulier/pluriel selon ``n`` et les regles de la langue."""
    return _current().ngettext(singular, plural, n)


def N_(message: str) -> str:  # noqa: N802 -- convention gettext
    """Marque ``message`` pour l'extraction sans le traduire (constantes)."""
    return message


__all__ = [
    "DOMAIN",
    "ENV_LANG",
    "ENV_LOCALEDIR",
    "N_",
    "_",
    "active_language",
    "available_languages",
    "locale_dirs",
    "ngettext",
    "requested_languages",
    "setup",
]
