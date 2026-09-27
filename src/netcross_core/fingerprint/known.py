"""
netcross_core.fingerprint.known -- base de correspondances empreinte ->
nom d'outil (issue #143, critere d'acceptation "base de fingerprints
connus chargeable").

Format du fichier JSON (`known_fingerprints.json`, a cote de ce module).
Deux formes de valeur sont acceptees pour chaque empreinte :

- forme courte, pour une base ecrite a la main :
  {"ja4": {"<empreinte>": "curl 8.18.0"}}
- forme enrichie, produite par
  `scripts/capture_reference_fingerprints.py` :
  {"ja4": {"<empreinte>": {"libelle": "curl 8.18.0", "outil": "curl",
                           "version": "<sortie complete de --version>",
                           "lisible": "<ciphers/extensions>",
                           "verifie_contre": "tshark 4.6.4",
                           "methode": "capture reelle sur boucle locale"}}}

La forme enrichie existe parce qu'une empreinte sans provenance ne vaut
pas grand-chose : savoir QUELLE version d'un outil l'a produite, et
contre quoi la valeur a ete verifiee, est ce qui permet de la contester
ou de la reproduire. `identify_tool` n'en renvoie que le libelle.

La base livree n'est PLUS vide (issue #259) : elle contient des
empreintes capturees sur du trafic reel en boucle locale, chacune
verifiee identique a celle calculee par l'implementation de reference de
Wireshark. Elle reste NON exhaustive -- elle ne couvre que les outils
presents sur la machine de generation. Relancer le script pour
l'enrichir.

`load_known_fingerprints` accepte un chemin de fichier alternatif (une
base maintenue par l'utilisateur, plus a jour ou plus large) ; sans
argument elle charge le fichier livre avec le projet.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

_DEFAULT_PATH = Path(__file__).with_name("known_fingerprints.json")


@lru_cache(maxsize=8)
def _load_cached(path: str) -> dict[str, dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    logger.debug("_load_cached: retour dict")
    return {"ja4": data.get("ja4", {}), "hassh": data.get("hassh", {})}


def load_known_fingerprints(path: str | Path | None = None) -> dict[str, dict]:
    """Charge la base {"ja4": {...}, "hassh": {...}}. Renvoie une base
    vide (jamais d'exception) si `path` est absent ou illisible -- une
    base de fingerprints manquante ne doit jamais faire echouer l'analyse,
    seulement priver l'analyste de l'identification lisible de l'outil."""
    try:
        logger.debug("load_known_fingerprints: retour _load_cached(...)")
        return _load_cached(str(path or _DEFAULT_PATH))
    except (OSError, json.JSONDecodeError):
        logger.exception("échec dans load_known_fingerprints")
        return {"ja4": {}, "hassh": {}}


def identify_tool(fingerprint_type: str, fingerprint: str, known: dict[str, dict] | None = None) -> str | None:
    """Nom d'outil connu pour `fingerprint` ("ja4" ou "hassh"), None si
    absent de la base (charge la base livree par defaut si `known` n'est
    pas fourni -- eviter de la recharger a chaque paquet quand on traite
    une capture entiere, voir `fingerprint.report`)."""
    known = known if known is not None else load_known_fingerprints()
    valeur = known.get(fingerprint_type, {}).get(fingerprint)
    if isinstance(valeur, dict):
        # Forme enrichie : on n'affiche que le libelle court. Le reste
        # (version complete, methode de verification) sert a documenter la
        # base, pas a encombrer une ligne de rapport.
        logger.debug("identify_tool: retour booleen")
        return valeur.get("libelle") or valeur.get("outil")
    logger.debug("identify_tool: retour valeur")
    return valeur
