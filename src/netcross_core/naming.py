"""
netcross_core.naming -- table locale de correspondance adresse/MAC -> nom
logique, type, contexte (Job 18 / issue #16-bis, section 6.15 de FEATURES.md).

Les rapports affichent par defaut des adresses IP brutes
(``10.24.12.31 -> 10.24.80.10``). Cette table permet de les remplacer par des
noms lisibles et contextualises (``PC-COMPTA-31 -> APP-SQL-01``), avec un type
(client / serveur / routeur / firewall / AP), un site et un role.

Persistance versionnable : JSON (stdlib, toujours disponible) ou YAML
(optionnel, si ``pyyaml`` est installe -- import lazy, le module reste
importable sans). Le format est choisi par l'extension du fichier
(``.json`` / ``.yaml`` / ``.yml``).

Le module est un CONSOMMATEUR pur : il ne depend ni du moteur de regles, ni
du CLI, du PDF ou de la GUI. Les rendus (CSV, JSON, PDF...) recuperent une
``NameTable`` resolue et l'appliquent au moment de l'affichage -- la table
ne modifie jamais les objets sources (``Pkt``, ``Flow``, ``Conversation``).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

#: Types d'equipement reconnus (non exhaustif -- tout type est accepte en
#: entree, la table ne valide pas le vocabulaire).
from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)
KNOWN_TYPES = ("client", "serveur", "routeur", "firewall", "ap", "autre")

#: Extensions de fichiers reconnues pour la persistance.
_JSON_EXTS = (".json",)
_YAML_EXTS = (".yaml", ".yml")


@dataclass(frozen=True)
class NameEntry:
    """Une entree de la table des noms.

    Au moins un identifiant parmi ``address`` / ``mac`` doit etre renseigne
    (sinon l'entree n'est pas resoluble). ``name`` est toujours requis.
    """

    name: str
    address: str | None = None
    mac: str | None = None
    type: str = "autre"
    site: str | None = None
    role: str | None = None
    comment: str | None = None

    def matches(self, address: str | None = None, mac: str | None = None) -> bool:
        """Vrai si l'entree correspond a l'adresse ou a la MAC donnee.

        La comparaison des MAC est insensible a la casse ; celle des
        adresses respecte la casse (les adresses IP n'en ont pas, mais les
        noms d'hotes IPv6 ou labels le pourraient).
        """
        logger.debug("matches: retour booleen")
        return (address is not None and self.address == address) or (
            mac is not None and self.mac is not None and self.mac.lower() == mac.lower()
        )


class NameTable:
    """Table des noms resoluble par adresse ou MAC.

    Index construit a l'initialisation (dictionnaires adresse -> entree et
    mac -> entree). Les recherches sont en O(1).
    """

    def __init__(self, entries: list[NameEntry] | None = None) -> None:
        logger.debug("NameTable.__init__: entries={}", summarize(entries, "entries"))
        self._by_address: dict[str, NameEntry] = {}
        self._by_mac: dict[str, NameEntry] = {}
        self._entries: list[NameEntry] = []
        for e in entries or ():
            self.add(e)
        logger.debug("NameTable.__init__: fin")

    # -- Mutation ---------------------------------------------------------

    def add(self, entry: NameEntry) -> None:
        """Ajoute une entree. Ecrase une entree precedente pour la meme
        adresse ou MAC."""
        if not entry.name:
            logger.trace("NameTable.add: refus, ValueError")
            logger.debug("NameTable.add: si not entry.name -> levée ValueError")
            raise ValueError("NameEntry.name est requis")
        if entry.address is None and entry.mac is None:
            logger.trace("NameTable.add: refus, ValueError")
            logger.debug("NameTable.add: si entry.address is None and entry.mac is None -> levée ValueError")
            raise ValueError("NameEntry doit avoir au moins une adresse ou une MAC")
        self._entries.append(entry)
        if entry.address is not None:
            self._by_address[entry.address] = entry
        if entry.mac is not None:
            self._by_mac[entry.mac.lower()] = entry
        logger.debug("NameTable.add: fin")

    # -- Resolution -------------------------------------------------------

    def resolve(self, address: str | None) -> NameEntry | None:
        """Retourne l'entree correspondant a une adresse, ou None."""
        if address is None:
            logger.debug("resolve: retour None")
            return None
        logger.debug("resolve: retour get(...)")
        return self._by_address.get(address)

    def resolve_mac(self, mac: str | None) -> NameEntry | None:
        """Retourne l'entree correspondant a une MAC, ou None."""
        logger.debug("NameTable.resolve_mac: mac={}", summarize(mac, "mac"))
        if mac is None:
            logger.debug("resolve_mac: retour None")
            return None
        logger.debug("resolve_mac: retour get(...)")
        return self._by_mac.get(mac.lower())

    def display(self, address: str | None) -> str:
        """Retourne le nom logique d'une adresse, ou l'adresse brute si
        aucune entree ne correspond (ou si l'adresse est None -> chaine
        vide). C'est le point d'entree unique des rendus."""
        if address is None:
            logger.debug("display: retour ''")
            return ""
        entry = self._by_address.get(address)
        logger.debug("display: retour conditionnel")
        return entry.name if entry is not None else address

    # -- Persistance ------------------------------------------------------

    def to_list(self) -> list[dict]:
        """Liste de dictionnaires (ordre stable) pour la serialisation."""
        logger.debug("to_list: retour liste")
        return [asdict(e) for e in self._entries]

    @classmethod
    def from_list(cls, items: list[dict]) -> NameTable:
        """Construit une table depuis une liste de dictionnaires. Les
        cles manquantes prennent leur valeur par defaut ; ``name`` est
        requis."""
        entries: list[NameEntry] = []
        for i, item in enumerate(items):
            if "name" not in item or not item["name"]:
                logger.trace("NameTable.from_list: refus, ValueError")
                logger.debug("NameTable.from_list: si 'name' not in item or not item['name'] -> levée ValueError")
                raise ValueError(f"entree #{i}: 'name' est requis")
            entries.append(
                NameEntry(
                    name=item["name"],
                    address=item.get("address"),
                    mac=item.get("mac"),
                    type=item.get("type", "autre"),
                    site=item.get("site"),
                    role=item.get("role"),
                    comment=item.get("comment"),
                )
            )
        logger.debug("from_list: retour cls(...)")
        return cls(entries)

    @classmethod
    def load(cls, path: str | Path) -> NameTable:
        """Charge une table depuis un fichier JSON ou YAML (choix par
        extension). YAML necessite ``pyyaml`` (import lazy)."""
        p = Path(path)
        if not p.exists():
            logger.trace("NameTable.load: refus, FileNotFoundError")
            logger.debug("NameTable.load: si not p.exists() -> levée FileNotFoundError")
            raise FileNotFoundError(f"table des noms introuvable: {path}")
        suffix = p.suffix.lower()
        text = p.read_text(encoding="utf-8")
        if suffix in _JSON_EXTS:
            data = json.loads(text)
        elif suffix in _YAML_EXTS:
            data = _load_yaml(text)
        else:
            # Par defaut on tente le JSON (format le plus portable).
            data = json.loads(text)
        if isinstance(data, dict):
            # Format { "entries": [...] } tolere pour lisibilite.
            data = data.get("entries", [])
        if not isinstance(data, list):
            logger.trace("NameTable.load: refus, ValueError")
            logger.debug("NameTable.load: si not isinstance(data, list) -> levée ValueError")
            raise ValueError(f"la table des noms doit etre une liste, pas {type(data).__name__}")
        logger.debug("load: retour from_list(...)")
        return cls.from_list(data)

    def save(self, path: str | Path) -> None:
        """Ecrit la table en JSON ou YAML selon l'extension."""
        p = Path(path)
        items = self.to_list()
        suffix = p.suffix.lower()
        if suffix in _YAML_EXTS:
            p.write_text(_dump_yaml(items), encoding="utf-8")
        else:
            p.write_text(
                json.dumps(items, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        logger.debug("NameTable.save: fin")

    # -- Divers -----------------------------------------------------------

    def __len__(self) -> int:
        logger.debug("__len__: retour len(...)")
        return len(self._entries)

    def __bool__(self) -> bool:
        logger.debug("__bool__: retour bool(...)")
        return bool(self._entries)


def _load_yaml(text: str):
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - branche dependante de l'env
        logger.debug("dépendance optionnelle absente: exc")
        raise ImportError(
            "lecture YAML requiert pyyaml (pip install pyyaml) ; utilisez un fichier .json pour eviter cette dependance"
        ) from exc
    logger.debug("_load_yaml: retour safe_load(...)")
    return yaml.safe_load(text)


def _dump_yaml(items: list[dict]) -> str:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - branche dependante de l'env
        logger.debug("dépendance optionnelle absente: exc")
        raise ImportError(
            "ecriture YAML requiert pyyaml (pip install pyyaml) ; "
            "utilisez un fichier .json pour eviter cette dependance"
        ) from exc
    logger.debug("_dump_yaml: retour safe_dump(...)")
    return yaml.safe_dump(items, allow_unicode=True, sort_keys=False)
