"""
netcross_core.plugins.api -- contrat des plugins (issue #284).

Deux points d'extension, pas plus :

- `Detector.analyse(contexte) -> list[dict]` : constats au MEME schema que
  `Report.security_findings` (`category`, `severity`, `detail`, `point`...),
  pour qu'ils traversent sans traitement particulier le tableau de bord, le
  rendu texte, le JSON, le HTML et l'export SIEM ;
- `Exporter.export(rapport, chemin) -> None` : une sortie propre a un SIEM
  ou a une plateforme interne.

Le contexte et le rapport remis a un plugin sont des VUES EN LECTURE SEULE :
un plugin qui reecrirait les constats des autres rendrait tout rapport
incontestable. Les vues ne donnent jamais acces aux objets du coeur : les
conteneurs (listes, dicts) sont rendus en copies profondes figees
(tuples, `MappingProxyType`), et toute affectation leve `PluginAccessError`.

Ce n'est PAS un bac a sable : un plugin reste du code Python arbitraire
execute dans le processus (voir docs/plugins.md, « limites de securite »).
La vue protege contre l'erreur et la negligence, pas contre la malveillance.
"""

from __future__ import annotations

import copy
import dataclasses
import math
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

SEVERITIES = ("critique", "elevee", "moyenne", "faible")
REQUIRED_KEYS = ("category", "severity", "detail")
_SCALARS = (str, int, float, bool, type(None))


class PluginAccessError(AttributeError):
    """Tentative de modification d'une vue en lecture seule."""


class InvalidFindingError(ValueError):
    """Constat renvoye par un plugin qui ne respecte pas le schema."""


def freeze(value: Any) -> Any:
    """Copie profonde figee : dict -> MappingProxyType, list/set -> tuple,
    dataclass/objet -> vue `ReadOnlyView`. Les scalaires traversent."""
    if isinstance(value, (*_SCALARS, bytes)):
        logger.debug("freeze: retour value")
        return value
    if isinstance(value, Mapping):
        logger.debug("freeze: retour MappingProxyType(...)")
        return MappingProxyType({k: freeze(v) for k, v in value.items()})
    if isinstance(value, list | tuple | set | frozenset):
        logger.debug("freeze: retour tuple(...)")
        return tuple(freeze(v) for v in value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        logger.debug("freeze: retour ReadOnlyView(...)")
        return ReadOnlyView(value)
    logger.debug("freeze: retour deepcopy(...)")
    return copy.deepcopy(value)


class ReadOnlyView:
    """Vue en lecture seule d'un objet du coeur (Pkt, Report...).

    Chaque attribut lu est gele par `freeze` : modifier la liste renvoyee
    est impossible (tuple), et modifier un element ne touche qu'une copie.
    """

    __slots__ = ("_target",)

    def __init__(self, target: Any) -> None:
        object.__setattr__(self, "_target", target)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        logger.debug("__getattr__: retour freeze(...)")
        return freeze(getattr(object.__getattribute__(self, "_target"), name))

    def __setattr__(self, name: str, value: Any) -> None:
        raise PluginAccessError(f"lecture seule : impossible de modifier {name!r}")

    def __delattr__(self, name: str) -> None:
        raise PluginAccessError(f"lecture seule : impossible de supprimer {name!r}")

    def __repr__(self) -> str:
        logger.debug("__repr__: retour valeur")
        return f"ReadOnlyView({type(object.__getattribute__(self, '_target')).__name__})"


class _Packets:
    """Sequence paresseuse de paquets en lecture seule (pas de copie des
    millions de `Pkt` d'une grosse capture : une vue par acces)."""

    __slots__ = ("_items",)

    def __init__(self, items: list[Any]) -> None:
        self._items = items

    def __len__(self) -> int:
        logger.debug("__len__: retour len(...)")
        return len(self._items)

    def __getitem__(self, index: int) -> ReadOnlyView:
        logger.debug("__getitem__: retour ReadOnlyView(...)")
        return ReadOnlyView(self._items[index])

    def __iter__(self) -> Iterator[ReadOnlyView]:
        logger.debug("__iter__: retour generateur")
        return (ReadOnlyView(p) for p in self._items)


@dataclasses.dataclass(frozen=True, slots=True)
class DetectorContext:
    """Ce qu'un detecteur voit de l'analyse.

    `packets` : paquets de tous les points, en vues lecture seule ;
    `report` : le `Report` en vue lecture seule ;
    `findings` : constats du coeur deja produits, en copies figees.
    """

    packets: Any
    report: ReadOnlyView
    findings: tuple[Mapping[str, Any], ...]

    @classmethod
    def build(cls, packets: list[Any], report: Any) -> DetectorContext:
        logger.debug("build: retour cls(...)")
        return cls(
            packets=_Packets(packets),
            report=ReadOnlyView(report),
            findings=freeze(list(getattr(report, "security_findings", None) or [])),
        )


@runtime_checkable
class Detector(Protocol):
    name: str

    def analyse(self, contexte: DetectorContext) -> list[dict]: ...


@runtime_checkable
class Exporter(Protocol):
    name: str

    def export(self, report: Any, chemin: Path) -> None: ...


def validate_finding(raw: Any) -> dict[str, Any]:
    """Valide et normalise un constat de plugin ; leve `InvalidFindingError`.

    Exigences : un dict ; `category`, `severity`, `detail` presents et non
    vides ; `severity` dans SEVERITIES ; toutes les valeurs scalaires JSON
    (pas d'objet arbitraire qui casserait le JSON ou le HTML), sauf `cves`
    (liste de chaines). Les flottants non finis sont refuses."""
    logger.debug("validate_finding: raw={}", summarize(raw, "raw"))
    if not isinstance(raw, Mapping):
        logger.debug("validate_finding: refus, InvalidFindingError")
        raise InvalidFindingError(f"constat de type {type(raw).__name__}, dict attendu")
    finding = dict(raw)
    for key in REQUIRED_KEYS:
        if not isinstance(finding.get(key), str) or not finding[key].strip():
            logger.debug("validate_finding: refus, InvalidFindingError")
            raise InvalidFindingError(f"cle {key!r} absente ou vide")
    severity = finding["severity"].lower()
    if severity not in SEVERITIES:
        logger.debug("validate_finding: refus, InvalidFindingError")
        raise InvalidFindingError(f"severite {finding['severity']!r} inconnue (attendu : {', '.join(SEVERITIES)})")
    finding["severity"] = severity
    for key, value in finding.items():
        if not isinstance(key, str):
            logger.debug("validate_finding: refus, InvalidFindingError")
            raise InvalidFindingError(f"cle non textuelle : {key!r}")
        if key == "cves":
            if not isinstance(value, list | tuple) or not all(isinstance(c, str) for c in value):
                logger.debug("validate_finding: refus, InvalidFindingError")
                raise InvalidFindingError("'cves' doit etre une liste de chaines")
            finding[key] = list(value)
        elif not isinstance(value, _SCALARS):
            logger.debug("validate_finding: refus, InvalidFindingError")
            raise InvalidFindingError(f"valeur non scalaire pour {key!r} ({type(value).__name__})")
        elif isinstance(value, float) and not math.isfinite(value):
            logger.debug("validate_finding: refus, InvalidFindingError")
            raise InvalidFindingError(f"valeur non finie pour {key!r}")
    logger.debug("validate_finding: retour finding")
    return finding
