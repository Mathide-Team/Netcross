"""Paquets de modeles partageables (issue #271).

Un **paquet de modele** est une archive ZIP autoportante qui transporte des
modeles de « bon etat transactionnel » (baseline de trafic normal) et, en
option, des exemples etiquetes (tunnel, c2, exfiltration...) pour enrichir la
base commune du depot via un ticket « modeles ».

Garanties (« sans garder d'infos ») :

- seuls des **vecteurs de caracteristiques** voyagent (tailles, entropies,
  ratios, regularite -- voir ``features``) : aucune adresse IP, aucun port,
  aucun nom d'hote, aucun horodatage de paquet, aucune charge utile ;
- vecteurs arrondis a 4 chiffres significatifs et **melanges** (l'ordre ne
  trahit pas la chronologie de la capture) ;
- textes libres (libelle, description) passes au ``TextScrubber`` des tickets
  de support (IP, MAC, e-mails, noms d'hote, chemins) ; date de creation
  reduite au jour ;
- consentement explicite obligatoire (comme ``--support-consent``) ;
- a la lecture, archive verifiee : noms de fichiers attendus seulement, taille
  bornee, empreintes SHA-256 du manifeste, schemas valides. Aucun pickle,
  aucun code : un paquet recu ne peut rien executer.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import random
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from netcross_ai.anomaly import Baseline, BaselineError
from netcross_ai.features import FEATURE_NAMES
from netcross_ai.flow_classifier import TRAINING_SCHEMA, is_feature_vector, sample_vector
from netcross_core.logging_config import get_logger
from netcross_core.support import TextScrubber

logger = get_logger(__name__)

PACK_SCHEMA = "netcross.ai.modelpack/1"
MANIFEST = "manifest.json"
BASELINE_FILE = "baseline.json"
TRAINING_FILE = "training.json"
TICKET_FILE = "TICKET.md"
_ALLOWED = (MANIFEST, BASELINE_FILE, TRAINING_FILE, TICKET_FILE)
MAX_ENTRY_BYTES = 32 * 1024 * 1024
MAX_PACK_BYTES = 64 * 1024 * 1024
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_SIGNIFICANT = 4


class ModelPackError(ValueError):
    """Paquet de modele invalide, ou export refuse."""


@dataclass
class ModelPack:
    name: str
    description: str = ""
    created: str = ""
    baseline: Baseline | None = None
    training: list[tuple[list[float], str]] = field(default_factory=list)

    @property
    def label_counts(self) -> dict[str, int]:
        return dict(sorted(Counter(label for _v, label in self.training).items()))

    def summary(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "created": self.created,
            "baseline_vectors": len(self.baseline.vectors) if self.baseline else 0,
            "baseline_label": self.baseline.label if self.baseline else "",
            "training_samples": len(self.training),
            "labels": self.label_counts,
        }


def _round(x: float) -> float:
    if x == 0 or not math.isfinite(x):
        return 0.0
    digits = _SIGNIFICANT - 1 - math.floor(math.log10(abs(x)))
    return round(x, digits)


def _clean_vectors(vectors: list[list[float]], rng: random.Random) -> list[list[float]]:
    out = [[_round(float(x)) for x in v] for v in vectors]
    rng.shuffle(out)
    return out


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_name(name: str) -> str:
    if not _NAME_RE.match(name):
        raise ModelPackError(f"nom de paquet invalide : {name!r} (minuscules, chiffres, '-' et '_', 64 caracteres max)")
    return name


def ticket_body(pack: ModelPack) -> str:
    """Texte du ticket « modeles » (a coller dans l'issue, archive en piece jointe)."""
    s = pack.summary()
    labels = ", ".join(f"{k} ({v})" for k, v in s["labels"].items()) or "aucun"
    return "\n".join(
        [
            f"## Paquet de modele : {s['name']}",
            "",
            s["description"] or "(pas de description)",
            "",
            f"- Schema : `{PACK_SCHEMA}`",
            f"- Cree le : {s['created']}",
            f"- Baseline : {s['baseline_vectors']} flux ({s['baseline_label'] or 'sans libelle'})",
            f"- Exemples etiquetes : {s['training_samples']} -- {labels}",
            f"- Caracteristiques : {', '.join(FEATURE_NAMES)}",
            "",
            "Contenu : vecteurs de caracteristiques uniquement (arrondis, melanges), "
            "aucune adresse, aucun port, aucun horodatage, aucune charge utile.",
            "",
            f"Archive jointe : `{s['name']}.zip` -- a verifier avec "
            f"`python3 src/netcross_ai_models_cli.py inspect {s['name']}.zip`.",
        ]
    )


def build_pack(
    out_path: str | Path,
    *,
    name: str,
    consent: bool,
    baseline: Baseline | None = None,
    training: list[tuple[dict | list[float], str]] | None = None,
    description: str = "",
    seed: int | None = None,
) -> ModelPack:
    """Ecrit le paquet ``out_path`` (ZIP) et le renvoie.

    ``training`` : exemples (flux FLOW-4 ou vecteurs) -- seuls les vecteurs
    sont conserves. ``seed`` : graine du melange (tests uniquement).
    """
    if not consent:
        logger.trace("build_pack: refus, ModelPackError")
        raise ModelPackError(
            "export refuse sans consentement explicite (--consent) : le paquet est destine a etre partage."
        )
    check_name(name)
    if baseline is None and not training:
        logger.trace("build_pack: refus, ModelPackError")
        raise ModelPackError("rien a exporter : fournir une baseline et/ou un jeu d'entrainement.")
    scrubber = TextScrubber()
    rng = random.Random(seed)
    pack = ModelPack(
        name=name,
        description=(scrubber.scrub(description)[0] or "").strip()[:2000],
        created=datetime.now(timezone.utc).date().isoformat(),
    )
    if baseline is not None:
        label = scrubber.scrub(baseline.label)[0] or ""
        pack.baseline = Baseline(_clean_vectors(baseline.vectors, rng), label[:200], pack.created)
    for sample, label in training or []:
        label = label.strip().lower()
        if not _LABEL_RE.match(label):
            logger.trace("build_pack: refus, ModelPackError")
            raise ModelPackError(f"etiquette invalide : {label!r} (ex. normal, tunnel, c2, exfiltration)")
        pack.training.append((sample_vector(sample), label))
    pack.training = [([_round(x) for x in v], label) for v, label in pack.training]
    rng.shuffle(pack.training)

    files: dict[str, bytes] = {}
    if pack.baseline is not None:
        files[BASELINE_FILE] = json.dumps(pack.baseline.to_dict(), ensure_ascii=False).encode()
    if pack.training:
        doc = {"schema": TRAINING_SCHEMA, "samples": [{"features": v, "label": lb} for v, lb in pack.training]}
        files[TRAINING_FILE] = json.dumps(doc, ensure_ascii=False).encode()
    files[TICKET_FILE] = ticket_body(pack).encode()
    manifest = {
        "schema": PACK_SCHEMA,
        **pack.summary(),
        "features": list(FEATURE_NAMES),
        "files": {n: _sha256(b) for n, b in files.items()},
    }
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(MANIFEST, json.dumps(manifest, ensure_ascii=False, indent=1))
        for n, b in files.items():
            zf.writestr(n, b)
    return pack


def _read_entries(path: Path) -> dict[str, bytes]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        logger.exception(f"échec dans _read_entries: {exc}")
        raise ModelPackError(f"paquet illisible ({path}) : {exc}") from exc
    if size > MAX_PACK_BYTES:
        raise ModelPackError(f"{path} : archive trop volumineuse ({size} octets)")
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            names = [i.filename for i in infos]
            unexpected = sorted(set(names) - set(_ALLOWED))
            if unexpected or len(names) != len(set(names)):
                raise ModelPackError(f"{path} : contenu inattendu ({', '.join(unexpected) or 'doublons'})")
            if MANIFEST not in names:
                raise ModelPackError(f"{path} : manifest.json absent, ce n'est pas un paquet de modele")
            entries = {}
            for info in infos:
                if info.file_size > MAX_ENTRY_BYTES:
                    raise ModelPackError(f"{path} : {info.filename} trop volumineux")
                with zf.open(info) as fh:
                    data = fh.read(MAX_ENTRY_BYTES + 1)
                if len(data) > MAX_ENTRY_BYTES:
                    raise ModelPackError(f"{path} : {info.filename} trop volumineux")
                entries[info.filename] = data
            return entries
    except (zipfile.BadZipFile, OSError) as exc:
        logger.exception(f"échec dans _read_entries: {exc}")
        raise ModelPackError(f"{path} : archive ZIP invalide ({exc})") from exc


def _json(entries: dict[str, bytes], name: str, path: Path) -> object:
    try:
        return json.loads(entries[name].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.exception(f"échec dans _json: {exc}")
        raise ModelPackError(f"{path} : {name} invalide ({exc})") from exc


def read_pack(path: str | Path) -> ModelPack:
    """Lit et **verifie** un paquet (voir les garanties du module)."""
    p = Path(path)
    entries = _read_entries(p)
    manifest = _json(entries, MANIFEST, p)
    if not isinstance(manifest, dict) or manifest.get("schema") != PACK_SCHEMA:
        raise ModelPackError(f"{p} : manifeste {PACK_SCHEMA} attendu")
    if manifest.get("features") != list(FEATURE_NAMES):
        raise ModelPackError(f"{p} : caracteristiques d'une autre version de Netcross, paquet a regenerer")
    declared = manifest.get("files")
    if not isinstance(declared, dict) or set(declared) != set(entries) - {MANIFEST}:
        raise ModelPackError(f"{p} : liste de fichiers du manifeste incoherente")
    for n, digest in declared.items():
        if _sha256(entries[n]) != digest:
            raise ModelPackError(f"{p} : empreinte SHA-256 de {n} incorrecte (archive alteree)")
    pack = ModelPack(
        name=check_name(str(manifest.get("name", ""))),
        description=str(manifest.get("description", ""))[:2000],
        created=str(manifest.get("created", "")),
    )
    if BASELINE_FILE in entries:
        try:
            pack.baseline = Baseline.from_dict(_json(entries, BASELINE_FILE, p), f"{p}:{BASELINE_FILE}")
        except BaselineError as exc:
            logger.exception(f"échec dans read_pack: {exc}")
            raise ModelPackError(str(exc)) from exc
    if TRAINING_FILE in entries:
        doc = _json(entries, TRAINING_FILE, p)
        if (
            not isinstance(doc, dict)
            or doc.get("schema") != TRAINING_SCHEMA
            or not isinstance(doc.get("samples"), list)
        ):
            raise ModelPackError(f"{p} : {TRAINING_FILE} invalide")
        for i, item in enumerate(doc["samples"]):
            label = item.get("label") if isinstance(item, dict) else None
            if not (isinstance(label, str) and _LABEL_RE.match(label) and is_feature_vector(item.get("features"))):
                raise ModelPackError(f"{p} : exemple {i} invalide (vecteur + etiquette attendus, aucun flux brut)")
            pack.training.append(([float(x) for x in item["features"]], label))
    if pack.baseline is None and not pack.training:
        raise ModelPackError(f"{p} : paquet vide")
    return pack


def import_pack(
    path: str | Path, *, baseline_path: str | Path | None = None, training_path: str | Path | None = None
) -> dict:
    """Fusionne un paquet verifie dans la base locale : baseline (vecteurs
    ajoutes) et/ou jeu d'entrainement (exemples ``features`` ajoutes). Les
    fichiers locaux sont crees s'ils n'existent pas."""
    if baseline_path is None and training_path is None:
        raise ModelPackError("preciser la baseline et/ou le jeu d'entrainement local a enrichir")
    pack = read_pack(path)
    result: dict = {"pack": pack.summary()}
    if baseline_path is not None and pack.baseline is not None:
        target = Path(baseline_path)
        merged = Baseline.load(target).merge(pack.baseline) if target.exists() else pack.baseline
        merged.save(target)
        result["baseline"] = {"path": str(target), "vectors": len(merged.vectors)}
    if training_path is not None and pack.training:
        target = Path(training_path)
        doc: dict = {"schema": TRAINING_SCHEMA, "samples": []}
        if target.exists():
            try:
                doc = json.loads(target.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.exception(f"échec dans import_pack: {exc}")
                raise ModelPackError(f"jeu local illisible ({target}) : {exc}") from exc
            if not isinstance(doc, dict) or doc.get("schema") != TRAINING_SCHEMA:
                raise ModelPackError(f"{target} n'est pas un jeu {TRAINING_SCHEMA}")
        doc.setdefault("samples", []).extend({"features": v, "label": lb} for v, lb in pack.training)
        buf = io.StringIO()
        json.dump(doc, buf, ensure_ascii=False, indent=1)
        target.write_text(buf.getvalue(), encoding="utf-8")
        result["training"] = {"path": str(target), "samples": len(doc["samples"])}
    return result
