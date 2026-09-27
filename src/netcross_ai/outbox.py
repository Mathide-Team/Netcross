"""Boite d'envoi hors connexion des paquets de modeles (issue #271).

Les remontees vers le depot peuvent devoir attendre une connexion : un
paquet est d'abord **mis en file** dans un repertoire local
(``~/.netcross/outbox/modeles`` par defaut), puis soumis plus tard, quand le
poste est connecte, sous forme de ticket « modeles » :

1. ``queue_pack`` copie le ZIP dans la boite d'envoi (verification comprise) ;
2. ``pending`` liste ce qui attend ;
3. ``submission`` prepare la soumission : URL de creation d'issue pre-remplie
   (titre, etiquette ``modeles``, corps TICKET.md) et chemin de l'archive a
   joindre au ticket -- GitHub n'accepte les pieces jointes que depuis son
   interface web ;
4. ``mark_sent`` range le paquet dans ``envoyes/`` une fois le ticket cree.

Netcross n'envoie **rien** de lui-meme : aucun jeton n'est stocke, aucune
requete n'est emise hormis, sur demande explicite, un simple test de
connectivite TCP (``is_online``).
"""

from __future__ import annotations

import shutil
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

from netcross_ai.model_pack import ModelPack, ModelPackError, check_name, read_pack, ticket_body
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

DEFAULT_OUTBOX = Path.home() / ".netcross" / "outbox" / "modeles"
DEFAULT_REPO = "MathildeDec/Netcross"
TICKET_LABEL = "modeles"
SENT_DIR = "envoyes"
_MAX_URL_BODY = 6000  # au-dela, GitHub tronque/refuse l'URL : corps a coller depuis TICKET.md


@dataclass
class Submission:
    name: str
    archive: Path
    url: str
    body: str
    body_in_url: bool


def queue_pack(pack_path: str | Path, outbox: str | Path = DEFAULT_OUTBOX) -> Path:
    """Verifie le paquet puis le copie dans la boite d'envoi (``NOM.zip``)."""
    pack = read_pack(pack_path)
    box = Path(outbox)
    box.mkdir(parents=True, exist_ok=True)
    target = box / f"{pack.name}.zip"
    if target.exists():
        logger.trace("queue_pack: refus, ModelPackError")
        raise ModelPackError(f"un paquet {pack.name} attend deja dans {box} (le renommer ou le soumettre d'abord)")
    shutil.copyfile(pack_path, target)
    return target


def pending(outbox: str | Path = DEFAULT_OUTBOX) -> list[ModelPack]:
    """Paquets en attente (illisibles ignores : ils sont signales par ``inspect``)."""
    box = Path(outbox)
    paths = sorted(box.glob("*.zip")) if box.is_dir() else []
    return [pack for pack in map(_try_read, paths) if pack is not None]


def _try_read(path: Path) -> ModelPack | None:
    try:
        return read_pack(path)
    except ModelPackError:
        logger.exception("erreur: ModelPackError")
        return None


def _archive(name: str, outbox: str | Path) -> Path:
    path = Path(outbox) / f"{check_name(name)}.zip"
    if not path.is_file():
        logger.trace("_archive: refus, ModelPackError")
        raise ModelPackError(f"aucun paquet {name} en attente dans {outbox}")
    return path


def submission(name: str, outbox: str | Path = DEFAULT_OUTBOX, repo: str = DEFAULT_REPO) -> Submission:
    """Prepare le ticket « modeles » d'un paquet en attente (aucun envoi)."""
    archive = _archive(name, outbox)
    pack = read_pack(archive)
    body = ticket_body(pack)
    body_in_url = len(body) <= _MAX_URL_BODY
    params = {"title": f"[modeles] {pack.name}", "labels": TICKET_LABEL}
    if body_in_url:
        params["body"] = body + "\n\n(archive a joindre ci-dessous)"
    url = f"https://github.com/{repo}/issues/new?{urlencode(params)}"
    return Submission(pack.name, archive, url, body, body_in_url)


def mark_sent(name: str, outbox: str | Path = DEFAULT_OUTBOX) -> Path:
    """Deplace le paquet dans ``envoyes/`` (le ticket a ete cree)."""
    archive = _archive(name, outbox)
    sent = Path(outbox) / SENT_DIR
    sent.mkdir(exist_ok=True)
    target = sent / archive.name
    if target.exists():
        target.unlink()
    return Path(shutil.move(str(archive), target))


def is_online(host: str = "github.com", port: int = 443, timeout: float = 3.0) -> bool:
    """Test de connectivite TCP (aucune donnee envoyee)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        logger.exception("erreur: OSError")
        return False
