"""
netcross_core.support.ticket -- remontee de tickets anonymisee (issue #269).

Construit un ticket de support autoportant a partir d'un incident
(exception, erreur de traitement) ou d'un simple etat de fonctionnement,
en passant TOUT le texte libre par netcross_core.support.scrubber avant
de l'ecrire. Trois principes non negociables :

1. **Consentement explicite, verifie au moment de l'ecriture.**
   ``build_ticket()`` ne fait que construire un objet en memoire ;
   ``write_ticket()`` refuse d'ecrire quoi que ce soit sans un
   ``Consent`` accorde (``ConsentRequiredError`` sinon). Il n'existe aucun
   chemin de code qui produise un fichier de ticket sans que
   l'utilisateur ait dit oui -- l'autorisation demandee par l'issue #269
   n'est pas un message d'avertissement, c'est une precondition.

2. **Anonymisation avant ecriture, jamais apres.** Le texte reel ne
   transite dans aucun champ du ticket : il est scrubbe au moment de la
   construction. Un ticket est donc sur a transmettre des l'instant ou il
   existe.

3. **Tout est trace, y compris "tout va bien".** Le ticket porte toujours
   une section ``anonymisation`` et une section ``auto_verification``,
   meme quand rien n'a ete redige et qu'aucune anomalie n'a ete trouvee
   (voir docs/quality/traceability-rule.md). Un champ vide est un
   resultat affirme, pas une information manquante.

Le ticket est un dict JSON-serialisable a schema versionne
(``SCHEMA_VERSION``), pensé pour etre relu par un outil autant que par un
humain -- c'est le format que la campagne de 100 traces utilisera pour
remonter les incidents (docs/quality/anonymization-plan.md).
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from netcross_core.logging_config import get_logger
from netcross_core.support.scrubber import ScrubReport, TextScrubber

logger = get_logger(__name__)

SCHEMA_VERSION = "1.0"

# Natures de ticket. ``diagnostic`` couvre le cas "rien n'a casse" : on
# remonte quand meme, c'est tout l'objet de la regle de tracabilite.
KINDS = ("crash", "erreur_traitement", "diagnostic")

# Portees de consentement. L'utilisateur autorise des CATEGORIES de
# contenu, pas un ticket en bloc : ce qu'il n'a pas autorise est absent du
# fichier, et son absence est tracee dans ``auto_verification``.
SCOPES = ("environnement", "journal", "trace_appels", "marqueurs")


class ConsentRequiredError(RuntimeError):
    """Levee par ``write_ticket`` sans consentement accorde."""


@dataclass(frozen=True)
class Consent:
    """Autorisation de l'utilisateur pour la remontee d'un ticket.

    ``granted=False`` est un etat parfaitement valide et attendu : il
    produit un refus propre et trace, pas une erreur silencieuse.
    ``scopes`` restreint le contenu ; par defaut, toutes les portees.
    """

    granted: bool
    scopes: tuple[str, ...] = SCOPES
    granted_at: str | None = None
    source: str = "cli"  # "cli", "gui", "api" -- d'ou vient l'accord

    def allows(self, scope: str) -> bool:
        logger.debug("allows: retour booleen")
        return self.granted and scope in self.scopes

    def to_dict(self) -> dict:
        logger.debug("to_dict: retour dict")
        return {
            "accorde": self.granted,
            "portees": list(self.scopes),
            "accorde_le": self.granted_at,
            "origine": self.source,
        }


@dataclass
class SupportTicket:
    """Ticket anonymise, pret a transmettre.

    Les champs textuels sont DEJA scrubbes (voir docstring de module) :
    aucune etape d'anonymisation ne reste a faire par l'appelant.
    """

    ticket_id: str
    kind: str
    created_at: str
    consent: Consent
    markers: dict[str, str | None] = field(default_factory=dict)
    environment: dict[str, str | None] = field(default_factory=dict)
    crash: dict | None = None
    errors: list[str] = field(default_factory=list)
    log_lines: list[str] = field(default_factory=list)
    anonymization: dict = field(default_factory=dict)
    self_check: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        logger.debug("to_dict: retour dict")
        return {
            "schema_version": SCHEMA_VERSION,
            "ticket_id": self.ticket_id,
            "nature": self.kind,
            "cree_le": self.created_at,
            "consentement": self.consent.to_dict(),
            "marqueurs": self.markers,
            "environnement": self.environment,
            "incident": self.crash,
            "erreurs_traitement": self.errors,
            "journal": self.log_lines,
            "anonymisation": self.anonymization,
            "auto_verification": self.self_check,
        }

    def to_json(self, *, indent: int = 2) -> str:
        logger.debug("to_json: retour dumps(...)")
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)


def collect_environment() -> dict[str, str | None]:
    """Contexte technique non identifiant : OS, Python, presence de tshark.

    Volontairement PAUVRE : ni nom de machine, ni nom d'utilisateur, ni
    variables d'environnement, ni chemin de travail. Ces elements aident
    peu au diagnostic et identifient beaucoup. Le nom du systeme
    (``platform.system()``) et sa version majeure suffisent a reproduire
    la majorite des incidents.
    """
    logger.debug("collect_environment()")
    tshark = shutil.which("tshark")
    logger.debug("collect_environment: retour dict")
    return {
        "systeme": platform.system(),
        "version_systeme": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "tshark_disponible": "oui" if tshark else "non",
        "netcross_log_level": os.environ.get("NETCROSS_LOG_LEVEL", "INFO"),
    }


def format_exception(exc: BaseException) -> tuple[str, str, list[str]]:
    """``(type, message, lignes_de_traceback)`` d'une exception.

    Le traceback est renvoye ligne a ligne (et non en bloc) pour que le
    scrubber puisse le traiter ligne par ligne -- les chemins de fichiers
    y sont nombreux et c'est precisement ce qu'il faut rediger.
    """
    lines = traceback.format_exception(type(exc), exc, exc.__traceback__)
    flat = [ln.rstrip("\n") for chunk in lines for ln in chunk.splitlines()]
    logger.debug("format_exception: retour tuple")
    return type(exc).__name__, str(exc), flat


def build_ticket(
    *,
    consent: Consent,
    kind: str = "diagnostic",
    exception: BaseException | None = None,
    errors=None,
    log_lines=None,
    markers=None,
    scrubber: TextScrubber | None = None,
) -> SupportTicket:
    """Construit un ticket anonymise en memoire (n'ecrit rien).

    ``kind`` par defaut ``"diagnostic"`` : un ticket sans exception ni
    erreur est legitime et utile -- il atteste que l'execution s'est bien
    passee, avec les marqueurs permettant de la relier a une trace de la
    campagne.

    Les portees non autorisees par ``consent`` sont OMISES du ticket, et
    chaque omission est inscrite dans ``auto_verification`` : le
    destinataire voit qu'un contenu manque parce qu'il n'a pas ete
    autorise, et non parce que l'outil a echoue a le collecter.
    """
    if kind not in KINDS:
        raise ValueError(f"nature de ticket inconnue : {kind!r} (attendu : {', '.join(KINDS)})")

    scrubber = scrubber or TextScrubber()
    checks: list[dict] = []
    reports: list[ScrubReport] = []

    def _note(nom: str, statut: str, detail: str) -> None:
        checks.append({"controle": nom, "statut": statut, "detail": detail})

    # -- marqueurs de correlation (trace_id / run_id / capture_id) --------
    markers_out: dict[str, str | None] = {}
    if consent.allows("marqueurs"):
        raw = dict(markers or {})
        raw.setdefault("run_id", uuid.uuid4().hex[:12])
        for key, value in raw.items():
            scrubbed, rep = scrubber.scrub(str(value) if value is not None else None)
            reports.append(rep)
            markers_out[key] = scrubbed
        _note(
            "marqueurs",
            "ok",
            f"{len(markers_out)} marqueur(s) joint(s) : {', '.join(sorted(markers_out))}"
            if markers_out
            else "aucun marqueur fourni par l'appelant",
        )
    else:
        _note("marqueurs", "omis", "portee 'marqueurs' non autorisee par l'utilisateur")

    # -- environnement ----------------------------------------------------
    env_out: dict[str, str | None] = {}
    if consent.allows("environnement"):
        env_out = collect_environment()
        _note("environnement", "ok", "contexte technique collecte (sans nom de machine ni d'utilisateur)")
    else:
        _note("environnement", "omis", "portee 'environnement' non autorisee par l'utilisateur")

    # -- incident ---------------------------------------------------------
    crash_out: dict | None = None
    if exception is not None:
        exc_type, exc_msg, tb_lines = format_exception(exception)
        msg_scrubbed, rep = scrubber.scrub(exc_msg)
        reports.append(rep)
        crash_out = {"type": exc_type, "message": msg_scrubbed}
        if consent.allows("trace_appels"):
            tb_scrubbed, rep_tb = scrubber.scrub_lines(tb_lines)
            reports.append(rep_tb)
            crash_out["trace_appels"] = tb_scrubbed
            _note("trace_appels", "ok", f"{len(tb_scrubbed)} ligne(s) de trace d'appels jointes")
        else:
            _note("trace_appels", "omis", "portee 'trace_appels' non autorisee par l'utilisateur")
        _note("incident", "ok", f"exception {exc_type} enregistree")
    else:
        _note("incident", "ok", "aucune exception : execution sans incident signale")

    # -- erreurs de traitement -------------------------------------------
    errors_out, rep_err = scrubber.scrub_lines(list(errors or []))
    reports.append(rep_err)
    _note(
        "erreurs_traitement",
        "ok",
        f"{len(errors_out)} erreur(s) de traitement remontee(s)"
        if errors_out
        else "aucune erreur de traitement signalee",
    )

    # -- journal ----------------------------------------------------------
    logs_out: list[str] = []
    if consent.allows("journal"):
        logs_out, rep_log = scrubber.scrub_lines(list(log_lines or []))
        reports.append(rep_log)
        _note(
            "journal",
            "ok",
            f"{len(logs_out)} ligne(s) de journal jointes" if logs_out else "aucune ligne de journal fournie",
        )
    else:
        _note("journal", "omis", "portee 'journal' non autorisee par l'utilisateur")

    # -- synthese d'anonymisation (toujours presente) ---------------------
    merged = ScrubReport()
    for rep in reports:
        for cat, n in rep.par_categorie.items():
            merged.par_categorie[cat] = merged.par_categorie.get(cat, 0) + n
    merged.total = sum(merged.par_categorie.values())
    merged.valeurs_distinctes = len(scrubber.mapping_csv_rows())

    anonymization = merged.to_dict()
    anonymization["mapping_joint"] = False
    anonymization["note_mapping"] = (
        "la correspondance valeur reelle <-> pseudonyme n'est jamais incluse "
        "dans le ticket ; elle reste chez l'operateur (voir --support-map)"
    )
    _note(
        "anonymisation",
        "ok",
        f"{merged.total} occurrence(s) redigee(s) sur {merged.valeurs_distinctes} valeur(s) distincte(s)"
        if merged.total
        else "passe d'anonymisation effectuee : aucune donnee sensible detectee",
    )

    ticket = SupportTicket(
        ticket_id=uuid.uuid4().hex,
        kind=kind,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        consent=consent,
        markers=markers_out,
        environment=env_out,
        crash=crash_out,
        errors=errors_out,
        log_lines=logs_out,
        anonymization=anonymization,
        self_check=checks,
    )
    logger.info(
        "ticket de support construit : id={} nature={} redactions={}",
        ticket.ticket_id,
        ticket.kind,
        merged.total,
    )
    return ticket


def write_ticket(ticket: SupportTicket, path: str) -> str:
    """Ecrit le ticket en JSON. Refuse sans consentement accorde.

    Le controle porte sur le consentement PORTE PAR LE TICKET, pas sur un
    parametre separe : il est donc impossible de construire un ticket avec
    un refus puis de l'ecrire quand meme.
    """
    if not ticket.consent.granted:
        logger.warning("ecriture de ticket refusee : consentement non accorde (id={})", ticket.ticket_id)
        raise ConsentRequiredError(
            "ecriture du ticket refusee : l'utilisateur n'a pas autorise la remontee (voir --support-consent)"
        )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(ticket.to_json())
        fh.write("\n")
    logger.info("ticket de support ecrit : {}", path)
    return path


def write_support_map_csv(scrubber: TextScrubber, path: str) -> str:
    """Ecrit la correspondance reelle <-> pseudonyme (usage OPERATEUR).

    Pendant de ``netcross_core.redact.write_redaction_map_csv``. Ce
    fichier NE DOIT JAMAIS accompagner le ticket : il permettrait de
    reconstituer les valeurs reelles. Il sert a l'operateur pour relire un
    ticket anonymise a la lumiere de son propre reseau.
    """
    rows = scrubber.mapping_csv_rows()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("valeur_reelle,pseudonyme,categorie\n")
        for real, pseudo, kind in rows:
            fh.write(f"{_csv(real)},{_csv(pseudo)},{kind}\n")
    logger.info("correspondance de scrubbing ecrite : {} ({} entrees)", path, len(rows))
    return path


def _csv(value: str) -> str:
    if any(c in value for c in ',"\n'):
        logger.debug("_csv: retour valeur")
        return '"' + value.replace('"', '""') + '"'
    logger.debug("_csv: retour value")
    return value


def install_crash_handler(
    path: str,
    consent: Consent,
    *,
    markers=None,
) -> None:
    """Installe un ``sys.excepthook`` qui ecrit un ticket sur crash.

    Sans consentement accorde, la fonction n'installe RIEN et le dit dans
    le journal -- plutot que d'installer un hook qui echouerait au pire
    moment (pendant un crash).
    """
    if not consent.granted:
        logger.info("gestionnaire de crash non installe : consentement non accorde")
        return

    previous = sys.excepthook

    def _hook(exc_type, exc_value, exc_tb):  # pragma: no cover - teste via _hook direct
        try:
            ticket = build_ticket(
                consent=consent,
                kind="crash",
                exception=exc_value,
                markers=markers,
            )
            write_ticket(ticket, path)
            print(f"\nTicket de support anonymise ecrit : {path}", file=sys.stderr)
        except Exception as inner:  # noqa: BLE001 - jamais masquer le crash d'origine
            logger.exception("erreur: inner")
            print(f"\nEchec d'ecriture du ticket de support : {inner}", file=sys.stderr)
        previous(exc_type, exc_value, exc_tb)

    sys.excepthook = _hook
    logger.info("gestionnaire de crash installe : ticket vers {}", path)
