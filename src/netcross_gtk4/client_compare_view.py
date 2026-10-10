"""netcross_gtk4.client_compare_view -- comparaison de postes dans la GUI
(issue #675).

Equivalent GUI de ``--client-group NOM=IP1[,IP2...]`` (repete),
``--client-reference`` et ``--client-diff-csv`` : meme moteur
(``netcross_core.client_diff.compare_clients``), memes validations.

Dans la GUI, les groupes tiennent dans un seul champ, separes par ``;`` :
``PosteA=10.0.0.5; PosteB=10.0.0.12,10.0.0.13``.

Module sans GTK (aucun import de gi) : testable sans interface graphique.
"""

from __future__ import annotations

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


class ClientGroupError(ValueError):
    """Saisie invalide des groupes de postes ou de la reference."""


def parse_client_groups(text: str) -> dict[str, set[str]]:
    """``NOM=IP1,IP2; NOM2=IP3`` -> ``{nom: {ip, ...}}``. Champ vide : {}.

    Meme format que ``--client-group`` (un groupe par segment) ; un nom
    repete cumule ses adresses, comme plusieurs ``--client-group`` du meme
    nom dans la CLI."""
    groups: dict[str, set[str]] = {}
    for raw in text.split(";"):
        spec = raw.strip()
        if not spec:
            continue
        if "=" not in spec:
            logger.debug("parse_client_groups: segment sans '=' {!r}", spec)
            raise ClientGroupError(f"groupe invalide : {spec!r} (attendu NOM=IP1[,IP2,...])")
        name, ips = spec.split("=", 1)
        name = name.strip()
        ip_set = {ip.strip() for ip in ips.split(",") if ip.strip()}
        if not name or not ip_set:
            logger.debug("parse_client_groups: nom ou IP manquant {!r}", spec)
            raise ClientGroupError(f"groupe invalide : {spec!r} (nom et IP requis)")
        groups.setdefault(name, set()).update(ip_set)
    logger.debug("parse_client_groups: {} groupe(s)", len(groups))
    return groups


def validate_client_settings(groups: dict[str, set[str]], reference: str | None, redact: bool) -> list[str]:
    """Erreurs bloquantes avant le lancement (liste vide = valide), avec
    les memes regles que la CLI."""
    errors: list[str] = []
    if not groups:
        if reference:
            errors.append("une reference de comparaison necessite au moins deux groupes de postes")
        return errors
    if len(groups) < 2:
        errors.append(
            f"la comparaison de postes necessite au moins 2 postes distincts (un seul fourni : {', '.join(groups)})"
        )
    if reference and reference not in groups:
        errors.append(f"reference {reference!r} absente des groupes (postes disponibles : {', '.join(sorted(groups))})")
    if redact:
        errors.append("comparaison de postes indisponible avec l'anonymisation (les groupes portent des IP reelles)")
    logger.debug("validate_client_settings: {} erreur(s)", len(errors))
    return errors


def comparison_summary(comparison) -> str:
    """Ligne de synthese pour la page Resultats."""
    if comparison is None:
        return "(renseignez au moins deux groupes de postes dans la configuration, puis relancez l'analyse)"
    others = [name for name in comparison.clients if name != comparison.reference]
    total = sum(len(f) for f in comparison.diffs.values())
    return (
        f"Reference : {comparison.reference} ; compare(s) : {', '.join(others)} ; "
        f"{total} ecart(s). Detail dans le rapport (section COMPARAISON CLIENT VS CLIENT)."
    )
