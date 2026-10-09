"""netcross_core.packet_limits -- ``--max-packets`` et ``--sample`` (issue
#283), partages par la CLI et la GUI (issue #672).

Appliques a la liste de paquets deja chargee, AVANT doublons et correlation,
pour que tout l'aval voie la meme population. La troncature n'est jamais
silencieuse : la note renvoyee va dans ``Report.truncation_note``.
"""

from __future__ import annotations

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)


def apply_packet_limits(all_packets, max_packets, sample_n):
    """Renvoie ``(paquets_retenus, note_ou_None)``. ``sample_n`` (garder 1
    paquet sur N) passe AVANT ``max_packets`` : l'ordre inverse laisserait
    l'echantillonnage sans effet visible si le plafond est plus restrictif.
    ``note`` vaut None si aucune limite n'a reellement tronque (fichier plus
    petit que la limite) : ``Report.truncated`` ne doit jamais devenir True
    sans raison."""
    logger.debug(
        "apply_packet_limits: all_packets={} max_packets={} sample_n={}",
        summarize(all_packets, "all_packets"),
        summarize(max_packets, "max_packets"),
        summarize(sample_n, "sample_n"),
    )
    total = len(all_packets)
    kept = all_packets
    notes = []
    if sample_n and sample_n > 1:
        kept = kept[::sample_n]
        notes.append(f"echantillonnage 1 paquet sur {sample_n} ({len(kept)} retenus sur {total})")
    if max_packets is not None and len(kept) > max_packets:
        before = len(kept)
        kept = kept[:max_packets]
        notes.append(f"analyse limitee aux {max_packets:,} premiers paquets sur {before:,}".replace(",", " "))
    if not notes:
        return kept, None
    return kept, "analyse tronquee -- " + " ; ".join(notes) + " -- les constats ne couvrent pas la capture entiere."
