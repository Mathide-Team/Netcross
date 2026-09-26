"""
netcross_gtk4.row_labels -- libelles et cles de tri des lignes affichees
par la GUI (issue #285, premier lot d'extraction de `app.py`).

Ces fonctions etaient definies dans `netcross_gtk4/app.py`. Elles sont
pures : une ligne de donnees en entree, une chaine ou une cle en sortie,
aucun widget, aucun etat. Elles etaient pourtant a **0 % de couverture**,
comme tout le reste de `app.py` -- non pas parce qu'elles etaient
difficiles a tester, mais parce qu'elles vivaient dans un module qui
`import gi` en tete : impossible a importer en CI, ou PyGObject est
absent. Le probleme n'etait pas un manque de tests, c'etait un fichier
qui les empechait.

Les deplacer ici les rend testables sans rien changer a leur
comportement. Meme demarche que `dashboard_context.py` (logique du
tableau de bord sortie de la vue, couverte a 88,6 %) : c'est la voie qui
a deja fonctionne dans ce paquet.

Deux familles :

- `*_row_label(row)` : le texte montre a l'utilisateur. C'est du rendu,
  donc l'endroit exact ou se cachent les defauts qu'il voit -- une valeur
  manquante affichee comme `None`, une unite oubliee, un separateur
  colle.
- `*_row_key(row)` : la valeur de tri/selection associee a la ligne.

Convention d'absence : une valeur absente est remplacee par `?`, jamais
laissee s'afficher en `None` et jamais escamotee. Un `?` dit « on ne sait
pas » ; un champ disparu laisse croire qu'il n'y avait rien a dire.
"""

from __future__ import annotations

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


def timeline_row_label(row) -> str:
    logger.debug("timeline_row_label: {} pertes={}", row["label"], row["loss_events"])
    return f"{row['label']} — {row['loss_events']} perte(s)"


def timeline_row_key(row):
    logger.debug("timeline_row_key: {}", row["bucket"])
    return row["bucket"]


def segment_row_label(row) -> str:
    # La latence est optionnelle : absente, on ne montre pas " latence None
    # ms" mais rien du tout -- le reste de la ligne (pertes, retransmissions)
    # reste informatif sans elle.
    if row["latency_ms"] is None:
        logger.debug("segment_row_label: {} sans latence, champ omis", row["pair"])
    lat = f", latence {row['latency_ms']} ms" if row["latency_ms"] is not None else ""
    logger.debug("segment_row_label: {} pertes={} retrans={}", row["pair"], row["loss"], row["retrans"])
    return f"{row['pair']} — {row['loss']} perte(s), {row['retrans']} retrans{lat}"


def segment_row_key(row):
    logger.debug("segment_row_key: {}", row["pair_tuple"][0])
    return row["pair_tuple"][0]


def flow_row_label(row) -> str:
    logger.debug("flow_row_label: {} paquets={}", row["label"], row["packets"])
    return f"{row['label']} — {row['packets']} paquets, {row['bytes']} octets"


def flow_row_key(row):
    logger.debug("flow_row_key: {}", row["flow_key"])
    return row["flow_key"]


def endpoint_row_label(row) -> str:
    peers = ", ".join(row["peers"]) or "?"
    if not row["peers"]:
        logger.debug("endpoint_row_label: {} sans pair connu, affiché ?", row["endpoint"])
    logger.debug("endpoint_row_label: {} flux={}", row["endpoint"], row["flows"])
    return f"{row['endpoint']} <-> {peers} — {row['flows']} flux, {row['packets']} paquets"


def endpoint_row_key(row):
    logger.debug("endpoint_row_key: {}", row["endpoint"])
    return row["endpoint"]


def proto_row_label(row) -> str:
    logger.debug("proto_row_label: {} flux={}", row["protocol"], row["flows"])
    return f"{row['protocol']} — {row['flows']} flux, {row['packets']} paquets"


def proto_row_key(row):
    logger.debug("proto_row_key: {}", row["protocol"])
    return row["protocol"]


def event_row_label(row) -> str:
    cat = row["category"] or "?"
    sev = row["severity"] or "?"
    proto = f" [{row['protocol']}]" if row["protocol"] else ""
    msg = row["message"] or ""
    if not row["category"] or not row["severity"]:
        logger.debug(
            "event_row_label: #{} catégorie={} sévérité={}, valeur absente affichée ?",
            row["id"],
            row["category"],
            row["severity"],
        )
    logger.debug("event_row_label: #{} {} ({})", row["id"], cat, sev)
    return f"#{row['id']} {cat} ({sev}){proto} — {msg}"


def event_row_key(row):
    logger.debug("event_row_key: {}", row["id"])
    return row["id"]
