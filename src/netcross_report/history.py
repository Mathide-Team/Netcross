"""
netcross_report.history -- persiste un resume de chaque run (analyse ou
diff) dans une base SQLite locale, pour observer une tendance dans le
temps (score de sante, nombre de constats par severite) sur des runs
successifs -- ce que --json-report/--pdf-report ne permettent pas :
chacun d'eux ne connait que l'instant present, rien n'est conserve entre
deux executions de la CLI.

Correspond a la piste "Historique inter-sessions (SQLite)" de
FEATURES.md section 5.2. Attention au mot "session", deux sens sans
rapport dans ce projet : ici, une "session" est une EXECUTION de la CLI
(cross_capture_analyzer_cli.py ou cross_capture_diff_cli.py), pas une
session de developpement Claude (vocabulaire de claude.md, "Session 29"
etc.) -- voir claude.md Session 29 pour la discussion complete de ce
choix de perimetre.

sqlite3 est dans la bibliotheque standard (comme json/datetime pour
json_report.py) : toujours disponible, aucune dependance supplementaire
a installer -- meme esprit que generate_json_report/generate_json_diff,
donc importe sans garde try/except dans netcross_report/__init__.py
(contrairement a pdf.py).

Une seule table "runs" : un resume compact par execution (score de
sante, nombre de constats par severite, points impliques, etiquette
libre optionnelle) -- PAS le detail des constats eux-memes (deja
couvert par --json-report/--pdf-report/--detail-csv, qui restent la
source de verite pour une execution donnee). L'historique repond a une
question differente : "est-ce que ca s'ameliore ou ca se degrade au fil
du temps ?", pas "que s'est-il passe exactement cette fois-ci ?".

Coherence du score de sante avec les autres sorties -- meme asymetrie
qu'entre generate_json_report et generate_json_diff (voir json_report.py
et claude.md Session 8) : record_run() integre tls_findings/quic_findings
au meme triage que le JSON/PDF d'un run d'analyse simple. record_diff_run()
n'accepte volontairement PAS de tls_findings_baseline/current ni de
quic_findings_baseline/current : sur un diff, TLS/QUIC ne connaissent
qu'un etat a un instant donne (pas de vraie diff semantique entre
baseline et courant), donc ne participent deja pas a rank_segments/
health_score sur le PDF/JSON de diff -- pas de raison de les integrer
ici alors qu'ils ne le sont nulle part ailleurs pour un diff.

list_history() accepte un filtre run_type ("analyse"/"diff") en plus du
filtre label, ajoute en Session 30 pour cross_history_cli.py -- le
script d'interrogation seule de l'historique, sans relancer d'analyse
(cf. la piste laissee ouverte en section 5.2 par la Session 29). Les
deux CLI d'analyse eux-memes (--history-show) n'exposent pas ce filtre :
ils savent deja de quel type est le run qu'ils viennent d'enregistrer,
le besoin ne se pose que pour une base consultee independamment.
"""

from __future__ import annotations

import datetime
import json
import os
import sqlite3
from collections import Counter
from dataclasses import dataclass

from netcross_core.logging_config import get_logger, summarize
from netcross_report.synthesis import build_findings
from netcross_report.triage import HEALTH_LABELS, health_label, health_score, rank_segments

logger = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at TEXT NOT NULL,
    run_type TEXT NOT NULL,
    label TEXT,
    points TEXT NOT NULL,
    health_score INTEGER NOT NULL,
    health_label TEXT NOT NULL,
    total_findings INTEGER NOT NULL,
    finding_counts TEXT NOT NULL,
    meta TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_label ON runs(label);
"""


@dataclass(frozen=True)
class HistoryEntry:
    id: int
    recorded_at: str
    run_type: str  # "analyse" ou "diff"
    label: str | None
    # liste (run_type="analyse") ou {"baseline": [...], "current": [...]}
    # (run_type="diff") -- voir record_run/record_diff_run.
    points: list[str] | dict[str, list[str]]
    health_score: int
    health_label: str
    total_findings: int
    finding_counts: dict[str, int]
    meta: dict


def _now_iso() -> str:
    # Meme convention que netcross_report.json_report._now_iso -- copiee
    # plutot que partagee (module autonome, une seule ligne, pas de
    # nouvelle dependance croisee pour ca).
    logger.debug("_now_iso: retour isoformat(...)")
    return datetime.datetime.now().astimezone().isoformat()


class HistoryDatabaseError(ValueError):
    """Le chemin --history-db / --db existe mais n'est pas une base netcross.

    Cas reels : chemin confondu avec un PCAP, base tronquee par un disque
    plein, fichier ecrit par un autre outil. sqlite3 leve alors une
    DatabaseError technique (« file is not a database ») qui remontait
    jusqu'a l'utilisateur sous forme de trace Python -- sans nommer le
    chemin fautif ni dire quoi faire (issue #287).

    Consequence la plus couteuse cote analyzer/diff : l'historique est
    ecrit a la FIN du run, donc le plantage survenait apres plusieurs
    minutes de lecture de capture, et tout le travail etait perdu. Une
    erreur de domaine permet aux trois CLI de rendre un message utilisable.
    """


def _message_base_invalide(db_path, cause) -> str:
    """Message unique pour les trois CLI : nomme le chemin, la cause lue et la
    seule action utile. Un message sans le chemin est inexploitable quand
    plusieurs bases sont suivies en parallele."""
    logger.debug("_message_base_invalide: retour valeur")
    return (
        f"Base d'historique illisible : {db_path} ({cause}). "
        "Ce fichier existe mais n'est pas une base SQLite netcross -- verifier "
        "le chemin, ou le supprimer pour qu'une nouvelle base soit creee."
    )


def _executer_schema(conn, db_path) -> None:
    """Applique le schema en traduisant l'echec sqlite3 en erreur de domaine.

    Le schema est applique a chaque ouverture (tolerant si le fichier est
    vide/neuf) : c'est donc ici que se detecte un fichier qui n'est pas du
    SQLite, aussi bien en lecture qu'en ecriture.
    """
    try:
        conn.executescript(_SCHEMA)
    except sqlite3.DatabaseError as exc:
        logger.exception(f"échec dans _executer_schema: {exc}")
        raise HistoryDatabaseError(_message_base_invalide(db_path, exc)) from exc


def _connect(db_path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    _executer_schema(conn, db_path)
    logger.debug("_connect: retour conn")
    return conn


def _finding_counts(findings) -> dict[str, int]:
    logger.debug("_finding_counts: retour dict(...)")
    return dict(Counter(f.severity for f in findings))


def _insert(conn, *, run_type, label, points, score, count_by_sev, total, meta) -> int:
    logger.debug(
        "_insert: conn={} run_type={} label={} points={} score={} count_by_sev={} total={} meta={}",
        summarize(conn, "conn"),
        summarize(run_type, "run_type"),
        summarize(label, "label"),
        summarize(points, "points"),
        summarize(score, "score"),
        summarize(count_by_sev, "count_by_sev"),
        summarize(total, "total"),
        summarize(meta, "meta"),
    )
    cur = conn.execute(
        "INSERT INTO runs (recorded_at, run_type, label, points, health_score, "
        "health_label, total_findings, finding_counts, meta) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            _now_iso(),
            run_type,
            label,
            json.dumps(points, ensure_ascii=False),
            score,
            health_label(score),
            total,
            json.dumps(count_by_sev, ensure_ascii=False),
            json.dumps(dict(meta) if meta else {}, ensure_ascii=False),
        ),
    )
    conn.commit()
    logger.debug("_insert: retour attribut")
    return cur.lastrowid


def record_run(r, db_path, findings=None, tls_findings=None, quic_findings=None, meta=None, label=None) -> int:
    """
    Enregistre un resume du run d'analyse (cross_capture_analyzer_cli.py)
    dans la base SQLite `db_path` (fichier cree si absent, table creee si
    absente). Renvoie l'id de la ligne inseree.

    r : objet Report (netcross_core.analyse). findings : liste de Finding
    deja calculee (synthesis.build_findings(r)) si l'appelant l'a deja
    fait, sinon calculee ici -- meme convention que generate_json_report.
    tls_findings/quic_findings : integres au meme triage que le JSON/PDF
    d'un run d'analyse (voir docstring de module pour le detail et la
    difference assumee avec record_diff_run). meta : memes metadonnees
    libres que --json-report/--pdf-report (ex: {"Anonymisation": ...}).
    label : etiquette libre optionnelle (nom de site/scenario) pour
    distinguer plusieurs historiques qui partagent le meme fichier .db.
    """
    logger.debug(
        "record_run: r={} db_path={} findings={} tls_findings={} quic_findings={} meta={} label={}",
        summarize(r, "r"),
        summarize(db_path, "db_path"),
        summarize(findings, "findings"),
        summarize(tls_findings, "tls_findings"),
        summarize(quic_findings, "quic_findings"),
        summarize(meta, "meta"),
        summarize(label, "label"),
    )
    if findings is None:
        findings = build_findings(r)
    all_findings = list(findings) + list(tls_findings or []) + list(quic_findings or [])
    ranked = rank_segments(all_findings)
    score = health_score(ranked)
    conn = _connect(db_path)
    try:
        logger.debug("record_run: retour _insert(...)")
        return _insert(
            conn,
            run_type="analyse",
            label=label,
            points=list(r.points),
            score=score,
            count_by_sev=_finding_counts(all_findings),
            total=len(all_findings),
            meta=meta,
        )
    finally:
        conn.close()


def record_diff_run(findings, baseline, current, db_path, meta=None, label=None) -> int:
    """
    Pendant de record_run() pour cross_capture_diff_cli.py.

    findings : liste de DiffFinding deja calculee par diff_reports() --
    toujours fournie par l'appelant (contrairement a build_findings() sur
    l'analyzer, diff_reports() n'est jamais lazy sur ce CLI, voir
    cross_capture_diff_cli.main()). baseline/current : les deux Report
    compares, uniquement pour lister leurs points respectifs.

    Volontairement PAS de parametres tls_findings_baseline/current ni
    quic_findings_baseline/current : voir docstring de module pour la
    raison (meme choix assume que generate_json_diff/generate_diff_pdf).
    """
    logger.debug(
        "record_diff_run: findings={} baseline={} current={} db_path={} meta={} label={}",
        summarize(findings, "findings"),
        summarize(baseline, "baseline"),
        summarize(current, "current"),
        summarize(db_path, "db_path"),
        summarize(meta, "meta"),
        summarize(label, "label"),
    )
    ranked = rank_segments(findings)
    score = health_score(ranked)
    conn = _connect(db_path)
    try:
        logger.debug("record_diff_run: retour _insert(...)")
        return _insert(
            conn,
            run_type="diff",
            label=label,
            points={"baseline": list(baseline.points), "current": list(current.points)},
            score=score,
            count_by_sev=_finding_counts(findings),
            total=len(findings),
            meta=meta,
        )
    finally:
        conn.close()


def list_history(db_path, limit=None, label=None, run_type=None) -> list[HistoryEntry]:
    """
    Renvoie les runs enregistres dans `db_path`, du plus recent au plus
    ancien (ORDER BY id DESC -- id auto-incremente = ordre d'insertion,
    plus fiable que recorded_at en cas d'horloge systeme qui reculerait
    entre deux runs).

    label : si fourni, ne renvoie que les runs portant cette etiquette
    exacte (utile sur un fichier .db partage entre plusieurs sites/
    scenarios, voir --history-label sur les deux CLI). run_type : si
    fourni ("analyse" ou "diff"), ne renvoie que les runs de ce type --
    utile sur un fichier .db qui melange les deux (voir
    cross_history_cli.py, seul endroit qui expose ce filtre : les deux
    CLI d'analyse n'ont pas besoin de filtrer leur propre historique par
    type, ils savent deja de quel type est le run qu'ils viennent
    d'enregistrer). Les deux filtres se combinent (ET logique) si fournis
    ensemble. limit : nombre maximum de lignes renvoyees (defaut :
    toutes).

    Si `db_path` n'existe pas encore (aucun run enregistre a ce jour sur
    ce fichier), renvoie une liste vide plutot que de lever une exception
    -- une base d'historique qui n'a jamais recu de run est un etat
    normal (premiere execution avec --history-db sur ce fichier), pas une
    erreur. Verifie explicitement avant de se connecter : sqlite3 cree le
    fichier des la connexion, meme pour une lecture seule -- sans cette
    verification, un simple --history-show sur un chemin qui n'existe pas
    encore creerait une base vide comme effet de bord surprenant.
    """
    logger.debug(
        "list_history: db_path={} limit={} label={} run_type={}",
        summarize(db_path, "db_path"),
        summarize(limit, "limit"),
        summarize(label, "label"),
        summarize(run_type, "run_type"),
    )
    if not os.path.exists(db_path):
        logger.debug("list_history: retour liste")
        return []
    conn = sqlite3.connect(db_path)
    try:
        _executer_schema(conn, db_path)  # tolerant si le fichier existe mais est vide/neuf
        query = (
            "SELECT id, recorded_at, run_type, label, points, health_score, "
            "health_label, total_findings, finding_counts, meta FROM runs"
        )
        conditions = []
        params: list = []
        if label is not None:
            conditions.append("label = ?")
            params.append(label)
        if run_type is not None:
            conditions.append("run_type = ?")
            params.append(run_type)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY id DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    logger.debug("list_history: retour liste")
    return [
        HistoryEntry(
            id=row[0],
            recorded_at=row[1],
            run_type=row[2],
            label=row[3],
            points=json.loads(row[4]),
            health_score=row[5],
            health_label=row[6],
            total_findings=row[7],
            finding_counts=json.loads(row[8]),
            meta=json.loads(row[9]),
        )
        for row in rows
    ]


def print_history(entries: list[HistoryEntry]) -> None:
    """Rendu texte console (meme esprit que triage.print_triage) -- affiche
    exactement les entrees recues, dans l'ordre recu (deja le plus recent
    d'abord si issues de list_history) ; le nombre affiche se regle en
    amont via l'argument `limit` de list_history, pas ici."""
    logger.debug("print_history: entries={}", summarize(entries, "entries"))
    print("=" * 70)
    print("HISTORIQUE DES RUNS ENREGISTRES")
    print("=" * 70)

    if not entries:
        print("\nAucun run enregistre pour l'instant dans cette base.")
        logger.debug("print_history: retour (None implicite)")
        return

    for e in entries:
        label_tag = f" [{e.label}]" if e.label else ""
        if e.run_type == "diff":
            points_map = e.points
            assert isinstance(points_map, dict)
            points_txt = f"baseline={','.join(points_map['baseline'])} courant={','.join(points_map['current'])}"
        else:
            points_txt = ",".join(e.points)
        counts_txt = ", ".join(f"{sev}={n}" for sev, n in sorted(e.finding_counts.items())) or "aucun"
        print(
            f"\n#{e.id}  {e.recorded_at}  {e.run_type:8s}{label_tag}\n"
            f"   points : {points_txt}\n"
            f"   score de sante : {e.health_score}/100 ({HEALTH_LABELS[e.health_label]})  --  "
            f"{e.total_findings} constat(s) ({counts_txt})"
        )
