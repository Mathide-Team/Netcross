#!/usr/bin/env python3
"""
cross_capture_diff_cli.py -- compare deux jeux de captures (avant/apres
un correctif, site A / site B...) et remonte les regressions et
ameliorations entre les deux runs.

Fichier volontairement separe de cross_capture_analyzer_cli.py : il
reutilise le meme moteur netcross_core (parse_capture, correlate,
analyse) mais l'appelle deux fois -- une fois par scenario -- puis
delegue la comparaison a netcross_core.baseline_diff, qui ne depend
d'aucun autre module de netcross_core.

Les memes labels de point doivent etre reutilises des deux cotes (ex:
LAN, WAN, DC pour le baseline ET pour le run courant) : c'est ce qui
permet de dire "le point WAN allait bien avant, il degrade maintenant"
plutot que de comparer des points sans rapport.

Prerequis :
    - tshark installe (paquet systeme tshark / wireshark-cli, voir
      install.sh) -- utilise par pcap_parser pour decoder les captures,
      y compris pour --tls/--quic
    - pour --live-current : declencher un vrai sniffing reseau demande
      soit de lancer cette CLI en root, soit d'avoir donne au binaire
      dumpcap les capacites CAP_NET_RAW/CAP_NET_ADMIN (setcap), soit
      d'etre dans le groupe systeme dedie si la distribution en fournit
      un (meme prerequis que --live sur cross_capture_analyzer_cli.py)
    - pip install cryptography --break-system-packages (necessaire
      uniquement pour --quic)
    - pip install reportlab matplotlib networkx --break-system-packages
      (necessaire uniquement pour --pdf-report)
    - --json-report n'a besoin de rien de plus (json/datetime sont dans
      la bibliotheque standard)

Exemple d'utilisation :
    python3 cross_capture_diff_cli.py \
        --baseline LAN=avant_lan.pcapng --baseline WAN=avant_wan.pcapng \
        --current  LAN=apres_lan.pcapng --current  WAN=apres_wan.pcapng \
        --diff-csv regressions.csv

Exemple avec triage console + diagnostics TLS/QUIC (executes separement
sur le baseline et sur le run courant -- voir --tls/--quic ci-dessous
pour la limite assumee sur ces deux options) :
    python3 cross_capture_diff_cli.py \
        --baseline LAN=avant_lan.pcapng --baseline WAN=avant_wan.pcapng \
        --current  LAN=apres_lan.pcapng --current  WAN=apres_wan.pcapng \
        --triage --tls --quic --pdf-report diff.pdf

Exemple avec le run courant capture en direct (le baseline reste un
fichier deja enregistre -- voir --live-current ci-dessous pour la
raison de cette dissymetrie) :
    python3 cross_capture_diff_cli.py \
        --baseline LAN=avant_lan.pcapng --baseline WAN=avant_wan.pcapng \
        --live-current LAN:eth0 \
        --live-duration 60 \
        --triage --diff-csv regressions.csv

Exemple avec anonymisation (mapping partage entre baseline et courant --
voir netcross_core.redact pour le detail et les limites de --redact) :
    python3 cross_capture_diff_cli.py \
        --baseline LAN=avant_lan.pcapng --current LAN=apres_lan.pcapng \
        --redact --redact-map correspondance_privee.csv \
        --pdf-report diff_a_partager.pdf

Exemple avec historique inter-runs (meme base .db que
cross_capture_analyzer_cli.py, analyses et diffs confondus -- voir
netcross_report.history) :
    python3 cross_capture_diff_cli.py \
        --baseline LAN=avant_lan.pcapng --current LAN=apres_lan.pcapng \
        --history-db suivi_site_a.db --history-label Site-A --history-show 10
"""

import argparse
import os
import signal
import sys
import threading
import time

from netcross_core import (
    AddressRedactor,
    analyse,
    build_conversations,
    build_flows,
    build_wireshark_expert_events,
    correlate,
    evaluate_compliance,
    parse_capture,
    parse_captures_parallel,
    parse_live,
    write_redaction_map_csv,
)
from netcross_core.baseline_diff import diff_reports, print_diff_report, write_diff_csv
from netcross_core.logging_config import add_debug_argument, apply_debug_argument, get_logger
from pcap_parser.ek_source import TsharkError, TsharkNotFoundError
from pcap_parser.remote import CaptureSourceError, parse_source, split_live_target

logger = get_logger(__name__)


def _parse_capture_args(raw_list, flag_name):
    """NOM=chemin1[,chemin2,...] par entree -> liste plate de (label, chemin).

    Comme sur cross_capture_analyzer_cli.py (--capture, meme logique --
    dupliquee plutot que partagee, voir docstring de module) : plusieurs
    chemins separes par des virgules pour un meme NOM rejouent une
    capture segmentee (rotation tcpdump/tshark) comme un seul point
    continu, a lister dans l'ordre chronologique -- aucun tri automatique.
    S'applique aussi bien a --baseline qu'a --current (jamais a
    --live-current, qui n'a pas de fichiers)."""
    captures = []
    for c in raw_list:
        if "=" not in c:
            print(
                f"Format invalide pour {flag_name}: {c} (attendu NOM=chemin[,chemin2,...])",
                file=sys.stderr,
            )
            sys.exit(1)
        label, paths_str = c.split("=", 1)
        paths = [p.strip() for p in paths_str.split(",")]
        if not label or not paths or any(not p for p in paths):
            print(
                f"Format invalide pour {flag_name}: {c} (attendu NOM=chemin[,chemin2,...], "
                "nom et chemin(s) requis -- pas de segment vide, ex: virgule en trop)",
                file=sys.stderr,
            )
            sys.exit(1)
        captures.extend((label, path) for path in paths)
    return captures


def _load_packets(scenario_name, captures, parallel, parallel_workers):
    if parallel:
        cpu_count = os.cpu_count() or 1
        effective_workers = parallel_workers or cpu_count
        print(
            f"[{scenario_name}] --parallel : {effective_workers} worker(s) effectif(s) "
            f"(os.cpu_count()={cpu_count} sur cette machine)."
        )
        if effective_workers <= 1:
            print(
                f"  [{scenario_name}] Avec un seul worker effectif, aucun gain de temps "
                "reel n'est a attendre par rapport a une lecture sequentielle -- "
                "seulement le cout de mise en place du pool de processus. Le "
                "parallelisme n'aide que sur un hote disposant de plusieurs coeurs "
                "CPU disponibles."
            )
        elif parallel_workers and parallel_workers > cpu_count:
            print(
                f"  [{scenario_name}] ATTENTION : {parallel_workers} workers demandes "
                f"pour {cpu_count} coeur(s) CPU disponible(s) -- au-dela du nombre de "
                "coeurs, les processus tshark se disputent le CPU au lieu de "
                "s'executer reellement en parallele, ce qui peut ralentir la lecture "
                "de chaque fichier individuellement plutot que l'accelerer."
            )
        all_packets, per_file_stats = parse_captures_parallel(captures, parallel_workers)
        any_error = False
        for s in per_file_stats:
            if s["error"]:
                any_error = True
                print(
                    f"[{scenario_name}/{s['label']}] ECHEC sur {s['path']} : {s['error']}",
                    file=sys.stderr,
                )
            else:
                print(
                    f"[{scenario_name}/{s['label']}] {s['count']} paquets charges depuis {s['path']} "
                    f"({s['seconds']:.2f}s)"
                )
        if any_error:
            print(
                f"\nATTENTION ({scenario_name}) : au moins un fichier n'a pas pu etre lu -- "
                f"l'analyse continue sur les fichiers restants, mais le resultat est incomplet.",
                file=sys.stderr,
            )
        return all_packets

    # Meme correction que sur l'analyzer (issue #287) : cette branche
    # sequentielle est celle par defaut, et elle avalait les echecs de lecture.
    # Un fichier introuvable s'affichait "0 paquets charges", indistinguable
    # d'une capture sans trafic IP, alors que la branche --parallel ci-dessus
    # rapportait ECHEC et concluait par un ATTENTION. Sur une comparaison
    # avant/apres, la consequence est pire qu'ailleurs : un cote vide produit
    # des ecarts spectaculaires qui ne sont que l'ombre du fichier manquant.
    all_packets = []
    any_error = False
    for label, path in captures:
        try:
            pkts = parse_capture(label, path, raise_on_error=True)
        except (TsharkNotFoundError, TsharkError) as exc:
            logger.exception(f"échec dans _load_packets: {exc}")
            any_error = True
            print(f"[{scenario_name}/{label}] ECHEC sur {path} : {exc}", file=sys.stderr)
            continue
        print(f"[{scenario_name}/{label}] {len(pkts)} paquets IP/TCP/UDP/ICMP charges depuis {path}")
        all_packets.extend(pkts)
    if any_error:
        print(
            f"\nATTENTION ({scenario_name}) : au moins un fichier n'a pas pu etre lu -- "
            "l'analyse continue sur les fichiers restants, mais le resultat est incomplet.",
            file=sys.stderr,
        )
    return all_packets


def _parse_live_spec(spec):
    """LABEL:INTERFACE[:FILTRE_BPF] -> (label, interface, bpf_ou_None).
    Copie volontaire de la fonction du meme nom dans
    cross_capture_analyzer_cli.py -- chaque CLI reste independante (voir
    docstring du module), pas de module partage pour un helper aussi
    court."""
    label, sep, rest = spec.partition(":")
    iface, bpf = split_live_target(rest) if sep else ("", None)
    if not label or not iface:
        print(
            f"Format invalide pour --live-current: {spec} (attendu LABEL:INTERFACE[:FILTRE_BPF], INTERFACE pouvant "
            "etre une source distante rpcap://, sshdump:// ou pipe://)",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        parse_source(iface)
    except CaptureSourceError as exc:
        logger.exception(f"échec dans _parse_live_spec: {exc}")
        print(f"Source invalide pour --live-current {label} : {exc}", file=sys.stderr)
        sys.exit(1)
    return label, iface, bpf or None


def _check_single_stdin(points):
    """Une seule source pipe://- (entree standard) par execution : deux
    lecteurs se partageraient les octets du meme flux pcap."""
    stdin_labels = [label for label, iface, _bpf in points if parse_source(iface).uses_stdin]
    if len(stdin_labels) > 1:
        print(
            f"Une seule source peut lire l'entree standard (pipe://-) : {', '.join(stdin_labels)}",
            file=sys.stderr,
        )
        sys.exit(1)


def _run_live_captures(live_specs, duration):
    """Capture en direct sur un ou plusieurs points simultanement pour le
    run COURANT uniquement (un thread par point) jusqu'a Ctrl+C ou
    --live-duration. Renvoie la liste de tous les paquets accumules.

    Copie volontaire de la fonction du meme nom dans
    cross_capture_analyzer_cli.py -- meme logique (voir ce fichier pour
    le detail : thread par point, arret sur SIGINT ou timer, un point en
    echec ne bloque pas les autres)."""
    points = [_parse_live_spec(s) for s in live_specs]
    _check_single_stdin(points)
    stop_event = threading.Event()
    packets_by_point = {label: [] for label, _iface, _bpf in points}
    lock = threading.Lock()

    def _worker(label, iface, bpf):
        count = 0
        last_log = time.monotonic()
        try:
            for pkt in parse_live(label, iface, bpf_filter=bpf, stop_event=stop_event):
                with lock:
                    packets_by_point[label].append(pkt)
                count += 1
                now = time.monotonic()
                if now - last_log >= 2.0:
                    print(f"[courant/{label}] {count} paquets...")
                    last_log = now
        except Exception as e:  # noqa: BLE001 -- thread de fond : une erreur sur
            # ce point doit etre rapportee sans arreter les autres points en cours.
            logger.exception(f"échec dans _worker: {e}")
            print(f"[courant/{label}] ERREUR : {e}", file=sys.stderr)
        print(f"[courant/{label}] capture arretee -- {count} paquet(s) au total.")

    def _on_sigint(_signum, _frame):
        print(
            "\nArret demande (Ctrl+C) -- fin de la capture en cours sur tous les points...",
            file=sys.stderr,
        )
        stop_event.set()

    def _on_duration_elapsed():
        print(
            f"\nDuree maximale ({duration}s) atteinte -- arret de la capture.",
            file=sys.stderr,
        )
        stop_event.set()

    old_handler = signal.signal(signal.SIGINT, _on_sigint)
    for label, iface, bpf in points:
        print(
            f"[courant/{label}] capture demarree sur {iface}"
            + (f" (filtre BPF: {bpf})" if bpf else "")
            + "... (Ctrl+C pour arreter)"
        )
    threads = [threading.Thread(target=_worker, args=(label, iface, bpf), daemon=True) for label, iface, bpf in points]
    for t in threads:
        t.start()

    timer = None
    if duration:
        timer = threading.Timer(duration, _on_duration_elapsed)
        timer.daemon = True
        timer.start()

    try:
        for t in threads:
            t.join()
    finally:
        if timer:
            timer.cancel()
        signal.signal(signal.SIGINT, old_handler)

    all_packets = []
    for label, _iface, _bpf in points:
        all_packets.extend(packets_by_point[label])
    return all_packets


def _analyse_packets(all_packets, points_order, args):
    flows = correlate(all_packets, args.nat_tolerant, args.nat_window_ms)
    return analyse(
        flows,
        points_order,
        all_packets,
        args.bucket_ms / 1000.0,
        args.nat_tolerant,
        args.rtp_clock_rate,
        idle_timeout_seconds=args.idle_timeout_seconds,
    )


def _run_scenario(name, captures, points_order, args, redactor=None):
    """Retourne (Report, all_packets) -- all_packets expose desormais
    (Session 37) pour permettre a l'appelant de construire Flow/
    Conversation (netcross_core.correlate.build_flows/build_conversations)
    sur le scenario COURANT sans reanalyser les fichiers."""
    all_packets = _load_packets(name, captures, args.parallel, args.parallel_workers)
    if redactor is not None:
        # meme objet redactor pour baseline ET courant (voir main()) : une
        # adresse reelle presente des deux cotes doit obtenir le meme
        # pseudonyme, sans quoi le diff entre les deux perdrait tout son sens.
        redactor.redact(all_packets)
    return _analyse_packets(all_packets, points_order, args), all_packets


def main():
    ap = argparse.ArgumentParser(
        description="Compare deux jeux de captures (avant/apres, site A / site B) et "
        "remonte les regressions/ameliorations"
    )
    ap.add_argument(
        "--baseline",
        action="append",
        required=True,
        help="NOM=chemin.pcap(ng)[,chemin2.pcap(ng),...] pour le scenario de "
        "reference, repetable (un point de capture par occurrence). Plusieurs "
        "chemins separes par des virgules pour un meme NOM rejouent une "
        "capture segmentee (rotation tcpdump/tshark) comme un seul point "
        "continu -- a lister dans l'ordre chronologique.",
    )
    ap.add_argument(
        "--current",
        action="append",
        help="NOM=chemin.pcap(ng)[,chemin2.pcap(ng),...] pour le scenario a "
        "evaluer, repetable -- reutiliser les MEMES noms que --baseline pour "
        "permettre la comparaison point par point (memes segments possibles "
        "que --baseline, voir ci-dessus). Mutuellement exclusif avec "
        "--live-current (au moins un des deux est requis).",
    )
    ap.add_argument(
        "--live-current",
        action="append",
        metavar="LABEL:INTERFACE[:FILTRE_BPF]",
        help="Capture en direct le run COURANT au lieu de le lire depuis des "
        "fichiers (repetable pour plusieurs points simultanes, un thread "
        "par point, sources distantes rpcap:// sshdump:// pipe:// "
        "comprises -- meme mecanique que --live sur "
        "cross_capture_analyzer_cli.py). S'arrete sur Ctrl+C ou "
        "--live-duration. Le BASELINE reste toujours un ou plusieurs "
        "fichiers via --baseline : une reference de comparaison est par "
        "nature deja enregistree, la capturer en direct simultanement "
        "n'aurait pas de sens (et n'a pas de precedent cote GUI). "
        "Mutuellement exclusif avec --current/--parallel/--tls/--quic "
        "(memes limitations assumees que --live sur l'autre CLI).",
    )
    ap.add_argument(
        "--live-duration",
        type=int,
        default=None,
        help="Duree maximale en secondes pour --live-current (defaut: illimitee, s'arrete uniquement sur Ctrl+C)",
    )
    ap.add_argument(
        "--order",
        help="Ordre physique des points, ex: LAN,WAN,DC (applique aux deux "
        "scenarios -- ils doivent partager la meme topologie logique)",
    )
    ap.add_argument(
        "--nat-tolerant",
        action="store_true",
        help="Correle par hash de payload + fenetre temporelle au lieu de IP/port",
    )
    ap.add_argument("--nat-window-ms", type=int, default=200)
    ap.add_argument("--bucket-ms", type=int, default=1000)
    ap.add_argument("--rtp-clock-rate", type=int, default=8000)
    ap.add_argument(
        "--idle-timeout-seconds",
        type=float,
        default=None,
        help="Silence minimal (secondes) entre deux paquets consecutifs au "
        "point amont pour detecter une coupure NAT/pare-feu silencieuse "
        "(defaut: 60s, voir netcross_core.analysis._IDLE_TIMEOUT_SECONDS). "
        "Applique identiquement au baseline et au courant.",
    )
    ap.add_argument(
        "--parallel",
        action="store_true",
        help="Lit les fichiers de capture en parallele (un processus par "
        "fichier), applique separement aux deux scenarios",
    )
    ap.add_argument("--parallel-workers", type=int, default=None)
    ap.add_argument(
        "--loss-threshold-pp",
        type=float,
        default=2.0,
        help="Ecart minimal en points de pourcentage pour signaler un changement de taux de pertes (defaut: 2.0)",
    )
    ap.add_argument(
        "--latency-threshold-ms",
        type=float,
        default=5.0,
        help="Ecart minimal en ms pour signaler un changement de latence "
        "(defaut: 5.0, la variation relative doit aussi depasser 20%%)",
    )
    ap.add_argument(
        "--triage",
        action="store_true",
        help="Affiche en plus un classement des segments par ou commencer a "
        "regarder, sur les ecarts baseline/courant (convergence de plusieurs "
        "categories de DiffFinding sur un meme segment). Deja inclus "
        "automatiquement en tete de --pdf-report ; ce flag l'affiche aussi "
        "sur la sortie console. Purement informatif.",
    )
    ap.add_argument(
        "--triage-top-n",
        type=int,
        default=5,
        help="Nombre de segments affiches par --triage (defaut: 5)",
    )
    ap.add_argument(
        "--tls",
        action="store_true",
        help="Diagnostic TLS execute separement sur le baseline et sur le "
        "run courant (ClientHello/SNI, ServerHello, alertes...), affiches "
        "l'un apres l'autre. Pas de vraie diff semantique entre les deux : "
        "tls_diagnostics ne connait qu'un etat a un instant donne, pas une "
        "paire avant/apres -- comparer les deux sections a l'oeil. Relit "
        "les memes fichiers passes a --baseline/--current avec un pipeline "
        "de decodage independant (mais toujours via tshark).",
    )
    ap.add_argument(
        "--quic",
        action="store_true",
        help="Diagnostic QUIC/HTTP3 execute separement sur le baseline et "
        "sur le run courant, meme principe et meme limite que --tls "
        "ci-dessus. Necessite cryptography.",
    )
    ap.add_argument("--diff-csv", help="Chemin de sortie pour le detail des ecarts (CSV)")
    ap.add_argument(
        "--pdf-report",
        help="Chemin de sortie pour un rapport PDF de comparaison (triage, "
        "synthese, table des ecarts, et diagnostics TLS/QUIC si --tls/--quic "
        "sont fournis). Necessite reportlab et matplotlib.",
    )
    ap.add_argument(
        "--json-report",
        help="Chemin de sortie pour un rapport JSON structure de comparaison "
        "(points baseline/courant, ecarts, triage, diagnostics TLS/QUIC si "
        "--tls/--quic sont fournis) -- pour l'integration externe. Aucune "
        "dependance supplementaire (contrairement a --pdf-report).",
    )
    ap.add_argument(
        "--redact",
        action="store_true",
        help="Anonymise les adresses IP (RFC 5737/3849) et MAC (OUI "
        "localement administre) avant l'analyse -- UN SEUL mapping partage "
        "entre baseline et courant, pour qu'une meme adresse reelle presente "
        "des deux cotes garde le meme pseudonyme (sinon le diff perdrait son "
        "sens). Ne couvre que les adresses (pas les noms DNS/HTTP/SAN TLS/"
        "SIP, voir netcross_core.redact). Mutuellement exclusif avec "
        "--tls/--quic, qui relisent les fichiers independamment de cette "
        "redaction.",
    )
    ap.add_argument(
        "--redact-map",
        metavar="CHEMIN",
        help="Avec --redact : ecrit la correspondance adresse reelle <-> "
        "pseudonyme (baseline + courant confondus) dans un CSV local -- a "
        "conserver en prive, ne jamais le transmettre avec le rapport.",
    )
    ap.add_argument(
        "--history-db",
        metavar="CHEMIN",
        help="Enregistre un resume de ce diff (score de sante, nombre "
        "d'ecarts par severite) dans une base SQLite locale, creee si "
        "absente -- meme mecanisme que sur cross_capture_analyzer_cli.py "
        "(voir netcross_report.history), pour suivre une serie de "
        "comparaisons dans le temps plutot qu'un seul run d'analyse.",
    )
    ap.add_argument(
        "--history-label",
        metavar="ETIQUETTE",
        help="Avec --history-db : etiquette libre associee a ce diff (ex: "
        "nom de site/scenario compare). Reutilisee automatiquement comme "
        "filtre par --history-show si elle est fournie.",
    )
    ap.add_argument(
        "--history-show",
        nargs="?",
        type=int,
        const=10,
        default=None,
        metavar="N",
        help="Avec --history-db : affiche apres le diff les N derniers runs "
        "enregistres (y compris celui-ci, analyses ET diffs confondus dans "
        "la meme base) -- defaut 10 si l'option est fournie sans valeur.",
    )
    add_debug_argument(ap)
    args = ap.parse_args()
    apply_debug_argument(args)

    if not args.current and not args.live_current:
        print("Il faut fournir au moins un --current ou un --live-current.", file=sys.stderr)
        sys.exit(1)
    if args.current and args.live_current:
        print(
            "--current et --live-current sont mutuellement exclusifs (le "
            "run courant est soit relu depuis des fichiers, soit capture "
            "en direct -- pas les deux a la fois).",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.live_current:
        if args.parallel:
            print(
                "--parallel n'a pas de sens avec --live-current (deja un "
                "thread par point, en parallele ; et --parallel s'appliquerait "
                "aussi au chargement du baseline, ce qui melangerait les deux "
                "mecaniques pour un gain marginal -- meme choix que --live sur "
                "cross_capture_analyzer_cli.py).",
                file=sys.stderr,
            )
            sys.exit(1)
        if args.tls or args.quic:
            print(
                "--tls/--quic ne sont pas disponibles avec --live-current : "
                "ils relisent les fichiers passes a --current avec un pipeline "
                "de decodage independant, ce qui n'existe pas (encore) pour "
                "une capture en direct. Meme limitation assumee que --live sur "
                "cross_capture_analyzer_cli.py.",
                file=sys.stderr,
            )
            sys.exit(1)

    if args.redact_map and not args.redact:
        print("--redact-map necessite --redact.", file=sys.stderr)
        sys.exit(1)
    if args.redact and (args.tls or args.quic):
        print(
            "--redact n'est pas disponible avec --tls/--quic : ces deux "
            "options relisent les fichiers passes a --baseline/--current "
            "avec leur propre pipeline, independamment des paquets "
            "anonymises par --redact -- les combiner laisserait filtrer des "
            "adresses reelles dans les sections TLS/QUIC du rapport sans le "
            "signaler. Voir netcross_core.redact pour le detail.",
            file=sys.stderr,
        )
        sys.exit(1)

    if (args.history_label or args.history_show is not None) and not args.history_db:
        print("--history-label/--history-show necessitent --history-db.", file=sys.stderr)
        sys.exit(1)

    baseline_captures = _parse_capture_args(args.baseline, "--baseline")
    current_captures = _parse_capture_args(args.current, "--current") if args.current else []
    points_order = args.order.split(",") if args.order else None
    redactor = AddressRedactor() if args.redact else None

    print("=" * 70)
    print("CHARGEMENT DU BASELINE")
    print("=" * 70)
    baseline_report, _baseline_packets = _run_scenario("baseline", baseline_captures, points_order, args, redactor)

    print()
    print("=" * 70)
    if args.live_current:
        print("CAPTURE EN DIRECT DU RUN COURANT")
    else:
        print("CHARGEMENT DU RUN COURANT")
    print("=" * 70)
    if args.live_current:
        current_packets = _run_live_captures(args.live_current, args.live_duration)
        print(f"\n{len(current_packets)} paquet(s) captures au total, analyse en cours...")
        if redactor is not None:
            redactor.redact(current_packets)
        current_report = _analyse_packets(current_packets, points_order, args)
    else:
        current_report, current_packets = _run_scenario("courant", current_captures, points_order, args, redactor)

    if redactor is not None:
        print(f"\n{len(redactor)} adresse(s) anonymisee(s) (IP/MAC) -- baseline et courant confondus.")
        if args.redact_map:
            write_redaction_map_csv(redactor, args.redact_map)
            print(
                f"Correspondance adresse reelle <-> pseudonyme ecrite dans {args.redact_map} "
                "(a conserver en prive, ne pas transmettre avec le rapport)."
            )

    print()
    findings = diff_reports(
        baseline_report,
        current_report,
        loss_min_pp=args.loss_threshold_pp,
        latency_min_ms=args.latency_threshold_ms,
    )
    print_diff_report(findings)

    if args.triage:
        from netcross_report import format_health_line, health_score, print_triage, rank_segments

        ranked = rank_segments(findings)
        print_triage(ranked, args.triage_top_n)
        print(format_health_line(health_score(ranked)))

    tls_findings_baseline = tls_findings_current = None
    quic_findings_baseline = quic_findings_current = None

    if args.tls or args.quic:
        print("\n" + "=" * 70)
        print(
            "DIAGNOSTICS TLS/QUIC (pipeline de decodage independant, execute "
            "separement sur le baseline et sur le run courant -- pas de diff "
            "semantique entre les deux, comparer les deux sections a l'oeil)"
        )
        print("=" * 70)

    if args.tls:
        from netcross_core.tls_diagnostics import (
            build_handshake_status,
            diagnose_tls,
            parse_tls_capture,
            print_tls_diagnostics,
        )

        def _tls_findings(scenario_name, captures):
            events = []
            for label, path in captures:
                found = parse_tls_capture(label, path)
                print(f"[{scenario_name}/{label}] {len(found)} evenements TLS trouves dans {path}")
                events.extend(found)
            return diagnose_tls(build_handshake_status(events), points_order)

        print("\n-- TLS : BASELINE --")
        tls_findings_baseline = _tls_findings("baseline", baseline_captures)
        print_tls_diagnostics(tls_findings_baseline)
        print("\n-- TLS : COURANT --")
        tls_findings_current = _tls_findings("courant", current_captures)
        print_tls_diagnostics(tls_findings_current)

    if args.quic:
        try:
            from netcross_core.quic_diagnostics import (
                diagnose_quic,
                parse_quic_capture,
                print_quic_diagnostics,
            )
        except ImportError:
            logger.debug("dépendance optionnelle absente: ImportError")
            print(
                "\n--quic necessite cryptography : pip install cryptography --break-system-packages",
                file=sys.stderr,
            )
            sys.exit(1)

        def _quic_findings(scenario_name, captures):
            events = []
            for label, path in captures:
                found = parse_quic_capture(label, path)
                print(f"[{scenario_name}/{label}] {len(found)} paquets QUIC Initial trouves dans {path}")
                events.extend(found)
            return diagnose_quic(events, points_order)

        print("\n-- QUIC : BASELINE --")
        quic_findings_baseline = _quic_findings("baseline", baseline_captures)
        print_quic_diagnostics(quic_findings_baseline)
        print("\n-- QUIC : COURANT --")
        quic_findings_current = _quic_findings("courant", current_captures)
        print_quic_diagnostics(quic_findings_current)

    if args.diff_csv:
        write_diff_csv(findings, args.diff_csv)
        print(f"\nDetail des ecarts ecrit dans {args.diff_csv}")

    if args.pdf_report:
        try:
            from netcross_report import generate_diff_pdf
        except ImportError:
            logger.debug("dépendance optionnelle absente: ImportError")
            generate_diff_pdf = None
        if generate_diff_pdf is None:
            print(
                "\n--pdf-report necessite reportlab, matplotlib et networkx : "
                "pip install reportlab matplotlib networkx --break-system-packages",
                file=sys.stderr,
            )
            sys.exit(1)
        generate_diff_pdf(
            findings,
            baseline_report,
            current_report,
            args.pdf_report,
            tls_findings_baseline=tls_findings_baseline,
            tls_findings_current=tls_findings_current,
            quic_findings_baseline=quic_findings_baseline,
            quic_findings_current=quic_findings_current,
            meta={"Anonymisation": "adresses IP/MAC anonymisees (--redact)"} if args.redact else None,
        )
        print(f"Rapport PDF ecrit dans {args.pdf_report}")

    if args.json_report:
        from netcross_report import build_diagnoses, build_expert_events, generate_json_diff

        # Objets de contrat de la Session 0 (FEATURES.md section 13.3) --
        # toujours cote COURANT uniquement, jamais le baseline, meme
        # decision que DiffFinding.evidence (Session 33) : voir
        # netcross_report.json_report.generate_json_diff pour le detail.
        current_flows = correlate(current_packets, args.nat_tolerant, args.nat_window_ms)
        flow_objs = build_flows(current_flows)
        conversations = build_conversations(flow_objs)
        expert_events = build_expert_events(findings)
        diagnoses = build_diagnoses(expert_events)
        compliance = evaluate_compliance(current_report)
        # Session 1 (FEATURES.md section 13.3) : signaux d'expertise
        # bruts tshark, cote COURANT uniquement (meme convention que les
        # objets Session 0 ci-dessus) -- voir netcross_core.wireshark_expert.
        wireshark_expert_events = build_wireshark_expert_events(current_packets)

        generate_json_diff(
            findings,
            baseline_report,
            current_report,
            args.json_report,
            tls_findings_baseline=tls_findings_baseline,
            tls_findings_current=tls_findings_current,
            quic_findings_baseline=quic_findings_baseline,
            quic_findings_current=quic_findings_current,
            flows=flow_objs,
            conversations=conversations,
            expert_events=expert_events,
            diagnoses=diagnoses,
            compliance=compliance,
            wireshark_expert_events=wireshark_expert_events,
            meta={"Anonymisation": "adresses IP/MAC anonymisees (--redact)"} if args.redact else None,
        )
        print(f"Rapport JSON ecrit dans {args.json_report}")

    if args.history_db:
        from netcross_report import HistoryDatabaseError, list_history, print_history, record_diff_run

        # Meme garde que sur l'analyzer (issue #287) : l'historique est ecrit
        # apres la comparaison, donc un chemin invalide faisait perdre tout le
        # travail sur une trace sqlite3 brute.
        try:
            record_diff_run(
                findings,
                baseline_report,
                current_report,
                args.history_db,
                meta={"Anonymisation": "adresses IP/MAC anonymisees (--redact)"} if args.redact else None,
                label=args.history_label,
            )
            label_txt = f" (etiquette: {args.history_label})" if args.history_label else ""
            print(f"\nResume de ce diff enregistre dans l'historique {args.history_db}{label_txt}.")
            if args.history_show is not None:
                entries = list_history(args.history_db, limit=args.history_show, label=args.history_label)
                print_history(entries)
        except HistoryDatabaseError as exc:
            logger.exception(f"échec dans _quic_findings: {exc}")
            print(exc, file=sys.stderr)
            sys.exit(1)

    if any(f.severity == "regression" for f in findings):
        sys.exit(1)  # code de sortie non nul : exploitable en CI/script pour detecter une regression


if __name__ == "__main__":
    main()
