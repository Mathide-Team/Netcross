#!/usr/bin/env python3
"""
scripts/bench_memory.py -- banc de mesure memoire pour de grosses captures
(issue #283, Etape 1 : "mesurer avant d'optimiser").

Aucune optimisation ne doit etre ecrite sans une courbe -- ce script genere
des captures synthetiques de taille croissante et mesure la crete memoire
(tracemalloc, allocations Python pures) et la RSS maximale du processus
(resource.getrusage, incluant les objets non traques par tracemalloc :
buffers C, memoire des sous-processus tshark/editcap le cas echeant) pour
le pipeline reel de netcross_core (parse_capture-like -> correlate ->
analyse) applique a ces captures.

Deux sources de paquets, memes que celles suggerees par l'issue :

  1. Objets Pkt synthetiques (par defaut, toujours disponible -- n'exige
     ni tshark ni editcap, seule la bibliotheque standard). Reproduit le
     cout memoire du pipeline netcross_core APRES le decodage tshark (donc
     une borne inferieure : la lecture -T ek elle-meme, hors de ce script,
     ajoute son propre pic transitoire, voir editcap ci-dessous).
  2. --editcap : genere un vrai fichier pcap via editcap (deja utilise par
     pcap_parser.capture pour --split, disponible en session et en CI --
     voir install.sh) en dupliquant un pcap graine, PUIS lit ce fichier
     avec parse_capture (pipeline complet, y compris le cout de tshark -T
     ek) -- plus lent, plus realiste, exige tshark/editcap installes.

Usage :
    python3 scripts/bench_memory.py
    python3 scripts/bench_memory.py --sizes 1000,10000,100000,1000000
    python3 scripts/bench_memory.py --editcap --sizes 1000,10000,100000

Sortie : un tableau "taille de capture -> crete memoire -> duree" sur
stdout, et le meme tableau en JSON si --json PATH est fourni (pour
consigner la courbe de reference dans l'issue #283, comme demande par son
Etape 1).
"""

from __future__ import annotations

import argparse
import dataclasses
import gc
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import tracemalloc
from dataclasses import dataclass

from loguru import logger  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from netcross_core.analysis import analyse  # noqa: E402
from netcross_core.correlate import correlate  # noqa: E402
from netcross_core.models import Pkt  # noqa: E402


def _neutral_default_for(field: dataclasses.Field) -> object:
    """Valeur neutre pour un champ Pkt sans defaut, d'apres son annotation
    de type -- generique plutot qu'une table nommee (Pkt porte ~65 champs
    sans defaut, la plupart facultatifs/protocole-specifiques, voir
    netcross_core.models) : None pour tout champ optionnel (``X | None``),
    sinon la valeur neutre du type de base (str vide, 0, False, tuple
    vide). Suffisant pour un banc de mesure memoire, qui ne lit jamais le
    CONTENU de ces champs, seulement leur presence en memoire."""
    annotation = field.type
    text = annotation if isinstance(annotation, str) else str(annotation)
    if "None" in text:
        return None
    if text.startswith("tuple"):
        return ()
    if text == "bool":
        return False
    if text == "int":
        return 0
    if text == "float":
        return 0.0
    return ""


def _make_synthetic_packets(count: int) -> list[Pkt]:
    """``count`` paquets Pkt synthetiques d'un flux TCP unique A->B,
    seq/ip_id/ts croissants -- assez varies pour que correlate()/analyse()
    fassent un travail representatif (pas juste des doublons identiques),
    sans avoir besoin de decoder quoi que ce soit. Les champs non
    explicitement varies ci-dessous recoivent une valeur neutre generique
    (voir _neutral_default_for) : Pkt n'a pas de defaut pour la plupart de
    ses ~65 champs (voir netcross_core.models), ce script ne doit pourtant
    dependre ni de tests/conftest.make_pkt (scripts/ != tests/) ni d'une
    table de valeurs dupliquee et vouee a se desynchroniser du dataclass
    reel a chaque champ ajoute."""
    fields = dataclasses.fields(Pkt)
    varying = {"point", "ts", "proto", "src", "dst", "length", "seq", "key_id", "ip_id"}
    neutral = {f.name: _neutral_default_for(f) for f in fields if f.name not in varying}
    return [
        Pkt(
            point="A",
            ts=float(i) * 0.001,
            proto="TCP",
            src="10.0.0.1",
            dst="10.0.0.2",
            length=100 + (i % 400),
            seq=1000 + i * 100,
            key_id=1000 + i,
            ip_id=(i % 65536),
            **neutral,
        )
        for i in range(count)
    ]


def _editcap_path() -> str | None:
    return shutil.which("editcap")


def _seed_pcap_bytes(count: int) -> bytes:
    """pcap classique minimal (memes entetes que tests/pcap_builders.py,
    reimplemente ici pour la meme raison que _neutral_default_for ci-dessus :
    pas de dependance a tests/) portant ``count`` paquets UDP factices."""
    import struct

    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    body = bytearray()
    payload = bytes(60)
    for i in range(count):
        record = struct.pack("<IIII", i, 0, len(payload), len(payload)) + payload
        body += record
    return header + bytes(body)


def _make_editcap_capture(count: int, tmpdir: str) -> str:
    """Duplique un pcap graine via ``editcap`` jusqu'a ``count`` paquets et
    renvoie le chemin du fichier resultant."""
    editcap = _editcap_path()
    if editcap is None:
        raise RuntimeError("editcap introuvable (paquet tshark/wireshark-cli) -- voir install.sh")
    seed_count = min(count, 1000) or 1
    seed_path = os.path.join(tmpdir, "seed.pcap")
    with open(seed_path, "wb") as f:
        f.write(_seed_pcap_bytes(seed_count))
    out_path = os.path.join(tmpdir, f"synth_{count}.pcap")
    repeats = max(1, -(-count // seed_count))  # ceil(count / seed_count)
    args = [editcap, "-F", "pcap"]
    for _ in range(repeats - 1):
        pass
    # editcap ne duplique pas nativement -- on concatene le graine `repeats`
    # fois via mergecap (livre avec le meme paquet que editcap) puis on
    # tronque a `count` paquets avec `editcap -r`.
    mergecap = shutil.which("mergecap")
    if mergecap is None:
        raise RuntimeError("mergecap introuvable (paquet tshark/wireshark-cli) -- voir install.sh")
    merged_path = os.path.join(tmpdir, f"merged_{count}.pcap")
    subprocess.run(
        [mergecap, "-w", merged_path, *([seed_path] * repeats)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    subprocess.run(
        [editcap, "-r", merged_path, out_path, f"1-{count}"],
        check=True,
        capture_output=True,
        timeout=120,
    )
    del args
    return out_path


@dataclass
class BenchResult:
    packet_count: int
    peak_tracemalloc_bytes: int
    peak_rss_kib: int
    duration_seconds: float
    source: str


def _run_one(count: int, use_editcap: bool) -> BenchResult:
    """Mesure un pipeline complet parse->correlate->analyse pour ``count``
    paquets. tracemalloc suit les allocations Python (crete d'objets Pkt,
    listes, dicts accumules par Report) ; resource.getrusage(RUSAGE_SELF)
    donne la RSS maximale du PROCESSUS entier depuis son demarrage --
    volontairement lue APRES chaque mesure (ru_maxrss ne redescend jamais,
    c'est un maximum cumule sur toute la vie du processus, voir `man
    getrusage`), donc chaque ligne du tableau final rapporte le maximum
    ATTEINT A CE POINT, pas un delta isole -- lancer ce script une seule
    fois par taille (jamais en boucle dans le meme processus pour plusieurs
    tailles) evite de fausser les tailles les plus petites avec la RSS
    laissee par une taille precedente plus grande."""
    tmpdir = tempfile.mkdtemp(prefix="netcross_bench_") if use_editcap else None
    try:
        gc.collect()
        tracemalloc.start()
        started = time.monotonic()
        if use_editcap:
            from pcap_parser.capture import parse_capture

            path = _make_editcap_capture(count, tmpdir)
            packets = parse_capture(path, raise_on_error=True)
            # parse_capture renvoie des RawPacket (pcap_parser), pas des
            # Pkt (netcross_core) -- meme conversion que
            # netcross_core.parsing._to_pkt, dupliquee ici a minima (seuls
            # les champs utilises par correlate()/analyse() comptent pour
            # une mesure memoire, pas la fidelite complete du decodage).
            varying = {"point", "ts", "proto", "src", "dst", "length", "seq", "key_id", "ip_id"}
            neutral = {f.name: _neutral_default_for(f) for f in dataclasses.fields(Pkt) if f.name not in varying}
            pkts = [
                Pkt(
                    point="A",
                    ts=p.ts,
                    proto=p.proto or "IP",
                    src=p.src or "0.0.0.0",
                    dst=p.dst or "0.0.0.0",
                    length=p.length,
                    seq=None,
                    key_id=p.ip_id,
                    ip_id=p.ip_id,
                    **neutral,
                )
                for p in packets
            ]
        else:
            pkts = _make_synthetic_packets(count)
        flows = correlate(pkts)
        analyse(flows, None, pkts, 1.0)
        duration = time.monotonic() - started
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # KiB sous Linux
        return BenchResult(
            packet_count=count,
            peak_tracemalloc_bytes=peak,
            peak_rss_kib=rss,
            duration_seconds=duration,
            source="editcap" if use_editcap else "synthetic",
        )
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def _format_bytes(n: float) -> str:
    for unit, factor in (("Go", 1_000_000_000), ("Mo", 1_000_000), ("Ko", 1_000)):
        if n >= factor:
            return f"{n / factor:.1f} {unit}"
    return f"{n:.0f} o"


def run_bench(sizes: list[int], use_editcap: bool) -> list[BenchResult]:
    results = []
    for count in sizes:
        print(f"-- {count:,} paquets ({'editcap' if use_editcap else 'synthetique'}) --".replace(",", " "))
        result = _run_one(count, use_editcap)
        print(
            f"   crete tracemalloc: {_format_bytes(result.peak_tracemalloc_bytes)} | "
            f"RSS max processus: {_format_bytes(result.peak_rss_kib * 1024)} | "
            f"duree: {result.duration_seconds:.2f}s"
        )
        results.append(result)
    return results


def print_table(results: list[BenchResult]) -> None:
    print("\n" + "=" * 78)
    print("Taille de capture -> crete memoire -> duree (issue #283, Etape 1)")
    print("=" * 78)
    header = f"{'paquets':>12} | {'tracemalloc':>14} | {'RSS max':>12} | {'duree':>8}"
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r.packet_count:>12,} | {_format_bytes(r.peak_tracemalloc_bytes):>14} | "
            f"{_format_bytes(r.peak_rss_kib * 1024):>12} | {r.duration_seconds:>7.2f}s"
        )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0] if __doc__ else "")
    ap.add_argument(
        "--sizes",
        default="1000,10000,100000,500000",
        help="Tailles de capture (nombre de paquets) a mesurer, separees par des virgules "
        "(defaut: 1000,10000,100000,500000).",
    )
    ap.add_argument(
        "--editcap",
        action="store_true",
        help="Utilise editcap/mergecap pour generer de vraies captures pcap et le pipeline "
        "complet parse_capture (plus lent, plus realiste) au lieu d'objets Pkt synthetiques "
        "(defaut). Exige tshark/wireshark-cli installe (voir install.sh).",
    )
    ap.add_argument(
        "--json",
        metavar="PATH",
        default=None,
        help="Ecrit aussi le tableau de resultats en JSON dans PATH (pour consigner la "
        "courbe de reference dans l'issue #283).",
    )
    args = ap.parse_args()

    try:
        sizes = [int(s.strip()) for s in args.sizes.split(",") if s.strip()]
    except ValueError:
        logger.error("--sizes : liste d'entiers separes par des virgules attendue, recu {!r}", args.sizes)
        print(f"--sizes : liste d'entiers separes par des virgules attendue, recu {args.sizes!r}", file=sys.stderr)
        logger.debug("main() retourne | 1 (argument invalide)")
        return 1
    if not sizes or any(s <= 0 for s in sizes):
        print("--sizes : toutes les tailles doivent etre des entiers > 0", file=sys.stderr)
        return 1

    if args.editcap and _editcap_path() is None:
        print("--editcap demande mais editcap est introuvable (paquet tshark/wireshark-cli).", file=sys.stderr)
        return 1

    results = run_bench(sizes, args.editcap)
    print_table(results)

    if args.json:
        payload = [
            {
                "packet_count": r.packet_count,
                "peak_tracemalloc_bytes": r.peak_tracemalloc_bytes,
                "peak_rss_kib": r.peak_rss_kib,
                "duration_seconds": r.duration_seconds,
                "source": r.source,
            }
            for r in results
        ]
        with open(args.json, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"\nResultats ecrits dans {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
