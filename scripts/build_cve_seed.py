#!/usr/bin/env python3
"""
scripts/build_cve_seed.py -- regenere la base CVE minimale embarquee
(`src/netcross_core/data/cve_seed.json`, issue #353).

Sans `--cve-db`, le rapport de securite n'avait aucune correlation CVE :
un Apache 2.4.49 n'etait pas qualifie vulnerable. La base embarquee
contient une selection courte de CVE critiques et tres exploitees sur les
produits reconnus par `cpe_match.PRODUCT_ALIASES`. Elle ne remplace pas
une base complete (`scripts/import_nvd.py`) : c'est un filet de securite
sans configuration.

Les enregistrements viennent de l'API NVD 2.0 (score CVSS, description,
ranges de versions reels, aucune valeur saisie a la main), passes par le
meme parseur que import_nvd.py, puis filtres aux couples (vendor, product)
catalogues pour garder un fichier court.

Usage (acces reseau vers services.nvd.nist.gov requis, ~6 s par CVE pour
respecter la limite de debit publique du NVD) :

    python3 scripts/build_cve_seed.py            # regenere le fichier
    python3 scripts/build_cve_seed.py --only CVE-2021-41773 --output /tmp/x.json
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from import_nvd import _fetch_page, iter_nvd_items, parse_nvd_item  # noqa: E402

from netcross_core.security.cpe_match import PRODUCT_ALIASES, vendor_candidates  # noqa: E402
from netcross_core.security.cve_seed import DEFAULT_SEED_PATH, SEED_FORMAT_VERSION  # noqa: E402

# Selection : CVE critiques/tres exploitees (catalogue CISA KEV pour la
# plupart) sur des services dont la version se lit dans une banniere.
SEED_CVE_IDS: tuple[str, ...] = (
    # Apache httpd
    "CVE-2021-41773",
    "CVE-2021-42013",
    "CVE-2021-44790",
    "CVE-2019-0211",
    "CVE-2017-15715",
    "CVE-2023-25690",
    "CVE-2024-38476",
    # OpenSSH
    "CVE-2024-6387",
    "CVE-2023-38408",
    "CVE-2018-15473",
    # OpenSSL
    "CVE-2014-0160",
    "CVE-2022-3602",
    "CVE-2016-2107",
    # nginx
    "CVE-2021-23017",
    "CVE-2013-2028",
    # FTP
    "CVE-2011-2523",
    "CVE-2015-3306",
    "CVE-2019-12815",
    # Messagerie
    "CVE-2019-10149",
    "CVE-2019-15846",
    # Partage, DNS, proxys, langages
    "CVE-2017-7494",
    "CVE-2017-14491",
    "CVE-2020-8617",
    "CVE-2023-25725",
    "CVE-2022-22707",
    "CVE-2024-4577",
    "CVE-2019-11043",
)

# Vendeurs historiques compris (LEGACY_VENDORS) : une CVE encore publiee
# sous l'ancien nom ne doit pas etre ecartee du seed.
_CATALOGUED = {
    (candidate, product)
    for vendor, product in PRODUCT_ALIASES.values()
    for candidate in vendor_candidates(vendor, product)
}


DEFAULT_CACHE_DIR = Path(tempfile.gettempdir()) / "netcross-nvd-cache"


def _fetch_cve(cve_id: str, *, attempts: int = 3, pause: float = 60.0) -> list[dict]:
    """Un enregistrement NVD ; la limitation de debit (page vide en HTTP
    200) est geree par import_nvd._fetch_page, puis re-tentee ici apres
    une longue pause (le NVD bride parfois plusieurs minutes)."""
    for attempt in range(attempts):
        if attempt:
            time.sleep(pause)
        try:
            return list(iter_nvd_items(_fetch_page({"cveId": cve_id})))
        except (OSError, RuntimeError) as exc:  # URLError/HTTPError, timeouts, limitation persistante
            logger.warning("CVE {} non recuperee : {}", cve_id, exc)
            print(f"{cve_id} : {exc}", file=sys.stderr)
    logger.debug("_recuperer_cve() retourne | vide")
    return []


def _cached_items(cve_id: str, cache_dir: Path | None) -> list[dict] | None:
    if cache_dir is None:
        return None
    path = cache_dir / f"{cve_id}.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _store_items(cve_id: str, items: list[dict], cache_dir: Path | None) -> None:
    if cache_dir is None or not items:
        return
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / f"{cve_id}.json").write_text(json.dumps(items), encoding="utf-8")


def build_seed(cve_ids: tuple[str, ...], *, delay: float, cache_dir: Path | None = None) -> dict:
    """cache_dir : reponses NVD deja obtenues, reutilisees a la relance --
    une generation interrompue par la limitation de debit reprend la ou
    elle s'est arretee au lieu de tout re-telecharger."""
    entries = []
    fetched = 0
    for cve_id in cve_ids:
        items = _cached_items(cve_id, cache_dir)
        if items is None:
            if fetched:
                time.sleep(delay)
            fetched += 1
            items = _fetch_cve(cve_id)
            _store_items(cve_id, items, cache_dir)
        if not items:
            raise SystemExit(f"{cve_id} : introuvable au NVD -- base non regeneree (aucun fichier partiel)")
        entry = parse_nvd_item(items[0])
        affected = [a for a in entry.affected if (a.vendor, a.product) in _CATALOGUED]
        if not affected:
            print(f"{cve_id} : aucun produit catalogue, ignoree", file=sys.stderr)
            continue
        record = asdict(entry)
        # dedoublonne (le NVD repete parfois un meme range dans plusieurs noeuds)
        seen: list[dict] = []
        for product in affected:
            item = asdict(product)
            if item not in seen:
                seen.append(item)
        record["affected"] = seen
        entries.append(record)
        print(f"{cve_id} : CVSS {entry.cvss_score}, {len(seen)} range(s)")
    return {
        "version": SEED_FORMAT_VERSION,
        "source": "NVD API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "cves": entries,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, default=DEFAULT_SEED_PATH)
    parser.add_argument("--only", nargs="+", metavar="CVE_ID", help="sous-ensemble de CVE (tests)")
    parser.add_argument("--delay", type=float, default=6.5, help="pause entre requetes NVD (s)")
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help=f"reponses NVD mises en cache pour reprendre une generation interrompue (defaut {DEFAULT_CACHE_DIR})",
    )
    parser.add_argument("--no-cache", action="store_true", help="tout re-telecharger, sans cache")
    args = parser.parse_args(argv)
    seed = build_seed(
        tuple(args.only) if args.only else SEED_CVE_IDS,
        delay=args.delay,
        cache_dir=None if args.no_cache else args.cache_dir,
    )
    args.output.write_text(json.dumps(seed, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{len(seed['cves'])} CVE ecrites dans {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
