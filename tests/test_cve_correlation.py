"""
tests/test_cve_correlation.py -- tests de la base CVE locale et de la
correlation de versions (netcross_core.security, issue #138 / CVE-4).

Aucun test ne touche le reseau : la base est peuplee soit directement
via cve_db.upsert_cve() (donnees construites en memoire), soit via
import_nvd.import_from_file() contre la fixture locale
tests/data/nvd_sample.json (format API NVD 2.0 reel, extrait figé) --
memes deux CVE Apache (path traversal 2021-41773/42013, bornes
volontairement adjacentes sur 2.4.49-2.4.50 pour tester les bornes
incluses/exclues) et une CVE OpenSSH a version exacte que l'exemple
donne par les criteres d'acceptation de l'issue.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from netcross_core.security import correlate_banner, correlate_versions
from netcross_core.security.cpe_match import (
    build_cpe23,
    compare_versions,
    parse_all_banners,
    parse_banner,
    version_in_range,
)
from netcross_core.security.cve_db import (
    AffectedProduct,
    CveEntry,
    connect_cve_db,
    count_cves,
    get_cve,
    init_db,
    query_by_product,
    upsert_cve,
)
from scripts.import_nvd import import_from_file, iter_nvd_items, parse_nvd_item

FIXTURE = Path(__file__).parent / "data" / "nvd_sample.json"


# -- cpe_match : parsing de bannieres ---------------------------------------


def test_parse_banner_apache_reconnu():
    parsed = parse_banner("Apache/2.4.41")
    assert parsed is not None
    assert parsed.vendor == "apache"
    assert parsed.product == "http_server"
    assert parsed.version == "2.4.41"


def test_parse_banner_produit_non_catalogue_renvoie_none():
    assert parse_banner("MonServeurMaison/3.0") is None


def test_parse_banner_premier_token_reconnu_dans_banniere_composite():
    parsed = parse_banner("Apache/2.4.41 (Unix) OpenSSL/1.1.1k")
    assert parsed is not None
    assert parsed.product_key == "apache"
    assert parsed.version == "2.4.41"


def test_parse_all_banners_recupere_tous_les_tokens():
    parsed = parse_all_banners("Apache/2.4.41 (Unix) OpenSSL/1.1.1k")
    keys = {p.product_key for p in parsed}
    assert keys == {"apache", "openssl"}


def test_parse_banner_separateur_underscore():
    parsed = parse_banner("OpenSSH_8.2p1")
    assert parsed is not None
    assert parsed.product == "openssh"
    assert parsed.version == "8.2p1"


def test_parse_banner_insensible_a_la_casse():
    parsed = parse_banner("apache/2.4.41")
    assert parsed is not None
    assert parsed.product_key == "apache"


def test_parsed_banner_cpe23():
    parsed = parse_banner("Apache/2.4.41")
    assert parsed.cpe23 == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"


def test_build_cpe23():
    assert build_cpe23("apache", "http_server", "2.4.41") == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"


# -- cpe_match : comparaison de versions -------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("2.4.41", "2.4.50", -1),
        ("2.4.50", "2.4.41", 1),
        ("2.4.41", "2.4.41", 0),
        ("1.1.1k", "1.1.1a", 1),
        ("8.2p1", "8.2p2", -1),
        ("2.4", "2.4.1", -1),
    ],
)
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected


def test_version_in_range_bornes_incluses():
    assert version_in_range("2.4.49", start_including="2.4.49", end_excluding="2.4.50") is True
    assert version_in_range("2.4.50", start_including="2.4.49", end_excluding="2.4.50") is False


def test_version_in_range_bornes_exclues():
    assert version_in_range("2.4.49", start_excluding="2.4.49") is False
    assert version_in_range("2.4.50", start_excluding="2.4.49") is True


def test_version_in_range_end_including():
    assert version_in_range("2.4.50", end_including="2.4.50") is True
    assert version_in_range("2.4.51", end_including="2.4.50") is False


def test_version_in_range_exact_sans_bornes():
    assert version_in_range("8.3", exact="8.3") is True
    assert version_in_range("8.4", exact="8.3") is False


def test_version_in_range_sans_aucune_contrainte_couvre_tout():
    assert version_in_range("9.9.9") is True


# -- cve_db : base SQLite (schema, upsert, requetes) -------------------------


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "cve.db"


def _apache_entry(cve_id, score, severity, start_incl=None, end_incl=None, end_excl=None):
    return CveEntry(
        cve_id=cve_id,
        description=f"description {cve_id}",
        cvss_score=score,
        cvss_severity=severity,
        published="2021-10-05T00:00:00",
        affected=[
            AffectedProduct(
                vendor="apache",
                product="http_server",
                version_start_including=start_incl,
                version_end_including=end_incl,
                version_end_excluding=end_excl,
            )
        ],
    )


def test_connect_cve_db_cree_le_schema(db_path):
    conn = connect_cve_db(db_path)
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {"cves", "cve_products"} <= tables
    conn.close()


def test_init_db_cree_le_fichier_et_le_schema_comme_connect_cve_db(db_path):
    assert not db_path.exists()
    conn = init_db(db_path)
    try:
        assert db_path.exists()
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert {"cves", "cve_products"} <= tables
        assert count_cves(conn) == 0
    finally:
        conn.close()


def test_upsert_et_get_cve_round_trip(db_path):
    conn = connect_cve_db(db_path)
    entry = _apache_entry("CVE-2021-41773", 7.5, "HIGH", start_incl="2.4.49", end_excl="2.4.50")
    upsert_cve(conn, entry)

    fetched = get_cve(conn, "CVE-2021-41773")
    assert fetched is not None
    assert fetched.cve_id == "CVE-2021-41773"
    assert fetched.cvss_score == 7.5
    assert fetched.cvss_severity == "HIGH"
    assert len(fetched.affected) == 1
    assert fetched.affected[0].vendor == "apache"
    conn.close()


def test_get_cve_inconnue_renvoie_none(db_path):
    conn = connect_cve_db(db_path)
    assert get_cve(conn, "CVE-9999-00000") is None
    conn.close()


def test_upsert_est_idempotent_pas_de_doublon(db_path):
    conn = connect_cve_db(db_path)
    entry = _apache_entry("CVE-2021-41773", 7.5, "HIGH", start_incl="2.4.49", end_excl="2.4.50")
    upsert_cve(conn, entry)
    upsert_cve(conn, entry)
    assert count_cves(conn) == 1
    assert len(get_cve(conn, "CVE-2021-41773").affected) == 1
    conn.close()


def test_upsert_met_a_jour_score_revise(db_path):
    conn = connect_cve_db(db_path)
    entry = _apache_entry("CVE-2021-41773", 7.5, "HIGH", start_incl="2.4.49", end_excl="2.4.50")
    upsert_cve(conn, entry)
    revised = _apache_entry("CVE-2021-41773", 8.1, "HIGH", start_incl="2.4.49", end_excl="2.4.50")
    upsert_cve(conn, revised)
    assert get_cve(conn, "CVE-2021-41773").cvss_score == 8.1
    conn.close()


def test_query_by_product_filtre_par_vendor_product(db_path):
    conn = connect_cve_db(db_path)
    upsert_cve(conn, _apache_entry("CVE-2021-41773", 7.5, "HIGH", start_incl="2.4.49", end_excl="2.4.50"))
    upsert_cve(
        conn,
        CveEntry(
            cve_id="CVE-2020-15778",
            description="openssh scp",
            cvss_score=6.8,
            cvss_severity="MEDIUM",
            published=None,
            affected=[AffectedProduct(vendor="openbsd", product="openssh", version="8.3")],
        ),
    )

    apache_matches = query_by_product(conn, "apache", "http_server")
    assert {e.cve_id for e in apache_matches} == {"CVE-2021-41773"}

    ssh_matches = query_by_product(conn, "openbsd", "openssh")
    assert {e.cve_id for e in ssh_matches} == {"CVE-2020-15778"}
    conn.close()


def test_query_by_product_insensible_a_la_casse(db_path):
    conn = connect_cve_db(db_path)
    upsert_cve(conn, _apache_entry("CVE-2021-41773", 7.5, "HIGH", start_incl="2.4.49", end_excl="2.4.50"))
    assert len(query_by_product(conn, "Apache", "HTTP_Server")) == 1
    conn.close()


def test_query_by_product_sans_correspondance_renvoie_liste_vide(db_path):
    conn = connect_cve_db(db_path)
    assert query_by_product(conn, "nginx", "nginx") == []
    conn.close()


def test_count_cves(db_path):
    conn = connect_cve_db(db_path)
    assert count_cves(conn) == 0
    upsert_cve(conn, _apache_entry("CVE-2021-41773", 7.5, "HIGH", start_incl="2.4.49", end_excl="2.4.50"))
    assert count_cves(conn) == 1
    conn.close()


# -- AffectedProduct.matches --------------------------------------------------

_APACHE_RANGE = AffectedProduct(
    vendor="apache",
    product="http_server",
    version_start_including="2.4.49",
    version_end_excluding="2.4.50",
)


@pytest.mark.parametrize(
    ("vendor", "product"),
    [
        ("nginx", "http_server"),  # autre editeur, meme produit
        ("apache", "tomcat"),  # meme editeur, autre produit
        ("nginx", "nginx"),  # ni l'un ni l'autre
    ],
)
def test_affected_product_matches_faux_si_vendor_ou_product_differe(vendor, product):
    # meme avec une version pourtant dans le range : vendor/product decident d'abord
    assert _APACHE_RANGE.matches(vendor, product, "2.4.49") is False


def test_affected_product_matches_delegue_la_version_au_range():
    assert _APACHE_RANGE.matches("apache", "http_server", "2.4.49") is True
    assert _APACHE_RANGE.matches("apache", "http_server", "2.4.50") is False  # borne exclue
    assert _APACHE_RANGE.matches("apache", "http_server", "2.4.48") is False  # sous la borne incluse


def test_affected_product_matches_insensible_a_la_casse():
    assert _APACHE_RANGE.matches("Apache", "HTTP_Server", "2.4.49") is True
    produit_majuscule = AffectedProduct(vendor="APACHE", product="Http_Server", version="2.4.49")
    assert produit_majuscule.matches("apache", "http_server", "2.4.49") is True


def test_affected_product_matches_version_exacte_sans_range():
    exact = AffectedProduct(vendor="openbsd", product="openssh", version="8.3")
    assert exact.matches("openbsd", "openssh", "8.3") is True
    assert exact.matches("openbsd", "openssh", "8.4") is False


# -- scripts/import_nvd.py : parsing du format API NVD 2.0 ------------------


def test_iter_nvd_items_fixture():
    import json

    payload = json.loads(FIXTURE.read_text())
    ids = [item["id"] for item in iter_nvd_items(payload)]
    assert ids == ["CVE-2021-41773", "CVE-2021-42013", "CVE-2020-15778"]


def test_parse_nvd_item_range():
    import json

    payload = json.loads(FIXTURE.read_text())
    item = next(iter_nvd_items(payload))
    entry = parse_nvd_item(item)
    assert entry.cve_id == "CVE-2021-41773"
    assert entry.cvss_score == 7.5
    assert entry.cvss_severity == "HIGH"
    assert len(entry.affected) == 1
    affected = entry.affected[0]
    assert (affected.vendor, affected.product) == ("apache", "http_server")
    assert affected.version_start_including == "2.4.49"
    assert affected.version_end_excluding == "2.4.50"


def test_parse_nvd_item_version_exacte():
    import json

    payload = json.loads(FIXTURE.read_text())
    items = list(iter_nvd_items(payload))
    ssh_item = next(i for i in items if i["id"] == "CVE-2020-15778")
    entry = parse_nvd_item(ssh_item)
    assert entry.cvss_score == 6.8
    assert entry.affected[0].version == "8.3"
    assert entry.affected[0].version_start_including is None


def test_import_from_file_peuple_la_base(db_path):
    count = import_from_file(FIXTURE, db_path)
    assert count == 3
    conn = sqlite3.connect(db_path)
    assert count_cves(conn) == 3
    conn.close()


def test_import_from_file_est_idempotent(db_path):
    import_from_file(FIXTURE, db_path)
    import_from_file(FIXTURE, db_path)
    conn = sqlite3.connect(db_path)
    assert count_cves(conn) == 3
    conn.close()


# -- correlate_banner / correlate_versions : bout en bout --------------------


@pytest.fixture
def populated_db(db_path):
    import_from_file(FIXTURE, db_path)
    conn = connect_cve_db(db_path)
    yield conn
    conn.close()


def test_correlate_banner_apache_vulnerable_aux_deux_cve(populated_db):
    matches = correlate_banner(populated_db, "Apache/2.4.49")
    assert {m.cve_id for m in matches} == {"CVE-2021-41773", "CVE-2021-42013"}


def test_correlate_banner_respecte_la_borne_exclue(populated_db):
    # 2.4.50 : exclu par CVE-2021-41773 (versionEndExcluding=2.4.50) mais
    # inclus par CVE-2021-42013 (versionEndIncluding=2.4.50) -- le cas
    # exact qui justifie de distinguer include/exclude plutot qu'un seul
    # operateur "<".
    matches = correlate_banner(populated_db, "Apache/2.4.50")
    assert {m.cve_id for m in matches} == {"CVE-2021-42013"}


def test_correlate_banner_version_non_affectee(populated_db):
    assert correlate_banner(populated_db, "Apache/2.4.48") == []
    assert correlate_banner(populated_db, "Apache/2.4.51") == []


def test_correlate_banner_produit_non_catalogue(populated_db):
    assert correlate_banner(populated_db, "MonServeurMaison/3.0") == []


def test_correlate_banner_version_exacte_openssh(populated_db):
    matches = correlate_banner(populated_db, "OpenSSH_8.3")
    assert [m.cve_id for m in matches] == ["CVE-2020-15778"]
    assert matches[0].cvss_score == 6.8

    assert correlate_banner(populated_db, "OpenSSH_8.4") == []


def test_correlate_banner_score_cvss_present_et_trie_desc(populated_db):
    matches = correlate_banner(populated_db, "Apache/2.4.49")
    scores = [m.cvss_score for m in matches]
    assert scores == sorted(scores, reverse=True)
    assert matches[0].cve_id == "CVE-2021-42013"  # score 9.8, le plus critique
    assert all(m.cvss_score is not None for m in matches)


def test_correlate_banner_expose_le_cpe_matche(populated_db):
    matches = correlate_banner(populated_db, "Apache/2.4.49")
    assert all(m.matched_cpe.startswith("cpe:2.3:a:apache:http_server:") for m in matches)


def test_correlate_versions_omet_les_bannieres_sans_correspondance(populated_db):
    result = correlate_versions(populated_db, ["Apache/2.4.49", "nginx/1.18.0", "Apache/2.4.48"])
    assert set(result.keys()) == {"Apache/2.4.49"}
    assert len(result["Apache/2.4.49"]) == 2


def test_correlate_versions_base_vide_ne_correle_rien(db_path):
    conn = connect_cve_db(db_path)
    assert correlate_versions(conn, ["Apache/2.4.49"]) == {}
    conn.close()
