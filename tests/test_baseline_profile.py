"""
tests/test_baseline_profile.py -- tests du profil de reference dynamique
(netcross_core.baseline_profile, Job 12/issue #9).

Verifie : construction de BaselineProfile, percentiles, lecture SQLite,
cas limites.
"""

import json
import sqlite3
import tempfile
from pathlib import Path

from netcross_core.baseline_profile import (
    build_baseline_profile,
    load_all_baselines,
    load_baseline_from_db,
)

# -- build_baseline_profile (pur calcul) -----------------------------------


def test_profile_vide_retourne_count_zero():
    profile = build_baseline_profile("test", [])
    assert profile.count == 0
    assert profile.mean == 0.0
    assert profile.median == 0.0
    assert profile.percentiles == {}


def test_profile_valeur_unique():
    profile = build_baseline_profile("test", [42.0])
    assert profile.count == 1
    assert profile.mean == 42.0
    assert profile.median == 42.0
    assert profile.min == 42.0
    assert profile.max == 42.0
    assert profile.variance == 0.0
    assert profile.std == 0.0


def test_profile_percentiles_calcules():
    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    profile = build_baseline_profile("test", values)
    assert profile.count == 10
    assert profile.mean == 5.5
    assert profile.median == 5.5
    assert profile.percentiles["P50"] == 5.5
    # P95 should be close to 9.55 (interpolation)
    assert 9.0 <= profile.percentiles["P95"] <= 10.0
    # P99 should be close to 9.91
    assert 9.0 <= profile.percentiles["P99"] <= 10.0


def test_profile_variance_ecart_type():
    values = [2.0, 4.0, 6.0, 8.0]
    profile = build_baseline_profile("test", values)
    assert profile.mean == 5.0
    # variance d'echantillon (n-1) = 20/3 ~ 6.667, std ~ 2.582
    assert abs(profile.variance - 6.667) < 0.01
    assert abs(profile.std - 2.582) < 0.01


def test_profile_min_max():
    values = [10.0, 5.0, 20.0, 1.0, 15.0]
    profile = build_baseline_profile("test", values)
    assert profile.min == 1.0
    assert profile.max == 20.0


def test_profile_values_triees():
    values = [3.0, 1.0, 2.0]
    profile = build_baseline_profile("test", values)
    assert profile.values == [1.0, 2.0, 3.0]


def test_profile_metric_name_preserve():
    profile = build_baseline_profile("health_score", [100.0])
    assert profile.metric == "health_score"


# -- Lecture SQLite --------------------------------------------------------


def _create_test_db(db_path: str, runs: list[dict]):
    """Cree une base SQLite de test avec le schema de history.py."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
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
        )
    """)
    for run in runs:
        conn.execute(
            "INSERT INTO runs (recorded_at, run_type, label, points, "
            "health_score, health_label, total_findings, finding_counts, meta) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run.get("recorded_at", "2026-01-01T00:00:00"),
                run.get("run_type", "analyse"),
                run.get("label"),
                run.get("points", "A,B"),
                run.get("health_score", 80),
                run.get("health_label", "bon"),
                run.get("total_findings", 5),
                json.dumps(run.get("finding_counts", {"anomalie": 1, "a_surveiller": 4})),
                json.dumps(run.get("meta", {})),
            ),
        )
    conn.commit()
    conn.close()


def test_load_baseline_health_score():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        _create_test_db(
            db_path,
            [
                {"health_score": 80, "total_findings": 5},
                {"health_score": 90, "total_findings": 3},
                {"health_score": 70, "total_findings": 8},
            ],
        )
        profile = load_baseline_from_db(db_path, "health_score")
        assert profile is not None
        assert profile.count == 3
        assert profile.mean == 80.0
        assert profile.median == 80.0
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_load_baseline_total_findings():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        _create_test_db(
            db_path,
            [
                {"health_score": 80, "total_findings": 5},
                {"health_score": 90, "total_findings": 3},
            ],
        )
        profile = load_baseline_from_db(db_path, "total_findings")
        assert profile is not None
        assert profile.count == 2
        assert profile.mean == 4.0
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_load_baseline_finding_count_severity():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        _create_test_db(
            db_path,
            [
                {"finding_counts": {"anomalie": 2, "a_surveiller": 3}},
                {"finding_counts": {"anomalie": 4, "a_surveiller": 1}},
            ],
        )
        profile = load_baseline_from_db(db_path, "finding_count:anomalie")
        assert profile is not None
        assert profile.count == 2
        assert profile.mean == 3.0
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_load_baseline_with_label_filter():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        _create_test_db(
            db_path,
            [
                {"health_score": 80, "label": "prod"},
                {"health_score": 90, "label": "staging"},
                {"health_score": 70, "label": "prod"},
            ],
        )
        profile = load_baseline_from_db(db_path, "health_score", label="prod")
        assert profile is not None
        assert profile.count == 2
        assert profile.mean == 75.0
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_load_baseline_with_limit():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        _create_test_db(
            db_path,
            [
                {"health_score": 80},
                {"health_score": 90},
                {"health_score": 70},
                {"health_score": 100},
                {"health_score": 60},
            ],
        )
        profile = load_baseline_from_db(db_path, "health_score", limit=3)
        assert profile is not None
        assert profile.count == 3  # seulement les 3 derniers
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_load_baseline_db_inexistante_retourne_none():
    profile = load_baseline_from_db("/nonexistent/path.db", "health_score")
    assert profile is None


def test_load_baseline_table_inexistante_retourne_none():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE other (id INTEGER)")
        conn.commit()
        conn.close()
        profile = load_baseline_from_db(db_path, "health_score")
        assert profile is None
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_load_baseline_metric_inexistante_retourne_none():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        _create_test_db(db_path, [{"health_score": 80}])
        profile = load_baseline_from_db(db_path, "nonexistent_metric")
        assert profile is None
    finally:
        Path(db_path).unlink(missing_ok=True)


# -- load_all_baselines ----------------------------------------------------


def test_load_all_baselines_retourne_plusieurs_profils():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        _create_test_db(
            db_path,
            [
                {"health_score": 80, "total_findings": 5, "finding_counts": {"anomalie": 1}},
                {"health_score": 90, "total_findings": 3, "finding_counts": {"anomalie": 0}},
            ],
        )
        profiles = load_all_baselines(db_path)
        assert len(profiles) >= 3  # health_score, total_findings, finding_count:anomalie
        metric_names = [p.metric for p in profiles]
        assert "health_score" in metric_names
        assert "total_findings" in metric_names
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_load_all_baselines_db_vide_retourne_liste_vide():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("""
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
            )
        """)
        conn.commit()
        conn.close()
        profiles = load_all_baselines(db_path)
        assert profiles == []
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_load_all_baselines_db_inexistante_retourne_liste_vide():
    profiles = load_all_baselines("/nonexistent/path.db")
    assert profiles == []


# -- Issue #689 : branches restantes ------------------------------------------


def test_percentile_liste_vide():
    """Lignes 77-78 : aucune valeur -> 0.0."""
    from netcross_core.baseline_profile import _percentile

    assert _percentile([], 50) == 0.0


def test_finding_counts_illisible_ignore():
    """Lignes 141-143 : JSON invalide -> seules les metriques de base."""
    from netcross_core.baseline_profile import _extract_metrics_from_row

    row = {"health_score": 70, "total_findings": 2, "finding_counts": "{pas du json"}
    assert _extract_metrics_from_row(row) == {"health_score": 70.0, "total_findings": 2.0}


def test_base_vide_filtre_label_et_table_absente():
    """Ligne 199 : base sans execution -> None ; lignes 238-239 : filtre par
    label ; ligne 244 : limite ; lignes 247-251 : table absente -> liste vide."""
    from netcross_core.baseline_profile import load_all_baselines, load_baseline_from_db

    with tempfile.TemporaryDirectory() as d:
        vide = str(Path(d) / "vide.db")
        _create_test_db(vide, [])
        assert load_baseline_from_db(vide) is None

        pleine = str(Path(d) / "pleine.db")
        _create_test_db(pleine, [{"label": "site-a", "health_score": 90}, {"label": "site-b", "health_score": 10}])
        profils = {p.metric: p for p in load_all_baselines(pleine, label="site-a")}
        assert profils["health_score"].values == [90.0]
        (dernier,) = [p for p in load_all_baselines(pleine, limit=1) if p.metric == "health_score"]
        assert dernier.values == [10.0]

        sans_table = str(Path(d) / "sans_table.db")
        sqlite3.connect(sans_table).close()
        assert load_all_baselines(sans_table) == []
