"""
netcross_core.compliance -- evaluate_compliance() (Session 36, objets
ReferenceProfile/ComplianceResult de la Session 0). Verifie le calcul des
deux metriques du registre par defaut, le statut INDETERMINE sur une
metrique/operateur inconnu, et que le statut ne produit jamais DEVIATION
(nuance explicitement hors perimetre de cette session, voir docstring de
compliance.py).
"""

from netcross_core.compliance import DEFAULT_REFERENCES, evaluate_compliance
from netcross_core.expert_model import ReferenceProfile
from netcross_core.models import Report


def test_evaluate_compliance_conforme_quand_seuil_respecte():
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 0
    results = evaluate_compliance(r, [DEFAULT_REFERENCES[0]])
    assert results[0].status == "CONFORME"
    assert results[0].observed == 0.0


def test_evaluate_compliance_violation_quand_seuil_depasse():
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 2
    results = evaluate_compliance(r, [DEFAULT_REFERENCES[0]])
    assert results[0].status == "VIOLATION"
    assert results[0].observed == 2.0


def test_evaluate_compliance_loss_rate_pct_agrege_tous_les_points():
    r = Report(points=["A", "B"])
    r.seen_count["A"] = 100
    r.loss_count["A"] = 1
    r.seen_count["B"] = 100
    r.loss_count["B"] = 4
    ref = next(ref for ref in DEFAULT_REFERENCES if ref.metric == "loss_rate_pct")
    results = evaluate_compliance(r, [ref])
    assert results[0].observed == 2.5  # (1+4) / (100+100) * 100
    assert results[0].status == "VIOLATION"  # seuil par defaut : <= 1%


def test_evaluate_compliance_loss_rate_zero_paquet_vu():
    r = Report(points=["A"])
    ref = next(ref for ref in DEFAULT_REFERENCES if ref.metric == "loss_rate_pct")
    results = evaluate_compliance(r, [ref])
    assert results[0].observed == 0.0
    assert results[0].status == "CONFORME"


def test_evaluate_compliance_metrique_inconnue_indetermine():
    r = Report(points=["A"])
    ref = ReferenceProfile(id="x", metric="metrique_qui_n_existe_pas", operator="<=", threshold=1.0, unit="", source="")
    results = evaluate_compliance(r, [ref])
    assert results[0].status == "INDETERMINE"
    assert results[0].observed is None


def test_evaluate_compliance_operateur_inconnu_indetermine():
    r = Report(points=["A"])
    ref = ReferenceProfile(id="x", metric="loss_rate_pct", operator="???", threshold=1.0, unit="", source="")
    results = evaluate_compliance(r, [ref])
    assert results[0].status == "INDETERMINE"


def test_evaluate_compliance_jamais_de_deviation():
    # Nuance explicitement hors perimetre de cette session (voir docstring
    # de compliance.py) -- seuls CONFORME/VIOLATION/INDETERMINE sont
    # produits par cet evaluateur.
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 1
    results = evaluate_compliance(r, DEFAULT_REFERENCES)
    assert all(res.status != "DEVIATION" for res in results)


def test_evaluate_compliance_defaut_utilise_default_references():
    r = Report(points=["A"])
    results = evaluate_compliance(r)
    assert len(results) == len(DEFAULT_REFERENCES)


# -- Issue #706 : couverture des metriques de compliance ---------------------


class _FakeReport:
    """Fake report avec les attributs optionnels utilises par les metriques."""

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def test_metric_throughput_mbps_avec_donnees():
    """Lignes 72-80 : _metric_throughput_mbps avec des donnees valides."""
    from netcross_core.compliance import _metric_throughput_mbps

    r = _FakeReport(
        total_bytes={"A": 1_000_000, "B": 500_000},
        capture_duration={"A": 1.0, "B": 2.0},
    )
    result = _metric_throughput_mbps(r)
    assert result > 0


def test_metric_throughput_mbps_sans_donnees():
    """Lignes 72-80 : _metric_throughput_mbps retourne 0.0 si duration <= 0."""
    from netcross_core.compliance import _metric_throughput_mbps

    r = _FakeReport(
        total_bytes={"A": 1000},
        capture_duration={"A": 0.0},
    )
    result = _metric_throughput_mbps(r)
    assert result == 0.0


def test_metric_latency_ms_avec_donnees():
    """Lignes 85-92 : _metric_latency_ms avec des valeurs positives."""
    from netcross_core.compliance import _metric_latency_ms

    r = _FakeReport(latency_ms={("A", "B"): 10.0, ("B", "A"): 20.0})
    result = _metric_latency_ms(r)
    assert result == 15.0


def test_metric_latency_ms_sans_donnees():
    """Lignes 85-92 : _metric_latency_ms retourne 0.0 sans valeurs."""
    from netcross_core.compliance import _metric_latency_ms

    r = _FakeReport(latency_ms={})
    result = _metric_latency_ms(r)
    assert result == 0.0


def test_metric_jitter_ms_avec_donnees():
    """Ligne 96-103 : _metric_jitter_ms avec des valeurs positives."""
    from netcross_core.compliance import _metric_jitter_ms

    r = _FakeReport(jitter_ms={("A", "B"): 5.0, ("B", "A"): 3.0})
    result = _metric_jitter_ms(r)
    assert result == 4.0


def test_metric_jitter_ms_sans_donnees():
    """Ligne 96-103 : _metric_jitter_ms retourne 0.0 sans valeurs."""
    from netcross_core.compliance import _metric_jitter_ms

    r = _FakeReport(jitter_ms={})
    result = _metric_jitter_ms(r)
    assert result == 0.0
