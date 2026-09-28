"""
netcross_core.alarms -- tests du moteur d'alarmes et surveillance de
seuils (§6.16, issue #26).

Tests ciblés sur le critère d'acceptation principal : une alarme ne se
déclenche PAS sur une valeur ponctuelle isolée. Tous les tests
utilisent des AlarmSignal synthétiques — aucune capture live nécessaire
(le moteur est déterministe et testable en pur Python).

Conventions de test calquées sur tests/test_rule_engine.py : noms en
français, docstrings explicites, un assert par comportement vérifié.
"""

from netcross_core.alarms import (
    AlarmConfig,
    AlarmEngine,
    AlarmSignal,
)


def _signal(rule_id: str, segment: str, value: float | None = None) -> AlarmSignal:
    """Fabrique un AlarmSignal de test avec une sévérité fixe."""
    return AlarmSignal(rule_id=rule_id, segment=segment, severity="anomalie", value=value)


def test_signal_isole_ne_leve_pas_alarme():
    """Un signal unique au milieu d'une fenêtre calme ne déclenche
    JAMAIS d'alarme, même si min_persistence_seconds est petit."""
    cfg = AlarmConfig(
        rule_id="loss_per_segment",
        segment="A",
        window_seconds=60.0,
        min_persistence_seconds=5.0,
        min_sample_ratio=0.5,
    )
    engine = AlarmEngine([cfg])

    # Cycle 0 : signal présent.
    engine.feed(0.0, [_signal("loss_per_segment", "A")])
    # Cycles 1 à 10 : silence.
    for t in range(1, 11):
        engine.feed(float(t), [])

    assert engine.events == []
    assert engine.active_alarms == []


def test_persistance_continue_leve_alarme():
    """Un signal présent à CHAQUE cycle pendant au moins
    min_persistence_seconds lève une alarme."""
    cfg = AlarmConfig(
        rule_id="loss_per_segment",
        segment="A",
        window_seconds=60.0,
        min_persistence_seconds=5.0,
        min_sample_ratio=0.5,
    )
    engine = AlarmEngine([cfg])

    # 10 cycles consécutifs avec signal.
    for t in range(10):
        engine.feed(float(t), [_signal("loss_per_segment", "A")])

    # L'alarme doit avoir été levée (à t=5 au plus tôt).
    raised = [e for e in engine.events if e.state == "raised"]
    assert len(raised) == 1
    assert raised[0].rule_id == "loss_per_segment"
    assert raised[0].segment == "A"
    assert raised[0].timestamp >= 5.0


def test_alarme_ne_se_redeclenche_pas_tant_que_non_clearée():
    """Une alarme déjà levée n'est pas re-émise à chaque cycle tant
    que la condition persiste — pas de flapping."""
    cfg = AlarmConfig(
        rule_id="saturation",
        segment="A",
        window_seconds=60.0,
        min_persistence_seconds=3.0,
        min_sample_ratio=0.5,
    )
    engine = AlarmEngine([cfg])

    for t in range(20):
        engine.feed(float(t), [_signal("saturation", "A")])

    raised = [e for e in engine.events if e.state == "raised"]
    assert len(raised) == 1  # un seul "raised", pas de re-déclenchement


def test_retour_a_la_normale_emet_cleared():
    """Quand le signal disparaît après une alarme levée, un événement
    "cleared" est émis."""
    cfg = AlarmConfig(
        rule_id="loss_per_segment",
        segment="A",
        window_seconds=30.0,
        min_persistence_seconds=3.0,
        min_sample_ratio=0.5,
    )
    engine = AlarmEngine([cfg])

    # Lever l'alarme.
    for t in range(10):
        engine.feed(float(t), [_signal("loss_per_segment", "A")])

    # Silence.
    for t in range(10, 15):
        engine.feed(float(t), [])

    cleared = [e for e in engine.events if e.state == "cleared"]
    assert len(cleared) == 1
    assert engine.active_alarms == []


def test_hysteresis_numerique_trigger_puis_clear():
    """Avec trigger_threshold et clear_threshold, l'alarme se lève
    au-dessus du trigger et se clear en dessous du clear (hystérésis) —
    un retour entre clear et trigger ne clear PAS."""
    cfg = AlarmConfig(
        rule_id="dns_slow_resolution",
        segment="global",
        window_seconds=60.0,
        min_persistence_seconds=2.0,
        min_sample_ratio=0.5,
        trigger_threshold=200.0,
        clear_threshold=100.0,
    )
    engine = AlarmEngine([cfg])

    # Valeurs au-dessus du trigger pendant 5 cycles → alarme levée.
    for t in range(5):
        engine.feed(float(t), [_signal("dns_slow_resolution", "global", value=250.0)])

    raised = [e for e in engine.events if e.state == "raised"]
    assert len(raised) == 1

    # Valeur entre clear et trigger (150) — ne doit PAS clearer.
    engine.feed(5.0, [_signal("dns_slow_resolution", "global", value=150.0)])
    cleared = [e for e in engine.events if e.state == "cleared"]
    assert len(cleared) == 0
    assert len(engine.active_alarms) == 1

    # Valeur sous le clear (50) — doit clearer.
    engine.feed(6.0, [_signal("dns_slow_resolution", "global", value=50.0)])
    cleared = [e for e in engine.events if e.state == "cleared"]
    assert len(cleared) == 1


def test_ratio_minimal_echantillons_positifs():
    """Avec min_sample_ratio=0.5, un signal présent moins de la moitié
    du temps ne lève pas d'alarme même sur une longue durée."""
    cfg = AlarmConfig(
        rule_id="loss_per_segment",
        segment="A",
        window_seconds=20.0,
        min_persistence_seconds=5.0,
        min_sample_ratio=0.5,
    )
    engine = AlarmEngine([cfg])

    # Alterne signal présent / absent (ratio 0.5 exact).
    for t in range(20):
        signals = [_signal("loss_per_segment", "A")] if t % 2 == 0 else []
        engine.feed(float(t), signals)

    # Ratio exactement 0.5 — l'alarme ne se lève pas car le dernier
    # échantillon négatif remet active_since à None périodiquement.
    raised = [e for e in engine.events if e.state == "raised"]
    assert len(raised) == 0


def test_fenetre_glissante_elimine_anciens_echantillons():
    """Les échantillons plus anciens que window_seconds sont éliminés —
    un signal ancien ne compte plus dans le ratio ni dans la
    persistance."""
    cfg = AlarmConfig(
        rule_id="loss_per_segment",
        segment="A",
        window_seconds=10.0,
        min_persistence_seconds=5.0,
        min_sample_ratio=0.5,
    )
    engine = AlarmEngine([cfg])

    # 3 cycles avec signal (t=0 à 2) — pas assez pour persistance (5s).
    for t in range(3):
        engine.feed(float(t), [_signal("loss_per_segment", "A")])
    assert engine.events == []

    # Long silence (t=3 à 20) — la fenêtre de 10s ne contient plus
    # que des échantillons négatifs, et active_since est reseté.
    for t in range(3, 21):
        engine.feed(float(t), [])

    # Puis 6 cycles avec signal (t=21 à 26) — persistance depuis t=21.
    for t in range(21, 27):
        engine.feed(float(t), [_signal("loss_per_segment", "A")])

    # L'alarme doit se lever à t=26 (persistance depuis t=21 = 5s).
    raised = [e for e in engine.events if e.state == "raised"]
    assert len(raised) == 1
    assert raised[0].timestamp >= 26.0


def test_segment_none_surveille_tous_les_segments():
    """Avec segment=None, la config surveille TOUS les segments
    rencontrés pour ce rule_id — un segment non vu n'est pas créé."""
    cfg = AlarmConfig(
        rule_id="loss_per_segment",
        segment=None,
        window_seconds=60.0,
        min_persistence_seconds=3.0,
        min_sample_ratio=0.5,
    )
    engine = AlarmEngine([cfg])

    for t in range(10):
        engine.feed(
            float(t),
            [
                _signal("loss_per_segment", "A"),
                _signal("loss_per_segment", "B"),
            ],
        )

    raised = [e for e in engine.events if e.state == "raised"]
    assert len(raised) == 2  # un par segment
    segments = {e.segment for e in raised}
    assert segments == {"A", "B"}


def test_signal_non_configure_est_ignore():
    """Un signal dont le rule_id ne correspond à aucune AlarmConfig est
    ignoré silencieusement."""
    cfg = AlarmConfig(rule_id="loss_per_segment", segment="A")
    engine = AlarmEngine([cfg])

    for t in range(10):
        engine.feed(float(t), [_signal("saturation", "A")])

    assert engine.events == []


def test_value_none_avec_trigger_threshold_est_negatif():
    """Si un trigger_threshold est défini mais le signal arrive sans
    value, l'échantillon est considéré négatif (prudence)."""
    cfg = AlarmConfig(
        rule_id="dns_slow_resolution",
        segment="global",
        trigger_threshold=200.0,
        min_persistence_seconds=2.0,
        min_sample_ratio=0.5,
    )
    engine = AlarmEngine([cfg])

    for t in range(10):
        engine.feed(float(t), [_signal("dns_slow_resolution", "global", value=None)])

    assert engine.events == []


def test_active_alarms_ne_garde_que_les_levees_non_clearées():
    """active_alarms reflète l'état courant — une alarme clearée
    n'apparaît plus."""
    cfg = AlarmConfig(
        rule_id="loss_per_segment",
        segment="A",
        min_persistence_seconds=2.0,
        min_sample_ratio=0.5,
    )
    engine = AlarmEngine([cfg])

    # Lever l'alarme.
    for t in range(5):
        engine.feed(float(t), [_signal("loss_per_segment", "A")])
    assert len(engine.active_alarms) == 1

    # Clearer.
    for t in range(5, 10):
        engine.feed(float(t), [])
    assert len(engine.active_alarms) == 0


def test_relever_apres_clear_possible():
    """Après un clear, une nouvelle persistance peut re-lever
    l'alarme."""
    cfg = AlarmConfig(
        rule_id="loss_per_segment",
        segment="A",
        min_persistence_seconds=2.0,
        min_sample_ratio=0.5,
    )
    engine = AlarmEngine([cfg])

    # Lever.
    for t in range(5):
        engine.feed(float(t), [_signal("loss_per_segment", "A")])
    # Clearer.
    for t in range(5, 10):
        engine.feed(float(t), [])
    # Re-lever.
    for t in range(10, 20):
        engine.feed(float(t), [_signal("loss_per_segment", "A")])

    raised = [e for e in engine.events if e.state == "raised"]
    assert len(raised) == 2  # deux cycles de lever/clear/re-lever


# -- Issue #752 : couverture ligne 320-321 de alarms.py -----------


def test_is_cleared_avec_value_none_retourne_false():
    """Lignes 320-321 : _is_cleared retourne False si value is None
    (clear_threshold defini mais valeur absente)."""
    from netcross_core.alarms import AlarmConfig, AlarmEngine

    cfg = AlarmConfig(
        rule_id="test",
        trigger_threshold=10,
        clear_threshold=5,
    )
    engine = AlarmEngine([cfg])
    # clear_threshold is not None, value is None -> return False
    result = engine._is_cleared(cfg, True, None)  # signal_present=True, value=None
    assert result is False
