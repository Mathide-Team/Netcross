"""tests/test_live_diff.py — Capture en continu + diff en direct (Job 33, issue #33).

Tests du module netcross_core.live_diff : conversion DiffFinding -> AlarmSignal,
fenetre glissante, evaluation periodique du diff, integration AlarmEngine.
Integration CaptureRingBuffer (Job 37, issue #157) en bas de fichier.
"""

import time
from importlib import import_module

import pytest

from netcross_core.alarms import AlarmConfig, AlarmEngine
from netcross_core.baseline_diff import DiffFinding
from netcross_core.live_diff import (
    LiveDiffConfig,
    LiveDiffEngine,
    LiveDiffState,
    finding_to_alarm_signal,
)
from netcross_core.models import Pkt, Report
from pcap_parser.capture import CaptureRingBuffer
from pcap_parser.ek_source import TsharkError


def _stub_analyse_et_correlate(monkeypatch):
    """Remplace correlate()/analyse() par des stubs pour isoler le cablage de
    _evaluate_diff(). Les cibles sont les VRAIS modules (via import_module),
    pas des chemins pointilles "netcross_core.correlate.correlate" : le
    package netcross_core re-exporte les fonctions correlate/analyse, qui
    eclipsent les sous-modules du meme nom et font echouer monkeypatch."""
    monkeypatch.setattr(import_module("netcross_core.correlate"), "correlate", lambda pkts: {})
    monkeypatch.setattr(
        import_module("netcross_core.analysis"),
        "analyse",
        lambda flows, points_order=None, all_packets=None: Report(points=["LAN"]),
    )


def _pkt(**kw):
    base = dict(  # noqa: C408
        point="LAN",
        ts=1.0,
        frame_number=1,
        proto="TCP",
        src="10.0.0.1",
        dst="10.0.0.2",
        sport=50000,
        dport=80,
        length=100,
        ttl=64,
        dscp=0,
        ecn=0,
        seq=1,
        ack=0,
        window=1000,
        flags=None,
        key_id=1,
        payload_hash=None,
        ip_id=1,
        is_fragment=False,
        df=False,
        is_retransmission=False,
        is_fast_retransmission=False,
        is_spurious_retransmission=False,
        mss_val=None,
        wscale_shift=None,
        sack_permitted=False,
        icmp_type=None,
        icmp_code=None,
        icmpv6_type=None,
        icmpv6_code=None,
        arp_opcode=None,
        arp_sender_mac=None,
        arp_is_gratuitous=False,
        stp_bpdu_type=None,
        stp_flags_tc=False,
        stp_root_id=None,
        tls_cert_not_before=None,
        tls_cert_not_after=None,
        tls_cert_san=None,
        tls_cert_serial=None,
        tls_cert_issuer=None,
        tls_cert_subject=None,
        tls_cert_sig_hash=None,
        tls_cert_key_type=None,
        tls_cert_key_bits=None,
        tls_cert_san_ip=None,
        tls_cert_chain_len=None,
        tls_client_hello=False,
        tls_server_hello=False,
        tls_application_data=False,
        vlan_id=None,
        vlan_prio=None,
        is_rtp=False,
        rtp_seq=None,
        rtp_ts=None,
        rtp_ssrc=None,
        encap_tags=(),
        dhcp_xid=None,
        dhcp_msg_type=None,
        dhcp_server_id=None,
        dhcp_vendor_class=None,
        sip_call_id=None,
        sip_msg_type=None,
        sip_cseq=None,
        sip_user_agent=None,
        sip_server=None,
        dns_txn_id=None,
        dns_is_response=False,
        dns_qry_name=None,
        dns_rcode=None,
        http_is_request=False,
        http_is_response=False,
        http_method=None,
        http_uri=None,
        http_status_code=None,
        http_response_time_ms=None,
        expert_flags=(),
        expert_details=(),
    )
    base.update(kw)
    return Pkt(**base)


def test_finding_to_alarm_signal_conversion():
    finding = DiffFinding(
        severity="anomalie",
        category="loss_per_segment",
        segment="LAN -> WAN",
        message="Perte 5%",
        before=1.0,
        after=5.0,
        sample_size=1000,
        evidence=[],
    )
    signal = finding_to_alarm_signal(finding)
    assert signal.rule_id == "loss_per_segment"
    assert signal.segment == "LAN -> WAN"
    assert signal.severity == "anomalie"
    assert signal.value == 5.0


def test_finding_to_alarm_signal_with_segment_override():
    finding = DiffFinding(
        severity="a_surveiller",
        category="latency_high",
        segment="LAN -> WAN",
        message="Latence elevee",
        before=50.0,
        after=150.0,
        sample_size=500,
        evidence=[],
    )
    signal = finding_to_alarm_signal(finding, segment="custom")
    assert signal.segment == "custom"


def test_live_diff_config_defaults():
    config = LiveDiffConfig()
    assert config.eval_interval_seconds == 5.0
    assert config.window_seconds == 60.0
    assert config.max_packets_per_window == 100000
    assert config.min_packets_for_diff == 100


def test_live_diff_config_custom():
    config = LiveDiffConfig(
        eval_interval_seconds=10.0,
        window_seconds=120.0,
        max_packets_per_window=50000,
        min_packets_for_diff=50,
    )
    assert config.eval_interval_seconds == 10.0
    assert config.window_seconds == 120.0
    assert config.max_packets_per_window == 50000
    assert config.min_packets_for_diff == 50


def test_live_diff_state_defaults():
    state = LiveDiffState()
    assert state.running is False
    assert len(state.packets_in_window) == 0
    assert state.last_eval_ts == 0.0
    assert state.last_diff_count == 0
    assert state.total_evaluations == 0


def test_live_diff_engine_creation():
    baseline = Report(points=["LAN", "WAN"])
    engine = LiveDiffEngine(baseline_report=baseline)
    assert engine.baseline is baseline
    assert isinstance(engine.alarm_engine, AlarmEngine)
    assert engine.state.running is False


def test_live_diff_engine_with_custom_alarm_engine():
    baseline = Report(points=["LAN"])
    custom_alarm = AlarmEngine([])
    engine = LiveDiffEngine(
        baseline_report=baseline,
        alarm_engine=custom_alarm,
    )
    assert engine.alarm_engine is custom_alarm


def test_live_diff_engine_start_stop():
    baseline = Report(points=["LAN"])
    engine = LiveDiffEngine(baseline_report=baseline)
    # On ne peut pas tester start() sans une vraie interface reseau.
    # On verifie juste que stop() sur un engine non demarre ne crash pas.
    engine.stop()


def test_live_diff_engine_start_twice_raises():
    baseline = Report(points=["LAN"])
    engine = LiveDiffEngine(baseline_report=baseline)
    # Simuler un engine deja en cours
    engine.state.running = True
    try:
        engine.start("eth0")
        raise AssertionError("RuntimeError attendu")
    except RuntimeError:
        pass
    finally:
        engine.state.running = False


def test_add_packet_respects_window():
    """La fenetre glissante doit eliminer les paquets trop anciens."""
    baseline = Report(points=["LAN"])
    engine = LiveDiffEngine(
        baseline_report=baseline,
        config=LiveDiffConfig(window_seconds=2.0),
    )
    # Ajouter des paquets avec des timestamps croissants
    for i in range(10):
        engine._add_packet(_pkt(ts=float(i), frame_number=i + 1))

    # Le paquet le plus ancien (ts=0) doit etre elimine car la fenetre
    # est de 2s et le dernier paquet a ts=9
    assert all(p.ts >= 7.0 for p in engine.state.packets_in_window)


def test_add_packet_respects_max_packets():
    """La limite de paquets doit etre respectee."""
    baseline = Report(points=["LAN"])
    engine = LiveDiffEngine(
        baseline_report=baseline,
        config=LiveDiffConfig(max_packets_per_window=5),
    )
    for i in range(20):
        engine._add_packet(_pkt(ts=float(i), frame_number=i + 1))

    assert len(engine.state.packets_in_window) <= 5


def test_evaluate_diff_skipped_with_too_few_packets():
    """L'evaluation doit etre sautee si pas assez de paquets."""
    baseline = Report(points=["LAN"])
    engine = LiveDiffEngine(
        baseline_report=baseline,
        config=LiveDiffConfig(min_packets_for_diff=100),
    )
    engine._add_packet(_pkt(ts=1.0, frame_number=1))
    findings = engine._evaluate_diff()
    assert findings == []
    assert engine.state.total_evaluations == 1
    assert engine.state.last_diff_count == 0


def test_evaluate_diff_increments_total_evaluations():
    """Chaque appel a _evaluate_diff doit incrementer total_evaluations."""
    baseline = Report(points=["LAN"])
    engine = LiveDiffEngine(
        baseline_report=baseline,
        config=LiveDiffConfig(min_packets_for_diff=1),
    )
    engine._add_packet(_pkt(ts=1.0, frame_number=1))
    engine._evaluate_diff()
    assert engine.state.total_evaluations == 1


def test_evaluate_diff_produces_findings_and_raises_alarm(monkeypatch):
    """Critere d'acceptation de l'issue #33 : le diff entre le baseline
    et la fenetre live doit etre visible en temps reel -- jusqu'a la
    notification (Job 26 / AlarmEngine), pas seulement calcule puis
    jete. Isole le pipeline analyse()/correlate()/diff_reports() pour
    verifier le CABLAGE de _evaluate_diff() plutot que la logique
    d'analyse elle-meme (deja testee ailleurs : test_analysis.py,
    test_baseline_diff.py)."""
    baseline = Report(points=["LAN"])

    fake_finding = DiffFinding(
        severity="anomalie",
        category="loss_per_segment",
        segment="LAN -> WAN",
        message="Perte 8% (baseline 0%)",
        before=0.0,
        after=8.0,
        sample_size=200,
        evidence=[],
    )

    monkeypatch.setattr(
        "netcross_core.live_diff.diff_reports",
        lambda base, current: [fake_finding],
    )
    _stub_analyse_et_correlate(monkeypatch)

    # min_persistence_seconds=0.0 : une seule evaluation positive suffit
    # a lever l'alarme -- suffisant pour verifier le cablage bout en
    # bout, la persistance/hysteresis elle-meme etant testee dans
    # test_alarms.py.
    alarm_engine = AlarmEngine(
        [AlarmConfig(rule_id="loss_per_segment", segment="LAN -> WAN", min_persistence_seconds=0.0)]
    )
    notified = []
    engine = LiveDiffEngine(
        baseline_report=baseline,
        config=LiveDiffConfig(min_packets_for_diff=1),
        alarm_engine=alarm_engine,
        on_alarm=notified.append,
    )
    engine._add_packet(_pkt(ts=1.0, frame_number=1))

    findings = engine._evaluate_diff()

    assert findings == [fake_finding]
    assert engine.state.last_diff_count == 1
    assert len(alarm_engine.active_alarms) == 1
    assert notified and notified[0].state == "raised"
    assert notified[0].rule_id == "loss_per_segment"
    assert notified[0].segment == "LAN -> WAN"


def test_evaluate_diff_sans_divergence_ne_leve_aucune_alarme(monkeypatch):
    """Controle negatif du test precedent : sans DiffFinding, aucun
    AlarmSignal n'est transmis au AlarmEngine et aucune notification
    n'est emise."""
    baseline = Report(points=["LAN"])

    monkeypatch.setattr("netcross_core.live_diff.diff_reports", lambda base, current: [])
    _stub_analyse_et_correlate(monkeypatch)

    alarm_engine = AlarmEngine(
        [AlarmConfig(rule_id="loss_per_segment", segment="LAN -> WAN", min_persistence_seconds=0.0)]
    )
    notified = []
    engine = LiveDiffEngine(
        baseline_report=baseline,
        config=LiveDiffConfig(min_packets_for_diff=1),
        alarm_engine=alarm_engine,
        on_alarm=notified.append,
    )
    engine._add_packet(_pkt(ts=1.0, frame_number=1))

    findings = engine._evaluate_diff()

    assert findings == []
    assert alarm_engine.active_alarms == []
    assert notified == []


# -- Integration CaptureRingBuffer (Job 37, issue #157) -----------------------


def test_add_packet_sans_ring_buffer_ne_fait_rien_de_special():
    """Controle negatif : sans ring_buffer (defaut), _add_packet ne doit
    ni planter ni creer quoi que ce soit -- comportement inchange."""
    baseline = Report(points=["LAN"])
    engine = LiveDiffEngine(baseline_report=baseline)
    assert engine.ring_buffer is None
    engine._add_packet(_pkt(ts=1.0, frame_number=1))  # ne doit pas lever


def test_add_packet_avance_le_ring_buffer_sur_le_temps_de_capture(tmp_path):
    """_add_packet doit avancer l'horloge du ring buffer sur pkt.ts (meme
    convention que la fenetre glissante), sans interrompre le diff live :
    plusieurs paquets espaces de plus de max_duration_per_file doivent
    declencher des rotations successives."""
    baseline = Report(points=["LAN"])
    ring = CaptureRingBuffer(str(tmp_path), max_duration_per_file=5.0, max_files=2)
    engine = LiveDiffEngine(baseline_report=baseline, ring_buffer=ring)

    engine._add_packet(_pkt(ts=0.0, frame_number=1))
    assert len(ring.files) == 1
    first = ring.current_path

    engine._add_packet(_pkt(ts=1.0, frame_number=2))  # < 5s depuis la 1ere rotation
    assert ring.current_path == first
    assert len(ring.files) == 1

    engine._add_packet(_pkt(ts=6.0, frame_number=3))  # >= 5s -- nouvelle rotation
    assert ring.current_path != first
    assert len(ring.files) == 2  # max_files=2 pas encore depasse (2 fichiers ouverts au total)
    assert first in ring.files

    engine._add_packet(_pkt(ts=12.0, frame_number=4))  # encore une rotation -- 3e fichier
    assert len(ring.files) == 2  # max_files atteint, le plus ancien a ete purge
    assert first not in ring.files


# -- start / start_multi : sources de capture live (Job 48, issue #168) --------
# parse_live / parse_live_multi sont remplaces par de faux generateurs qui
# rendent quelques paquets puis "capturent" jusqu'a stop_event -- jamais de
# tshark reel. On verifie le cablage de l'engine (arguments, thread, arret),
# pas la capture elle-meme (voir tests/test_capture.py).


def _wait_until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def _live_source(packets, stop_event, then_raise=None):
    """Faux flux live : rend `packets`, puis leve `then_raise` (interface en
    erreur) ou attend stop_event (capture qui continue jusqu'a l'arret)."""
    yield from packets
    if then_raise is not None:
        raise then_raise
    stop_event.wait(5.0)


def test_start_multi_consomme_les_paquets_etiquetes_et_s_arrete_sur_stop(monkeypatch):
    seen = {}

    def fake_parse_live_multi(interfaces, stop_event=None, *, bpf_filter=None):
        seen.update(interfaces=list(interfaces), stop_event=stop_event, bpf_filter=bpf_filter)
        return _live_source([_pkt(point="LAN", ts=1.0), _pkt(point="WAN", ts=1.5)], stop_event)

    monkeypatch.setattr("netcross_core.parsing.parse_live_multi", fake_parse_live_multi)
    engine = LiveDiffEngine(baseline_report=Report(points=["LAN", "WAN"]))

    engine.start_multi([("LAN", "eth0"), ("WAN", "eth1")], bpf_filter="tcp")
    try:
        assert _wait_until(lambda: len(engine.state.packets_in_window) == 2)
        assert engine.state.running is True
    finally:
        engine.stop()

    assert [p.point for p in engine.state.packets_in_window] == ["LAN", "WAN"]
    assert engine.state.running is False
    assert seen["interfaces"] == [("LAN", "eth0"), ("WAN", "eth1")]
    assert seen["bpf_filter"] == "tcp"
    # l'arret de l'engine est bien celui que la capture multi-interfaces surveille
    assert seen["stop_event"] is engine._stop_event


def test_start_multi_valide_ses_arguments_avant_de_demarrer():
    engine = LiveDiffEngine(baseline_report=Report(points=["LAN"]))

    with pytest.raises(ValueError, match="au moins une interface"):
        engine.start_multi([])
    with pytest.raises(ValueError, match="en double"):
        engine.start_multi([("LAN", "eth0"), ("LAN", "eth1")])

    # echec propre : aucun thread lance, l'engine reste utilisable
    assert engine.state.running is False
    assert engine._thread is None


def test_start_multi_refuse_un_second_demarrage(monkeypatch):
    monkeypatch.setattr(
        "netcross_core.parsing.parse_live_multi",
        lambda interfaces, stop_event=None, *, bpf_filter=None: _live_source([], stop_event),
    )
    engine = LiveDiffEngine(baseline_report=Report(points=["LAN"]))
    engine.start_multi([("LAN", "eth0")])
    try:
        with pytest.raises(RuntimeError, match="deja en cours"):
            engine.start_multi([("LAN", "eth0")])
        with pytest.raises(RuntimeError, match="deja en cours"):
            engine.start("eth0")
    finally:
        engine.stop()


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_start_multi_interface_en_erreur_arrete_l_engine(monkeypatch):
    # l'erreur remonte (elle est levee dans le thread de capture, donc affichee
    # par le hook des threads) et l'engine ne reste pas "running" a comparer
    # au baseline des donnees auxquelles il manque un point
    monkeypatch.setattr(
        "netcross_core.parsing.parse_live_multi",
        lambda interfaces, stop_event=None, *, bpf_filter=None: _live_source(
            [_pkt(point="LAN", ts=1.0)],
            stop_event,
            then_raise=TsharkError("interface inconnue", returncode=1, stderr=""),
        ),
    )
    engine = LiveDiffEngine(baseline_report=Report(points=["LAN", "WAN"]))
    engine.start_multi([("LAN", "eth0"), ("WAN", "eth1")])
    try:
        assert _wait_until(lambda: engine.state.running is False)
    finally:
        engine.stop()
    assert engine.state.running is False


def test_start_une_interface_utilise_l_interface_comme_label(monkeypatch):
    # non-regression du refactor start/_run/_consume : le mode une interface
    # continue de passer par parse_live, avec label == interface
    seen = {}

    def fake_parse_live(label, interface, bpf_filter=None, stop_event=None):
        seen.update(label=label, interface=interface, bpf_filter=bpf_filter, stop_event=stop_event)
        return _live_source([_pkt(point=label, ts=1.0)], stop_event)

    monkeypatch.setattr("netcross_core.parsing.parse_live", fake_parse_live)
    engine = LiveDiffEngine(baseline_report=Report(points=["eth0"]))

    engine.start("eth0", bpf_filter="udp")
    try:
        assert _wait_until(lambda: len(engine.state.packets_in_window) == 1)
    finally:
        engine.stop()

    assert (seen["label"], seen["interface"], seen["bpf_filter"]) == ("eth0", "eth0", "udp")
    assert seen["stop_event"] is engine._stop_event
    assert engine.state.packets_in_window[0].point == "eth0"
    assert engine.state.running is False



# -- Issue #759 : couverture lignes 245, 253->255 de live_diff.py ----------


def test_consume_arrete_sur_stop_event():
    """Ligne 245 : _consume s'arrete quand stop_event est set."""
    from netcross_core.live_diff import LiveDiffEngine, LiveDiffConfig
    from conftest import make_pkt

    config = LiveDiffConfig(eval_interval_seconds=999)
    engine = LiveDiffEngine(config)
    engine.state.running = True
    engine._stop_event.set()  # stop_event actif des le depart

    pkts = iter([make_pkt(point="A", sport=1), make_pkt(point="B", sport=1)])
    engine._consume(pkts)

    # Le premier paquet n'est jamais ajoute car break avant _add_packet
    assert len(engine.state.packets_in_window) == 0


def test_consume_exception_avec_running_false():
    """Branche 253->255 : exception dans _consume avec running=False
    (saute le self.state.running = False)."""
    from netcross_core.live_diff import LiveDiffEngine, LiveDiffConfig
    from conftest import make_pkt

    config = LiveDiffConfig(eval_interval_seconds=999)
    engine = LiveDiffEngine(config)
    engine.state.running = False  # deja False -> saute la ligne 254

    # Provoque une exception en passant un iterateur qui leve
    def bad_packets():
        yield make_pkt(point="A", sport=1)
        raise RuntimeError("boom")

    try:
        engine._consume(bad_packets())
        assert False, "devrait lever RuntimeError"
    except RuntimeError:
        pass

    # running reste False (n'a pas ete re-set a False car deja False)
    assert engine.state.running is False

