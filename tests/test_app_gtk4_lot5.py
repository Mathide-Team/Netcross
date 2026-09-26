"""Couverture GTK4 de app.py, lot 5 (issue #426, sous-issue de #421).

Portee (lignes 1545-1718) : cycle de vie complet d'une capture en direct --
_on_live_duration_elapsed, _live_capture_worker, _end_live_capture,
_join_live_and_analyze, _reset_live_ui -- et _load_packets (lecture
sequentielle/parallele des captures fichier). Cette derniere methode n'est
appelee nulle part ailleurs dans le depot a ce jour (remplacee par la
fonction module-level `load_packets()` de analysis_pipeline.py, voir son
commentaire "Remplace MainWindow._load_packets") mais reste presente et non
couverte sur MainWindow : testee ici directement, sans passer par le thread
d'analyse qui l'appelait autrefois.

Threads reels (capture + jonction/analyse) avec des cibles monkeypatchees
(parse_live/parse_capture/parse_captures_parallel) pour rester rapide et
deterministe -- pas de vrai tshark/pcap. GLib.idle_add() est egalement
monkeypatche pour executer son callback immediatement : ces methodes
tournent sur des threads d'arriere-plan et planifient leurs mises a jour
d'UI sur la boucle principale GTK, qui ne tourne pas dans ces tests (pas de
Gtk.main()/GLib.MainLoop.run()) -- sans ce monkeypatch les callbacks
resteraient simplement en attente et les etats finaux (journal, widgets,
page affichee) ne seraient jamais observables.

Meme garde que tests/test_gui_security_window.py : ignore proprement si
GTK4/pygobject ou un affichage manquent (CI sans libgtk-4) -- aucun test de
ce fichier ne doit exiger GTK4 en CI.
"""

import itertools
import threading
import time

import pytest
from conftest import make_pkt

gi = pytest.importorskip("gi", reason="pygobject absent")
try:
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk
except (ValueError, ImportError):
    pytest.skip("GTK4 absent", allow_module_level=True)
if not Gtk.init_check():
    pytest.skip("pas d'affichage pour GTK4", allow_module_level=True)

from netcross_gtk4 import app as app_module  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402

_APP_COUNTER = 0


def _make_window():
    """Fenetre MainWindow fraiche, avec un identifiant d'application unique.

    Plusieurs tests en construisent chacun la leur (etat _live_* mute
    massivement d'un test a l'autre) ; un identifiant unique evite tout
    risque de collision entre applications GTK dans le meme processus (pas
    de bus D-Bus dans ce bac a sable, donc pas d'unicite globale imposee,
    mais autant ne pas en dependre).
    """
    global _APP_COUNTER
    _APP_COUNTER += 1
    app = Gtk.Application(application_id=f"org.netcross.test426.n{_APP_COUNTER}")
    app.register(None)
    return MainWindow(app)


@pytest.fixture
def window():
    return _make_window()


@pytest.fixture(autouse=True)
def _run_idle_synchronously(monkeypatch):
    """Voir la note en tete de fichier : execute immediatement les callbacks
    planifies via GLib.idle_add, comme le ferait la boucle principale."""

    def _immediate(func, *args, **kwargs):
        func(*args, **kwargs)
        return 0

    monkeypatch.setattr(app_module.GLib, "idle_add", _immediate)


def _wait_until(predicate, timeout=5.0, interval=0.01):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def _prepare_live_state(window, **overrides):
    """Reproduit l'etat minimal que _begin_live_capture() mettrait en place
    (attributs _live_* + widgets desactives), sans dependre des lignes de
    configuration (labels/interfaces reseau) -- hors de la portee de ce
    lot (voir lot 2/issue #423 pour LiveCaptureRow/CaptureListPanel)."""
    window._live_capturing = True
    window._live_stop_event = threading.Event()
    window._live_packets = []
    window._live_lock = threading.Lock()
    window._live_threads = []
    window._live_bucket_ms = 100.0
    window._live_rtp_rate = 50
    window._live_nat_tolerant = False
    window._live_triage = False
    window._live_triage_topn = 5
    window._live_points_order = None
    window._live_detect_duplicates = False
    window._live_exclude_duplicates = False
    window._live_duplicate_threshold_ms = 50.0
    for name, value in overrides.items():
        setattr(window, name, value)
    window.live_panel.set_sensitive(False)
    window.live_extra_box.set_sensitive(False)
    window.ring_buffer_box.set_sensitive(False)
    window.work_stop_btn.set_visible(True)
    window.work_stop_btn.set_sensitive(True)
    window.run_btn.set_label("Arreter et analyser")
    return window


def _sample_flow_packets():
    """Deux paquets d'un meme flux vus par deux points -- suffisant pour que
    correlate()/analyse() produisent un rapport reel non trivial."""
    return [
        make_pkt(point="A", src="10.0.0.5", dst="10.0.0.9", sport=51000, dport=443, seq=1000, ts=0.0),
        make_pkt(point="B", src="10.0.0.5", dst="10.0.0.9", sport=51000, dport=443, seq=1000, ts=0.01),
    ]


def _text(view):
    buf = view.get_buffer()
    return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)


# ================= _on_live_duration_elapsed =================


def test_duration_elapsed_arrete_la_session_courante(window, monkeypatch):
    calls = []
    monkeypatch.setattr(window, "_end_live_capture", lambda: calls.append(True))
    window._live_capturing = True
    window._live_session_id = 7

    result = window._on_live_duration_elapsed(7)

    assert calls == [True]
    assert result is False  # GLib.timeout_add_seconds : ne pas repeter le minuteur


def test_duration_elapsed_ignore_une_session_perimee(window, monkeypatch):
    """Garde-fou reellement present dans le code (`session_id ==
    self._live_session_id`, incremente a chaque _begin_live_capture) : si
    l'utilisateur a relance une capture entre-temps, _live_session_id a
    change et le minuteur de l'ancienne session ne doit pas arreter la
    nouvelle capture en cours."""
    calls = []
    monkeypatch.setattr(window, "_end_live_capture", lambda: calls.append(True))
    window._live_capturing = True
    window._live_session_id = 9  # une nouvelle capture a ete relancee depuis

    result = window._on_live_duration_elapsed(7)  # minuteur programme pour l'ancienne session 7

    assert calls == []
    assert result is False


def test_duration_elapsed_ignore_si_capture_deja_terminee(window, monkeypatch):
    calls = []
    monkeypatch.setattr(window, "_end_live_capture", lambda: calls.append(True))
    window._live_capturing = False
    window._live_session_id = 7

    result = window._on_live_duration_elapsed(7)

    assert calls == []
    assert result is False


# ================= _live_capture_worker =================


def test_live_capture_worker_s_arrete_proprement_sur_stop_event(window, monkeypatch):
    """Generateur infini respectant stop_event, comme le ferait un vrai
    parse_live() en train de suivre une interface -- prouve que le
    stop_event partage interrompt le thread sans le laisser actif a la fin
    du test."""

    def fake_parse_live(label, interface, bpf_filter=None, stop_event=None):
        seq = 0
        while not (stop_event is not None and stop_event.is_set()):
            yield make_pkt(point=label, seq=seq)
            seq += 1

    monkeypatch.setattr(app_module, "parse_live", fake_parse_live)
    window._live_stop_event = threading.Event()
    window._live_packets = []
    window._live_lock = threading.Lock()

    worker = threading.Thread(target=window._live_capture_worker, args=("A", "lo", None), daemon=True)
    worker.start()
    assert _wait_until(lambda: len(window._live_packets) >= 5)

    window._live_stop_event.set()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert len(window._live_packets) >= 5


def test_live_capture_worker_capture_l_erreur_sans_tuer_le_thread(window, monkeypatch):
    def fake_parse_live(label, interface, bpf_filter=None, stop_event=None):
        yield make_pkt(point=label, seq=0)
        raise RuntimeError("interface disparue")

    monkeypatch.setattr(app_module, "parse_live", fake_parse_live)
    window._live_stop_event = threading.Event()
    window._live_packets = []
    window._live_lock = threading.Lock()

    worker = threading.Thread(target=window._live_capture_worker, args=("A", "lo", "tcp port 80"), daemon=True)
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive()  # l'exception n'a pas tue le thread en silence
    assert len(window._live_packets) == 1
    assert "ERREUR : interface disparue" in _text(window.log_view)


def test_live_capture_worker_journalise_periodiquement(window, monkeypatch):
    """Une ligne de progression est journalisee des qu'au moins une seconde
    (temps reel, time.time()) s'est ecoulee depuis la precedente -- simule
    ici en monkeypatchant time.time() plutot qu'en attendant reellement,
    pour declencher la branche sans ralentir la suite."""

    def fake_parse_live(label, interface, bpf_filter=None, stop_event=None):
        for i in range(3):
            yield make_pkt(point=label, seq=i)

    monkeypatch.setattr(app_module, "parse_live", fake_parse_live)
    # Chaque appel avance l'horloge de 1.5 s : le seuil (>= 1.0 s) est
    # depasse a chaque paquet, quel que soit le nombre exact d'appels a
    # time.time() dans la methode.
    fake_clock = itertools.count(0.0, 1.5)
    monkeypatch.setattr(app_module.time, "time", lambda: next(fake_clock))
    window._live_stop_event = threading.Event()
    window._live_packets = []
    window._live_lock = threading.Lock()

    window._live_capture_worker("A", "lo", None)  # generateur fini : pas besoin d'un thread

    assert "paquets..." in _text(window.log_view)


# ================= _end_live_capture =================


def test_end_live_capture_ignore_si_pas_de_capture_en_cours(window):
    window._live_capturing = False
    window._live_stop_event = threading.Event()

    window._end_live_capture()  # retour anticipe : rien ne doit se declencher

    assert not window._live_stop_event.is_set()


def test_end_live_capture_ignore_si_deja_en_cours_d_arret(window, monkeypatch):
    """Double-clic (bouton config + bouton page Travail) : le second appel
    ne doit pas relancer un second thread de jonction/analyse sur les memes
    paquets."""
    _prepare_live_state(window)
    window._live_stop_event.set()  # arret deja engage par un premier appel

    def _echoue(*_args, **_kwargs):
        raise AssertionError("un second thread de jonction n'aurait pas du demarrer")

    monkeypatch.setattr(app_module.threading, "Thread", _echoue)
    window.run_btn.set_label("Arreter la capture")
    window.work_stop_btn.set_sensitive(True)

    window._end_live_capture()  # ne doit rien declencher (retour anticipe)

    # Le retour anticipe precede aussi toute mise a jour de l'interface.
    assert window.run_btn.get_label() == "Arreter la capture"
    assert window.work_stop_btn.get_sensitive()


def test_arret_manuel_et_arret_automatique_convergent(monkeypatch):
    """_end_live_capture() (bouton "Arreter et analyser") et
    _on_live_duration_elapsed() (duree maximale ecoulee) passent tous deux
    par le meme code d'arret -- ils doivent aboutir au meme etat final
    d'interface, cote lignes 1545-1718 de ce lot.

    _on_analysis_done est remplace par un espion inerte : son propre
    traitement (tableau de bord, etc.) est hors de la portee de ce lot --
    voir la note detaillee dans test_join_live_and_analyze_transition_vers_
    les_resultats juste apres, qui documente un defaut preexistant et sans
    rapport avec ce lot decouvert a cette occasion."""

    def run(trigger):
        w = _make_window()
        monkeypatch.setattr(w, "_on_analysis_done", lambda *a, **k: None)
        monkeypatch.setattr(app_module, "parse_live", lambda *a, **k: iter(_sample_flow_packets()))
        _prepare_live_state(w)
        worker = threading.Thread(target=w._live_capture_worker, args=("A", "lo", None), daemon=True)
        w._live_threads.append(worker)
        worker.start()
        worker.join(timeout=5)

        trigger(w)
        assert _wait_until(lambda: w._live_capturing is False)
        return w

    manuel = run(lambda w: w._end_live_capture())
    auto = run(lambda w: w._on_live_duration_elapsed(w._live_session_id))

    def etat(w):
        return {
            "live_capturing": w._live_capturing,
            "live_panel_sensible": w.live_panel.get_sensitive(),
            "live_extra_box_sensible": w.live_extra_box.get_sensitive(),
            "ring_buffer_box_sensible": w.ring_buffer_box.get_sensitive(),
            "work_stop_btn_visible": w.work_stop_btn.get_visible(),
            "work_stop_btn_sensible": w.work_stop_btn.get_sensitive(),
            "stop_event_arme": w._live_stop_event.is_set(),
        }

    assert etat(manuel) == etat(auto)
    assert etat(manuel)["stop_event_arme"] is True
    assert etat(manuel)["live_panel_sensible"] is True  # _reset_live_ui a reactive le panneau


# ================= _join_live_and_analyze =================


def test_join_live_and_analyze_transition_vers_les_resultats(window, monkeypatch):
    """Ne delegue PAS a _run_analysis_thread (verifie dans le code) : le
    pipeline (correlation/analyse/mise en forme) est reimplemente en ligne
    dans cette methode -- on verifie ici les valeurs qu'elle construit et
    transmet a _on_analysis_done, avec detection de doublons ET triage
    actives pour couvrir aussi ces deux branches optionnelles.

    _on_analysis_done est remplace par un espion plutot que laisse tourner
    reellement : son propre traitement (_refresh_dashboard ->
    build_dashboard_snapshot) est hors de la portee des lignes 1545-1718
    couvertes par ce lot, et s'est revele planter sur des flux realistes --
    `flows` transmis ici (et par le chemin fichier _run_analysis_thread /
    run_analysis_pipeline, meme constat) est le dict brut retourne par
    correlate() (cle -> {point: [Pkt]}), alors que build_dashboard_snapshot
    attend une list[Flow] (netcross_core.correlate.build_flows() n'est
    appelee nulle part sur ce chemin). Defaut preexistant, indépendant de ce
    lot et hors de son perimetre (pas de correction ici, cf. consigne
    'sans modifier le comportement') ; signale separement dans une issue
    dediee."""
    calls = []
    monkeypatch.setattr(window, "_on_analysis_done", lambda *a, **k: calls.append((a, k)))
    _prepare_live_state(
        window,
        _live_detect_duplicates=True,
        _live_triage=True,
        _live_duplicate_threshold_ms=50.0,
    )
    window._live_packets = _sample_flow_packets()

    window._join_live_and_analyze()

    assert len(calls) == 1
    args, kwargs = calls[0]
    assert kwargs == {}
    mode, _report, flows, findings, text, tls_findings, quic_findings, _expert_events = args
    assert mode == "single"
    assert len(flows) == 1  # un seul flux correle entre les points A et B
    assert findings is not None  # triage active : les Finding sont recalcules
    assert tls_findings is None
    assert quic_findings is None
    assert "TRIAGE" in text
    assert "Analyse terminee" in _text(window.log_view)
    assert window._live_capturing is False  # _reset_live_ui a bien tourne apres l'analyse


def test_join_live_and_analyze_remonte_l_erreur_et_reinitialise_l_ui(window, monkeypatch):
    def boom(*_args, **_kwargs):
        raise ValueError("flux corrompu")

    monkeypatch.setattr(app_module, "correlate", boom)
    _prepare_live_state(window)
    window._live_packets = _sample_flow_packets()

    window._join_live_and_analyze()

    assert "Erreur : flux corrompu" in window.work_status_label.get_text()
    assert window._live_capturing is False  # l'UI est quand meme reinitialisee (pas bloquee)
    assert window.stack.get_visible_child_name() != "results"
    assert "ERREUR : flux corrompu" in _text(window.log_view)


# ================= _reset_live_ui =================


def test_reset_live_ui_reactive_les_widgets_et_l_etat(window):
    _prepare_live_state(window)

    result = window._reset_live_ui()

    assert result is False
    assert window._live_capturing is False
    assert window.live_panel.get_sensitive() is True
    assert window.live_extra_box.get_sensitive() is True
    assert window.ring_buffer_box.get_sensitive() is True
    assert window.work_stop_btn.get_visible() is False
    assert window.work_stop_btn.get_sensitive() is True


# ================= _load_packets =================


def test_load_packets_sequentiel_agrege_dans_l_ordre(window, monkeypatch):
    calls = []

    def fake_parse_capture(label, path):
        calls.append((label, path))
        return [make_pkt(point=label)] * (2 if label == "A" else 3)

    monkeypatch.setattr(app_module, "parse_capture", fake_parse_capture)

    result = window._load_packets([("A", "a.pcap"), ("B", "b.pcap")], parallel=False)

    assert calls == [("A", "a.pcap"), ("B", "b.pcap")]
    assert len(result) == 5
    assert [p.point for p in result] == ["A", "A", "B", "B", "B"]
    assert "a.pcap" in _text(window.log_view)


def test_load_packets_parallele_journalise_succes_et_echec(window, monkeypatch):
    fake_packets = [make_pkt(point="A"), make_pkt(point="B")]
    stats = [
        {"label": "A", "error": None, "path": "a.pcap", "count": 1, "seconds": 0.01},
        {"label": "B", "error": "fichier illisible", "path": "b.pcap", "count": 0, "seconds": 0.0},
    ]
    monkeypatch.setattr(app_module, "parse_captures_parallel", lambda captures: (fake_packets, stats))

    result = window._load_packets([("A", "a.pcap"), ("B", "b.pcap")], parallel=True)

    assert result == fake_packets
    log = _text(window.log_view)
    assert "a.pcap" in log
    assert "ECHEC sur b.pcap : fichier illisible" in log


def test_load_packets_sequentiel_erreur_de_lecture_remonte(window, monkeypatch):
    """Contrairement au mode parallele (erreurs consignees par fichier dans
    per_file_stats, sans exception), le mode sequentiel n'a AUCUN
    try/except autour de parse_capture() (verifie dans le code) : une
    erreur de lecture doit remonter telle quelle a l'appelant plutot que de
    planter le thread silencieusement."""

    def fake_parse_capture(label, path):
        raise OSError("fichier illisible")

    monkeypatch.setattr(app_module, "parse_capture", fake_parse_capture)

    with pytest.raises(OSError, match="fichier illisible"):
        window._load_packets([("A", "a.pcap")], parallel=False)
