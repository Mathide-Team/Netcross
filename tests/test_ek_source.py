"""
pcap_parser.ek_source -- couche 1 (subprocess tshark). tshark n'etant
disponible dans aucun des environnements ou ce projet a ete developpe
jusqu'ici (voir claude.md, Sessions 1/3/4/5, "tshark non disponible dans
cet environnement" repete a chaque session), aucun test de ce fichier ne
le lance : on teste les fonctions pures (parsing du timestamp
nanoseconde, filtrage du flux NDJSON, construction des arguments de la
ligne de commande, verification de lisibilite de la capture) et, avec un
faux subprocess.Popen, iter_ek_records / _terminate_on_event -- y compris
leurs chemins d'erreur (arret force, kill, stderr illisible, code de
retour en echec). Couverture visee par l'issue #700 : 100 % lignes et
branches de ek_source.py.
"""

import io
import subprocess
import threading
from typing import ClassVar

import pytest

from pcap_parser import ek_source
from pcap_parser.ek_source import (
    CaptureAccessError,
    TsharkError,
    TsharkNotFoundError,
    _build_args,
    _iter_ndjson_records,
    _parse_frame_time_epoch,
    _terminate_on_event,
    check_capture_readable,
    iter_ek_records,
)

# -- _parse_frame_time_epoch -------------------------------------------


def test_parse_frame_time_epoch_nanoseconde():
    # verification independante via calendar.timegm plutot qu'un epoch
    # code en dur (fragile face aux erreurs de calcul manuel) :
    import calendar
    import datetime

    ts = _parse_frame_time_epoch("2026-08-20T20:19:51.632525000Z")
    expected_int = calendar.timegm(datetime.datetime(2026, 8, 20, 20, 19, 51, tzinfo=datetime.timezone.utc).timetuple())
    assert ts == pytest.approx(expected_int + 0.632525, abs=1e-6)


def test_parse_frame_time_epoch_sans_z_final():
    assert _parse_frame_time_epoch("2026-08-20T20:19:51.000000000") is not None


def test_parse_frame_time_epoch_none_ou_vide():
    assert _parse_frame_time_epoch(None) is None
    assert _parse_frame_time_epoch("") is None


def test_parse_frame_time_epoch_format_invalide():
    assert _parse_frame_time_epoch("pas-une-date") is None


def test_parse_frame_time_epoch_fraction_courte_completee_a_droite():
    # "123" nanosecondes -> 123 000 000 ns, pas 000 000 123 ns
    ts_court = _parse_frame_time_epoch("2026-01-01T00:00:00.123Z")
    ts_long = _parse_frame_time_epoch("2026-01-01T00:00:00.123000000Z")
    assert ts_court == ts_long


# -- _iter_ndjson_records -------------------------------------------------


def test_iter_ndjson_records_filtre_les_lignes_index():
    stream = io.StringIO(
        '{"index": {}}\n'
        '{"layers": {"ip": {}}, "timestamp": "1"}\n'
        '{"index": {}}\n'
        '{"layers": {"tcp": {}}, "timestamp": "2"}\n'
    )
    records = list(_iter_ndjson_records(stream))
    assert len(records) == 2
    assert records[0]["layers"] == {"ip": {}}
    assert records[1]["layers"] == {"tcp": {}}


def test_iter_ndjson_records_ignore_les_lignes_vides():
    stream = io.StringIO('\n\n{"layers": {}}\n\n')
    records = list(_iter_ndjson_records(stream))
    assert len(records) == 1


def test_iter_ndjson_records_ligne_corrompue_ne_casse_pas_le_flux():
    stream = io.StringIO('{"layers": {"a": 1}}\n{ceci n\'est pas du json\n{"layers": {"a": 2}}\n')
    records = list(_iter_ndjson_records(stream))
    assert [r["layers"]["a"] for r in records] == [1, 2]


# -- _build_args ------------------------------------------------------------


def test_build_args_exige_path_ou_interface_pas_les_deux():
    with pytest.raises(ValueError):
        _build_args()
    with pytest.raises(ValueError):
        _build_args(path="a.pcapng", interface="eth0")


def test_build_args_leve_si_tshark_absent(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(TsharkNotFoundError):
        _build_args(path="a.pcapng")


def test_build_args_mode_fichier(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    args = _build_args(path="a.pcapng")
    assert args[0] == "/usr/bin/tshark"
    assert "-r" in args and args[args.index("-r") + 1] == "a.pcapng"
    assert "-T" in args and args[args.index("-T") + 1] == "ek"
    # rtp.heuristic_rtp:TRUE doit toujours etre active par defaut
    assert "rtp.heuristic_rtp:TRUE" in args


def test_build_args_mode_live_avec_filtre_bpf(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    args = _build_args(interface="eth0", bpf_filter="tcp port 443")
    assert "-i" in args and args[args.index("-i") + 1] == "eth0"
    assert "-f" in args and args[args.index("-f") + 1] == "tcp port 443"
    assert "-l" in args  # flush ligne par ligne, indispensable en live


def test_build_args_filtre_affichage_prefs_scripts_lua_et_args_supplementaires(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    args = _build_args(
        path="a.pcapng",
        display_filter="tcp.analysis.flags",
        extra_prefs=("tcp.desegment_tcp_streams:FALSE",),
        lua_scripts=("/opt/x.lua",),
        extra_args=("-n",),
    )
    assert args[args.index("-Y") + 1] == "tcp.analysis.flags"
    assert "tcp.desegment_tcp_streams:FALSE" in args
    assert args[args.index("-X") + 1] == "lua_script:/opt/x.lua"
    assert "-f" not in args  # pas de filtre de capture en mode fichier sans bpf_filter
    # -T ek precede les arguments supplementaires, qui restent en queue
    assert args[-1] == "-n" and args.index("-T") < args.index("-n")


def test_build_args_lecture_via_stdin(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    args = _build_args(path="a.pcapng", read_via_stdin=True)
    assert args[args.index("-r") + 1] == "-"
    assert "a.pcapng" not in args


# -- check_capture_readable -------------------------------------------------


def test_check_capture_readable_fichier_lisible(tmp_path):
    f = tmp_path / "c.pcap"
    f.write_bytes(b"x")
    assert check_capture_readable(str(f)) is None


def test_check_capture_readable_introuvable(tmp_path):
    with pytest.raises(CaptureAccessError, match="introuvable"):
        check_capture_readable(str(tmp_path / "absent.pcap"))


def test_check_capture_readable_repertoire(tmp_path):
    with pytest.raises(CaptureAccessError, match="repertoire"):
        check_capture_readable(str(tmp_path))


def test_check_capture_readable_droits_insuffisants_avec_detail(tmp_path, monkeypatch):
    f = tmp_path / "c.pcap"
    f.write_bytes(b"x")
    f.chmod(0o640)
    # os.access est simule : sous root, un fichier 0o000 reste lisible
    monkeypatch.setattr(ek_source.os, "access", lambda path, mode: False)
    with pytest.raises(CaptureAccessError) as info:
        check_capture_readable(str(f))
    msg = str(info.value)
    assert "droits insuffisants" in msg
    assert "droits 640" in msg and "proprietaire uid" in msg
    assert "chmod u+r" in msg


def test_check_capture_readable_droits_insuffisants_stat_impossible(monkeypatch):
    # fichier "existant" mais dont le stat echoue (course : supprime entre-temps)
    monkeypatch.setattr(ek_source.os.path, "exists", lambda p: True)
    monkeypatch.setattr(ek_source.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(ek_source.os, "access", lambda path, mode: False)

    def _stat_echoue(path):
        raise OSError("disparu")

    monkeypatch.setattr(ek_source.os, "stat", _stat_echoue)
    with pytest.raises(CaptureAccessError) as info:
        check_capture_readable("/tmp/fantome.pcap")
    msg = str(info.value)
    assert "droits insuffisants pour lire /tmp/fantome.pcap." in msg  # pas de detail entre parentheses
    assert "proprietaire" not in msg


# -- _terminate_on_event ----------------------------------------------------


class _ProcSimple:
    """Sous-processus minimal pour _terminate_on_event."""

    pid = 4242

    def __init__(self, returncode):
        self.returncode = returncode
        self.terminated = 0

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated += 1


def test_terminate_on_event_termine_le_processus_vivant():
    proc = _ProcSimple(returncode=None)
    ev = threading.Event()
    ev.set()
    _terminate_on_event(proc, ev)
    assert proc.terminated == 1


def test_terminate_on_event_ne_touche_pas_un_processus_deja_termine():
    proc = _ProcSimple(returncode=0)
    ev = threading.Event()
    ev.set()
    _terminate_on_event(proc, ev)
    assert proc.terminated == 0


# -- iter_ek_records (tshark simule par un faux Popen) ---------------------

_LIGNE = '{"timestamp": "1500", "layers": {"frame": {"frame_frame_time_epoch": "2026-01-01T00:00:00.500000000Z"}}}\n'


class _FakePopen:
    """Remplace subprocess.Popen : stdout/stderr en memoire, code de retour
    et comportement de terminate()/wait() configurables."""

    instances: ClassVar[list] = []
    cfg: ClassVar[dict] = {}

    def __init__(self, args, **kwargs):
        cfg = _FakePopen.cfg
        self.args = list(args)
        self.kwargs = kwargs
        self.pid = 1234
        self.stdout = io.StringIO(cfg.get("stdout", ""))
        self.stderr = cfg.get("stderr", io.StringIO(""))
        self.returncode = cfg.get("returncode", 0)
        self._alive = cfg.get("alive", False)
        self._terminate_sets_returncode = cfg.get("terminate_sets_returncode", True)
        self._wait_timeouts = cfg.get("wait_timeouts", 0)
        self.terminated = False
        self.killed = False
        _FakePopen.instances.append(self)

    def poll(self):
        return None if self._alive else self.returncode

    def terminate(self):
        self.terminated = True
        if self._terminate_sets_returncode:
            self._alive = False
            self.returncode = -15

    def wait(self, timeout=None):
        if self._wait_timeouts > 0:
            self._wait_timeouts -= 1
            raise subprocess.TimeoutExpired(cmd="tshark", timeout=timeout)
        self._alive = False
        return self.returncode

    def kill(self):
        self.killed = True
        self._alive = False
        self.returncode = -9


@pytest.fixture
def faux_tshark(monkeypatch):
    """Installe le faux Popen ; ``faux_tshark(**cfg)`` le configure."""
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    _FakePopen.instances = []

    def configure(**cfg):
        _FakePopen.cfg = cfg
        return _FakePopen

    configure()
    return configure


def test_iter_ek_records_yield_un_enregistrement_avec_ts_nanoseconde(faux_tshark):
    faux_tshark(stdout=_LIGNE)
    recs = list(iter_ek_records(interface="eth0"))
    assert len(recs) == 1
    assert recs[0].ts == pytest.approx(1767225600.5)
    assert "frame" in recs[0].layers


def test_iter_ek_records_leve_si_fichier_illisible(faux_tshark, tmp_path):
    with pytest.raises(CaptureAccessError):
        list(iter_ek_records(path=str(tmp_path / "absent.pcap")))
    assert _FakePopen.instances == []  # tshark n'est jamais lance


def test_iter_ek_records_repli_sur_timestamp_racine_en_millisecondes(faux_tshark):
    faux_tshark(stdout='{"timestamp": "1500", "layers": {"ip": {}}}\n')
    (rec,) = list(iter_ek_records(interface="eth0"))
    assert rec.ts == 1.5


@pytest.mark.parametrize(
    "ligne",
    [
        '{"timestamp": "pas-un-nombre", "layers": {"frame": {}}}\n',  # ValueError
        '{"timestamp": null, "layers": {"frame": null}}\n',  # TypeError, frame absente
        '{"layers": {}}\n',  # ni frame ni timestamp
    ],
)
def test_iter_ek_records_horodatage_illisible_donne_zero(faux_tshark, ligne):
    faux_tshark(stdout=ligne)
    (rec,) = list(iter_ek_records(interface="eth0"))
    assert rec.ts == 0.0


def test_iter_ek_records_lecture_via_stdin_ferme_le_descripteur_parent(faux_tshark, tmp_path):
    f = tmp_path / "c.pcap"
    f.write_bytes(b"pcap")
    faux_tshark(stdout=_LIGNE)
    gen = iter_ek_records(path=str(f), read_via_stdin=True)
    next(gen)
    proc = _FakePopen.instances[0]
    assert proc.args[proc.args.index("-r") + 1] == "-"
    stdin = proc.kwargs["stdin"]
    assert stdin is not None and stdin.closed  # le parent a ferme sa copie du descripteur
    gen.close()


def test_iter_ek_records_mode_fichier_sans_stdin(faux_tshark, tmp_path):
    f = tmp_path / "c.pcap"
    f.write_bytes(b"pcap")
    faux_tshark(stdout=_LIGNE)
    list(iter_ek_records(path=str(f)))
    assert _FakePopen.instances[0].kwargs["stdin"] is None


def test_iter_ek_records_demarre_le_thread_daemon_de_stop_event(faux_tshark, monkeypatch):
    demarres = []

    class _FauxThread:
        def __init__(self, target, args, daemon):
            demarres.append((target, args, daemon))

        def start(self):
            demarres.append("start")

    monkeypatch.setattr(ek_source.threading, "Thread", _FauxThread)
    faux_tshark(stdout=_LIGNE)
    ev = threading.Event()
    list(iter_ek_records(interface="eth0", stop_event=ev))
    target, args, daemon = demarres[0]
    assert target is _terminate_on_event and daemon is True
    assert args[1] is ev and args[0] is _FakePopen.instances[0]
    assert demarres[1] == "start"


def test_iter_ek_records_sans_stop_event_aucun_thread(faux_tshark, monkeypatch):
    def _interdit(*a, **k):
        raise AssertionError("aucun thread attendu sans stop_event")

    monkeypatch.setattr(ek_source.threading, "Thread", _interdit)
    faux_tshark(stdout=_LIGNE)
    assert len(list(iter_ek_records(interface="eth0"))) == 1


def test_iter_ek_records_fermeture_precoce_termine_tshark_vivant(faux_tshark):
    faux_tshark(stdout=_LIGNE * 3, alive=True)
    gen = iter_ek_records(interface="eth0")
    next(gen)
    gen.close()  # GeneratorExit -> finally
    proc = _FakePopen.instances[0]
    assert proc.terminated and not proc.killed


def test_iter_ek_records_kill_si_tshark_ne_sarrete_pas(faux_tshark):
    faux_tshark(stdout=_LIGNE, alive=True, terminate_sets_returncode=False, wait_timeouts=1)
    list(iter_ek_records(interface="eth0"))
    proc = _FakePopen.instances[0]
    assert proc.terminated and proc.killed


def test_iter_ek_records_echec_sans_paquet_leve_tsharkerror(faux_tshark):
    faux_tshark(returncode=2, stderr=io.StringIO("  permission denied\n"))
    with pytest.raises(TsharkError) as info:
        list(iter_ek_records(interface="eth0"))
    assert info.value.returncode == 2
    assert info.value.stderr == "  permission denied\n"
    assert "code 2" in str(info.value) and "permission denied" in str(info.value)


def test_iter_ek_records_echec_apres_des_paquets_ne_leve_pas(faux_tshark):
    faux_tshark(stdout=_LIGNE, returncode=2, stderr=io.StringIO("avertissement"))
    assert len(list(iter_ek_records(interface="eth0"))) == 1


@pytest.mark.parametrize("code", [0, -15])
def test_iter_ek_records_codes_normaux_sans_paquet_ne_levent_pas(faux_tshark, code):
    # 0 : fichier vide ; -15 : SIGTERM envoye par nous-memes en live
    faux_tshark(returncode=code)
    assert list(iter_ek_records(interface="eth0")) == []


def test_iter_ek_records_code_indetermine_ne_leve_pas(faux_tshark):
    # processus vivant que terminate() ne fait pas sortir : returncode reste None
    faux_tshark(alive=True, returncode=None, terminate_sets_returncode=False)
    assert list(iter_ek_records(interface="eth0")) == []


@pytest.mark.parametrize("erreur", [OSError("pipe fermee"), ValueError("I/O on closed file")])
def test_iter_ek_records_lecture_stderr_best_effort(faux_tshark, erreur):
    class _StderrCasse:
        def read(self):
            raise erreur

    faux_tshark(returncode=1, stderr=_StderrCasse())
    with pytest.raises(TsharkError) as info:
        list(iter_ek_records(interface="eth0"))
    assert info.value.stderr == ""  # l'echec de lecture ne masque pas l'erreur tshark


def test_iter_ek_records_stderr_absent(faux_tshark):
    faux_tshark(returncode=3, stderr=None)
    with pytest.raises(TsharkError) as info:
        list(iter_ek_records(interface="eth0"))
    assert info.value.returncode == 3 and info.value.stderr == ""
