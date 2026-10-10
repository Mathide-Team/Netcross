"""Issue #676 : --ring-buffer enregistre reellement la capture en rotation.

Avant ce correctif, l'option creait des repertoires temporaires vides et
faisait avancer l'horloge d'un CaptureRingBuffer sans jamais ecrire une
trame. Desormais un tshark d'enregistrement par point utilise le ring
buffer natif de tshark (-w ... -b files:N -b duration:S).
"""

import os
import signal
import subprocess
import sys

import pytest

from pcap_parser import capture
from pcap_parser.remote import CaptureSourceError


@pytest.fixture(autouse=True)
def _fake_tshark(monkeypatch):
    monkeypatch.setattr(capture, "_tshark_path", lambda: "/usr/bin/tshark")


def test_args_interface_locale():
    args = capture.ring_recorder_args("eth0", "/tmp/rb", max_files=5, max_duration_per_file=60, prefix="LAN")
    assert args == [
        "/usr/bin/tshark",
        "-i",
        "eth0",
        "-q",
        "-w",
        os.path.join("/tmp/rb", "LAN.pcapng"),
        "-b",
        "files:5",
        "-b",
        "duration:60",
    ]


def test_args_filtre_bpf():
    args = capture.ring_recorder_args(
        "eth0", "/tmp/rb", max_files=2, max_duration_per_file=10, bpf_filter="tcp port 443"
    )
    i = args.index("-f")
    assert args[i + 1] == "tcp port 443"
    assert args.index("-f") < args.index("-w")


def test_args_duree_arrondie_a_l_entier_superieur():
    args = capture.ring_recorder_args("eth0", "/tmp/rb", max_files=3, max_duration_per_file=30.5)
    assert "duration:31" in args
    args = capture.ring_recorder_args("eth0", "/tmp/rb", max_files=3, max_duration_per_file=0.2)
    assert "duration:1" in args


def test_args_source_distante_transmet_les_arguments_tshark(monkeypatch):
    source = capture.CaptureSource(kind="rpcap", interface="rpcap://h/eth0", extra_args=("-A", "u:p"))
    monkeypatch.setattr(capture, "parse_source", lambda _i: source)
    args = capture.ring_recorder_args("rpcap://h/eth0", "/tmp/rb", max_files=1, max_duration_per_file=5)
    assert args[1:3] == ["-i", "rpcap://h/eth0"]
    assert args[args.index("-A") + 1] == "u:p"


def test_args_source_pipe_refusee(monkeypatch):
    source = capture.CaptureSource(kind="pipe", interface="-", uses_stdin=True)
    monkeypatch.setattr(capture, "parse_source", lambda _i: source)
    with pytest.raises(CaptureSourceError, match="pipe://"):
        capture.ring_recorder_args("pipe://-", "/tmp/rb", max_files=1, max_duration_per_file=5)


@pytest.mark.parametrize(("files", "duration"), [(0, 60), (5, 0), (5, -1)])
def test_args_valeurs_invalides(files, duration):
    with pytest.raises(ValueError):
        capture.ring_recorder_args("eth0", "/tmp/rb", max_files=files, max_duration_per_file=duration)


def test_start_puis_stop_processus_reel(tmp_path, monkeypatch):
    """Cycle complet avec un vrai processus (python qui ecrit sur stderr puis
    attend) a la place de tshark : lancement, arret par SIGTERM, stderr relu."""
    directory = tmp_path / "ring"
    script = "import sys,time; sys.stderr.write('Capturing on eth0'); sys.stderr.flush(); time.sleep(60)"
    monkeypatch.setattr(capture, "ring_recorder_args", lambda *a, **k: [sys.executable, "-c", script])
    proc = capture.start_ring_recorder("eth0", str(directory), max_files=2, max_duration_per_file=5)
    assert directory.is_dir()
    assert proc.poll() is None
    # laisser le temps au processus d'ecrire son message
    for _ in range(50):
        proc.netcross_err_file.seek(0)
        if proc.netcross_err_file.read():
            break
        import time

        time.sleep(0.05)
    err = capture.stop_ring_recorder(proc)
    assert proc.returncode == -signal.SIGTERM
    assert err == "Capturing on eth0"
    assert proc.netcross_err_file.closed


def test_stop_processus_deja_termine(monkeypatch, tmp_path):
    monkeypatch.setattr(capture, "ring_recorder_args", lambda *a, **k: [sys.executable, "-c", "pass"])
    proc = capture.start_ring_recorder("eth0", str(tmp_path), max_files=1, max_duration_per_file=1)
    proc.wait(timeout=10)
    assert capture.stop_ring_recorder(proc) == ""
    assert proc.returncode == 0


def test_stop_kill_si_sigterm_ignore(monkeypatch, tmp_path):
    script = "import signal as s,time; s.signal(s.SIGTERM, s.SIG_IGN); print('ok', flush=True); time.sleep(60)"
    monkeypatch.setattr(capture, "ring_recorder_args", lambda *a, **k: [sys.executable, "-c", script])
    monkeypatch.setattr(capture.subprocess, "Popen", _popen_stdout_pipe(subprocess.Popen))
    proc = capture.start_ring_recorder("eth0", str(tmp_path), max_files=1, max_duration_per_file=1)
    proc.stdout.readline()  # le gestionnaire SIGTERM est installe
    capture.stop_ring_recorder(proc, timeout=0.3)
    assert proc.returncode == -signal.SIGKILL


def _popen_stdout_pipe(real_popen):
    def _popen(args, **kwargs):
        kwargs["stdout"] = subprocess.PIPE
        return real_popen(args, **kwargs)

    return _popen


# --- Cablage CLI --------------------------------------------------------------


def test_cli_sans_ring_buffer_aucun_enregistreur():
    from cross_capture_analyzer_cli import _start_ring_recorders

    assert _start_ring_recorders([("LAN", "eth0", None)], None) == {}
    assert _start_ring_recorders([("LAN", "eth0", None)], (None, None)) == {}


def test_cli_lance_un_enregistreur_par_point(monkeypatch, capsys):
    import cross_capture_analyzer_cli as cli

    appels = []

    class _Proc:
        returncode = None

    def _start(iface, directory, **kwargs):
        appels.append((iface, directory, kwargs))
        return _Proc()

    monkeypatch.setattr(capture, "start_ring_recorder", _start)
    recorders = cli._start_ring_recorders([("LAN", "eth0", "tcp"), ("WAN", "eth1", None)], (4, 30.0))
    try:
        assert set(recorders) == {"LAN", "WAN"}
        assert [a[0] for a in appels] == ["eth0", "eth1"]
        assert appels[0][2] == {"max_files": 4, "max_duration_per_file": 30.0, "prefix": "LAN", "bpf_filter": "tcp"}
        out = capsys.readouterr().out
        assert "[LAN] rotation de capture : 4 fichier(s) de 30 s max dans" in out
    finally:
        for _proc, directory in recorders.values():
            os.rmdir(directory)


def test_cli_source_pipe_quitte_avec_message(monkeypatch, capsys):
    import cross_capture_analyzer_cli as cli

    def _start(*_a, **_k):
        raise CaptureSourceError("rotation de capture impossible sur une source pipe://")

    monkeypatch.setattr(capture, "start_ring_recorder", _start)
    with pytest.raises(SystemExit) as exc:
        cli._start_ring_recorders([("P", "pipe://-", None)], (2, 10.0))
    assert exc.value.code == 1
    assert "--ring-buffer [P] : rotation de capture impossible" in capsys.readouterr().err


def test_cli_stop_affiche_les_fichiers_conserves(monkeypatch, tmp_path, capsys):
    import cross_capture_analyzer_cli as cli

    for name in ("LAN_00001.pcapng", "LAN_00002.pcapng", ".cache"):
        (tmp_path / name).write_bytes(b"")

    class _Proc:
        returncode = 1

    monkeypatch.setattr(capture, "stop_ring_recorder", lambda _p: "tshark: interface introuvable")
    cli._stop_ring_recorders({"LAN": (_Proc(), str(tmp_path))})
    captured = capsys.readouterr()
    assert f"[LAN] rotation de capture : 2 fichier(s) conserve(s) dans {tmp_path}" in captured.out
    assert "[LAN] enregistreur tshark : tshark: interface introuvable" in captured.err


def test_cli_stop_sans_enregistreur_ne_fait_rien(capsys):
    from cross_capture_analyzer_cli import _stop_ring_recorders

    _stop_ring_recorders({})
    assert capsys.readouterr().out == ""
