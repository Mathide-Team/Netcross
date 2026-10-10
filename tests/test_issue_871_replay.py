"""Issue #871 : rejeu d'une capture depuis la GUI (onglet « Rejeu »,
interruptible, confirmation obligatoire) et l'API (``POST /tools/replay``,
interfaces autorisées par l'administrateur seulement)."""

from __future__ import annotations

import importlib
import subprocess
import threading
import time

import pytest
from pcap_builders import pcap_bytes, synthetic_packets, write_pcap

from netcross_core import capture_tools

A = synthetic_packets(3)


def test_interfaces_autorisees():
    assert capture_tools.allowed_replay_interfaces({}) == frozenset()
    env = {capture_tools.REPLAY_INTERFACES_ENV: " veth0, ,lo "}
    assert capture_tools.allowed_replay_interfaces(env) == {"veth0", "lo"}


def test_commande_identique_a_replay_capture(tmp_path, monkeypatch):
    from pcap_parser import capture

    write_pcap(tmp_path / "a.pcap", A)
    monkeypatch.setattr(capture, "_tcpreplay_path", lambda: "/usr/bin/tcpreplay")
    vus = []
    monkeypatch.setattr(capture, "_run_tcpreplay", vus.append)
    capture.replay_capture(str(tmp_path / "a.pcap"), "veth0", speed="topspeed", loop=2)
    assert vus == [capture.replay_command(str(tmp_path / "a.pcap"), "veth0", "topspeed", 2)]
    assert vus[0][1:4] == ["--intf1=veth0", "--loop=2", "--topspeed"]
    with pytest.raises(ValueError, match="loop doit etre >= 1"):
        capture.replay_command(str(tmp_path / "a.pcap"), "veth0", 1.0, 0)


def test_wait_replay_erreur_et_arret():
    from pcap_parser.capture import TcpreplayError, wait_replay

    proc = subprocess.Popen(
        ["sh", "-c", "echo boom >&2; exit 3"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    with pytest.raises(TcpreplayError, match="code 3"):
        wait_replay(proc)
    proc = subprocess.Popen(["sleep", "30"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    proc.terminate()
    wait_replay(proc, stopped=True)


# -- API -----------------------------------------------------------------------

pytest.importorskip("fastapi", reason="extra [api] non installé")
pytest.importorskip("multipart", reason="python-multipart non installé")
from fastapi.testclient import TestClient  # noqa: E402

api = importlib.import_module("netcross_api.app")
client = TestClient(api.app)


def _post(**data):
    return client.post("/tools/replay", files={"file": ("a.pcap", pcap_bytes(A))}, data={"interface": "veth0", **data})


def test_api_rejeu_desactive_par_defaut(monkeypatch):
    monkeypatch.delenv(capture_tools.REPLAY_INTERFACES_ENV, raising=False)
    rep = _post()
    assert rep.status_code == 403
    assert "rejeu desactive" in rep.json()["detail"]


def test_api_interface_non_autorisee(monkeypatch):
    monkeypatch.setenv(capture_tools.REPLAY_INTERFACES_ENV, "lo")
    rep = _post()
    assert rep.status_code == 403
    assert "non autorisee" in rep.json()["detail"]


def test_api_rejeu(monkeypatch):
    monkeypatch.setenv(capture_tools.REPLAY_INTERFACES_ENV, "veth0")
    vus = []
    monkeypatch.setattr(capture_tools, "replay_capture", lambda p, i, speed, loop: vus.append((i, speed, loop)))
    rep = _post(speed="2.0", loop="3")
    assert rep.status_code == 200, rep.text
    assert rep.json() == {"message": "a.pcap rejoue sur veth0 (speed=2.0, loop=3)."}
    assert vus == [("veth0", "2.0", 3)]


def test_api_parametres_refuses(monkeypatch):
    monkeypatch.setenv(capture_tools.REPLAY_INTERFACES_ENV, "veth0")
    from pcap_parser import capture

    monkeypatch.setattr(capture, "_tcpreplay_path", lambda: "/bin/true")
    assert _post(loop="0").status_code == 400
    assert _post(speed="vite").status_code == 400


def test_api_tcpreplay_absent(monkeypatch):
    from pcap_parser import capture

    monkeypatch.setenv(capture_tools.REPLAY_INTERFACES_ENV, "veth0")

    def absent():
        raise capture.TcpreplayNotFoundError("tcpreplay introuvable")

    monkeypatch.setattr(capture, "_tcpreplay_path", absent)
    assert _post().status_code == 503


# -- GUI -----------------------------------------------------------------------


@pytest.fixture
def win(tmp_path):
    from gtk4_display import exiger_gtk4_avec_affichage

    exiger_gtk4_avec_affichage()
    from netcross_gtk4.capture_tools_window import CaptureToolsWindow

    write_pcap(tmp_path / "a.pcap", A)
    w = CaptureToolsWindow(start_thread=lambda fn: fn())
    w.replay_source.set_path(str(tmp_path / "a.pcap"))
    w.replay_interface.set_text("veth0")
    return w


def test_gui_confirmation_obligatoire(win):
    with pytest.raises(ValueError, match="confirmation"):
        win.run_replay()


def test_gui_rejeu_termine(win, monkeypatch):
    lances = []

    def faux(path, interface, speed, loop):
        lances.append((interface, speed, loop))
        return subprocess.Popen(["true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    monkeypatch.setattr(capture_tools, "start_replay", faux)
    win.replay_confirm.set_active(True)
    win.replay_loop.set_value(2)
    assert win.run_replay().endswith("rejoue sur veth0 (speed=1.0, loop=2).")
    assert lances == [("veth0", "1.0", 2)]


def test_gui_rejeu_interrompu(win, monkeypatch):
    monkeypatch.setattr(
        capture_tools,
        "start_replay",
        lambda *a, **k: subprocess.Popen(["sleep", "30"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True),
    )
    win.replay_confirm.set_active(True)
    resultat = []
    t = threading.Thread(target=lambda: resultat.append(win.run_replay()))
    t.start()
    for _ in range(100):
        if win._replay_proc is not None:
            break
        time.sleep(0.02)
    win.stop_replay()
    t.join(5)
    assert resultat and resultat[0].endswith("sur veth0 interrompu.")
    assert win._replay_proc is None


def test_gui_echec_tcpreplay_affiche(win, monkeypatch):
    monkeypatch.setattr(
        capture_tools,
        "start_replay",
        lambda *a, **k: subprocess.Popen(
            ["sh", "-c", "echo 'interface inconnue' >&2; exit 1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ),
    )
    win.replay_confirm.set_active(True)
    win._launch(win.run_replay)
    from gi.repository import GLib

    ctx = GLib.MainContext.default()
    while ctx.pending():
        ctx.iteration(False)
    assert "interface inconnue" in win.status_label.get_text()
