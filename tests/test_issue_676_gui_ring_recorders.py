"""Issue #676 : rotation de capture de la GUI (netcross_gtk4.ring_recorders,
module sans GTK). tshark n'est jamais lance : starter/stopper simules."""

import signal

import pytest

from netcross_gtk4.ring_recorders import RingRecorderError, start_ring_recorders, stop_ring_recorders
from pcap_parser.capture import TsharkNotFoundError
from pcap_parser.remote import CaptureSourceError


class _Proc:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.pid = 4242

    def poll(self):
        return self.returncode


def _mkdtemp_in(tmp_path):
    created = []

    def mkdtemp(prefix):
        d = tmp_path / f"{prefix}{len(created)}"
        d.mkdir()
        created.append(d)
        return str(d)

    return mkdtemp, created


def test_start_lance_un_enregistreur_par_point_avec_les_bons_parametres(tmp_path):
    calls = []
    mkdtemp, created = _mkdtemp_in(tmp_path)

    def starter(interface, directory, **kw):
        calls.append((interface, directory, kw))
        return _Proc()

    recorders, messages = start_ring_recorders(
        [("LAN", "eth0", None), ("WAN", "eth1", "udp")], 5, 30.0, starter=starter, mkdtemp=mkdtemp
    )

    assert list(recorders) == ["LAN", "WAN"]
    assert calls[0] == (
        "eth0",
        str(created[0]),
        {"max_files": 5, "max_duration_per_file": 30.0, "prefix": "LAN", "bpf_filter": None},
    )
    assert calls[1][2]["bpf_filter"] == "udp"
    assert messages[0] == f"[LAN] rotation de capture : 5 fichier(s) de 30 s max dans {created[0]}"
    assert "netcross-ring-WAN-" in str(created[1])


@pytest.mark.parametrize(
    "exc",
    [CaptureSourceError("pipe:// refuse"), TsharkNotFoundError("tshark absent"), OSError("disque plein")],
)
def test_start_refus_d_un_point_arrete_ceux_deja_lances(tmp_path, exc):
    mkdtemp, _ = _mkdtemp_in(tmp_path)
    started = []

    def starter(interface, directory, **kw):
        if interface == "pipe://x":
            raise exc
        proc = _Proc()
        started.append(proc)
        return proc

    with pytest.raises(RingRecorderError, match=r"^\[B\] ") as info:
        start_ring_recorders([("A", "eth0", None), ("B", "pipe://x", None)], 3, 10, starter=starter, mkdtemp=mkdtemp)

    assert info.value.__cause__ is exc
    assert len(started) == 1  # A a bien ete lance puis arrete (stop_ring_recorder reel, processus deja fini)


def test_start_sans_point_ne_lance_rien():
    assert start_ring_recorders([], 3, 10, starter=pytest.fail) == ({}, [])


def test_stop_compte_les_fichiers_conserves_et_ignore_les_fichiers_caches(tmp_path):
    (tmp_path / "LAN_00001.pcapng").write_bytes(b"x")
    (tmp_path / "LAN_00002.pcapng").write_bytes(b"x")
    (tmp_path / ".cache").write_bytes(b"x")
    stopped = []

    messages = stop_ring_recorders(
        {"LAN": (_Proc(-signal.SIGTERM), str(tmp_path))}, stopper=lambda p: stopped.append(p) or "bruit"
    )

    assert len(stopped) == 1
    # SIGTERM = arret normal : le stderr n'est pas une erreur a afficher.
    assert messages == [f"[LAN] rotation de capture : 2 fichier(s) conserve(s) dans {tmp_path}"]


def test_stop_remonte_l_erreur_tshark_si_code_anormal(tmp_path):
    messages = stop_ring_recorders({"LAN": (_Proc(2), str(tmp_path))}, stopper=lambda p: "permission refusee")

    assert messages == [
        f"[LAN] rotation de capture : 0 fichier(s) conserve(s) dans {tmp_path}",
        "[LAN] enregistreur tshark : permission refusee",
    ]


def test_stop_code_anormal_sans_stderr_n_ajoute_rien(tmp_path):
    messages = stop_ring_recorders({"LAN": (_Proc(1), str(tmp_path))}, stopper=lambda p: "")
    assert len(messages) == 1


def test_stop_repertoire_disparu(tmp_path):
    missing = tmp_path / "absent"
    messages = stop_ring_recorders({"LAN": (_Proc(0), str(missing))}, stopper=lambda p: "")
    assert messages == [f"[LAN] rotation de capture : 0 fichier(s) conserve(s) dans {missing}"]
