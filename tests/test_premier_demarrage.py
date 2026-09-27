"""#468 -- premier demarrage : ressources locales absentes et captures
illisibles ne doivent ni produire de traces ERROR trompeuses, ni un message
brut de tshark sans piste de correction."""

from __future__ import annotations

import os
import stat

import pytest
from loguru import logger

from netcross_core import bpf_filters, i18n
from pcap_parser import capture, ek_source
from pcap_parser.ek_source import CaptureAccessError, TsharkError, _build_args, check_capture_readable


@pytest.fixture
def niveaux(monkeypatch):
    """Capture les niveaux des messages loguru emis pendant le test."""
    logger.enable("pcap_parser")
    logger.enable("netcross_core")
    vus: list[str] = []
    sink = logger.add(lambda m: vus.append(m.record["level"].name), level="TRACE")
    yield vus
    logger.remove(sink)


def test_filtres_bpf_absents_sans_erreur(tmp_path, niveaux):
    assert bpf_filters.load_bpf_filters(tmp_path / "absent.json") == []
    assert "ERROR" not in niveaux


def test_i18n_sans_catalogue_sans_erreur(tmp_path, monkeypatch, niveaux):
    monkeypatch.setattr(i18n, "locale_dirs", lambda: [tmp_path / "a", tmp_path / "b"])
    trad = i18n.setup("fr")
    assert trad.gettext("bonjour") == "bonjour"
    assert "ERROR" not in niveaux


def test_capture_introuvable(tmp_path):
    with pytest.raises(CaptureAccessError, match="introuvable"):
        check_capture_readable(str(tmp_path / "absent.pcap"))


def test_capture_repertoire(tmp_path):
    with pytest.raises(CaptureAccessError, match="repertoire"):
        check_capture_readable(str(tmp_path))


@pytest.mark.skipif(os.geteuid() == 0, reason="root lit tous les fichiers")
def test_capture_sans_droit_de_lecture(tmp_path):
    f = tmp_path / "prive.pcap"
    f.write_bytes(b"\x00")
    f.chmod(0)
    try:
        with pytest.raises(CaptureAccessError, match="droits insuffisants") as exc:
            check_capture_readable(str(f))
        assert "chmod u+r" in str(exc.value)
    finally:
        f.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_capture_access_error_est_une_tsharkerror():
    # compatibilite : les appelants qui attrapent TsharkError continuent de fonctionner
    assert issubclass(CaptureAccessError, TsharkError)


def test_build_args_lecture_stdin(monkeypatch):
    monkeypatch.setattr(ek_source, "_tshark_path", lambda: "tshark")
    args = _build_args(path="/tmp/x.pcap", read_via_stdin=True)
    assert args[1:3] == ["-r", "-"]
    assert "/tmp/x.pcap" not in args


def test_is_permission_error():
    err = TsharkError("tshark a echoue (code 3)", 3, "tshark: You don't have permission to read the file")
    assert ek_source.is_permission_error(err)
    assert not ek_source.is_permission_error(TsharkError("autre", 2, "format inconnu"))


def test_parse_capture_repli_stdin_si_tshark_confine(tmp_path, monkeypatch):
    f = tmp_path / "c.pcap"
    f.write_bytes(b"\x00")
    appels: list[bool] = []

    def faux_iter(*, path, read_via_stdin=False):
        appels.append(read_via_stdin)
        if not read_via_stdin:
            raise TsharkError("tshark a echoue (code 3)", 3, "You don't have permission to read the file")
        yield ek_source.EkRecord(ts=1.0, layers={})

    monkeypatch.setattr(capture, "iter_ek_records", faux_iter)
    monkeypatch.setattr(capture, "build_packet", lambda ts, layers: ("pkt", ts))
    assert capture.parse_capture(str(f), raise_on_error=True) == [("pkt", 1.0)]
    assert appels == [False, True]


def test_parse_capture_sans_repli_pour_autre_erreur(tmp_path, monkeypatch):
    f = tmp_path / "c.pcap"
    f.write_bytes(b"\x00")

    def faux_iter(*, path, read_via_stdin=False):
        raise TsharkError("tshark a echoue (code 2)", 2, "format inconnu")
        yield  # pragma: no cover

    monkeypatch.setattr(capture, "iter_ek_records", faux_iter)
    with pytest.raises(TsharkError, match="code 2"):
        capture.parse_capture(str(f), raise_on_error=True)


def test_parse_capture_acces_refuse_sans_trace(tmp_path, niveaux, capsys):
    assert capture.parse_capture(str(tmp_path / "absent.pcap")) == []
    assert "introuvable" in capsys.readouterr().err
    assert "ERROR" in niveaux
