"""Issues #868, #869, #870, #886, #887 : manipulation de captures dans
l'API (/tools/*), mêmes résultats et mêmes refus que la CLI."""

from __future__ import annotations

import importlib
import io
import shutil
import zipfile

import pytest
from pcap_builders import pcap_bytes, read_pcap, synthetic_packets, write_pcap

import cross_capture_analyzer_cli as cli
from netcross_core import capture_tools

pytest.importorskip("fastapi", reason="extra [api] non installé")
pytest.importorskip("multipart", reason="python-multipart non installé")

from fastapi.testclient import TestClient  # noqa: E402

api = importlib.import_module("netcross_api.app")
client = TestClient(api.app)
outils = pytest.mark.skipif(
    any(shutil.which(t) is None for t in ("tshark", "editcap", "mergecap", "reordercap")),
    reason="outils Wireshark absents",
)

A = synthetic_packets(6, start_us=1_700_000_000_000_000)
B = synthetic_packets(4, start_us=1_700_000_000_050_000)


def _f(name, packets):
    return (name, pcap_bytes(packets), "application/vnd.tcpdump.pcap")


def _records(data: bytes, tmp_path, name="r.pcap"):
    p = tmp_path / name
    p.write_bytes(data)
    return read_pcap(p)[1]


@outils
@pytest.mark.parametrize("dedup", [False, True])
def test_fusion_identique_a_la_cli(tmp_path, dedup, monkeypatch):
    rep = client.post(
        "/tools/merge",
        files=[("files", _f("a.pcap", A)), ("files", _f("b.pcap", B))],
        data={"format": "pcap", "dedup": str(dedup).lower()},
    )
    assert rep.status_code == 200, rep.text
    assert "netcross-merge.pcap" in rep.headers["content-disposition"]
    write_pcap(tmp_path / "a.pcap", A)
    write_pcap(tmp_path / "b.pcap", B)
    argv = ["netcross", "--capture", f"A={tmp_path / 'a.pcap'}", "--capture", f"B={tmp_path / 'b.pcap'}"]
    argv += ["--merge", str(tmp_path / "cli.pcap"), *(["--merge-dedup"] if dedup else [])]
    monkeypatch.setattr("sys.argv", argv)
    try:
        cli.main()
    except SystemExit as exc:
        assert exc.code in (0, None)
    assert _records(rep.content, tmp_path) == read_pcap(tmp_path / "cli.pcap")[1]
    assert len(_records(rep.content, tmp_path)) == 10


@outils
def test_decoupage_archive_dans_l_ordre(tmp_path):
    rep = client.post("/tools/split", files={"file": _f("a.pcap", A)}, data={"split": "count:2"})
    assert rep.status_code == 200, rep.text
    zf = zipfile.ZipFile(io.BytesIO(rep.content))
    noms = zf.namelist()
    assert len(noms) == 3
    write_pcap(tmp_path / "a.pcap", A)
    attendus = capture_tools.split(str(tmp_path / "a.pcap"), str(tmp_path / "seg"), "count:2")
    assert [len(_records(zf.read(n), tmp_path, f"{i}.pcap")) for i, n in enumerate(noms)] == [2, 2, 2]
    assert len(attendus) == 3


@pytest.mark.parametrize("spec", ["count", "time:0", "size:10MiB", "lignes:3"])
def test_decoupage_refus_comme_la_cli(spec, capsys):
    rep = client.post("/tools/split", files={"file": _f("a.pcap", A)}, data={"split": spec})
    assert rep.status_code == 400
    with pytest.raises(SystemExit):
        cli._parse_split_spec(spec)
    assert capsys.readouterr().err.strip() == rep.json()["detail"]


@outils
@pytest.mark.parametrize("fmt", ["pcap", "pcapng", "csv", "json"])
def test_conversion(tmp_path, fmt):
    rep = client.post("/tools/convert", files={"file": _f("a.pcap", A)}, data={"format": fmt})
    assert rep.status_code == 200, rep.text
    assert f"netcross-convert.{fmt}" in rep.headers["content-disposition"]
    write_pcap(tmp_path / "a.pcap", A)
    capture_tools.convert(str(tmp_path / "a.pcap"), str(tmp_path / f"cli.{fmt}"), fmt)
    attendu = (tmp_path / f"cli.{fmt}").read_bytes()
    if fmt in ("pcap", "csv", "json"):
        assert rep.content == attendu
    else:
        assert rep.content[:4] == attendu[:4] == b"\x0a\x0d\x0d\x0a"


def test_conversion_format_inconnu():
    rep = client.post("/tools/convert", files={"file": _f("a.pcap", A)}, data={"format": "txt"})
    assert rep.status_code == 400
    assert "format inconnu" in rep.json()["detail"]


@outils
def test_export_filtre(tmp_path):
    rep = client.post(
        "/tools/export",
        files={"file": _f("a.pcap", A)},
        data={"bpf": "frame.number <= 3", "format": "pcap"},
    )
    assert rep.status_code == 200, rep.text
    assert len(_records(rep.content, tmp_path)) == 3


@outils
def test_recalage(tmp_path):
    rep = client.post(
        "/tools/adjust-time", files={"file": _f("a.pcap", A)}, data={"normalize": "true", "format": "pcap"}
    )
    assert rep.status_code == 200, rep.text
    recs = _records(rep.content, tmp_path)
    assert recs[0][0] == 0
    ref = client.post(
        "/tools/adjust-time",
        files={"file": _f("a.pcap", A), "align_to": _f("b.pcap", B)},
        data={"format": "pcap"},
    )
    assert ref.status_code == 200, ref.text
    premier = _records(ref.content, tmp_path, "ref.pcap")[0]
    assert premier[0] == 1_700_000_000 and abs(premier[1] - 50_000) <= 1  # editcap -t : arrondi flottant


def test_recalage_modes_exclusifs():
    rep = client.post(
        "/tools/adjust-time", files={"file": _f("a.pcap", A)}, data={"normalize": "true", "time_offset": "3"}
    )
    assert rep.status_code == 400
    assert rep.json()["detail"] == "--time-offset, --normalize-time et --align-to sont mutuellement exclusifs."


def test_outils_absents_503(monkeypatch):
    from pcap_parser.capture import TsharkNotFoundError

    def absent(*_a, **_k):
        raise TsharkNotFoundError("mergecap introuvable")

    monkeypatch.setattr(capture_tools, "merge_captures", absent)
    rep = client.post("/tools/merge", files=[("files", _f("a.pcap", A))])
    assert rep.status_code == 503


def test_trop_de_fichiers(monkeypatch):
    monkeypatch.setattr(api, "_MAX_FILES", 1)
    rep = client.post("/tools/merge", files=[("files", _f("a.pcap", A)), ("files", _f("b.pcap", B))])
    assert rep.status_code == 413


def test_parse_endpoints():
    assert capture_tools.parse_endpoints(" 10.0.0.1, ,10.0.0.2 ") == ["10.0.0.1", "10.0.0.2"]
    assert capture_tools.parse_endpoints("") is None
