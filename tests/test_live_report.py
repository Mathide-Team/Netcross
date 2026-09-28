"""Issue #274 : rapport temps reel du mode --live (dictionnaire structure,
instantane + journal, page a relecture successive ou completive)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import urllib.request
from types import SimpleNamespace

import pytest
from conftest import make_pkt

import cross_capture_analyzer_cli as cli
from netcross_core.live_report import MAX_HOST_EVENTS, SCHEMA, LiveAggregator, LiveReporter, LiveReportWriter
from netcross_report.live_html import render_live_html


def _types(events):
    return [e["type"] for e in events]


def test_instantane_et_deltas():
    agg = LiveAggregator(started_at=100.0)
    agg.register("LAN")
    for i in range(10):
        agg.add(make_pkt(point="LAN", ts=100.0 + i, length=100, proto="TCP"))
    snap, journal = agg.tick(now=105.0)
    assert snap["schema"] == journal["schema"] == SCHEMA
    assert snap["totals"] == {"packets": 10, "bytes": 1000, "hosts": 2}
    assert snap["points"]["LAN"]["pps"] == 2.0 and snap["points"]["LAN"]["bps"] == 1600
    assert journal["points"]["LAN"] == {"packets": 10, "bytes": 1000, "pps": 2.0, "bps": 1600}
    assert snap["top_conversations"][0] == {"src": "10.0.0.1", "dst": "10.0.0.2", "proto": "TCP", "bytes": 1000}
    agg.add(make_pkt(point="LAN", ts=106.0, length=50, proto="UDP"))
    snap2, journal2 = agg.tick(now=110.0)
    assert journal2["seq"] == 2 and journal2["points"]["LAN"]["packets"] == 1  # journal : ajouts seuls
    assert snap2["totals"]["packets"] == 11 and snap2["protocols"] == {"TCP": 10, "UDP": 1}  # instantane : cumul
    assert journal2["events"] == []  # evenements consommes au releve precedent


def test_evenements_hotes_silence_reprise_pic_et_erreur():
    agg = LiveAggregator(started_at=0.0)
    agg.add(make_pkt(point="A", src="1.1.1.1", dst="2.2.2.2"))
    _s, j = agg.tick(now=1.0)
    assert _types(j["events"]) == ["nouvel_hote", "nouvel_hote"]
    _s, j = agg.tick(now=2.0)
    assert _types(j["events"]) == ["point_silencieux"]
    _s, j = agg.tick(now=3.0)
    assert j["events"] == []  # signale une seule fois
    for _ in range(600):
        agg.add(make_pkt(point="A", src="1.1.1.1", dst="2.2.2.2"))
    _s, j = agg.tick(now=4.0)
    assert _types(j["events"]) == ["point_repris", "pic_de_debit"]
    agg.set_status("A", "erreur", "interface disparue")
    snap, j = agg.tick(now=5.0)
    assert j["events"][0] == {"type": "point_erreur", "point": "A", "detail": "interface disparue", "t": j["t"]}
    assert snap["points"]["A"]["status"] == "erreur"


def test_scan_un_seul_evenement_de_synthese():
    agg = LiveAggregator(started_at=0.0)
    for i in range(MAX_HOST_EVENTS + 50):
        agg.add(make_pkt(point="A", src="10.0.0.1", dst=f"10.1.{i // 250}.{i % 250}"))
    _s, j = agg.tick(now=1.0)
    assert _types(j["events"]).count("nouvel_hote") == MAX_HOST_EVENTS
    assert j["events"][-1] == {"type": "nouveaux_hotes_nombreux", "count": 51, "t": j["t"]}


def test_releve_final():
    agg = LiveAggregator(started_at=0.0)
    agg.add(make_pkt(point="A"))
    snap, j = agg.tick(now=1.0, final=True)
    assert snap["final"] and j["final"] and snap["points"]["A"]["status"] == "arrete"


def test_ecrivain_fichiers_atomiques_et_page(tmp_path):
    writer = LiveReportWriter(tmp_path / "live", render_live_html, interval=2)
    agg = LiveAggregator(started_at=0.0)
    agg.add(make_pkt(point="A", src="</script><img src=x onerror=alert(1)>"))
    for now in (1.0, 2.0, 3.0):
        writer.publish(*agg.tick(now=now))
    lines = [json.loads(line) for line in writer.journal_path.read_text().splitlines()]
    assert [line["seq"] for line in lines] == [1, 2, 3]
    assert json.loads(writer.snapshot_path.read_text())["seq"] == 3
    assert sorted(p.name for p in writer.out_dir.iterdir()) == ["index.html", "live.json", "live.jsonl"]
    html = writer.html_path.read_text()
    assert "<img" not in html and "\\u003c/script\\u003e" in html
    data = json.loads(re.search(r'id="netcross-live">(.*?)</script>', html, re.S).group(1))
    assert data["snapshot"]["seq"] == 3 and len(data["journal"]) == 3
    assert "setInterval(poll, INTERVAL)" in html and "INTERVAL = 2 * 1000" in html


def test_nouvelle_session_repart_d_un_journal_vide(tmp_path):
    (tmp_path / "live.jsonl").write_text('{"seq": 99}\n')
    assert LiveReportWriter(tmp_path).journal_path.read_text() == ""


@pytest.mark.skipif(shutil.which("node") is None, reason="node absent")
def test_script_de_la_page_syntaxiquement_valide(tmp_path):
    snap, j = LiveAggregator(started_at=0.0).tick(now=1.0)
    html = render_live_html(snap, [j], 5)
    script = html.rsplit("<script>", 1)[1].split("</script>", 1)[0]
    (tmp_path / "page.js").write_text(script)
    subprocess.run(["node", "--check", str(tmp_path / "page.js")], check=True)


def test_erreur_d_ecriture_n_interrompt_pas(tmp_path):
    writer = LiveReportWriter(tmp_path, interval=1)

    def boom(*_a):
        raise OSError("disque plein")

    writer.publish = boom  # type: ignore[method-assign]
    reporter = LiveReporter(writer)
    reporter.start()
    reporter.add(make_pkt(point="A"))
    reporter.stop()
    assert reporter.failures == 2  # releve initial + releve final


def test_capture_live_alimente_le_rapport_et_http(monkeypatch, tmp_path):
    def fake_live(label, iface, bpf_filter=None, stop_event=None):
        for i in range(5):
            yield make_pkt(point=label, ts=float(i))
        if iface == "eth1":
            raise RuntimeError("interface disparue")

    monkeypatch.setattr(cli, "parse_live", fake_live)
    args = SimpleNamespace(live_report=str(tmp_path / "live"), live_report_interval=1.0, live_report_serve=0)
    reporter, server = cli._start_live_report(args)
    try:
        packets = cli._run_live_captures(["LAN:eth0", "WAN:eth1"], None, reporter)
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/live.json") as resp:  # noqa: S310
            snap = json.loads(resp.read())
    finally:
        server.shutdown()
    assert len(packets) == 10
    assert snap["final"] and snap["totals"]["packets"] == 10
    assert snap["points"]["LAN"]["status"] == "arrete"
    assert snap["points"]["WAN"] == {**snap["points"]["WAN"], "status": "erreur", "error": "interface disparue"}
    journal = (tmp_path / "live" / "live.jsonl").read_text().splitlines()
    assert json.loads(journal[-1])["final"] is True


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--capture", "A=x.pcap", "--live-report", "d"], "--live-report necessite --live"),
        (["--capture", "A=x.pcap", "--live-report-serve", "8080"], "necessitent --live-report"),
        (["--live", "A:eth0", "--live-report", "d", "--live-report-interval", "0.5"], "1 seconde minimum"),
        (["--live", "A:eth0", "--live-report", "d", "--live-report-serve", "70000"], "port entre 1 et 65535"),
    ],
)
def test_validations_cli(monkeypatch, capsys, tmp_path, argv, message):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "x.pcap").write_bytes(b"")
    monkeypatch.setattr(sys, "argv", ["cli", *argv])
    with pytest.raises(SystemExit):
        cli.main()
    assert message in capsys.readouterr().err


# -- Issue #732 : ecriture atomique en echec et boucle de publication ---------


def test_atomic_write_nettoie_le_temporaire_en_cas_d_echec(tmp_path, monkeypatch):
    """Lignes 214-219 : si le remplacement echoue, le temporaire est
    supprime et l'exception propagee."""
    import os

    from netcross_core import live_report

    def _boom(src, dst):
        raise OSError("disque plein")

    monkeypatch.setattr(os, "replace", _boom)
    with pytest.raises(OSError, match="disque plein"):
        live_report._atomic_write(tmp_path / "live.json", "{}")
    assert list(tmp_path.iterdir()) == []


def test_boucle_publie_tant_que_non_arrete(tmp_path):
    """Ligne 295 : la boucle publie a chaque intervalle jusqu'a l'arret."""
    calls = []

    class _Writer:
        interval = 0.0

        def publish(self, snapshot, journal):
            calls.append(snapshot)
            if len(calls) >= 2:
                reporter._stop.set()

    reporter = LiveReporter(_Writer())
    reporter._loop()
    assert len(calls) >= 2
