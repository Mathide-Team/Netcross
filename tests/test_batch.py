"""
Mode batch (issue #277) : regroupement conservateur, justification ecrite,
invariant entrees = groupees + isolees + echecs, et CLI de lot.

Le CLI est teste avec parse_capture remplace par un faux decodeur : les
fichiers existent (pour l'inventaire du dossier) mais leur contenu est
fourni par le test -- aucune dependance a tshark.
"""

import dataclasses
import json
import os
import shutil
import sys

import pytest
from conftest import make_pkt

import cross_capture_batch_cli as cli
from netcross_core.batch import (
    CaptureInventory,
    evaluate_pair,
    format_batch_index,
    inventory_from_packets,
    justify,
    plan_batch,
)

T0 = 1_700_000_000.0


def _flux(point, t0, n=20, pas=1.0, src="10.0.0.5", dst="10.0.0.9", **kw):
    return [make_pkt(point=point, ts=t0 + i * pas, src=src, dst=dst, **kw) for i in range(n)]


def _inv(label, t0, n=20, **kw):
    return inventory_from_packets(label, f"/x/{label}.pcap", _flux(label, t0, n, **kw))


# -- inventaire ----------------------------------------------------------------


def test_inventaire_exclut_infrastructure_et_multicast():
    pkts = [
        *_flux("A", T0, 3),
        make_pkt(ts=T0, src="10.0.0.5", dst="10.0.0.53", sport=40000, dport=53, proto="UDP"),
        make_pkt(ts=T0, src="10.0.0.5", dst="224.0.0.251", sport=5353, dport=5353, proto="UDP"),
        make_pkt(ts=T0, src="10.0.0.7", dst="255.255.255.255", sport=68, dport=67, proto="UDP"),
        make_pkt(ts=T0, src="fe80::1", dst="10.0.0.5", sport=1, dport=2),
    ]
    inv = inventory_from_packets("A", "a.pcap", pkts)
    assert inv.ips == {"10.0.0.5", "10.0.0.9"}
    assert set(inv.pairs) == {("10.0.0.5", "10.0.0.9")}
    assert inv.packet_count == 7
    assert inv.protocols == {"TCP", "UDP"}
    assert inv.start == T0 and inv.end == T0 + 2


def test_inventaire_serialisation_aller_retour():
    inv = _inv("A", T0)
    back = CaptureInventory.from_dict(json.loads(json.dumps(inv.to_dict())))
    assert back == inv


# -- criteres de regroupement --------------------------------------------------


def test_deux_points_de_vue_du_meme_flux_sont_compatibles():
    a, b = _inv("A", T0), _inv("B", T0 + 0.002)
    ev = evaluate_pair(a, b)
    assert ev.compatible
    txt = justify(ev)
    assert "recouvrement" in txt and "2 IP communes" in txt and "10.0.0.5->10.0.0.9" in txt
    assert "decalage" not in txt  # 2 ms : latence, pas horloge


def test_captures_eloignees_de_jours_sont_hors_fenetre():
    ev = evaluate_pair(_inv("A", T0), _inv("B", T0 + 3 * 86400))
    assert not ev.compatible
    assert any("hors fenetre" in f and "jour" in f for f in ev.failed)


def test_recouvrement_partiel_insuffisant():
    # B commence aux 3/4 de A : recouvrement de 25 % < 50 %
    a = _inv("A", T0, n=41)
    b = _inv("B", T0 + 30, n=41)
    ev = evaluate_pair(a, b, group_window=0)
    assert any("recouvrement temporel" in f for f in ev.failed)


def test_meme_reseau_sans_conversation_commune_non_regroupe():
    """Deux captures d'un meme LAN voient les memes machines mais pas la
    meme conversation : c'est le critere 3 qui les separe."""
    a = inventory_from_packets(
        "A", "a", _flux("A", T0, src="10.0.0.5", dst="10.0.0.9") + _flux("A", T0, src="10.0.0.6", dst="10.0.0.8")
    )
    b = inventory_from_packets(
        "B", "b", _flux("B", T0, src="10.0.0.9", dst="10.0.0.6") + _flux("B", T0, src="10.0.0.8", dst="10.0.0.5")
    )
    ev = evaluate_pair(a, b)
    assert "aucune conversation commune" in ev.failed
    assert len(ev.common_ips) == 4


def test_une_seule_ip_commune_insuffisante():
    a = inventory_from_packets("A", "a", _flux("A", T0, src="10.0.0.5", dst="10.0.0.9"))
    b = inventory_from_packets("B", "b", _flux("B", T0, src="10.0.0.5", dst="10.0.0.10"))
    ev = evaluate_pair(a, b)
    assert "1 IP commune(s) < 2" in ev.failed
    assert "aucune IP commune" in evaluate_pair(a, _inv("C", T0, src="10.1.0.1", dst="10.1.0.2")).failed


def test_decalage_horloge_estime_corrige_et_mentionne():
    # B a 30 s d'avance et ne dure que 20 s : sans correction, recouvrement
    # nul ; avec correction (fenetre 60 s par defaut), 100 %.
    a, b = _inv("A", T0), _inv("B", T0 + 30)
    ev = evaluate_pair(a, b)
    assert ev.compatible and ev.offset_applied
    assert ev.clock_offset == pytest.approx(30.0)
    assert "decalage d'horloge estime +30.000 s" in justify(ev)
    # hors fenetre : pas de correction, refus
    ev2 = evaluate_pair(a, b, group_window=10)
    assert not ev2.compatible and not ev2.offset_applied


def test_capture_ponctuelle():
    a = _inv("A", T0, n=1)
    b = _inv("B", T0 - 5, n=20)
    assert evaluate_pair(a, b, group_window=0).overlap_ratio == 1.0


def test_sans_horodatage():
    a = CaptureInventory("A", "a", packet_count=1)
    assert "aucun horodatage exploitable" in evaluate_pair(a, _inv("B", T0)).failed


# -- plan de lot -----------------------------------------------------------------


def _lot():
    return [
        _inv("A", T0),
        _inv("B", T0 + 0.001),
        _inv("C", T0 + 3 * 86400),
        _inv("D", T0, src="10.9.0.1", dst="10.9.0.2"),
        CaptureInventory("E", "/x/E.pcap", error="en-tete tronque"),
        CaptureInventory("F", "/x/F.pcap"),  # lisible mais vide
    ]


def test_plan_invariant_et_decisions_justifiees():
    plan = plan_batch(_lot())
    assert plan.total == 6
    assert [g.labels for g in plan.groups] == [["A", "B"]]
    iso = {i.capture.label: i.reason for i in plan.isolated}
    assert set(iso) == {"C", "D", "F"}
    assert "hors fenetre" in iso["C"] and "candidat le plus proche" in iso["C"]
    assert "aucune IP commune" in iso["D"]
    assert iso["F"] == "aucun paquet IP exploitable"
    assert [f.label for f in plan.failures] == ["E"]
    plan.check_invariant()
    assert plan.grouped_count + len(plan.isolated) + len(plan.failures) == plan.total


def test_invariant_detecte_une_perte():
    plan = plan_batch(_lot())
    plan.isolated.pop()
    with pytest.raises(AssertionError, match="invariant du lot viole"):
        plan.check_invariant()


def test_no_group():
    plan = plan_batch(_lot(), group=False)
    assert plan.groups == []
    assert not plan.grouping_enabled
    assert sum("--no-group" in i.reason for i in plan.isolated) == 4
    assert "regroupement desactive" in format_batch_index(plan, "/x")


def test_pas_de_chainage():
    """A~B et B~C mais A et C sans conversation commune : pas de groupe
    A+B+C -- C reste isole et le motif le dit."""
    a = inventory_from_packets("A", "a", _flux("A", T0, src="10.0.0.1", dst="10.0.0.2"))
    b = inventory_from_packets(
        "B", "b", _flux("B", T0, src="10.0.0.1", dst="10.0.0.2") + _flux("B", T0, src="10.0.0.3", dst="10.0.0.4")
    )
    c = inventory_from_packets("C", "c", _flux("C", T0, src="10.0.0.3", dst="10.0.0.4"))
    plan = plan_batch([a, b, c])
    assert [g.labels for g in plan.groups] == [["A", "B"]]
    assert "pas avec tous les membres de son groupe" in plan.isolated[0].reason


def test_seule_capture():
    plan = plan_batch([_inv("A", T0)])
    assert plan.isolated[0].reason == "seule capture exploitable du lot"


def test_index_de_lot():
    plan = plan_batch(_lot())
    txt = format_batch_index(
        plan,
        "/data/lot",
        group_reports={1: "rapport-groupe-1.txt"},
        capture_reports={"C": "rapport-C.txt"},
        synthesis=["3 paquets"],
    )
    assert txt.startswith("LOT : 6 capture(s), /data/lot")
    assert "1 groupe(s) (2 capture(s)), 3 capture(s) isolee(s), 1 echec(s)" in txt
    assert "[groupe 1] A + B  -> analyse croisee : rapport-groupe-1.txt" in txt
    assert "-> rapport-C.txt" in txt
    txt2 = format_batch_index(plan, "/x", capture_reports={"A": "rapport-A.txt", "B": "rapport-B.txt"})
    assert "rapports individuels : rapport-A.txt, rapport-B.txt" in txt2
    assert "E (/x/E.pcap) : en-tete tronque" in txt
    assert "synthese :" in txt


# -- CLI -------------------------------------------------------------------------


@pytest.fixture
def dossier(tmp_path, monkeypatch):
    """Dossier : amont/aval du meme flux, une capture illisible, une sans
    rapport, un fichier non-capture."""
    src = tmp_path / "lot"
    src.mkdir()
    contenu = {
        "amont.pcap": _flux("x", T0, 20),
        "aval.pcapng": _flux("x", T0 + 0.003, 18),
        "autre.pcap": _flux("x", T0 + 86400, 5, src="192.168.1.1", dst="192.168.1.2"),
        "casse.pcap": None,
    }
    for name in [*contenu, "notes.txt"]:
        (src / name).write_bytes(b"\0")

    def faux_parse(label, path, raise_on_error=False):
        pk = contenu[os.path.basename(path)]
        if pk is None:
            raise RuntimeError("tshark: The file appears to be damaged or corrupt.\ndetail")
        return [dataclasses.replace(p, point=label) for p in pk]

    monkeypatch.setattr(cli, "parse_capture", faux_parse)
    return src, tmp_path / "out"


def _main(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["cross_capture_batch_cli.py", *map(str, args)])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def test_cli_lot_complet(dossier, monkeypatch, capsys):
    src, out = dossier
    code = _main(monkeypatch, "--input", src, "--output", out, "--security-report")
    assert code == 2  # une capture en echec
    index = (out / "index.txt").read_text()
    assert "LOT : 4 capture(s)" in index
    assert "[groupe 1] amont + aval  -> analyse croisee : rapport-groupe-1.txt" in index
    assert "autre (" in index and "hors fenetre" in index
    assert "casse (" in index and "damaged or corrupt" in index
    assert "notes.txt" in index and "extension non reconnue" in index
    for name in ("rapport-amont.txt", "rapport-aval.txt", "rapport-autre.txt", "rapport-groupe-1.txt"):
        assert "ANALYSE CROISEE" in (out / name).read_text()
    assert not (out / "rapport-casse.txt").exists()
    assert "Index du lot ecrit" in capsys.readouterr().out


def test_cli_skip_existing_reutilise_cache_et_rapports(dossier, monkeypatch, capsys):
    src, out = dossier
    _main(monkeypatch, "--input", src, "--output", out)
    capsys.readouterr()

    # la capture cassee n'est pas mise en cache : elle est retentee
    appels = []
    orig = cli.parse_capture

    def compte(label, path, raise_on_error=False):
        appels.append(label)
        return orig(label, path, raise_on_error)

    monkeypatch.setattr(cli, "parse_capture", compte)
    _main(monkeypatch, "--input", src, "--output", out, "--skip-existing")
    assert appels == ["casse"]
    assert "deja present, conserve (--skip-existing)" in capsys.readouterr().out


def test_cli_no_group(dossier, monkeypatch):
    src, out = dossier
    _main(monkeypatch, "--input", src, "--output", out, "--no-group")
    index = (out / "index.txt").read_text()
    assert "regroupement desactive" in index
    assert not (out / "rapport-groupe-1.txt").exists()


def test_cli_analyse_en_echec_n_arrete_pas_le_lot(dossier, monkeypatch):
    src, out = dossier

    def boom(*_a, **_k):
        raise ValueError("boom")

    monkeypatch.setattr(cli, "analyse", boom)
    assert _main(monkeypatch, "--input", src, "--output", out) == 2
    assert "analyse groupe 1 en echec : boom" in (out / "index.txt").read_text()


@pytest.mark.parametrize(
    ("args", "msg"),
    [
        (["--jobs", "0"], "--jobs doit etre >= 1"),
        (["--min-overlap", "0"], "--min-overlap"),
        (["--min-common-ips", "0"], "--min-common-ips"),
        (["--group-window", "-1"], "--group-window"),
    ],
)
def test_cli_validations(tmp_path, monkeypatch, capsys, args, msg):
    assert _main(monkeypatch, "--input", tmp_path, "--output", tmp_path / "o", *args) == 1
    assert msg in capsys.readouterr().err


def test_cli_dossier_absent_ou_vide(tmp_path, monkeypatch, capsys):
    assert _main(monkeypatch, "--input", tmp_path / "nope", "--output", tmp_path) == 1
    assert "dossier introuvable" in capsys.readouterr().err
    assert _main(monkeypatch, "--input", tmp_path, "--output", tmp_path / "o") == 1
    assert "Aucune capture" in capsys.readouterr().err


def test_list_captures_recursif_et_labels(tmp_path):
    (tmp_path / "s").mkdir()
    for p in ("a.pcap", "s/a.pcap", "b.PCAPNG", "c.pcap.gz", "x.txt"):
        (tmp_path / p).write_bytes(b"")
    caps, ign = cli.list_captures(str(tmp_path))
    assert [os.path.basename(c) for c in caps] == ["a.pcap", "b.PCAPNG", "c.pcap.gz"]
    assert [os.path.basename(i) for i in ign] == ["x.txt"]
    caps_r, _ = cli.list_captures(str(tmp_path), recursive=True)
    assert len(caps_r) == 4
    labels = cli.make_labels(caps_r)
    assert sorted(labels.values()) == ["a", "a_2", "b", "c"]


def test_build_inventory_capture_l_erreur(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("")

    monkeypatch.setattr(cli, "parse_capture", boom)
    inv = cli.build_inventory("A", "a.pcap")
    assert inv.error == "RuntimeError"


# -- bout en bout avec tshark (CI) -----------------------------------------------


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent du PATH")
def test_cli_bout_en_bout_tshark(tmp_path, monkeypatch):
    from test_cli_entrypoints import _ecrire_capture

    src = tmp_path / "lot"
    src.mkdir()
    _ecrire_capture(src / "amont.pcap", nb_paquets=20)
    _ecrire_capture(src / "aval.pcap", nb_paquets=18)
    (src / "casse.pcap").write_bytes(b"pas une capture")
    out = tmp_path / "out"
    assert _main(monkeypatch, "--input", src, "--output", out) == 2
    index = (out / "index.txt").read_text()
    assert "[groupe 1] amont + aval" in index
    assert "casse (" in index
    assert "ANALYSE CROISEE" in (out / "rapport-groupe-1.txt").read_text()


# -- Issue #729 : couverture des branches defensives de batch.py ------------


def test_capture_inventory_duration_none():
    """Lignes 73-74 : CaptureInventory.duration retourne 0.0 si start
    ou end est None."""
    inv = CaptureInventory(label="A", path="/x/A.pcap")
    assert inv.duration == 0.0


def test_is_meaningful_ip_invalide():
    """Lignes 113-116 : _is_meaningful_ip retourne False pour une adresse
    invalide."""
    from netcross_core.batch import _is_meaningful_ip

    assert _is_meaningful_ip("not-an-ip") is False


def test_fmt_ts_none():
    """Lignes 201-202 : _fmt_ts retourne '?' pour ts=None."""
    from netcross_core.batch import _fmt_ts

    assert _fmt_ts(None) == "?"


def test_fmt_list_avec_plus_de_limit():
    """Ligne 213 : _fmt_list ajoute '...' quand il y a plus d'items que
    la limite."""
    from netcross_core.batch import _fmt_list

    result = _fmt_list(["a", "b", "c", "d", "e"], limit=3)
    assert "..." in result
    assert "+2" in result


def test_fmt_gap_minutes():
    """Lignes 227-228 : _fmt_gap formate en minutes quand seconds >= 60."""
    from netcross_core.batch import _fmt_gap

    result = _fmt_gap(120.0)
    assert "min" in result


# -- Issue #728 : branches restantes de cross_capture_batch_cli.py ------------


def test_list_captures_recursif_ignore_le_cache(tmp_path):
    """Ligne 74 : le dossier de cache du lot n'est jamais reparcouru."""
    (tmp_path / "a.pcap").write_bytes(b"")
    cache = tmp_path / cli.CACHE_DIR / "inventaire"
    cache.mkdir(parents=True)
    (cache / "b.pcap").write_bytes(b"")
    captures, _ignored = cli.list_captures(str(tmp_path), recursive=True)
    assert captures == [str(tmp_path / "a.pcap")]


def test_cache_d_inventaire_perime(tmp_path):
    """Lignes 139-142 : empreinte differente -> cache ignore."""
    capture = tmp_path / "a.pcap"
    capture.write_bytes(b"x")
    cache = tmp_path / cli.CACHE_DIR / "inventaire" / "A.json"
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps({"fingerprint": [0, 0], "inventory": {"path": str(capture)}}), encoding="utf-8")
    assert cli.load_cached_inventory(str(tmp_path), "A", str(capture)) is None


def test_collect_inventories_en_parallele(monkeypatch):
    """Lignes 178-179 : jobs > 1 et plusieurs captures -> pool de processus."""
    vus = []

    class _Pool:
        def __init__(self, max_workers):
            vus.append(max_workers)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def map(self, fn, *iterables):
            return map(fn, *iterables)

    from types import SimpleNamespace

    monkeypatch.setattr(cli, "ProcessPoolExecutor", _Pool)
    monkeypatch.setattr(cli, "build_inventory", lambda label, path: SimpleNamespace(label=label, error="illisible"))
    res = cli.collect_inventories(["p1", "p2"], {"p1": "A", "p2": "B"}, "out", jobs=3)
    assert [inv.label for inv in res] == ["A", "B"]
    assert vus == [3]


def test_analyse_and_write_compte_les_constats(tmp_path, monkeypatch):
    """Lignes 213-214 : constats de securite comptes par severite (repli
    "faible" si absente)."""
    from types import SimpleNamespace

    rapport = SimpleNamespace(security_findings=[])

    def _constats(report, packets):
        report.security_findings = [{"severity": "critique"}, {"severity": None}, {}]

    monkeypatch.setattr(cli, "parse_capture", lambda label, path, raise_on_error: [])
    monkeypatch.setattr(cli, "correlate", lambda pkts: [])
    monkeypatch.setattr(cli, "analyse", lambda *a: rapport)
    monkeypatch.setattr(cli, "print_report", lambda r: print("rapport"))
    monkeypatch.setattr(cli.security_findings, "apply_security_findings", _constats)
    monkeypatch.setattr(cli, "build_security_report", lambda r: r)
    monkeypatch.setattr(cli, "print_security_report", lambda r: print("securite"))
    membres = [SimpleNamespace(label="A", path="a.pcap")]
    res = cli.analyse_and_write(membres, str(tmp_path / "r.txt"), security=True)
    assert res == {"findings": {"critique": 1, "faible": 2}}
    assert (tmp_path / "r.txt").read_text(encoding="utf-8") == "rapport\nsecurite\n"


def test_build_synthesis_rapports_graves():
    """Ligne 276 : rapports avec constats critiques/eleves listes."""
    from types import SimpleNamespace

    plan = SimpleNamespace(groups=[], isolated=[])
    resumes = {"r2": {"findings": {"elevee": 1}}, "r1": {"findings": {"critique": 2}}, "r3": {"findings": {}}}
    lignes = cli.build_synthesis(plan, resumes, [], [], True)
    assert "2 rapport(s) avec constats de severite critique/elevee : r1, r2" in lignes


def test_main_sans_echec_se_termine_normalement(dossier, monkeypatch, capsys):
    """Ligne 390 : lot sans capture illisible -> pas de sys.exit."""
    src, out = dossier
    (src / "casse.pcap").unlink()
    monkeypatch.setattr(sys, "argv", ["cross_capture_batch_cli.py", "--input", str(src), "--output", str(out)])
    cli.main()
    assert (out / "index.txt").is_file()
    assert "Index du lot ecrit dans" in capsys.readouterr().out
