"""Plusieurs captures dans un seul fichier pcapng (issue #474) :
pcap_parser.capture.list_interfaces / split_by_interface et l'option
--split-interfaces de cross_capture_analyzer_cli.py.

Deux familles de tests, comme test_merge_captures :
  - unitaires, SANS tshark : subprocess.run et _tshark_path sont remplaces,
    on verifie l'inventaire, le nommage des points, les arguments passes a
    tshark et le nettoyage en cas d'echec ;
  - d'integration, avec le VRAI tshark (sautes s'il est absent du PATH) :
    pcapng ecrits a la main (struct), puis analyse croisee complete sur les
    captures d'exemple du guide reunies dans un seul fichier.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import cross_capture_analyzer_cli as analyzer_cli
import pcap_parser
import pcap_parser.capture as capture_mod
import pcap_parser.ek_source as ek_source_mod
from pcap_parser.capture import InterfaceSlice, _slice_names, list_interfaces, split_by_interface
from pcap_parser.ek_source import TsharkError

requires_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark non installe")
requires_editcap = pytest.mark.skipif(shutil.which("editcap") is None, reason="editcap non installe")

EXEMPLES = Path(__file__).resolve().parent.parent / "docs" / "guide" / "exemples"


# -- fabrication de pcapng (sans tshark) --------------------------------------

_TRAME = bytes.fromhex("ffffffffffff0011223344550800") + bytes(46)  # 60 octets


def _opt(code: int, valeur: bytes) -> bytes:
    return struct.pack("<HH", code, len(valeur)) + valeur + bytes(-len(valeur) % 4)


def _bloc(type_bloc: int, corps: bytes) -> bytes:
    total = 12 + len(corps)
    return struct.pack("<II", type_bloc, total) + corps + struct.pack("<I", total)


def _shb() -> bytes:
    return _bloc(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + _opt(0, b""))


def _idb(nom: str | None = None) -> bytes:
    options = (_opt(2, nom.encode()) if nom else b"") + struct.pack("<HH", 0, 0)
    return _bloc(1, struct.pack("<HHI", 1, 0, 65535) + options)


def _epb(interface: int, i: int) -> bytes:
    ts = (1700000000 + i) * 1_000_000
    corps = struct.pack("<IIIII", interface, ts >> 32, ts & 0xFFFFFFFF, len(_TRAME), len(_TRAME))
    return _bloc(6, corps + _TRAME + bytes(-len(_TRAME) % 4))


def _section(noms: list[str | None], paquets: list[int]) -> bytes:
    """Une section : une IDB par nom, puis paquets[k] paquets sur l'interface k."""
    out = _shb() + b"".join(_idb(nom) for nom in noms)
    i = 0
    for interface, nombre in enumerate(paquets):
        for _ in range(nombre):
            out += _epb(interface, i)
            i += 1
    return out


# -- nommage des points --------------------------------------------------------


def test_nom_d_interface_repris_tel_quel():
    noms = _slice_names([(1, 0), (1, 1)], {(1, 0): "eth0", (1, 1): "eth1"})
    assert noms == {(1, 0): "eth0", (1, 1): "eth1"}


def test_sans_nom_une_section_donne_if_n():
    assert _slice_names([(1, 0), (1, 1)], {}) == {(1, 0): "if0", (1, 1): "if1"}


def test_sans_nom_plusieurs_sections_donne_s_if():
    """Fichiers concatenes : l'interface_id repart de 0, la section seule
    distingue les deux captures."""
    assert _slice_names([(1, 0), (2, 0)], {}) == {(1, 0): "s1-if0", (2, 0): "s2-if0"}


def test_meme_nom_dans_deux_sections_jamais_fusionne():
    """Deux postes captures chacun sur eth0 : deux points distincts, pas un."""
    noms = _slice_names([(1, 0), (2, 0)], {(1, 0): "eth0", (2, 0): "eth0"})
    assert noms == {(1, 0): "eth0-s1-if0", (2, 0): "eth0-s2-if0"}
    assert len(set(noms.values())) == 2


# -- list_interfaces / split_by_interface, tshark simule -----------------------


class _FauxTshark:
    """Remplace subprocess.run : renvoie `sortie` pour l'inventaire, et
    ecrit un fichier (ou echoue) pour chaque extraction -Y."""

    def __init__(self, sortie: str, echec_extraction: int | None = None):
        self.sortie = sortie
        self.echec_extraction = echec_extraction
        self.appels: list[list[str]] = []

    def __call__(self, args, **_kwargs):
        self.appels.append(list(args))
        if "-T" in args:
            return subprocess.CompletedProcess(args, 0, stdout=self.sortie, stderr="")
        extractions = [a for a in self.appels if "-Y" in a]
        if self.echec_extraction is not None and len(extractions) == self.echec_extraction:
            return subprocess.CompletedProcess(args, 2, stdout="", stderr="boum")
        Path(args[args.index("-w") + 1]).write_bytes(b"extrait")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")


@pytest.fixture
def capture(tmp_path):
    chemin = tmp_path / "site.pcapng"
    chemin.write_bytes(b"contenu sans importance, tshark est simule")
    return chemin


def _simuler(monkeypatch, faux: _FauxTshark) -> _FauxTshark:
    monkeypatch.setattr(ek_source_mod, "_tshark_path", lambda: "/usr/bin/tshark")
    monkeypatch.setattr(capture_mod.subprocess, "run", faux)
    return faux


def test_inventaire_compte_les_paquets_par_section_et_interface(monkeypatch, capture):
    sortie = "1\t0\teth0\n1\t0\teth0\n1\t1\tunknown\n2\t0\t\n2\t0\t\n2\t0\t\n"
    _simuler(monkeypatch, _FauxTshark(sortie))
    assert list_interfaces(str(capture)) == [
        InterfaceSlice(1, 0, "eth0", 2),
        InterfaceSlice(1, 1, "s1-if1", 1),
        InterfaceSlice(2, 0, "s2-if0", 3),
    ]


def test_inventaire_pcap_classique_sans_numero_de_section(monkeypatch, capture):
    """frame.section_number est vide sur un pcap classique : section 1."""
    _simuler(monkeypatch, _FauxTshark("\t0\tunknown\n\t0\tunknown\n"))
    assert list_interfaces(str(capture)) == [InterfaceSlice(1, 0, "if0", 2)]


def test_inventaire_ignore_une_ligne_illisible(monkeypatch, capture):
    _simuler(monkeypatch, _FauxTshark("1\t0\teth0\nabc\tdef\n"))
    assert list_interfaces(str(capture)) == [InterfaceSlice(1, 0, "eth0", 1)]


def test_inventaire_echec_de_tshark(monkeypatch, capture):
    def echoue(args, **_kwargs):
        return subprocess.CompletedProcess(args, 2, stdout="", stderr="fichier corrompu")

    monkeypatch.setattr(ek_source_mod, "_tshark_path", lambda: "/usr/bin/tshark")
    monkeypatch.setattr(capture_mod.subprocess, "run", echoue)
    with pytest.raises(TsharkError, match="fichier corrompu"):
        list_interfaces(str(capture))


def test_capture_absente(tmp_path):
    with pytest.raises(FileNotFoundError):
        list_interfaces(str(tmp_path / "absente.pcapng"))


def test_une_seule_capture_rien_n_est_ecrit(monkeypatch, capture, tmp_path):
    faux = _simuler(monkeypatch, _FauxTshark("1\t0\teth0\n"))
    sortie = tmp_path / "sortie"
    assert split_by_interface(str(capture), str(sortie)) == [InterfaceSlice(1, 0, "eth0", 1, str(capture))]
    assert not sortie.exists()
    assert not [a for a in faux.appels if "-Y" in a]


def test_separation_filtre_par_section_et_interface(monkeypatch, capture, tmp_path):
    faux = _simuler(monkeypatch, _FauxTshark("1\t0\teth0\n2\t0\teth0\n"))
    tranches = split_by_interface(str(capture), str(tmp_path / "sortie"))
    assert [t.name for t in tranches] == ["eth0-s1-if0", "eth0-s2-if0"]
    assert all(Path(t.path).is_file() for t in tranches)
    filtres = [a[a.index("-Y") + 1] for a in faux.appels if "-Y" in a]
    assert filtres == [
        "frame.section_number == 1 && frame.interface_id == 0",
        "frame.section_number == 2 && frame.interface_id == 0",
    ]
    # toujours du pcapng : seul format qui garde l'IDB de chaque capture
    assert all(a[a.index("-F") + 1] == "pcapng" for a in faux.appels if "-Y" in a)


def test_nom_d_interface_rendu_sur_pour_le_fichier(monkeypatch, capture, tmp_path):
    _simuler(monkeypatch, _FauxTshark("1\t0\t\\Device\\NPF_{A1}\n1\t1\teth0:1\n"))
    tranches = split_by_interface(str(capture), str(tmp_path / "sortie"))
    assert [t.name for t in tranches] == ["\\Device\\NPF_{A1}", "eth0:1"]
    assert [Path(t.path).name for t in tranches] == ["site__Device_NPF__A1_.pcapng", "site_eth0_1.pcapng"]


def test_rien_n_est_ecrase(monkeypatch, capture, tmp_path):
    faux = _simuler(monkeypatch, _FauxTshark("1\t0\t\n1\t1\t\n"))
    sortie = tmp_path / "sortie"
    sortie.mkdir()
    (sortie / "site_if1.pcapng").write_bytes(b"ancien")
    with pytest.raises(FileExistsError, match="site_if1"):
        split_by_interface(str(capture), str(sortie))
    assert (sortie / "site_if1.pcapng").read_bytes() == b"ancien"
    assert not [a for a in faux.appels if "-Y" in a]


def test_echec_d_extraction_supprime_les_fichiers_partiels(monkeypatch, capture, tmp_path):
    _simuler(monkeypatch, _FauxTshark("1\t0\t\n1\t1\t\n1\t2\t\n", echec_extraction=2))
    sortie = tmp_path / "sortie"
    with pytest.raises(TsharkError, match="boum"):
        split_by_interface(str(capture), str(sortie))
    assert list(sortie.iterdir()) == []


def test_exporte_par_le_paquet():
    assert pcap_parser.split_by_interface is split_by_interface
    assert pcap_parser.list_interfaces is list_interfaces
    assert pcap_parser.InterfaceSlice is InterfaceSlice


# -- CLI, separation simulee ----------------------------------------------------


def _run_cli(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *args])
    analyzer_cli.main()


def test_expansion_nomme_les_points_nom_interface(monkeypatch, tmp_path, capsys):
    def faux_split(path, output_dir):
        if path == "seul.pcapng":
            return [InterfaceSlice(1, 0, "if0", 3, path)]
        return [InterfaceSlice(1, 0, "eth0", 4, f"{output_dir}/a"), InterfaceSlice(1, 1, "eth1", 2, f"{output_dir}/b")]

    monkeypatch.setattr(analyzer_cli, "split_by_interface", faux_split)
    captures = analyzer_cli._expand_split_interfaces([("SITE", "multi.pcapng"), ("B", "seul.pcapng")])
    labels = [label for label, _path in captures]
    assert labels == ["SITE:eth0", "SITE:eth1", "B"]
    assert captures[2] == ("B", "seul.pcapng")
    sortie = capsys.readouterr().out
    assert "2 captures dans multi.pcapng" in sortie
    assert "une seule capture dans seul.pcapng" in sortie


def test_expansion_fichier_illisible_laisse_tel_quel(monkeypatch, capsys):
    def echoue(path, output_dir):
        raise TsharkError("illisible", returncode=2, stderr="illisible")

    monkeypatch.setattr(analyzer_cli, "split_by_interface", echoue)
    assert analyzer_cli._expand_split_interfaces([("A", "x.pcapng")]) == [("A", "x.pcapng")]
    assert "non separe" in capsys.readouterr().err


def test_incompatible_avec_live(monkeypatch, capsys):
    with pytest.raises(SystemExit) as exc:
        _run_cli(monkeypatch, "--live", "A:eth0", "--split-interfaces")
    assert exc.value.code == 1
    assert "--split-interfaces" in capsys.readouterr().err


# -- integration, vrai tshark -----------------------------------------------------


@requires_tshark
def test_reel_deux_interfaces_nommees(tmp_path):
    chemin = tmp_path / "deux.pcapng"
    chemin.write_bytes(_section(["eth0", "eth1"], [3, 2]))
    assert list_interfaces(str(chemin)) == [InterfaceSlice(1, 0, "eth0", 3), InterfaceSlice(1, 1, "eth1", 2)]
    tranches = split_by_interface(str(chemin), str(tmp_path / "sortie"))
    # chaque fichier extrait ne contient que les paquets de son interface
    for tranche, attendu in zip(tranches, (3, 2)):
        assert sum(t.packets for t in list_interfaces(tranche.path)) == attendu


@requires_tshark
def test_reel_sections_concatenees(tmp_path):
    chemin = tmp_path / "cat.pcapng"
    chemin.write_bytes(_section([None], [4]) + _section([None], [1]))
    assert list_interfaces(str(chemin)) == [InterfaceSlice(1, 0, "s1-if0", 4), InterfaceSlice(2, 0, "s2-if0", 1)]
    tranches = split_by_interface(str(chemin), str(tmp_path / "sortie"))
    assert [sum(t.packets for t in list_interfaces(tr.path)) for tr in tranches] == [4, 1]


@requires_tshark
@requires_editcap
def test_reel_analyse_croisee_dans_un_seul_fichier(monkeypatch, tmp_path, capsys):
    """Les captures LAN et WAN du guide, reunies dans UN fichier, donnent la
    meme conclusion que passees separement : 5 pertes entre les deux."""
    morceaux = []
    for nom in ("lan", "wan"):
        sortie = tmp_path / f"{nom}.pcapng"
        subprocess.run(["editcap", "-F", "pcapng", str(EXEMPLES / f"{nom}.pcap"), str(sortie)], check=True)
        morceaux.append(sortie.read_bytes())
    site = tmp_path / "site.pcapng"
    site.write_bytes(b"".join(morceaux))

    _run_cli(monkeypatch, "--capture", f"SITE={site}", "--split-interfaces")
    sortie = capsys.readouterr().out
    assert "[SITE] --split-interfaces : 2 captures" in sortie
    assert "SITE:s1-if0 -> SITE:s2-if0" in sortie
    assert "SITE:s2-if0     : 5 paquets manquants" in sortie
