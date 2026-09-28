"""
netcross_core.naming -- tests de la table des noms (Job 18 / issue #17,
section 6.15) et de son integration dans les sorties CSV detail et JSON.

Couvre : resolution par adresse et MAC (insensible a la casse), affichage
avec repli sur l'adresse brute, validation des entrees, persistance JSON et
YAML (round-trip), tolerance du format {"entries": [...]}, table vide,
et integration -- write_detail_csv + generate_json_report affichent les
noms logiques a la place des adresses IP brutes.
"""

from __future__ import annotations

import csv
import json

import pytest
from conftest import make_pkt

from netcross_core.correlate import build_conversations, build_flows, correlate
from netcross_core.models import Report
from netcross_core.naming import NameEntry, NameTable
from netcross_report.json_report import generate_json_report

# -- NameEntry.matches ------------------------------------------------------


def test_name_entry_matches_par_adresse():
    e = NameEntry(name="PC-COMPTA-31", address="10.0.0.1")
    assert e.matches(address="10.0.0.1")
    assert not e.matches(address="10.0.0.2")


def test_name_entry_matches_par_mac_insensible_casse():
    e = NameEntry(name="SW-CORE", mac="AA:BB:CC:DD:EE:FF")
    assert e.matches(mac="aa:bb:cc:dd:ee:ff")
    assert e.matches(mac="AA:BB:CC:DD:EE:FF")
    assert not e.matches(mac="11:22:33:44:55:66")


def test_name_entry_matches_aucun_identifiant():
    e = NameEntry(name="X", address="10.0.0.1")
    assert not e.matches()  # ni adresse ni MAC fournis


# -- NameTable : add / resolve / display ------------------------------------


def test_table_add_et_resolve_par_adresse():
    t = NameTable()
    t.add(NameEntry(name="PC-COMPTA-31", address="10.0.0.1", type="client"))
    e = t.resolve("10.0.0.1")
    assert e is not None
    assert e.name == "PC-COMPTA-31"
    assert e.type == "client"
    assert t.resolve("10.0.0.99") is None


def test_table_resolve_mac_insensible_casse():
    t = NameTable([NameEntry(name="SW-CORE", mac="AA:BB:CC:DD:EE:FF")])
    assert t.resolve_mac("aa:bb:cc:dd:ee:ff").name == "SW-CORE"
    assert t.resolve_mac(None) is None


def test_table_display_replie_sur_adresse_brute():
    t = NameTable([NameEntry(name="APP-SQL-01", address="10.0.0.2")])
    assert t.display("10.0.0.2") == "APP-SQL-01"
    # Adresse inconnue -> renvoie l'adresse telle quelle.
    assert t.display("10.0.0.99") == "10.0.0.99"
    # None -> chaine vide (cellule CSV vide).
    assert t.display(None) == ""


def test_table_display_table_vide_replie_sur_brut():
    t = NameTable()
    assert t.display("10.0.0.1") == "10.0.0.1"
    assert len(t) == 0
    assert not t


def test_table_add_ecrase_entree_precedente_pour_meme_adresse():
    t = NameTable()
    t.add(NameEntry(name="OLD", address="10.0.0.1"))
    t.add(NameEntry(name="NEW", address="10.0.0.1"))
    assert t.resolve("10.0.0.1").name == "NEW"
    assert len(t) == 2  # l'entree precedente reste dans la liste interne


# -- Validation -------------------------------------------------------------


def test_table_add_name_requis():
    with pytest.raises(ValueError, match="name"):
        NameTable().add(NameEntry(name="", address="10.0.0.1"))


def test_table_add_identifiant_requis():
    with pytest.raises(ValueError, match="adresse ou une MAC"):
        NameTable().add(NameEntry(name="X"))  # ni adresse ni MAC


# -- Persistance JSON -------------------------------------------------------


def test_from_list_to_list_round_trip_json():
    entries = [
        {
            "name": "PC-COMPTA-31",
            "address": "10.0.0.1",
            "type": "client",
            "site": "Besancon",
            "role": "compta",
            "comment": None,
        },
        {"name": "SW-CORE", "mac": "aa:bb:cc:dd:ee:ff", "type": "routeur"},
    ]
    t = NameTable.from_list(entries)
    out = t.to_list()
    assert out[0]["name"] == "PC-COMPTA-31"
    assert out[0]["address"] == "10.0.0.1"
    assert out[0]["site"] == "Besancon"
    assert out[1]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_save_load_json_round_trip(tmp_path):
    path = tmp_path / "names.json"
    t = NameTable(
        [
            NameEntry(name="PC-COMPTA-31", address="10.0.0.1", type="client"),
            NameEntry(name="SW-CORE", mac="aa:bb:cc:dd:ee:ff", type="routeur"),
        ]
    )
    t.save(path)
    loaded = NameTable.load(path)
    assert loaded.display("10.0.0.1") == "PC-COMPTA-31"
    assert loaded.resolve_mac("AA:BB:CC:DD:EE:FF").name == "SW-CORE"


def test_load_json_format_dict_entries_tolere(tmp_path):
    path = tmp_path / "names.json"
    path.write_text(
        json.dumps({"entries": [{"name": "X", "address": "10.0.0.1"}]}),
        encoding="utf-8",
    )
    t = NameTable.load(path)
    assert t.display("10.0.0.1") == "X"


def test_load_fichier_introuvable_leve_erreur(tmp_path):
    with pytest.raises(FileNotFoundError):
        NameTable.load(tmp_path / "absent.json")


def test_load_name_manquant_leve_erreur(tmp_path):
    path = tmp_path / "names.json"
    path.write_text(json.dumps([{"address": "10.0.0.1"}]), encoding="utf-8")
    with pytest.raises(ValueError, match="name"):
        NameTable.load(path)


# -- Persistance YAML (optionnel) ------------------------------------------


def test_save_load_yaml_round_trip(tmp_path):
    yaml = pytest.importorskip("yaml")
    path = tmp_path / "names.yaml"
    t = NameTable([NameEntry(name="PC-COMPTA-31", address="10.0.0.1", type="client")])
    t.save(path)
    # Le fichier est bien du YAML (mapping, pas du JSON pur).
    assert isinstance(yaml.safe_load(path.read_text(encoding="utf-8")), list)
    loaded = NameTable.load(path)
    assert loaded.display("10.0.0.1") == "PC-COMPTA-31"


# -- Integration : write_detail_csv -----------------------------------------


def test_write_detail_csv_affiche_les_noms_logiques(tmp_path):
    from netcross_core.report_text import write_detail_csv

    pkts = [
        make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", sport=1, dport=443),
    ]
    flows = correlate(pkts)
    names = NameTable(
        [
            NameEntry(name="PC-COMPTA-31", address="10.0.0.1"),
            NameEntry(name="APP-SQL-01", address="10.0.0.2"),
        ]
    )
    out = tmp_path / "detail.csv"
    write_detail_csv(out, flows, ["A"], names=names)

    with open(out, encoding="utf-8") as f:
        rows = list(csv.reader(f))
    header = rows[0]
    body = rows[1]
    src_idx = header.index("src")
    dst_idx = header.index("dst")
    assert body[src_idx] == "PC-COMPTA-31"
    assert body[dst_idx] == "APP-SQL-01"


def test_write_detail_csv_sans_table_garde_adresses_brutes(tmp_path):
    from netcross_core.report_text import write_detail_csv

    pkts = [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", sport=1)]
    flows = correlate(pkts)
    out = tmp_path / "detail.csv"
    write_detail_csv(out, flows, ["A"])  # names=None
    with open(out, encoding="utf-8") as f:
        rows = list(csv.reader(f))
    header = rows[0]
    body = rows[1]
    assert body[header.index("src")] == "10.0.0.1"
    assert body[header.index("dst")] == "10.0.0.2"


# -- Integration : generate_json_report -------------------------------------


def test_generate_json_report_expose_endpoints_labels(tmp_path):
    pkts = [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", sport=1)]
    flows = correlate(pkts)
    flow_objs = build_flows(flows)
    conversations = build_conversations(flow_objs)
    r = Report(points=["A"])
    names = NameTable(
        [
            NameEntry(name="PC-COMPTA-31", address="10.0.0.1"),
            NameEntry(name="APP-SQL-01", address="10.0.0.2"),
        ]
    )
    out = tmp_path / "report.json"
    generate_json_report(r, out, flows=flow_objs, conversations=conversations, names=names)
    doc = json.loads(out.read_text(encoding="utf-8"))
    # Les endpoints bruts restent disponibles cote consommateur programmatique.
    assert doc["flows"][0]["endpoints"] == ["10.0.0.1", "10.0.0.2"]
    assert doc["flows"][0]["endpoints_labels"] == ["PC-COMPTA-31", "APP-SQL-01"]
    assert doc["conversations"][0]["endpoints_labels"] == [
        "PC-COMPTA-31",
        "APP-SQL-01",
    ]


def test_generate_json_report_sans_names_pas_de_labels(tmp_path):
    pkts = [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", sport=1)]
    flow_objs = build_flows(correlate(pkts))
    r = Report(points=["A"])
    out = tmp_path / "report.json"
    generate_json_report(r, out, flows=flow_objs)
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert "endpoints_labels" not in doc["flows"][0]


# -- Issue #726 : couverture des branches defensives de naming.py ------------


def test_table_resolve_none():
    """Lignes 109-110 : NameTable.resolve(None) retourne None."""
    t = NameTable()
    assert t.resolve(None) is None


def test_load_json_list_pas_dict(tmp_path):
    """Lignes 183, 188-190 : NameTable.load avec JSON qui n'est ni liste
    ni dict avec 'entries' -- leve ValueError."""
    import pytest
    path = tmp_path / "names.json"
    path.write_text(json.dumps("just a string"), encoding="utf-8")
    with pytest.raises(ValueError, match="liste"):
        NameTable.load(path)
