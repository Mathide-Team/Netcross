"""Issue #671 : dans la GUI, deux lignes de meme nom forment un seul point
(capture en rotation, comme ``--capture NOM=a,b`` de la CLI)."""

from conftest import make_pkt

from netcross_gtk4 import analysis_pipeline, diff_pipeline
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline
from netcross_gtk4.capture_list import ordre_des_points, segments_par_point


def test_ordre_des_points_garde_la_premiere_position():
    captures = [("LAN", "a"), ("WAN", "w"), ("LAN", "b"), ("DC", "d")]
    assert ordre_des_points(captures) == ["LAN", "WAN", "DC"]


def test_ordre_des_points_sans_rotation_inchange():
    assert ordre_des_points([("LAN", "a"), ("DC", "d")]) == ["LAN", "DC"]
    assert ordre_des_points([]) == []


def test_segments_par_point_ne_liste_que_la_rotation():
    captures = [("LAN", "a"), ("LAN", "b"), ("LAN", "c"), ("DC", "d")]
    assert segments_par_point(captures) == {"LAN": 3}
    assert segments_par_point([("LAN", "a"), ("DC", "d")]) == {}


def test_pipeline_concatene_les_segments_d_un_point(monkeypatch):
    par_fichier = {
        "lan_1.pcap": [make_pkt(point="LAN", sport=1)],
        "lan_2.pcap": [make_pkt(point="LAN", sport=2, ts=1000.0)],
        "dc.pcap": [make_pkt(point="DC", sport=2, ts=1000.004)],
    }
    monkeypatch.setattr(analysis_pipeline, "parse_capture", lambda label, path: list(par_fichier[path]))
    journal = []
    result = run_analysis_pipeline(
        [("LAN", "lan_1.pcap"), ("LAN", "lan_2.pcap"), ("DC", "dc.pcap")],
        AnalysisOptions(parallel=False, auto_topology=False),
        on_progress=journal.append,
    )
    assert list(result.report.points) == ["LAN", "DC"]
    assert result.report.loss_count.get("DC") == 1
    assert any("[LAN] 2 segments lus a la suite" in ligne for ligne in journal)


def test_diff_pipeline_utilise_l_ordre_des_points():
    assert diff_pipeline.capture_list.ordre_des_points is ordre_des_points
