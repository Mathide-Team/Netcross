"""POST /captures/multi : analyse croisee entre points via l'API (issue #354).

parse_capture est remplace par des paquets synthetiques par etiquette :
le scenario LAN -> DC reprend test_analysis (un paquet vu au LAN manque au
DC alors que les deux hotes y echangent : perte sur le segment).
"""

import pytest
from conftest import make_pkt

try:
    import importlib

    from fastapi.testclient import TestClient

    api_module = importlib.import_module("netcross_api.app")
    from netcross_api.app import app, segment_losses
    from netcross_api.store import store
except ImportError:
    pytest.skip("fastapi non installe (extra [api])", allow_module_level=True)

client = TestClient(app)

PAQUETS = {
    "LAN": [make_pkt(point="LAN", sport=1), make_pkt(point="LAN", sport=2, ts=1000.0)],
    "DC": [make_pkt(point="DC", sport=2, ts=1000.004)],
}


@pytest.fixture(autouse=True)
def _captures(monkeypatch):
    store._store.clear()
    monkeypatch.setattr(api_module, "parse_capture", lambda label, path: list(PAQUETS.get(label, [])))
    monkeypatch.setattr(api_module, "scan_capture_exploits", lambda label, path: [])
    yield
    store._store.clear()


def _post(labels="LAN,DC", points_order="LAN,DC", noms=("lan.pcap", "dc.pcap")):
    files = [("files", (nom, b"\xd4\xc3\xb2\xa1" + b"\x00" * 20, "application/octet-stream")) for nom in noms]
    data = {"labels": labels}
    if points_order is not None:
        data["points_order"] = points_order
    return client.post("/captures/multi?wait=true", files=files, data=data)


def test_deux_captures_lan_dc_pertes_par_segment():
    response = _post()
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["points"] == ["LAN", "DC"]
    assert body["order_source"] == "points_order"
    assert body["packet_count"] == 3
    (segment,) = body["segments"]
    assert segment["segment"] == "LAN -> DC"
    assert (segment["upstream"], segment["downstream"]) == ("LAN", "DC")
    assert segment["loss_count"] == 1
    assert segment["seen_downstream"] == 1
    assert segment["loss_pct"] == 100.0
    assert segment["off_path_count"] == 0


def test_ordre_deduit_sans_points_order():
    response = _post(points_order=None)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["order_source"] == "auto"
    assert sorted(body["points"]) == ["DC", "LAN"]


def test_rapport_complet_multipoints_serialisable():
    """Les champs par segment (cles tuple) faisaient echouer GET /analyses/{id}."""
    analysis_id = _post().json()["analysis_id"]
    response = client.get(f"/analyses/{analysis_id}")
    assert response.status_code == 200, response.text
    doc = response.json()
    assert doc["points"] == ["LAN", "DC"]
    assert doc["pairs"] == [["LAN", "DC"]]
    assert doc["loss_count"]["DC"] == 1
    assert "LAN -> DC" in doc["latency"]


def test_metadonnees_conservees():
    analysis_id = _post().json()["analysis_id"]
    meta = store.get(analysis_id)["metadata"]
    options = meta.pop("options")  # issue #330 : options d'analyse retenues
    assert meta == {
        "files": ["lan.pcap", "dc.pcap"],
        "labels": ["LAN", "DC"],
        "points_order": ["LAN", "DC"],
        "split_interfaces": False,
        "rotation": False,
    }
    assert options["nat_tolerant"] is False and options["redact"] is False


@pytest.mark.parametrize(
    ("labels", "points_order", "fragment"),
    [
        ("", "LAN,DC", "une étiquette non vide par fichier"),
        ("LAN", None, "une étiquette non vide par fichier"),
        ("LAN,", None, "une étiquette non vide par fichier"),
        ("LAN,LAN", None, "Étiquettes dupliquées : LAN"),
        ("LAN,DC", "LAN,WAN", "inconnue(s) : WAN"),
        ("LAN,DC", "LAN", "absente(s) : DC"),
        ("LAN,DC", "LAN,DC,LAN", "exactement une fois"),
    ],
)
def test_etiquettes_et_ordre_invalides_refuses(labels, points_order, fragment):
    response = _post(labels=labels, points_order=points_order)
    assert response.status_code == 400
    assert fragment in response.json()["detail"]
    assert store.list_ids() == []


def test_un_seul_fichier_accepte_capture_unique():
    # Issue #474 lot 2 : une capture seule, sans analyse croisée.
    response = _post(labels="LAN", points_order=None, noms=("lan.pcap",))
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["points"] == ["LAN"]
    assert body["segments"] == []


def _post_rotation(monkeypatch, labels, points_order=None, noms=("lan_00001.pcap", "lan_00002.pcap", "dc.pcap")):
    # Chaque fichier donne ses propres paquets : le segment LAN_2 porte le
    # paquet que le DC voit, le segment LAN_1 le paquet perdu.
    par_fichier = iter(
        [
            [make_pkt(point="LAN", sport=1)],
            [make_pkt(point="LAN", sport=2, ts=1000.0)],
            [make_pkt(point="DC", sport=2, ts=1000.004)],
        ]
    )
    monkeypatch.setattr(api_module, "parse_capture", lambda label, path: next(par_fichier))
    files = [("files", (nom, b"\xd4\xc3\xb2\xa1" + b"\x00" * 20, "application/octet-stream")) for nom in noms]
    data = {"labels": labels, "rotation": "true"}
    if points_order is not None:
        data["points_order"] = points_order
    return client.post("/captures/multi?wait=true", files=files, data=data)


def test_rotation_segments_d_un_meme_point(monkeypatch):
    # Issue #671 : LAN en deux fichiers, lus a la suite comme un seul point.
    response = _post_rotation(monkeypatch, "LAN,LAN,DC", "LAN,DC")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["points"] == ["LAN", "DC"]
    assert body["packet_count"] == 3
    (segment,) = body["segments"]
    assert segment["segment"] == "LAN -> DC"
    assert segment["loss_count"] == 1
    meta = store.get(body["analysis_id"])["metadata"]
    assert meta["labels"] == ["LAN", "LAN", "DC"]
    assert meta["points_order"] == ["LAN", "DC"]
    assert meta["rotation"] is True


def test_rotation_ordre_deduit(monkeypatch):
    response = _post_rotation(monkeypatch, "LAN,LAN,DC")
    assert response.status_code == 201, response.text
    assert sorted(response.json()["points"]) == ["DC", "LAN"]


def test_rotation_points_order_cite_chaque_point_une_fois(monkeypatch):
    response = _post_rotation(monkeypatch, "LAN,LAN,DC", "LAN,LAN,DC")
    assert response.status_code == 400
    assert "exactement une fois" in response.json()["detail"]


def test_etiquette_repetee_refusee_sans_rotation():
    response = _post(labels="LAN,LAN", points_order=None)
    assert response.status_code == 400
    assert "Étiquettes dupliquées : LAN" in response.json()["detail"]


def test_aucun_fichier_refuse():
    response = client.post("/captures/multi?wait=true", data={"labels": ""})
    assert response.status_code in (400, 422)


def _tranches(monkeypatch, noms=("eth0", "eth1"), echec=None):
    from pcap_parser.capture import InterfaceSlice

    appels = []

    def faux_split(path, output_dir):
        appels.append((path, output_dir))
        if echec is not None:
            raise echec
        tranches = []
        for i, nom in enumerate(noms):
            cible = f"{output_dir}/{nom}.pcapng"
            with open(cible, "wb") as fh:
                fh.write(b"x")
            tranches.append(InterfaceSlice(section=0, interface_id=i, name=nom, packets=1, path=cible))
        return tranches

    monkeypatch.setattr(api_module, "split_by_interface", faux_split)
    return appels


def test_split_interfaces_un_point_par_interface(monkeypatch):
    import os

    appels = _tranches(monkeypatch)
    PAQUETS["SW:eth0"] = [make_pkt(point="SW:eth0", sport=2, ts=1000.0)]
    PAQUETS["SW:eth1"] = [make_pkt(point="SW:eth1", sport=2, ts=1000.004)]
    try:
        files = [("files", ("sw.pcapng", b"\x0a\x0d\x0d\x0a" + b"\x00" * 20, "application/octet-stream"))]
        data = {"labels": "SW", "split_interfaces": "true", "points_order": "SW:eth0,SW:eth1"}
        response = client.post("/captures/multi?wait=true", files=files, data=data)
    finally:
        del PAQUETS["SW:eth0"], PAQUETS["SW:eth1"]
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["points"] == ["SW:eth0", "SW:eth1"]
    assert body["order_source"] == "points_order"
    ((origine, repertoire),) = appels
    assert not os.path.exists(origine)
    assert not os.path.exists(repertoire)


def test_split_interfaces_ordre_valide_apres_separation(monkeypatch):
    import os

    appels = _tranches(monkeypatch)
    files = [("files", ("sw.pcapng", b"\x00" * 24, "application/octet-stream"))]
    data = {"labels": "SW", "split_interfaces": "true", "points_order": "SW"}
    response = client.post("/captures/multi?wait=true", files=files, data=data)
    assert response.status_code == 400
    assert "inconnue(s)" in response.json()["detail"] or "absente(s)" in response.json()["detail"]
    ((_origine, repertoire),) = appels
    assert not os.path.exists(repertoire)
    assert store.list_ids() == []


def test_split_interfaces_echec_de_separation_400(monkeypatch):
    import os

    from pcap_parser.ek_source import TsharkError

    appels = _tranches(monkeypatch, echec=TsharkError("illisible"))
    files = [("files", ("sw.pcapng", b"\x00" * 24, "application/octet-stream"))]
    response = client.post("/captures/multi?wait=true", files=files, data={"labels": "SW", "split_interfaces": "true"})
    assert response.status_code == 400
    assert "séparation des interfaces impossible" in response.json()["detail"]
    ((origine, repertoire),) = appels
    assert not os.path.exists(origine)
    assert not os.path.exists(repertoire)


def test_split_interfaces_une_seule_capture_garde_l_etiquette(monkeypatch):
    _tranches(monkeypatch, noms=("eth0",))
    files = [("files", ("lan.pcapng", b"\x00" * 24, "application/octet-stream"))]
    response = client.post("/captures/multi?wait=true", files=files, data={"labels": "LAN", "split_interfaces": "true"})
    assert response.status_code == 201, response.text
    assert response.json()["points"] == ["LAN"]


def test_capture_vide_refusee(monkeypatch):
    monkeypatch.setattr(api_module, "parse_capture", lambda label, path: [] if label == "DC" else list(PAQUETS[label]))
    response = _post()
    assert response.status_code == 400
    assert "Aucun paquet trouvé dans la capture DC" in response.json()["detail"]


def test_limite_de_taille_appliquee(monkeypatch):
    monkeypatch.setattr(api_module, "_MAX_UPLOAD_BYTES", 10)
    response = _post()
    assert response.status_code == 413
    assert "LAN" in response.json()["detail"]


def test_jeton_exige_comme_les_autres_routes(monkeypatch):
    monkeypatch.setattr(api_module, "_API_TOKEN", "secret")
    assert _post().status_code == 401
    files = [("files", (n, b"x" * 8, "application/octet-stream")) for n in ("a.pcap", "b.pcap")]
    ok = client.post(
        "/captures/multi?wait=true", files=files, data={"labels": "LAN,DC"}, headers={"X-API-Key": "secret"}
    )
    assert ok.status_code == 201, ok.text


def test_segment_losses_sans_paquet_aval():
    """Aucun paquet vu en aval : taux None plutot qu'une division par zero."""
    from netcross_core.models import Report

    report = Report(points=["A", "B"], pairs=[("A", "B")])
    (seg,) = segment_losses(report)
    assert seg.loss_pct is None
    assert seg.latency_avg_ms is None


def test_captures_simple_lit_l_etiquette_du_formulaire():
    """Le -F label=... documente etait ignore (parametre de requete)."""
    response = client.post(
        "/captures?wait=true",
        files={"file": ("lan.pcap", b"x" * 8, "application/octet-stream")},
        data={"label": "LAN"},
    )
    assert response.status_code == 201, response.text
    meta = store.get(response.json()["analysis_id"])["metadata"]
    assert meta["label"] == "LAN"
