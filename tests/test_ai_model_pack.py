"""Issue #271 : paquets de modeles partageables (ZIP anonyme, verifie) et
boite d'envoi hors connexion. Aucun test ne necessite scikit-learn ni le
reseau (is_online est simule)."""

from __future__ import annotations

import hashlib
import json
import random
import zipfile

import pytest

import netcross_ai.outbox as outbox_mod
import netcross_ai_models_cli as models_cli
from netcross_ai import FEATURE_NAMES
from netcross_ai.anomaly import Baseline
from netcross_ai.flow_classifier import TRAINING_SCHEMA, load_training_set
from netcross_ai.model_pack import (
    BASELINE_FILE,
    MANIFEST,
    PACK_SCHEMA,
    TRAINING_FILE,
    ModelPackError,
    build_pack,
    import_pack,
    read_pack,
)
from netcross_ai.outbox import mark_sent, pending, queue_pack, submission

W = len(FEATURE_NAMES)


def _vectors(n, seed=0):
    rng = random.Random(seed)
    return [[rng.uniform(0.1, 1000.0) for _ in range(W)] for _ in range(n)]


def _flow(src, dst, size):
    sizes = [size] * 10
    return {
        "src": src,
        "dst": dst,
        "packet_count": 10,
        "byte_count": sum(sizes),
        "splt": [[s, 0.1] for s in sizes],
        "size_distribution": {size: 10},
        "upload_bytes": sum(sizes),
        "download_bytes": 0,
        "inter_arrivals": [0.1] * 9,
        "classification": "normal",
    }


@pytest.fixture
def baseline():
    return Baseline(_vectors(30), label="LAN 192.168.10.0/24 chez alice@example.com")


def _pack(tmp_path, baseline=None, training=None, name="bureau-lan", **kw):
    out = tmp_path / f"{name}.zip"
    build_pack(out, name=name, consent=True, baseline=baseline, training=training, seed=1, **kw)
    return out


# -- export -------------------------------------------------------------------


def test_export_exige_le_consentement(tmp_path, baseline):
    with pytest.raises(ModelPackError, match="consentement"):
        build_pack(tmp_path / "x.zip", name="x", consent=False, baseline=baseline)
    assert not (tmp_path / "x.zip").exists()


@pytest.mark.parametrize("name", ["", "Bureau", "a b", "../x", "-x", "x" * 65])
def test_export_nom_invalide(tmp_path, baseline, name):
    with pytest.raises(ModelPackError, match="nom de paquet invalide"):
        build_pack(tmp_path / "x.zip", name=name, consent=True, baseline=baseline)


def test_export_vide_refuse(tmp_path):
    with pytest.raises(ModelPackError, match="rien a exporter"):
        build_pack(tmp_path / "x.zip", name="x", consent=True)


def test_paquet_sans_identifiant(tmp_path, baseline):
    training = [(_flow("10.1.2.3:51000", "203.0.113.9:443", 1400), "exfiltration")] * 3
    training += [(_flow("10.1.2.4:51001", "198.51.100.7:80", 200), "normal")] * 3
    path = _pack(tmp_path, baseline, training, description="Capture du 10.1.2.3 sur srv-compta.corp.local")
    with zipfile.ZipFile(path) as zf:
        assert sorted(zf.namelist()) == sorted([MANIFEST, BASELINE_FILE, TRAINING_FILE, "TICKET.md"])
        blob = b"".join(zf.read(n) for n in zf.namelist()).decode()
    for secret in ("10.1.2.3", "203.0.113.9", "198.51.100.7", "192.168.10", "alice@example.com", "srv-compta", "51000"):
        assert secret not in blob
    training_doc = json.loads(zipfile.ZipFile(path).read(TRAINING_FILE))
    assert all(set(s) == {"features", "label"} for s in training_doc["samples"])


def test_vecteurs_arrondis_et_melanges(tmp_path, baseline):
    pack = read_pack(_pack(tmp_path, baseline))
    assert len(pack.baseline.vectors) == len(baseline.vectors)
    assert pack.baseline.vectors != [[round(x, 6) for x in v] for v in baseline.vectors]  # ordre change
    for v in pack.baseline.vectors:
        for x in v:
            assert len(f"{x:.10g}".replace(".", "").replace("-", "").lstrip("0")) <= 4
    assert len(pack.created) == 10  # jour seulement


def test_etiquettes_restent_alignees(tmp_path):
    training = [([float(i)] * W, "petit" if i < 10 else "grand") for i in range(20)]
    pack = read_pack(_pack(tmp_path, training=training))
    assert all((v[0] < 10) == (label == "petit") for v, label in pack.training)
    assert pack.label_counts == {"grand": 10, "petit": 10}


def test_etiquette_invalide(tmp_path):
    with pytest.raises(ModelPackError, match="etiquette invalide"):
        _pack(tmp_path, training=[([1.0] * W, "Pas Bon !")])


# -- lecture verifiee ---------------------------------------------------------


def _rewrite(path, replace=None, extra=None, drop=()):
    with zipfile.ZipFile(path) as zf:
        entries = {n: zf.read(n) for n in zf.namelist() if n not in drop}
    entries.update(replace or {})
    entries.update(extra or {})
    with zipfile.ZipFile(path, "w") as zf:
        for n, b in entries.items():
            zf.writestr(n, b)


def test_archive_alteree_detectee(tmp_path, baseline):
    path = _pack(tmp_path, baseline)
    doc = json.loads(zipfile.ZipFile(path).read(BASELINE_FILE))
    doc["vectors"][0][0] = 123456.0
    _rewrite(path, replace={BASELINE_FILE: json.dumps(doc)})
    with pytest.raises(ModelPackError, match="SHA-256"):
        read_pack(path)


@pytest.mark.parametrize("intrus", ["../evil.py", "model.pkl", "sub/baseline.json"])
def test_fichier_inattendu_refuse(tmp_path, baseline, intrus):
    path = _pack(tmp_path, baseline)
    _rewrite(path, extra={intrus: b"x"})
    with pytest.raises(ModelPackError, match="contenu inattendu"):
        read_pack(path)


def test_manifeste_absent_ou_incoherent(tmp_path, baseline):
    path = _pack(tmp_path, baseline)
    _rewrite(path, drop=(MANIFEST,))
    with pytest.raises(ModelPackError, match="manifest"):
        read_pack(path)
    path = _pack(tmp_path, baseline, name="autre")
    _rewrite(path, drop=(BASELINE_FILE,))
    with pytest.raises(ModelPackError, match="incoherente"):
        read_pack(path)


def test_schema_et_version_des_caracteristiques(tmp_path, baseline):
    path = _pack(tmp_path, baseline)
    manifest = json.loads(zipfile.ZipFile(path).read(MANIFEST))
    manifest["features"] = ["x"]
    _rewrite(path, replace={MANIFEST: json.dumps(manifest)})
    with pytest.raises(ModelPackError, match="autre version"):
        read_pack(path)
    (tmp_path / "pas-zip.zip").write_text("bonjour")
    with pytest.raises(ModelPackError, match="ZIP invalide"):
        read_pack(tmp_path / "pas-zip.zip")


def test_flux_brut_refuse_dans_un_paquet(tmp_path):
    path = _pack(tmp_path, training=[([1.0] * W, "normal")])
    doc = {"schema": TRAINING_SCHEMA, "samples": [{"flow": _flow("10.0.0.1:1", "10.0.0.2:2", 100), "label": "normal"}]}
    raw = json.dumps(doc).encode()
    manifest = json.loads(zipfile.ZipFile(path).read(MANIFEST))
    manifest["files"][TRAINING_FILE] = hashlib.sha256(raw).hexdigest()
    _rewrite(path, replace={TRAINING_FILE: raw, MANIFEST: json.dumps(manifest)})
    with pytest.raises(ModelPackError, match="aucun flux brut"):
        read_pack(path)


def test_schema_manifeste(tmp_path, baseline):
    path = _pack(tmp_path, baseline)
    manifest = json.loads(zipfile.ZipFile(path).read(MANIFEST))
    assert manifest["schema"] == PACK_SCHEMA
    manifest["schema"] = "autre/1"
    _rewrite(path, replace={MANIFEST: json.dumps(manifest)})
    with pytest.raises(ModelPackError, match=PACK_SCHEMA):
        read_pack(path)


# -- import -------------------------------------------------------------------


def test_import_enrichit_la_base_locale(tmp_path, baseline):
    path = _pack(tmp_path, baseline, [([1.0] * W, "tunnel"), ([2.0] * W, "normal")])
    local_base = tmp_path / "base.json"
    Baseline(_vectors(5, seed=9), label="local").save(local_base)
    local_training = tmp_path / "entrainement.json"
    result = import_pack(path, baseline_path=local_base, training_path=local_training)
    assert result["baseline"]["vectors"] == 35
    assert Baseline.load(local_base).label == "local"
    samples = load_training_set(local_training)
    assert sorted(label for _v, label in samples) == ["normal", "tunnel"]
    import_pack(path, training_path=local_training)
    assert len(load_training_set(local_training)) == 4


def test_import_sans_cible(tmp_path, baseline):
    with pytest.raises(ModelPackError, match="preciser"):
        import_pack(_pack(tmp_path, baseline))


def test_jeu_mixte_flux_et_vecteurs_charge(tmp_path):
    doc = {
        "schema": TRAINING_SCHEMA,
        "samples": [
            {"flow": _flow("10.0.0.1:1", "10.0.0.2:2", 100), "label": "normal"},
            {"features": [1.0] * W, "label": "tunnel"},
        ],
    }
    path = tmp_path / "t.json"
    path.write_text(json.dumps(doc))
    samples = load_training_set(path)
    assert isinstance(samples[0][0], dict) and samples[1][0] == [1.0] * W
    doc["samples"][1]["features"] = [1.0] * (W - 1)
    path.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="features"):
        load_training_set(path)


# -- boite d'envoi ------------------------------------------------------------


def test_file_d_attente_et_soumission(tmp_path, baseline):
    box = tmp_path / "outbox"
    queued = queue_pack(_pack(tmp_path, baseline), box)
    assert queued == box / "bureau-lan.zip"
    with pytest.raises(ModelPackError, match="attend deja"):
        queue_pack(_pack(tmp_path, baseline), box)
    assert [p.name for p in pending(box)] == ["bureau-lan"]
    sub = submission("bureau-lan", box, repo="org/depot")
    assert sub.url.startswith("https://github.com/org/depot/issues/new?")
    assert "labels=modeles" in sub.url and "bureau-lan" in sub.url and sub.body_in_url
    sent = mark_sent("bureau-lan", box)
    assert sent == box / "envoyes" / "bureau-lan.zip" and sent.exists()
    assert pending(box) == []
    with pytest.raises(ModelPackError, match="aucun paquet"):
        submission("bureau-lan", box)


def test_pending_ignore_les_archives_illisibles(tmp_path):
    box = tmp_path / "outbox"
    box.mkdir()
    (box / "casse.zip").write_bytes(b"pas un zip")
    assert pending(box) == []
    assert pending(tmp_path / "absent") == []


def test_queue_verifie_le_paquet(tmp_path):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"x")
    with pytest.raises(ModelPackError):
        queue_pack(bad, tmp_path / "outbox")


# -- CLI ----------------------------------------------------------------------


def test_cli_parcours_complet(tmp_path, baseline, monkeypatch, capsys):
    base = tmp_path / "base.json"
    baseline.save(base)
    box = tmp_path / "outbox"
    out = tmp_path / "bureau.zip"
    argv = ["export", "--baseline", str(base), "--name", "bureau", "-o", str(out), "--queue", "--outbox", str(box)]
    assert models_cli.main(argv) == 1  # sans --consent
    assert "consentement" in capsys.readouterr().err
    assert models_cli.main([*argv, "--consent"]) == 0
    assert (box / "bureau.zip").exists()

    capsys.readouterr()
    assert models_cli.main(["inspect", str(out)]) == 0
    assert "Archive verifiee" in capsys.readouterr().out
    assert models_cli.main(["outbox", "list", "--outbox", str(box)]) == 0
    assert "bureau" in capsys.readouterr().out

    monkeypatch.setattr(outbox_mod, "is_online", lambda *a, **k: False)
    monkeypatch.setattr(models_cli, "is_online", lambda *a, **k: False)
    assert models_cli.main(["outbox", "send", "--outbox", str(box)]) == models_cli.EXIT_OFFLINE
    assert "Hors connexion" in capsys.readouterr().out

    opened = []
    monkeypatch.setattr(models_cli, "is_online", lambda *a, **k: True)
    monkeypatch.setattr(models_cli.webbrowser, "open", opened.append)
    assert models_cli.main(["outbox", "send", "--outbox", str(box), "--open"]) == 0
    assert "issues/new" in capsys.readouterr().out and len(opened) == 1
    assert models_cli.main(["outbox", "done", "bureau", "--outbox", str(box)]) == 0
    assert (box / "envoyes" / "bureau.zip").exists()

    local = tmp_path / "local.json"
    assert models_cli.main(["import", str(out), "--baseline", str(local)]) == 0
    assert "Baseline enrichie" in capsys.readouterr().out
    assert len(Baseline.load(local).vectors) == 30


def test_cli_inspect_json(tmp_path, baseline, capsys):
    out = _pack(tmp_path, baseline)
    assert models_cli.main(["inspect", str(out), "--json"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["baseline_vectors"] == 30 and summary["name"] == "bureau-lan"


def test_cli_erreurs(tmp_path, capsys):
    assert models_cli.main(["inspect", str(tmp_path / "absent.zip")]) == 1
    assert models_cli.main(["outbox", "add", "--outbox", str(tmp_path)]) == 1
    assert models_cli.main(["outbox", "send", "--outbox", str(tmp_path / "vide")]) == 0
    assert "vide" in capsys.readouterr().out


# -- Issue #694 : renvoi d'un paquet deja archive et test de connectivite ----


def test_mark_sent_remplace_une_archive_deja_envoyee(tmp_path):
    """Ligne 114 : une archive du meme nom deja dans envoyes/ est remplacee."""
    from netcross_ai.outbox import SENT_DIR

    (tmp_path / "reseau-a.zip").write_bytes(b"nouveau")
    (tmp_path / SENT_DIR).mkdir()
    (tmp_path / SENT_DIR / "reseau-a.zip").write_bytes(b"ancien")
    cible = mark_sent("reseau-a", tmp_path)
    assert cible.read_bytes() == b"nouveau"
    assert not (tmp_path / "reseau-a.zip").exists()


def test_is_online_connexion_reussie_et_echouee(monkeypatch):
    """Lignes 121-128 : connexion TCP etablie -> True ; OSError -> False."""
    import contextlib

    from netcross_ai import outbox

    appels = []

    def _ok(addr, timeout):
        appels.append((addr, timeout))
        return contextlib.nullcontext()

    monkeypatch.setattr(outbox.socket, "create_connection", _ok)
    assert outbox.is_online("example.test", 443, timeout=1.0) is True
    assert appels == [(("example.test", 443), 1.0)]

    def _ko(addr, timeout):
        raise OSError("reseau injoignable")

    monkeypatch.setattr(outbox.socket, "create_connection", _ko)
    assert outbox.is_online() is False


# -- Issue #703 : refus restants de read_pack / import_pack --------------------


def _resigne(path, replace=None, drop=()):
    """Reecrit l'archive en recalculant les empreintes du manifeste, pour
    atteindre les controles situes apres la verification SHA-256."""
    import hashlib

    with zipfile.ZipFile(path) as zf:
        entries = {n: zf.read(n) for n in zf.namelist() if n not in drop}
    entries.update(replace or {})
    manifest = json.loads(entries[MANIFEST])
    manifest["files"] = {n: hashlib.sha256(b).hexdigest() for n, b in entries.items() if n != MANIFEST}
    entries[MANIFEST] = json.dumps(manifest).encode()
    with zipfile.ZipFile(path, "w") as zf:
        for n, b in entries.items():
            zf.writestr(n, b)


def test_limites_de_taille(tmp_path, baseline, monkeypatch):
    """Lignes 220-221 : archive trop volumineuse ; lignes 236-237 : entree
    trop volumineuse."""
    from netcross_ai import model_pack

    path = _pack(tmp_path, baseline)
    monkeypatch.setattr(model_pack, "MAX_PACK_BYTES", 10)
    with pytest.raises(ModelPackError, match="archive trop volumineuse"):
        read_pack(path)
    monkeypatch.setattr(model_pack, "MAX_PACK_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(model_pack, "MAX_ENTRY_BYTES", 10)
    with pytest.raises(ModelPackError, match="trop volumineux"):
        read_pack(path)


def test_manifeste_non_json(tmp_path, baseline):
    """Lignes 255-257 : manifeste qui n'est pas du JSON UTF-8."""
    path = _pack(tmp_path, baseline)
    _rewrite(path, replace={MANIFEST: b"\xff\xfe"})
    with pytest.raises(ModelPackError, match=r"manifest\.json invalide"):
        read_pack(path)


def test_baseline_et_entrainement_invalides_et_paquet_vide(tmp_path, baseline):
    """Lignes 291-293 : baseline refusee ; lignes 301-304 : jeu
    d'entrainement d'un autre schema ; lignes 314-315 : paquet sans
    contenu."""
    path = _pack(tmp_path, baseline)
    _resigne(path, replace={BASELINE_FILE: json.dumps({"vectors": "non"}).encode()})
    with pytest.raises(ModelPackError):
        read_pack(path)

    path = _pack(tmp_path, training=[([1.0] * W, "a")], name="entrainement")
    _resigne(path, replace={TRAINING_FILE: json.dumps({"schema": "autre", "samples": []}).encode()})
    with pytest.raises(ModelPackError, match=r"training\.json invalide"):
        read_pack(path)

    path = _pack(tmp_path, baseline, name="vide")
    _resigne(path, drop=(BASELINE_FILE,))
    with pytest.raises(ModelPackError, match="paquet vide"):
        read_pack(path)


def test_import_dans_un_jeu_local_illisible_ou_d_un_autre_schema(tmp_path):
    """Lignes 342-344 : jeu local non JSON ; lignes 346-349 : autre schema."""
    path = _pack(tmp_path, training=[([1.0] * W, "a")])
    local = tmp_path / "local.json"
    local.write_text("{pas du json", encoding="utf-8")
    with pytest.raises(ModelPackError, match="jeu local illisible"):
        import_pack(path, training_path=local)
    local.write_text(json.dumps({"schema": "autre"}), encoding="utf-8")
    with pytest.raises(ModelPackError, match="n'est pas un jeu"):
        import_pack(path, training_path=local)
