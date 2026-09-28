"""Issue #696 (suite de #665) : branches restantes de ``netcross_ai_models_cli``.

Complete ``tests/test_ai_model_pack.py`` (parcours nominal) : description du
paquet, export sans mise en file, import d'un seul type de modele ou de rien,
sous-commandes ``outbox`` add/list/done/send dans leurs variantes. Aucun
reseau : ``is_online`` n'est jamais appele (``--skip-check``) et
``webbrowser`` n'est jamais ouvert.
"""

from __future__ import annotations

import json
import random

import pytest

import netcross_ai.outbox as outbox_mod
import netcross_ai_models_cli as cli
from netcross_ai import FEATURE_NAMES
from netcross_ai.anomaly import Baseline
from netcross_ai.flow_classifier import TRAINING_SCHEMA
from netcross_ai.model_pack import build_pack

W = len(FEATURE_NAMES)


def _baseline() -> Baseline:
    rng = random.Random(0)
    return Baseline([[rng.uniform(0.1, 1000.0) for _ in range(W)] for _ in range(30)], label="lan")


def _training_doc() -> dict:
    return {
        "schema": TRAINING_SCHEMA,
        "samples": [{"features": [1.0] * W, "label": "tunnel"}, {"features": [2.0] * W, "label": "normal"}],
    }


def _pack(tmp_path, name="bureau", *, baseline=True, training=True):
    out = tmp_path / f"{name}.zip"
    build_pack(
        out,
        name=name,
        consent=True,
        baseline=_baseline() if baseline else None,
        training=[([1.0] * W, "tunnel"), ([2.0] * W, "normal")] if training else None,
        seed=1,
    )
    return out


# -- export ------------------------------------------------------------------------


def test_export_avec_description_sans_mise_en_file(tmp_path, capsys):
    base = tmp_path / "base.json"
    _baseline().save(base)
    train = tmp_path / "train.json"
    train.write_text(json.dumps(_training_doc()))
    out = tmp_path / "p.zip"
    argv = ["export", "--baseline", str(base), "--training", str(train), "--name", "bureau", "--consent"]
    assert cli.main([*argv, "--description", "reseau de test", "-o", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "Paquet ecrit" in printed and "  reseau de test" in printed
    assert "Mis en file" not in printed


# -- import ------------------------------------------------------------------------


def test_import_du_seul_jeu_d_entrainement(tmp_path, capsys):
    pack = _pack(tmp_path, baseline=False)
    local = tmp_path / "train.json"
    assert cli.main(["import", str(pack), "--training", str(local)]) == 0
    printed = capsys.readouterr().out
    assert "Jeu enrichi" in printed and "2 exemples" in printed
    assert "Baseline enrichie" not in printed


def test_import_rien_a_importer(tmp_path, capsys):
    pack = _pack(tmp_path, training=False)  # baseline seule
    local = tmp_path / "train.json"
    assert cli.main(["import", str(pack), "--training", str(local)]) == 0
    assert "Rien a importer" in capsys.readouterr().out
    assert not local.exists()


# -- outbox ------------------------------------------------------------------------


def test_outbox_add_avec_cible_puis_list(tmp_path, capsys):
    box = tmp_path / "box"
    pack = _pack(tmp_path)
    assert cli.main(["outbox", "add", str(pack), "--outbox", str(box)]) == 0
    assert "Mis en file" in capsys.readouterr().out and (box / "bureau.zip").is_file()
    assert cli.main(["outbox", "list", "--outbox", str(box)]) == 0
    assert "Paquet bureau" in capsys.readouterr().out


def test_outbox_list_boite_vide(tmp_path, capsys):
    assert cli.main(["outbox", "list", "--outbox", str(tmp_path / "vide")]) == 0
    assert "Boite d'envoi vide" in capsys.readouterr().out


def test_outbox_done_sans_nom_refuse(tmp_path, capsys):
    assert cli.main(["outbox", "done", "--outbox", str(tmp_path)]) == 1
    assert "nom du paquet attendu" in capsys.readouterr().err


@pytest.mark.parametrize("in_url", [True, False])
def test_outbox_send_sans_ouverture_du_navigateur(tmp_path, capsys, monkeypatch, in_url):
    box = tmp_path / "box"
    outbox_mod.queue_pack(_pack(tmp_path, "un"), box)
    outbox_mod.queue_pack(_pack(tmp_path, "deux"), box)
    if not in_url:
        monkeypatch.setattr(outbox_mod, "_MAX_URL_BODY", 1)  # corps trop long pour l'URL
    monkeypatch.setattr(cli.webbrowser, "open", lambda *_a: pytest.fail("navigateur ouvert sans --open"))
    assert cli.main(["outbox", "send", "--outbox", str(box), "--skip-check"]) == 0
    printed = capsys.readouterr().out
    assert "[un]" in printed and "[deux]" in printed
    assert ("corps trop long pour l'URL" in printed) is (not in_url)
