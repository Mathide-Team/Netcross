"""Issue #699 (suite de #665) : branches restantes de ``netcross_core.plugins.loader``.

Complete ``tests/test_plugins.py`` : sources non lisibles ou non Python,
fichier plugin sans specification importable, entry points dont le module
est introuvable ou dont le chargement echoue, exporteur declare par entry
point, exporteur local non autorise, ``list_plugins`` sur un fichier en
erreur. Les entry points sont fabriques a la main (aucune installation).
"""

from __future__ import annotations

import sys
import textwrap
from importlib import metadata

import pytest

from netcross_core.plugins import list_plugins, load_plugins
from netcross_core.plugins import loader as loader_mod
from netcross_core.plugins.loader import PluginLoadError, load_path_module


def _fake_entry_points(monkeypatch, *eps):
    monkeypatch.setattr(loader_mod, "_entry_points", lambda group: [e for e in eps if e.group == group])


# -- _check_source ------------------------------------------------------------------


@pytest.mark.parametrize("path", [None, "", "extension.so"])
def test_check_source_ignore_ce_qui_n_est_pas_un_source_python(path):
    assert loader_mod._check_source(path, "plugin x") is None


def test_check_source_ignore_un_source_illisible(tmp_path):
    assert loader_mod._check_source(str(tmp_path / "absent.py"), "plugin x") is None


# -- fichier --plugin-path ----------------------------------------------------------


def test_plugin_path_sans_specification_importable(tmp_path):
    not_python = tmp_path / "plugin.txt"
    not_python.write_text("DETECTORS = []\n", encoding="utf-8")
    with pytest.raises(PluginLoadError, match="module Python non chargeable"):
        load_path_module(str(not_python))
    assert "non chargeable" in load_plugins(["x"], [str(not_python)]).errors[0]["reason"]


def test_exporteur_local_non_autorise_ignore(tmp_path):
    local = tmp_path / "local.py"
    local.write_text(
        textwrap.dedent("""
        class Det:
            name = "det"
            def analyse(self, contexte):
                return []

        class Exp:
            name = "exp"
            def export(self, report, chemin):
                pass

        DETECTORS = [Det]
        EXPORTERS = [Exp]
        """),
        encoding="utf-8",
    )
    loaded = load_plugins(["det"], [str(local)])
    assert [d.name for d in loaded.detectors] == ["det"]
    assert loaded.exporters == {} and loaded.errors == []


# -- entry points -------------------------------------------------------------------


def test_entry_point_dont_le_module_est_introuvable(monkeypatch):
    _fake_entry_points(monkeypatch, metadata.EntryPoint("fantome", "absent_pkg_699.sous:Maison", "netcross.detectors"))
    loaded = load_plugins(["fantome"])
    assert loaded.detectors == []
    assert loaded.errors[0]["plugin"] == "fantome"
    assert "module absent_pkg_699.sous introuvable" in loaded.errors[0]["reason"]


def test_entry_point_dont_le_chargement_echoue(monkeypatch):
    # le module existe (stdlib) mais l'attribut demande non : ep.load() leve AttributeError
    _fake_entry_points(monkeypatch, metadata.EntryPoint("casse", "json:absent_699", "netcross.detectors"))
    loaded = load_plugins(["casse"])
    assert loaded.detectors == []
    assert "plugin casse : import en erreur (AttributeError" in loaded.errors[0]["reason"]


def test_exporteur_declare_par_entry_point(tmp_path, monkeypatch):
    (tmp_path / "plugin_exp_699.py").write_text(
        textwrap.dedent("""
        class Exp:
            name = "exp"
            def export(self, report, chemin):
                pass
        """),
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "plugin_exp_699", raising=False)
    _fake_entry_points(monkeypatch, metadata.EntryPoint("exp", "plugin_exp_699:Exp", "netcross.exporters"))
    try:
        loaded = load_plugins(["exp"])
    finally:
        sys.modules.pop("plugin_exp_699", None)
    assert list(loaded.exporters) == ["exp"] and loaded.detectors == [] and loaded.errors == []


# -- list_plugins -------------------------------------------------------------------


def test_list_plugins_signale_un_fichier_en_erreur(tmp_path):
    absent = str(tmp_path / "absent.py")
    row = next(r for r in list_plugins([], [absent]) if r["name"] == absent)
    assert row["kind"] == "?" and row["origin"] == f"fichier:{absent}" and row["authorized"] is False
    assert row["error"].endswith("fichier introuvable")
