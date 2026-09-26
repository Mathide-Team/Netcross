"""Garde commune des tests GTK4 (tests/gtk4_display.py).

Sans serveur graphique, un module de test GTK4 doit être SAUTÉ, pas faire
planter tout le processus pytest : sous GTK 4.22, ``Gtk.init_check()``
renvoie ``True`` sans affichage et le premier widget créé provoque une
erreur de segmentation. Le cas est rejoué dans un sous-processus sans
``DISPLAY`` ni ``WAYLAND_DISPLAY`` -- une segmentation fault ne doit pas
emporter la session pytest qui exécute ce test.

Ne tourne que là où pygobject et GTK4 sont installés (job CI GTK4, postes
de développement) ; ailleurs il est sauté, comme les tests GTK eux-mêmes.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent

gi = pytest.importorskip("gi", reason="pygobject absent")
try:
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk  # noqa: F401
except (ValueError, ImportError):
    pytest.skip("GTK4 absent", allow_module_level=True)


def _pytest_sans_affichage(tmp_path: Path, corps: str) -> subprocess.CompletedProcess:
    module = tmp_path / "test_module_gtk.py"
    module.write_text(textwrap.dedent(corps), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in {"DISPLAY", "WAYLAND_DISPLAY", "GDK_BACKEND"}}
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(TESTS), env.get("PYTHONPATH")]))
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-rs",
            "-p",
            "no:cacheprovider",
            "--rootdir",
            str(tmp_path),
            str(module),
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        timeout=120,
        check=False,
    )


def test_sans_affichage_le_module_est_saute_sans_planter(tmp_path):
    result = _pytest_sans_affichage(
        tmp_path,
        """
        from gtk4_display import exiger_gtk4_avec_affichage

        Gtk = exiger_gtk4_avec_affichage()


        def test_cree_un_widget():
            assert Gtk.Label(label="x").get_text() == "x"
        """,
    )
    sortie = result.stdout + result.stderr
    # Saut au niveau du module : aucun test exécuté, code 5 de pytest. Avec
    # l'ancienne garde (Gtk.init_check() seul), le processus mourait sur
    # SIGSEGV (code -11) en créant le Gtk.Label.
    assert result.returncode == pytest.ExitCode.NO_TESTS_COLLECTED, sortie
    assert "1 skipped" in result.stdout, sortie
    assert "pas d'affichage pour GTK4" in result.stdout, sortie
