"""Issue #675 : extraction des contenus depuis la GUI (equivalent de
--extract-contents / --extract-kinds). Partie sans GTK."""

from __future__ import annotations

import pytest

from netcross_core.extract.contents import KINDS
from netcross_gtk4.extraction_view import (
    UNAVAILABLE_NO_FILES,
    UNAVAILABLE_REDACTED,
    check_out_dir,
    selected_kinds,
    unavailable_reason,
)


def test_types_coches_dans_l_ordre_de_la_cli():
    assert selected_kinds({"documents": True, "audio": True}) == ("audio", "documents")
    assert selected_kinds(dict.fromkeys(KINDS, True)) == KINDS


def test_aucun_type_refuse():
    with pytest.raises(ValueError, match="au moins un type"):
        selected_kinds(dict.fromkeys(KINDS, False))


def test_disponibilite():
    assert unavailable_reason(None, False) == UNAVAILABLE_NO_FILES
    assert unavailable_reason([], False) == UNAVAILABLE_NO_FILES
    assert unavailable_reason([("A", "a.pcap")], True) == UNAVAILABLE_REDACTED
    assert unavailable_reason([("A", "a.pcap")], False) is None


def test_repertoire_cree_en_0700(tmp_path):
    cible = tmp_path / "neuf"
    assert check_out_dir(str(cible)) == str(cible)
    assert cible.is_dir()
    assert (cible.stat().st_mode & 0o777) == 0o700


def test_repertoire_non_vide_refuse(tmp_path):
    (tmp_path / "x").write_text("deja la")
    with pytest.raises(ValueError, match="pas un repertoire vide"):
        check_out_dir(str(tmp_path))
