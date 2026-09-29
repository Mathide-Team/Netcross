"""Issue #676 : CLI ring buffer, BPF library, et parite GUI/CLI.

Tests unitaires des nouvelles options CLI --ring-buffer et --bpf-library,
et de la parite des surfaces (ring buffer et BPF library desormais en CLI).
"""

import pytest


def test_parse_ring_buffer_spec_valid():
    """--ring-buffer 5:60 parse en (5, 60.0)."""
    from cross_capture_analyzer_cli import _parse_ring_buffer_spec

    max_files, max_duration = _parse_ring_buffer_spec("5:60")
    assert max_files == 5
    assert max_duration == 60.0


def test_parse_ring_buffer_spec_empty():
    """Spec vide retourne (None, None)."""
    from cross_capture_analyzer_cli import _parse_ring_buffer_spec

    assert _parse_ring_buffer_spec(None) == (None, None)
    assert _parse_ring_buffer_spec("") == (None, None)


def test_parse_ring_buffer_spec_invalid_format():
    """Format invalide -> SystemExit."""
    from cross_capture_analyzer_cli import _parse_ring_buffer_spec

    with pytest.raises(SystemExit):
        _parse_ring_buffer_spec("invalid")


def test_parse_ring_buffer_spec_invalid_values():
    """Valeurs invalides -> SystemExit."""
    from cross_capture_analyzer_cli import _parse_ring_buffer_spec

    with pytest.raises(SystemExit):
        _parse_ring_buffer_spec("0:60")  # max_files < 1
    with pytest.raises(SystemExit):
        _parse_ring_buffer_spec("5:0")  # max_duration <= 0


def test_parse_ring_buffer_spec_decimal():
    """Decimales acceptees pour les secondes."""
    from cross_capture_analyzer_cli import _parse_ring_buffer_spec

    max_files, max_duration = _parse_ring_buffer_spec("3:30.5")
    assert max_files == 3
    assert max_duration == 30.5


def test_load_bpf_from_library_none():
    """Nom vide -> None."""
    from cross_capture_analyzer_cli import _load_bpf_from_library

    assert _load_bpf_from_library(None) is None
    assert _load_bpf_from_library("") is None


def test_load_bpf_from_library_not_found():
    """Nom introuvable -> SystemExit."""
    from cross_capture_analyzer_cli import _load_bpf_from_library

    with pytest.raises(SystemExit):
        _load_bpf_from_library("ZZZZ_NOT_A_REAL_FILTER")


def test_load_bpf_from_library_found():
    """Un filtre predefini est trouvable par nom."""
    from cross_capture_analyzer_cli import _load_bpf_from_library

    # Les filtres predefinis incluent HTTP, HTTPS, DNS etc.
    expr = _load_bpf_from_library("HTTP")
    assert expr is not None
    assert isinstance(expr, str)
    assert len(expr) > 0


def test_load_bpf_from_library_case_insensitive():
    """La recherche est insensible a la casse."""
    from cross_capture_analyzer_cli import _load_bpf_from_library

    expr_lower = _load_bpf_from_library("http")
    expr_upper = _load_bpf_from_library("HTTP")
    assert expr_lower == expr_upper


def test_cli_args_exist():
    """Les arguments --ring-buffer et --bpf-library sont definis."""
    import cross_capture_analyzer_cli as cli

    # Cherche les arguments dans le module source
    with open(cli.__file__) as fh:
        source = fh.read()
    assert "--ring-buffer" in source
    assert "--bpf-library" in source


def test_ring_buffer_option_documented():
    """L'option --ring-buffer est classee dans parite-surfaces.md."""
    with open("docs/parite-surfaces.md") as fh:
        page = fh.read()
    assert "`--ring-buffer" in page


def test_bpf_library_option_documented():
    """L'option --bpf-library est classee dans parite-surfaces.md."""
    with open("docs/parite-surfaces.md") as fh:
        page = fh.read()
    assert "`--bpf-library" in page
