"""Test du repli ImportError de netcross_report/__init__.py (lignes 85-88, #680).

netcross_report importe netcross_report.pdf (reportlab/matplotlib/networkx)
dans un try/except ImportError : si ces dependances optionnelles sont
absentes, generate_pdf et generate_diff_pdf valent None au lieu de faire
planter l'import de tout le package (le triage et le JSON restent
utilisables). Ce test simule l'absence en placant None dans sys.modules
(ce qui fait lever ImportError a `from netcross_report.pdf import ...`),
puis recharge le package. Le package est recharge une seconde fois en fin
de test pour retrouver son etat normal.
"""

from __future__ import annotations

import importlib
import sys
from unittest import mock

import netcross_report


def test_generate_pdf_vaut_none_sans_dependances_pdf():
    """Lignes 85-88 : ImportError sur netcross_report.pdf -> repli sur None."""
    try:
        with mock.patch.dict(sys.modules, {"netcross_report.pdf": None}):
            module = importlib.reload(netcross_report)

            assert module.generate_pdf is None
            assert module.generate_diff_pdf is None
            # Le pur Python reste disponible malgre l'absence du module PDF.
            assert callable(module.build_findings)
            assert callable(module.generate_json_report)
            assert callable(module.rank_segments)
    finally:
        importlib.reload(netcross_report)
