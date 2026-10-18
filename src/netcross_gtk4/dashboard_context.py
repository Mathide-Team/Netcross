"""
netcross_gtk4.dashboard_context -- alias de netcross_core.dashboard.

Le contexte du dashboard (issue #18) est pur Python : il a été déplacé dans
netcross_core.dashboard (issue #911) pour que la CLI (--dashboard) et l'API
(GET /analyses/{id}/dashboard) calculent exactement les mêmes vues que la GUI.
Ce module reste importable sous l'ancien nom (même objet module : les
monkeypatch des tests et les imports de app.py restent valides).
"""

from __future__ import annotations

import sys

from netcross_core import dashboard as _dashboard

sys.modules[__name__] = _dashboard
