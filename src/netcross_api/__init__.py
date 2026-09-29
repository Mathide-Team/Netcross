"""
netcross_api -- service REST FastAPI pour exposer les analyses Netcross
(issue #209).

Démarre le service avec :

    pip install fastapi uvicorn python-multipart
    uvicorn netcross_api.app:app --reload

Endpoints :
    POST /captures        — upload d'un pcap, lance l'analyse, retourne l'ID
    GET  /analyses/{id}   — rapport complet (JSON)
    GET  /analyses/{id}/security — constats de sécurité uniquement
    GET  /health          — health check
    GET  /openapi.json    — spécification OpenAPI (auto FastAPI)
"""

from netcross_api.app import app
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

__all__ = ["app"]
