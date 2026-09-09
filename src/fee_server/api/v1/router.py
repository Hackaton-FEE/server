"""Registro explícito de rutas de la API v1."""

from fastapi import APIRouter, Depends

from fee_server.api.v1.health import router as health_router
from fee_server.core.rate_limit import limit_auth_requests
from fee_server.modules.auth.router import router as auth_router
from fee_server.modules.scans.router import router as scans_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health_router)
api_router.include_router(auth_router, dependencies=[Depends(limit_auth_requests)])
api_router.include_router(scans_router)
