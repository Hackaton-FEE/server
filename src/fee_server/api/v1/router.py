"""Registro explícito de rutas de la API v1."""

from fastapi import APIRouter

from fee_server.api.v1.auth import router as auth_router
from fee_server.api.v1.health import router as health_router
from fee_server.api.v1.osint import router as osint_router
from fee_server.api.v1.verification import router as verification_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(osint_router)
api_router.include_router(verification_router)
