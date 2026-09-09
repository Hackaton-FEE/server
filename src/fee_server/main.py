"""Fábrica ASGI usada por Uvicorn y por las pruebas."""

from fastapi import FastAPI

from fee_server import __version__
from fee_server.api.v1.router import api_router
from fee_server.core.config import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings if settings is not None else Settings()
    app = FastAPI(
        title="FEE Server",
        description="Base inicial de la API. Disponible: salud del proceso.",
        version=__version__,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    app.include_router(api_router)
    return app
