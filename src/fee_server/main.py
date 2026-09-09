"""Fábrica ASGI usada por Uvicorn y por las pruebas."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError

from fee_server import __version__
from fee_server.api.v1.router import api_router
from fee_server.core.config import Settings
from fee_server.core.database import Database
from fee_server.core.http import PrivateAPIHeadersMiddleware, database_error, validation_error
from fee_server.core.rate_limit import AuthRateLimiter
from fee_server.modules.auth.security import TokenService
from fee_server.modules.scans.registry import build_registry


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings if settings is not None else Settings()
    database = Database(settings.database_url)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            yield
        finally:
            database.dispose()

    app = FastAPI(
        title="FEE Server",
        description="API de FEE: autenticación, sesiones y capacidades de escaneo.",
        version=__version__,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.token_service = TokenService(settings)
    app.state.auth_rate_limiter = AuthRateLimiter(database, settings)
    app.state.scan_registry = build_registry()
    app.add_exception_handler(RequestValidationError, validation_error)
    app.add_exception_handler(SQLAlchemyError, database_error)
    app.add_middleware(PrivateAPIHeadersMiddleware, max_body_bytes=settings.max_request_body_bytes)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
        )
    app.include_router(api_router)
    return app
