"""Fábrica ASGI usada por Uvicorn y por las pruebas."""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

from fee_server import __version__
from fee_server.api.middleware import MaxBodySizeMiddleware, SecurityHeadersMiddleware
from fee_server.api.v1.router import api_router
from fee_server.api.well_known import router as well_known_router
from fee_server.core.config import Settings
from fee_server.core.problem import install_error_handlers, problem_response
from fee_server.core.rate_limit import limiter
from fee_server.db.session import configure as configure_database


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings if settings is not None else Settings()

    # Prepara el engine (SQLAlchemy conecta de forma perezosa; esto no abre red).
    configure_database(settings)

    app = FastAPI(
        title="FEE Server",
        description="API de la plataforma FEE. Autenticación por passkey (FIDO2).",
        version=__version__,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    app.state.settings = settings
    app.state.limiter = limiter

    install_error_handlers(app)

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limited(request: Request, exc: RateLimitExceeded):
        return problem_response(
            status_code=429,
            code="rate-limited",
            detail="Demasiadas peticiones. Espera unos segundos e inténtalo de nuevo.",
            instance=request.url.path,
        )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
        )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.max_request_body_bytes)

    app.include_router(api_router)
    app.include_router(well_known_router)
    return app
