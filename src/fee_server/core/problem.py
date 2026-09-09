"""Errores de autenticación y su representación RFC 7807 (Problem Details).

Todas las respuestas de error de `/auth` usan `application/problem+json`, igual
que el resto del contrato de la plataforma. Los mensajes son genéricos y nunca
reflejan la entrada del usuario.
"""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

ERROR_BASE = "https://api.fee.local/errors/"


class AuthError(Exception):
    """Base de los errores de autenticación. Cada subclase fija estado y código."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "auth-error"
    detail: str = "No fue posible completar la autenticación."


class InvalidChallengeError(AuthError):
    code = "invalid-challenge"
    detail = "El reto de autenticación es inválido o expiró. Vuelve a intentarlo."


class InvalidCredentialError(AuthError):
    code = "invalid-credential"
    detail = "La passkey no pudo verificarse."


class UnknownCredentialError(AuthError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "unknown-credential"
    detail = "No reconocemos esta passkey."


class InvalidSessionError(AuthError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "invalid-session"
    detail = "La sesión no es válida. Inicia sesión de nuevo."


def problem_response(*, status_code: int, code: str, detail: str, instance: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        media_type="application/problem+json",
        content={
            "type": ERROR_BASE + code,
            "title": code.replace("-", " ").title(),
            "status": status_code,
            "detail": detail,
            "instance": instance,
        },
    )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthError)
    async def _handle_auth_error(request: Request, exc: AuthError) -> JSONResponse:
        return problem_response(
            status_code=exc.status_code,
            code=exc.code,
            detail=exc.detail,
            instance=request.url.path,
        )
