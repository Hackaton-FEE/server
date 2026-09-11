"""Errores de dominio y su representación RFC 7807 (Problem Details).

Todas las respuestas de error de la API usan `application/problem+json`, igual
que el resto del contrato de la plataforma. Los mensajes son genéricos y nunca
reflejan la entrada del usuario.
"""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

ERROR_BASE = "https://api.fee.local/errors/"


class ProblemError(Exception):
    """Base de los errores de dominio. Cada subclase fija estado y código."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "error"
    detail: str = "No fue posible completar la operación."


class AuthError(ProblemError):
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


class VerificationError(ProblemError):
    """Base de los errores de verificación de correo."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "verification-error"
    detail: str = "No fue posible completar la verificación."


class InvalidVerificationTokenError(VerificationError):
    code = "invalid-verification-token"
    detail = "La verificación es inválida o expiró. Vuelve a solicitar el código."


class InvalidVerificationCodeError(VerificationError):
    code = "invalid-verification-code"
    detail = "El código de verificación no es correcto."


class AssistantError(ProblemError):
    """Base de los errores del asistente conversacional."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "assistant-error"
    detail: str = "No fue posible procesar la conversación."


class InvalidConversationError(AssistantError):
    code = "invalid-conversation"
    detail = "La conversación no es válida: revisa los mensajes enviados."


class AssistantUnavailableError(AssistantError):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    code = "assistant-unavailable"
    detail = "El asistente no está disponible en este momento."


class OsintError(ProblemError):
    """Base de los errores del motor OSINT."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "osint-error"
    detail: str = "No fue posible procesar el escaneo."


class InvalidIdentifierError(OsintError):
    code = "invalid-identifier"
    detail = "El identificador no tiene un formato válido para este tipo de escaneo."


class UnsupportedTargetTypeError(OsintError):
    code = "unsupported-target-type"
    detail = "El tipo de objetivo no está soportado."


class ConsentRequiredError(OsintError):
    code = "consent-required"
    detail = (
        "Se necesita el consentimiento de auto-auditoría o un token de "
        "consentimiento del titular del correo para iniciar el escaneo."
    )


class InvalidConsentError(OsintError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "invalid-consent"
    detail = "El consentimiento del titular del correo es inválido o expiró."


class ScanNotFoundError(OsintError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "scan-not-found"
    detail = "No encontramos ese escaneo."


class ScanNotReadyError(OsintError):
    status_code = status.HTTP_409_CONFLICT
    code = "scan-not-ready"
    detail = "El escaneo todavía no tiene resultados."


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
    @app.exception_handler(ProblemError)
    async def _handle_problem_error(request: Request, exc: ProblemError) -> JSONResponse:
        return problem_response(
            status_code=exc.status_code,
            code=exc.code,
            detail=exc.detail,
            instance=request.url.path,
        )
