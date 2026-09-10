"""Rutas de verificación de correo.

Prueban que el titular de un correo consiente que su huella digital sea
escaneada por otra cuenta. Dos pasos: `request` (el servidor prepara la
verificación) y `confirm` (el titular devuelve el código). El `consent_token`
resultante se pasa a `POST /api/v1/osint/scans`. Ver `docs/osint-architecture.md`.
"""

from fastapi import APIRouter, Request

from fee_server.api.dependencies import CurrentUserDep, VerificationServiceDep
from fee_server.core.rate_limit import limiter
from fee_server.domain.verification.schemas import (
    EmailVerificationConfirm,
    EmailVerificationConfirmed,
    EmailVerificationRequest,
    EmailVerificationRequested,
)

router = APIRouter(prefix="/verification", tags=["verification"])


@router.post("/email/request", response_model=EmailVerificationRequested)
@limiter.limit("10/minute")
def request_email_verification(
    request: Request,
    body: EmailVerificationRequest,
    user: CurrentUserDep,
    service: VerificationServiceDep,
) -> EmailVerificationRequested:
    return service.request_email(body.email, user.id)


@router.post("/email/confirm", response_model=EmailVerificationConfirmed)
@limiter.limit("5/minute")
def confirm_email_verification(
    request: Request,
    body: EmailVerificationConfirm,
    user: CurrentUserDep,
    service: VerificationServiceDep,
) -> EmailVerificationConfirmed:
    return service.confirm_email(body.verification_token, body.code, user.id)
