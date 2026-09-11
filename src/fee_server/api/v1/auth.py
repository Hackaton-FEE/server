"""Acceso por passkey (FIDO2 / WebAuthn) o sesión individual de pruebas.

Sin usuario ni contraseña. El registro y el login constan de dos pasos:
`.../options` (el servidor propone un reto) y `.../verify` (el servidor valida
la respuesta del autenticador y abre sesión).
El acceso sin autenticador requiere habilitar explícitamente el modo `testing`.
"""

from fastapi import APIRouter, Request, Response, status

from fee_server.api.dependencies import AuthServiceDep, CurrentUserDep
from fee_server.core.rate_limit import limiter
from fee_server.domain.auth.schemas import (
    AuthenticationOptionsRequest,
    AuthenticationVerifyRequest,
    ChallengeOptionsResponse,
    LogoutRequest,
    MeResponse,
    RefreshRequest,
    RegistrationOptionsRequest,
    RegistrationVerifyRequest,
    SessionResponse,
    TestingSessionRequest,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/testing/session", response_model=SessionResponse, status_code=status.HTTP_201_CREATED
)
@limiter.limit("10/minute")
def testing_session(
    request: Request, body: TestingSessionRequest, service: AuthServiceDep
) -> SessionResponse:
    return service.start_testing_session()


@router.post("/passkey/registration/options", response_model=ChallengeOptionsResponse)
@limiter.limit("30/minute")
def registration_options(
    request: Request, body: RegistrationOptionsRequest, service: AuthServiceDep
) -> ChallengeOptionsResponse:
    return service.start_registration(body.label)


@router.post(
    "/passkey/registration/verify",
    response_model=SessionResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("10/minute")
def registration_verify(
    request: Request, body: RegistrationVerifyRequest, service: AuthServiceDep
) -> SessionResponse:
    return service.finish_registration(body.challenge_token, body.credential)


@router.post("/passkey/authentication/options", response_model=ChallengeOptionsResponse)
@limiter.limit("30/minute")
def authentication_options(
    request: Request, body: AuthenticationOptionsRequest, service: AuthServiceDep
) -> ChallengeOptionsResponse:
    return service.start_authentication()


@router.post("/passkey/authentication/verify", response_model=SessionResponse)
@limiter.limit("10/minute")
def authentication_verify(
    request: Request, body: AuthenticationVerifyRequest, service: AuthServiceDep
) -> SessionResponse:
    return service.finish_authentication(body.challenge_token, body.credential)


@router.post("/token/refresh", response_model=SessionResponse)
@limiter.limit("20/minute")
def token_refresh(
    request: Request, body: RefreshRequest, service: AuthServiceDep
) -> SessionResponse:
    return service.refresh(body.refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("20/minute")
def logout(request: Request, body: LogoutRequest, service: AuthServiceDep) -> Response:
    service.logout(body.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=MeResponse)
@limiter.limit("60/minute")
def me(request: Request, user: CurrentUserDep, service: AuthServiceDep) -> MeResponse:
    return service.me(user)
