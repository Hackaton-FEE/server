"""Dependencias compartidas de la capa HTTP."""

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from fee_server.core.config import Settings
from fee_server.core.problem import InvalidSessionError
from fee_server.core.security.tokens import InvalidAccessToken, read_access_token
from fee_server.db.models import User
from fee_server.db.session import get_session
from fee_server.domain.auth import repository
from fee_server.domain.auth.service import AuthService
from fee_server.domain.osint.service import ScanService
from fee_server.domain.verification.service import VerificationService


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


SettingsDep = Annotated[Settings, Depends(get_settings)]
SessionDep = Annotated[Session, Depends(get_session)]


def get_auth_service(session: SessionDep, settings: SettingsDep) -> AuthService:
    return AuthService(session, settings)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


def get_osint_service(session: SessionDep, settings: SettingsDep) -> ScanService:
    return ScanService(session, settings)


OsintServiceDep = Annotated[ScanService, Depends(get_osint_service)]


def get_verification_service(settings: SettingsDep) -> VerificationService:
    return VerificationService(settings)


VerificationServiceDep = Annotated[VerificationService, Depends(get_verification_service)]


def get_current_user(request: Request, session: SessionDep, settings: SettingsDep) -> User:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise InvalidSessionError()

    try:
        user_id = read_access_token(
            secret=settings.jwt_secret,
            token=header.removeprefix("Bearer ").strip(),
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
        )
    except InvalidAccessToken as exc:
        raise InvalidSessionError() from exc

    user = repository.get_user(session, user_id)
    if user is None:
        raise InvalidSessionError()
    return user


CurrentUserDep = Annotated[User, Depends(get_current_user)]
