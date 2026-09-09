from typing import Annotated

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from fee_server.core.database import get_db
from fee_server.modules.auth.errors import unauthorized
from fee_server.modules.auth.models import AuthSession, User, utcnow
from fee_server.modules.auth.security import Actor
from fee_server.modules.auth.service import AuthService

DatabaseSession = Annotated[Session, Depends(get_db)]
_bearer = HTTPBearer(auto_error=False)


def get_auth_service(request: Request, db: DatabaseSession) -> AuthService:
    return AuthService(db, request.app.state.token_service, request.app.state.settings)


AuthServiceDependency = Annotated[AuthService, Depends(get_auth_service)]


def get_current_actor(
    request: Request,
    db: DatabaseSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Actor:
    if credentials is None or len(credentials.credentials) > 4096:
        raise unauthorized("invalid_access_token")
    try:
        actor = request.app.state.token_service.decode_access_token(credentials.credentials)
    except jwt.InvalidTokenError:
        raise unauthorized("invalid_access_token") from None
    active = db.scalar(
        select(AuthSession.id)
        .join(User, User.id == AuthSession.user_id)
        .where(
            AuthSession.id == actor.session_id,
            AuthSession.user_id == actor.user_id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > utcnow(),
            User.is_active.is_(True),
        )
    )
    if active is None:
        raise unauthorized("invalid_access_token")
    return actor


CurrentActor = Annotated[Actor, Depends(get_current_actor)]
