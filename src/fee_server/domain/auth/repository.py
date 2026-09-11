"""Acceso a datos de autenticación: funciones simples sobre una `Session`.

Ninguna función hace commit; eso lo decide la dependencia `get_session`.
"""

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from fee_server.db.models import Credential, RefreshToken, User
from fee_server.util.time import utcnow


def create_testing_user(session: Session, *, handle: bytes) -> User:
    user = User(handle=handle, label="Pruebas")
    session.add(user)
    session.flush()
    return user


def create_user_with_credential(
    session: Session,
    *,
    handle: bytes,
    label: str,
    credential_id: bytes,
    public_key: bytes,
    sign_count: int,
) -> User:
    user = User(handle=handle, label=label)
    user.credentials.append(
        Credential(
            credential_id=credential_id,
            public_key=public_key,
            sign_count=sign_count,
        )
    )
    session.add(user)
    session.flush()
    return user


def get_credential(session: Session, credential_id: bytes) -> Credential | None:
    return session.scalar(select(Credential).where(Credential.credential_id == credential_id))


def get_user(session: Session, user_id: str) -> User | None:
    return session.get(User, user_id)


def count_credentials(session: Session, user_id: str) -> int:
    total = session.scalar(
        select(func.count()).select_from(Credential).where(Credential.user_id == user_id)
    )
    return int(total or 0)


def store_refresh_token(
    session: Session, *, user_id: str, token_hash: str, ttl_seconds: int
) -> None:
    session.add(
        RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=utcnow() + timedelta(seconds=ttl_seconds),
        )
    )


def get_refresh_token(session: Session, token_hash: str) -> RefreshToken | None:
    return session.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))


def revoke_all_refresh_tokens(session: Session, user_id: str) -> None:
    rows = session.scalars(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked_at.is_(None),
        )
    )
    now = utcnow()
    for row in rows:
        row.revoked_at = now
