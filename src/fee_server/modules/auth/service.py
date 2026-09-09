import math
from datetime import timedelta
from uuid import UUID

from sqlalchemy import case, exists, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from fee_server.core.config import Settings
from fee_server.modules.auth.errors import (
    registration_conflict,
    session_not_found,
    unauthorized,
)
from fee_server.modules.auth.models import AuthSession, RefreshToken, User, as_utc, utcnow
from fee_server.modules.auth.schemas import SessionResponse, TokenResponse, UserResponse
from fee_server.modules.auth.security import Actor, TokenService


class AuthService:
    """Authentication use cases own commits; refresh families map to sessions."""

    def __init__(self, db: Session, tokens: TokenService, settings: Settings):
        self.db = db
        self.tokens = tokens
        self.settings = settings

    def register(self, email: str, password: str) -> UserResponse:
        user = User(email=email, password_hash=self.tokens.hash_password(password))
        self.db.add(user)
        try:
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
            raise registration_conflict() from None
        return UserResponse.model_validate(user)

    def login(self, email: str, password: str) -> TokenResponse:
        user = self.db.scalar(select(User).where(User.email == email))
        valid = self.tokens.verify_password(password, user.password_hash if user else None)
        now = utcnow()
        if user is None:
            raise unauthorized()
        if not valid:
            self._record_failed_login(user)
            raise unauthorized()
        # A conditional write serializes admission with password changes and failed
        # attempts. A stale password hash cannot create a session after a change.
        admitted = self.db.execute(
            update(User)
            .where(
                User.id == user.id,
                User.password_hash == user.password_hash,
                User.is_active.is_(True),
                or_(User.locked_until.is_(None), User.locked_until <= now),
            )
            .values(failed_login_attempts=0, locked_until=None)
            .execution_options(synchronize_session=False)
        ).rowcount
        if admitted != 1:
            self.db.rollback()
            raise unauthorized()
        session = AuthSession(
            user_id=user.id,
            created_at=now,
            last_used_at=now,
            expires_at=now + timedelta(seconds=self.tokens.refresh_ttl),
        )
        self.db.add(session)
        self.db.flush()
        response = self._issue_tokens(session)
        self.db.commit()
        return response

    def _record_failed_login(self, user: User) -> None:
        now = utcnow()
        # The next count is calculated in SQL, so concurrent failures cannot
        # overwrite each other. An expired lock starts a new attempt window.
        next_attempts = case((User.locked_until <= now, 1), else_=User.failed_login_attempts + 1)
        self.db.execute(
            update(User)
            .where(
                User.id == user.id,
                User.password_hash == user.password_hash,
                User.is_active.is_(True),
                or_(User.locked_until.is_(None), User.locked_until <= now),
            )
            .values(
                failed_login_attempts=next_attempts,
                locked_until=case(
                    (
                        next_attempts >= self.settings.auth_login_max_attempts,
                        now + timedelta(seconds=self.settings.auth_login_lock_seconds),
                    ),
                    else_=None,
                ),
            )
            .execution_options(synchronize_session=False)
        )
        self.db.commit()

    def refresh(self, raw_token: str) -> TokenResponse:
        token_hash = self.tokens.hash_refresh_token(raw_token)
        candidate = self.db.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        if candidate is None:
            raise unauthorized("invalid_refresh_token")
        now = utcnow()
        # Lock the stable parent first, matching revocation/cleanup ordering.
        # An atomic UPDATE provides this guarantee on SQLite as well as PostgreSQL.
        active_account = exists().where(User.id == AuthSession.user_id, User.is_active.is_(True))
        renewed = self.db.execute(
            update(AuthSession)
            .where(
                AuthSession.id == candidate.session_id,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > now,
                active_account,
            )
            .values(last_used_at=now)
            .execution_options(synchronize_session=False)
        ).rowcount
        if renewed != 1:
            self.db.rollback()
            raise unauthorized("invalid_refresh_token")
        # Compare-and-set is enforced by both SQLite and PostgreSQL. Exactly one
        # concurrent request can consume a token, including across API workers.
        consumed = self.db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.id == candidate.id,
                RefreshToken.consumed_at.is_(None),
                RefreshToken.expires_at > now,
            )
            .values(consumed_at=now)
            .execution_options(synchronize_session=False)
        ).rowcount
        if consumed != 1:
            # Keep consumed hashes until the session expires: replay invalidates
            # the entire family, including the replacement already issued.
            self.db.execute(
                update(AuthSession)
                .where(AuthSession.id == candidate.session_id, AuthSession.revoked_at.is_(None))
                .values(revoked_at=now)
                .execution_options(synchronize_session=False)
            )
            self.db.commit()
            raise unauthorized("invalid_refresh_token")
        session = self.db.get(AuthSession, candidate.session_id)
        assert session is not None
        response = self._issue_tokens(session)
        self.db.commit()
        return response

    def _issue_tokens(self, session: AuthSession) -> TokenResponse:
        raw_token = self.tokens.create_refresh_token()
        self.db.add(
            RefreshToken(
                session_id=session.id,
                token_hash=self.tokens.hash_refresh_token(raw_token),
                expires_at=session.expires_at,
            )
        )
        access_token, expires_in = self.tokens.create_access_token(
            session.user_id, session.id, session.expires_at
        )
        if expires_in == 0:
            self.db.rollback()
            raise unauthorized("invalid_refresh_token")
        return TokenResponse(
            access_token=access_token,
            refresh_token=raw_token,
            expires_in=expires_in,
            refresh_expires_in=max(
                0, math.ceil((as_utc(session.expires_at) - utcnow()).total_seconds())
            ),
            session_id=session.id,
        )

    def me(self, actor: Actor) -> UserResponse:
        user = self.db.get(User, actor.user_id)
        if user is None or not user.is_active:
            raise unauthorized("invalid_access_token")
        return UserResponse.model_validate(user)

    def sessions(self, actor: Actor) -> list[SessionResponse]:
        sessions = self.db.scalars(
            select(AuthSession)
            .where(
                AuthSession.user_id == actor.user_id,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > utcnow(),
            )
            .order_by(AuthSession.created_at.desc(), AuthSession.id)
        )
        return [
            SessionResponse(
                id=session.id,
                created_at=session.created_at,
                expires_at=session.expires_at,
                last_used_at=session.last_used_at,
                is_current=session.id == actor.session_id,
            )
            for session in sessions
        ]

    def revoke_session(self, actor: Actor, session_id: UUID) -> None:
        session = self.db.scalar(
            select(AuthSession.id).where(
                AuthSession.id == session_id, AuthSession.user_id == actor.user_id
            )
        )
        if session is None:
            raise session_not_found()
        self.db.execute(
            update(AuthSession)
            .where(
                AuthSession.id == session_id,
                AuthSession.user_id == actor.user_id,
                AuthSession.revoked_at.is_(None),
            )
            .values(revoked_at=utcnow())
            .execution_options(synchronize_session=False)
        )
        self.db.commit()

    def change_password(self, actor: Actor, current_password: str, new_password: str) -> None:
        user = self.db.get(User, actor.user_id)
        valid = self.tokens.verify_password(current_password, user.password_hash if user else None)
        if user is None or not valid:
            if user is not None:
                self._record_failed_login(user)
            raise unauthorized()
        now = utcnow()
        # Acquire the same user write lock as login, then revoke every session
        # in the same transaction as the credential update (including this one).
        changed = self.db.execute(
            update(User)
            .where(
                User.id == actor.user_id,
                User.password_hash == user.password_hash,
                User.is_active.is_(True),
                or_(User.locked_until.is_(None), User.locked_until <= now),
            )
            .values(
                password_hash=self.tokens.hash_password(new_password),
                failed_login_attempts=0,
                locked_until=None,
            )
            .execution_options(synchronize_session=False)
        ).rowcount
        if changed != 1:
            self.db.rollback()
            raise unauthorized()
        self.db.execute(
            update(AuthSession)
            .where(AuthSession.user_id == actor.user_id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=now)
            .execution_options(synchronize_session=False)
        )
        self.db.commit()
