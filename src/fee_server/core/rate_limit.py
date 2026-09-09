"""Shared SQL fixed-window limits for public authentication entry points."""

import hashlib
import hmac
import secrets
import time

from fastapi import HTTPException, Request
from sqlalchemy import Integer, String, delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Mapped, mapped_column

from fee_server.core.config import Settings
from fee_server.core.database import Base, Database


class RequestLimit(Base):
    __tablename__ = "auth_request_limits"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[int] = mapped_column(Integer, index=True, nullable=False)


class AuthRateLimiter:
    def __init__(self, database: Database, settings: Settings):
        self.database = database
        self.limit = settings.auth_request_limit
        self.window = settings.auth_request_window_seconds
        self.secret = (
            settings.auth_secret_key.get_secret_value()
            if settings.auth_secret_key
            else secrets.token_urlsafe(48)
        ).encode()

    def check(self, peer: str, path: str) -> None:
        now = int(time.time())
        bucket = now // self.window
        expires = (bucket + 1) * self.window
        key = hmac.new(self.secret, f"{peer}|{path}|{bucket}".encode(), hashlib.sha256).hexdigest()
        insert = sqlite_insert if self.database.engine.dialect.name == "sqlite" else pg_insert
        statement = (
            insert(RequestLimit)
            .values(key=key, count=1, expires_at=expires)
            .on_conflict_do_update(
                index_elements=[RequestLimit.key], set_={"count": RequestLimit.count + 1}
            )
            .returning(RequestLimit.count)
        )
        with self.database.session_factory.begin() as session:
            session.execute(delete(RequestLimit).where(RequestLimit.expires_at <= now))
            count = session.execute(statement).scalar_one()
        if count > self.limit:
            raise HTTPException(
                status_code=429,
                detail={"code": "rate_limited", "message": "Too many authentication requests"},
                headers={"Retry-After": str(max(1, expires - now))},
            )


def limit_auth_requests(request: Request) -> None:
    if request.url.path.rstrip("/") in {
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
    }:
        peer = request.client.host if request.client else "unknown"
        request.app.state.auth_rate_limiter.check(peer, request.url.path.rstrip("/"))
