import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid4

import jwt
from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError

from fee_server.core.config import Settings
from fee_server.modules.auth.models import as_utc, utcnow


@dataclass(frozen=True)
class Actor:
    """Public authentication context; identifiers are UUID instances."""

    user_id: UUID
    session_id: UUID


class TokenService:
    def __init__(self, settings: Settings):
        self._secret_key = (
            settings.auth_secret_key.get_secret_value()
            if settings.auth_secret_key is not None
            else secrets.token_urlsafe(48)
        )
        self._issuer = settings.auth_issuer
        self._audience = settings.auth_audience
        self.access_ttl = settings.access_token_ttl_seconds
        self.refresh_ttl = settings.refresh_token_ttl_seconds
        self._password_hash = PasswordHash.recommended()
        self._dummy_hash = self.hash_password(secrets.token_urlsafe(32))

    def hash_password(self, password: str) -> str:
        return self._password_hash.hash(password)

    def verify_password(self, password: str, password_hash: str | None) -> bool:
        try:
            valid = self._password_hash.verify(password, password_hash or self._dummy_hash)
        except (UnknownHashError, ValueError):
            # Corrupt/obsolete hashes fail closed without a cheap account-existence signal.
            self._password_hash.verify(password, self._dummy_hash)
            return False
        return password_hash is not None and valid

    def create_access_token(
        self, user_id: UUID, session_id: UUID, session_expires_at: datetime
    ) -> tuple[str, int]:
        now = utcnow()
        expires_at = min(now + timedelta(seconds=self.access_ttl), as_utc(session_expires_at))
        payload = {
            "sub": str(user_id),
            "sid": str(session_id),
            "jti": str(uuid4()),
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": self._issuer,
            "aud": self._audience,
            "type": "access",
        }
        token = jwt.encode(payload, self._secret_key, algorithm="HS256")
        return token, max(0, payload["exp"] - payload["iat"])

    def decode_access_token(self, token: str) -> Actor:
        payload = jwt.decode(
            token,
            self._secret_key,
            algorithms=["HS256"],
            issuer=self._issuer,
            audience=self._audience,
            options={
                "require": ["sub", "sid", "jti", "iat", "exp", "iss", "aud", "type"],
                "strict_aud": True,
            },
        )
        if (
            payload["type"] != "access"
            or type(payload["iat"]) is not int
            or type(payload["exp"]) is not int
            or payload["exp"] <= payload["iat"]
        ):
            raise jwt.InvalidTokenError("Invalid access claims")
        try:
            UUID(payload["jti"])
            return Actor(user_id=UUID(payload["sub"]), session_id=UUID(payload["sid"]))
        except (ValueError, TypeError, AttributeError):
            raise jwt.InvalidTokenError("Invalid access subject") from None

    @staticmethod
    def create_refresh_token() -> str:
        return "fee_rt_" + secrets.token_urlsafe(48)

    @staticmethod
    def hash_refresh_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
