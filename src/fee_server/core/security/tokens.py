"""Tokens de sesión: JWT de acceso (corto) + refresh token opaco.

El JWT lleva la identidad del usuario y caduca en 1 hora. El refresh token es
una cadena aleatoria que solo se guarda hasheada; se rota en cada uso.
"""

import secrets
from hashlib import sha256

import jwt

from fee_server.util.time import utcnow

ALGORITHM = "HS256"


class InvalidAccessToken(Exception):
    """El JWT de acceso es inválido, expiró o no cuadra con iss/aud."""


def create_access_token(
    *,
    secret: str,
    subject: str,
    issuer: str,
    audience: str,
    ttl_seconds: int,
) -> str:
    now = utcnow()
    claims = {
        "sub": subject,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now.timestamp() + ttl_seconds,
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(claims, secret, algorithm=ALGORITHM)


def read_access_token(*, secret: str, token: str, issuer: str, audience: str) -> str:
    """Devuelve el `sub` (id de usuario) si el token es válido."""
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=[ALGORITHM],  # allowlist explícita: "none" queda descartado
            issuer=issuer,
            audience=audience,
            leeway=5,
        )
    except jwt.PyJWTError as exc:
        raise InvalidAccessToken(str(exc)) from exc

    subject = claims.get("sub")
    if not subject:
        raise InvalidAccessToken("sin sujeto")
    return subject


def generate_refresh_token() -> tuple[str, str]:
    """Devuelve `(valor_en_claro, hash)`. El claro se entrega una sola vez."""
    raw = secrets.token_urlsafe(32)
    return raw, hash_refresh_token(raw)


def hash_refresh_token(raw: str) -> str:
    return sha256(raw.encode()).hexdigest()
