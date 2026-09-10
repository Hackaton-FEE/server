"""Token firmado y sin estado (HMAC-SHA256).

Empaqueta un pequeño payload JSON con un propósito y una caducidad, firmado con
un secreto compartido, de modo que el cliente lo devuelva intacto y el servidor
no tenga que guardar nada entre peticiones.

Es la generalización del patrón de `core/security/challenge.py` (retos WebAuthn),
sin la allowlist de propósitos. Coste asumido: el token es reutilizable durante
su corta vida; para un solo uso real haría falta almacenamiento (Redis/tabla).
"""

import hmac
import json
import time
from hashlib import sha256

_SEPARATOR = "."


class InvalidSignedToken(Exception):
    """El token está manipulado, expiró o su propósito no coincide."""


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, sha256).hexdigest()


def sign(secret: str, purpose: str, ttl_seconds: int, data: dict) -> str:
    """Genera un token que caduca en `ttl_seconds`."""
    payload = {
        "p": purpose,
        "exp": int(time.time()) + ttl_seconds,
        "d": data,
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return body.hex() + _SEPARATOR + _sign(secret, body)


def read(secret: str, token: str, purpose: str) -> dict:
    """Valida firma, propósito y caducidad; devuelve el `data` original.

    Lanza `InvalidSignedToken` ante cualquier fallo.
    """
    try:
        body_hex, signature = token.split(_SEPARATOR, 1)
        body = bytes.fromhex(body_hex)
    except ValueError as exc:
        raise InvalidSignedToken("formato de token inválido") from exc

    if not hmac.compare_digest(_sign(secret, body), signature):
        raise InvalidSignedToken("firma inválida")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise InvalidSignedToken("contenido ilegible") from exc

    if payload.get("p") != purpose:
        raise InvalidSignedToken("propósito incorrecto")
    try:
        expires_at = int(payload.get("exp", 0))
    except (TypeError, ValueError) as exc:
        raise InvalidSignedToken("caducidad ilegible") from exc
    if expires_at < int(time.time()):
        raise InvalidSignedToken("token expirado")

    data = payload.get("d")
    if not isinstance(data, dict):
        raise InvalidSignedToken("payload sin datos")
    return data
