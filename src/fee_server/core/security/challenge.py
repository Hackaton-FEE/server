"""Reto (challenge) WebAuthn firmado y sin estado.

En vez de guardar el reto en el servidor entre la petición de opciones y la de
verificación, lo empaquetamos en un token firmado con HMAC-SHA256 que el cliente
devuelve intacto. Ventajas: sin almacenamiento, escala en varias instancias.

Coste: el token es reutilizable durante su corta vida (`challenge_ttl_seconds`,
120 s por defecto). El reto de un solo uso con Redis queda como mejora futura.
"""

import hmac
import json
import secrets
import time
from hashlib import sha256

CHALLENGE_BYTES = 32
VALID_PURPOSES = ("register", "authenticate")


class InvalidChallenge(Exception):
    """El token de reto está manipulado, expiró o no corresponde al propósito."""


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, sha256).hexdigest()


def issue_challenge(
    secret: str,
    purpose: str,
    ttl_seconds: int,
    data: dict | None = None,
) -> tuple[bytes, str]:
    """Genera un reto nuevo.

    Devuelve `(challenge_bytes, challenge_token)`. `challenge_bytes` se pasa a la
    librería WebAuthn; `challenge_token` viaja al cliente y vuelve sin cambios.
    `data` guarda datos pequeños que necesitamos recuperar en la verificación
    (por ejemplo el `handle` del usuario durante el registro).
    """
    if purpose not in VALID_PURPOSES:
        raise ValueError(f"purpose desconocido: {purpose}")

    challenge = secrets.token_bytes(CHALLENGE_BYTES)
    payload = {
        "c": challenge.hex(),
        "p": purpose,
        "exp": int(time.time()) + ttl_seconds,
        "d": data or {},
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    token = body.hex() + "." + _sign(secret, body)
    return challenge, token


def read_challenge(secret: str, token: str, purpose: str) -> tuple[bytes, dict]:
    """Valida el token y devuelve `(challenge_bytes, data)`.

    Lanza `InvalidChallenge` si la firma no cuadra, el propósito no coincide o
    el reto expiró.
    """
    try:
        body_hex, signature = token.split(".", 1)
        body = bytes.fromhex(body_hex)
    except ValueError as exc:
        raise InvalidChallenge("formato de token inválido") from exc

    if not hmac.compare_digest(_sign(secret, body), signature):
        raise InvalidChallenge("firma inválida")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise InvalidChallenge("contenido ilegible") from exc

    if payload.get("p") != purpose:
        raise InvalidChallenge("propósito incorrecto")
    if int(payload.get("exp", 0)) < int(time.time()):
        raise InvalidChallenge("reto expirado")

    return bytes.fromhex(payload["c"]), payload.get("d", {})
