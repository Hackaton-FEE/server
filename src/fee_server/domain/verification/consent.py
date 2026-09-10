"""Propósitos de token y verificación del consentimiento de terceros.

Aislado del `VerificationService` para que `domain/osint` pueda comprobar un
`consent_token` sin arrastrar toda la lógica de verificación.
"""

from hashlib import sha256

from fee_server.core.problem import InvalidConsentError
from fee_server.core.security import signed_token

# Propósitos de los tokens firmados de este flujo.
PURPOSE_VERIFY_EMAIL = "verify_email"
PURPOSE_THIRD_PARTY_CONSENT = "osint_third_party_consent"


def email_digest(email: str) -> str:
    """`sha256` del correo normalizado (sin espacios, minúsculas)."""
    return sha256(email.strip().casefold().encode("utf-8")).hexdigest()


def verify_consent_token(secret: str, consent_token: str, email: str, requester_id: str) -> None:
    """Comprueba que `consent_token` autoriza a `requester_id` a escanear `email`.

    Lanza `InvalidConsentError` si la firma, el propósito o la caducidad fallan,
    si el token no corresponde a ese correo, o si lo emitió el flujo de otra
    cuenta (el token está ligado a quien lo solicitó).
    """
    try:
        data = signed_token.read(secret, consent_token, PURPOSE_THIRD_PARTY_CONSENT)
    except signed_token.InvalidSignedToken as exc:
        raise InvalidConsentError() from exc

    if data.get("email_sha256") != email_digest(email):
        raise InvalidConsentError()
    if data.get("requester_id") != requester_id:
        raise InvalidConsentError()
