"""Casos de uso de la verificación de correo.

Hackathon: el código es estático (`FEE_VERIFICATION_STATIC_CODE`, por defecto
`"1234"`) y no se envía ningún correo. Todo lo demás — validación del correo,
tokens firmados, `consent_token` — es el comportamiento definitivo.

Para hacerlo funcional (ver `docs/osint-architecture.md`):
  1. `request_email`: generar un código aleatorio, guardar `sha256(code)` en el
     payload del `verification_token` y enviarlo por correo (`EmailSender`).
  2. `confirm_email`: comparar `sha256(code)` con el hash del token en vez del
     código estático.
  3. Vaciar `FEE_VERIFICATION_STATIC_CODE`.
"""

import hmac

from fee_server.core.config import Settings
from fee_server.core.problem import (
    InvalidVerificationCodeError,
    InvalidVerificationTokenError,
)
from fee_server.core.security import signed_token
from fee_server.domain.osint.catalog import is_valid_identifier
from fee_server.domain.verification.consent import (
    PURPOSE_THIRD_PARTY_CONSENT,
    PURPOSE_VERIFY_EMAIL,
    email_digest,
)
from fee_server.domain.verification.schemas import (
    EmailVerificationConfirmed,
    EmailVerificationRequested,
)


class VerificationService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def request_email(self, email: str, requester_id: str) -> EmailVerificationRequested:
        if not is_valid_identifier("email", email):
            raise InvalidVerificationTokenError()

        ttl = self._settings.verification_code_ttl_seconds
        token = signed_token.sign(
            self._settings.jwt_secret,
            PURPOSE_VERIFY_EMAIL,
            ttl,
            {"email_sha256": email_digest(email), "requester_id": requester_id},
        )
        # TODO(funcional): generar código aleatorio y EmailSender.send_code(email, code).
        return EmailVerificationRequested(verification_token=token, expires_in=ttl)

    def confirm_email(
        self, verification_token: str, code: str, requester_id: str
    ) -> EmailVerificationConfirmed:
        try:
            data = signed_token.read(
                self._settings.jwt_secret, verification_token, PURPOSE_VERIFY_EMAIL
            )
        except signed_token.InvalidSignedToken as exc:
            raise InvalidVerificationTokenError() from exc

        # El token debe pertenecer a quien lo confirma (mismo flujo, misma cuenta).
        if data.get("requester_id") != requester_id:
            raise InvalidVerificationTokenError()
        if not self._code_is_valid(code):
            raise InvalidVerificationCodeError()

        ttl = self._settings.osint_consent_ttl_seconds
        consent_token = signed_token.sign(
            self._settings.jwt_secret,
            PURPOSE_THIRD_PARTY_CONSENT,
            ttl,
            {"email_sha256": data["email_sha256"], "requester_id": requester_id},
        )
        return EmailVerificationConfirmed(consent_token=consent_token, expires_in=ttl)

    def _code_is_valid(self, code: str) -> bool:
        expected = self._settings.verification_static_code
        # Un código estático vacío significa que el modo real aún no está
        # implementado: en ese caso ningún código es válido.
        return bool(expected) and hmac.compare_digest(code, expected)
