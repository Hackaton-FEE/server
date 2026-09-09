"""Única frontera con la librería `webauthn` (py_webauthn).

Aquí se fijan, en un solo sitio, los parámetros de seguridad que NINGÚN endpoint
puede relajar:
  - `require_user_verification=True`  -> exige biometría / PIN
  - `resident_key=REQUIRED`           -> passkey descubrible (login sin usuario)
  - `attestation=NONE`                -> no rastreamos el modelo del autenticador
  - `expected_origin`                 -> allowlist exacta de `Settings`
"""

import json

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from fee_server.core.config import Settings
from fee_server.core.problem import InvalidCredentialError

_SELECTION = AuthenticatorSelectionCriteria(
    resident_key=ResidentKeyRequirement.REQUIRED,
    user_verification=UserVerificationRequirement.REQUIRED,
)


class VerifiedRegistration:
    def __init__(self, credential_id: bytes, public_key: bytes, sign_count: int) -> None:
        self.credential_id = credential_id
        self.public_key = public_key
        self.sign_count = sign_count


def registration_options(
    settings: Settings, *, user_handle: bytes, label: str, challenge: bytes
) -> dict:
    options = generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        user_id=user_handle,
        user_name=label or "Usuario FEE",
        user_display_name=label or "Usuario FEE",
        challenge=challenge,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=_SELECTION,
    )
    return json.loads(options_to_json(options))


def verify_registration(
    settings: Settings, *, credential: dict, challenge: bytes
) -> VerifiedRegistration:
    try:
        result = verify_registration_response(
            credential=json.dumps(credential),
            expected_challenge=challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=list(settings.webauthn_origins),
            require_user_verification=True,
        )
    except Exception as exc:  # noqa: BLE001 - respuesta externa: cualquier fallo aquí es 400
        raise InvalidCredentialError() from exc
    return VerifiedRegistration(
        credential_id=result.credential_id,
        public_key=result.credential_public_key,
        sign_count=result.sign_count,
    )


def authentication_options(settings: Settings, *, challenge: bytes) -> dict:
    options = generate_authentication_options(
        rp_id=settings.webauthn_rp_id,
        challenge=challenge,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(options))


def verify_authentication(
    settings: Settings,
    *,
    credential: dict,
    challenge: bytes,
    public_key: bytes,
    sign_count: int,
) -> int:
    """Devuelve el nuevo `sign_count` informado por el autenticador."""
    try:
        result = verify_authentication_response(
            credential=json.dumps(credential),
            expected_challenge=challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=list(settings.webauthn_origins),
            credential_public_key=public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )
    except Exception as exc:  # noqa: BLE001 - respuesta externa: cualquier fallo aquí es 400
        raise InvalidCredentialError() from exc
    return result.new_sign_count
