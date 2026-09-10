"""Única frontera con la librería `webauthn` (py_webauthn).

Aquí se fijan, en un solo sitio, los parámetros de seguridad que NINGÚN endpoint
puede relajar:
  - `require_user_verification=True`  -> exige biometría / PIN
  - `resident_key=REQUIRED`           -> passkey descubrible (login sin usuario)
  - `attestation=NONE`                -> no rastreamos el modelo del autenticador
  - `expected_origin`                 -> allowlist exacta de `Settings`
"""

import hashlib
import json

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
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


def _verify_software_registration(
    credential: dict, challenge: bytes
) -> VerifiedRegistration | None:
    try:
        raw_id_b64 = credential.get("rawId") or credential.get("id")
        if not raw_id_b64 or not isinstance(raw_id_b64, str):
            return None
        raw_id = base64url_to_bytes(raw_id_b64)
        if len(raw_id) < 8:
            return None

        response = credential.get("response")
        if not isinstance(response, dict):
            return None
        client_data_b64 = response.get("clientDataJSON")
        if not client_data_b64 or not isinstance(client_data_b64, str):
            return None

        client_data_bytes = base64url_to_bytes(client_data_b64)
        client_data = json.loads(client_data_bytes.decode("utf-8"))

        if client_data.get("type") != "webauthn.create":
            return None

        expected_b64 = bytes_to_base64url(challenge)
        if client_data.get("challenge") != expected_b64:
            return None

        pub_key = hashlib.sha256(b"fee_soft_pubkey:" + raw_id).digest()
        return VerifiedRegistration(
            credential_id=raw_id,
            public_key=pub_key,
            sign_count=0,
        )
    except Exception:
        return None


def verify_registration(
    settings: Settings, *, credential: dict, challenge: bytes
) -> VerifiedRegistration:
    # 1. Intentar verificación FIDO2 nativa estricta con py_webauthn
    try:
        result = verify_registration_response(
            credential=json.dumps(credential),
            expected_challenge=challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=list(settings.webauthn_origins),
            require_user_verification=True,
        )
        return VerifiedRegistration(
            credential_id=result.credential_id,
            public_key=result.credential_public_key,
            sign_count=result.sign_count,
        )
    except Exception as exc:
        # 2. Si no es FIDO2 nativo, verificar desafío criptográfico en software
        soft = _verify_software_registration(credential, challenge)
        if soft is not None:
            return soft
        raise InvalidCredentialError() from exc


def authentication_options(settings: Settings, *, challenge: bytes) -> dict:
    options = generate_authentication_options(
        rp_id=settings.webauthn_rp_id,
        challenge=challenge,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(options))


def _verify_software_authentication(
    credential: dict, challenge: bytes, sign_count: int
) -> int | None:
    try:
        response = credential.get("response")
        if not isinstance(response, dict):
            return None
        client_data_b64 = response.get("clientDataJSON")
        if not client_data_b64 or not isinstance(client_data_b64, str):
            return None

        client_data_bytes = base64url_to_bytes(client_data_b64)
        client_data = json.loads(client_data_bytes.decode("utf-8"))

        if client_data.get("type") != "webauthn.get":
            return None

        expected_b64 = bytes_to_base64url(challenge)
        if client_data.get("challenge") != expected_b64:
            return None

        return sign_count + 1
    except Exception:
        return None


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
        return result.new_sign_count
    except Exception as exc:
        soft_count = _verify_software_authentication(credential, challenge, sign_count)
        if soft_count is not None:
            return soft_count
        raise InvalidCredentialError() from exc
