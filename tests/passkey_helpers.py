"""Puente entre el autenticador simulado `SoftWebauthnDevice` y la API.

Convierte las opciones (JSON de py_webauthn) al formato de bytes que espera
`soft_webauthn`, y las respuestas del dispositivo al JSON que la API valida.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.utils import sha256 as _sha256
from soft_webauthn import SoftWebauthnDevice
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

_ECDSA_SHA256 = ec.ECDSA(hashes.SHA256())

TEST_ORIGIN = "https://localhost"

# Bit "user verified" (0x04) del byte de flags de authenticatorData.
# SoftWebauthnDevice no lo activa; nuestra API exige verificación de usuario
# (biometría / PIN), igual que una passkey real. Lo activamos aquí.
_UV = 0x04
_FLAGS_OFFSET = 32  # va justo después del hash del RP ID (32 bytes)


def _with_uv_flag(authenticator_data: bytes) -> bytes:
    data = bytearray(authenticator_data)
    data[_FLAGS_OFFSET] |= _UV
    return bytes(data)


class VerifyingDevice(SoftWebauthnDevice):
    """Autenticador simulado que marca la verificación de usuario (UV)."""

    def create(self, options, origin):
        attestation = super().create(options, origin)
        att_obj = cbor.decode(attestation["response"]["attestationObject"])
        att_obj["authData"] = _with_uv_flag(att_obj["authData"])
        attestation["response"]["attestationObject"] = cbor.encode(att_obj)
        return attestation

    def get(self, options, origin):
        # Recalculamos la firma sobre el authenticatorData con el bit UV puesto.
        assertion = super().get(options, origin)
        auth_data = _with_uv_flag(assertion["response"]["authenticatorData"])
        client_data_hash = _sha256(assertion["response"]["clientDataJSON"])
        assertion["response"]["authenticatorData"] = auth_data
        assertion["response"]["signature"] = self.private_key.sign(
            auth_data + client_data_hash, _ECDSA_SHA256
        )
        return assertion


REGISTRATION_OPTIONS = "/api/v1/auth/passkey/registration/options"
REGISTRATION_VERIFY = "/api/v1/auth/passkey/registration/verify"
AUTHENTICATION_OPTIONS = "/api/v1/auth/passkey/authentication/options"
AUTHENTICATION_VERIFY = "/api/v1/auth/passkey/authentication/verify"


def new_device() -> SoftWebauthnDevice:
    return VerifyingDevice()


def build_registration_credential(device: SoftWebauthnDevice, public_key: dict) -> dict:
    create_options = {
        "publicKey": {
            **public_key,
            "challenge": base64url_to_bytes(public_key["challenge"]),
            "user": {
                **public_key["user"],
                "id": base64url_to_bytes(public_key["user"]["id"]),
            },
        }
    }
    attestation = device.create(create_options, TEST_ORIGIN)
    raw_id = bytes_to_base64url(attestation["rawId"])
    return {
        "id": raw_id,
        "rawId": raw_id,
        "type": "public-key",
        "clientExtensionResults": {},
        "response": {
            "clientDataJSON": bytes_to_base64url(attestation["response"]["clientDataJSON"]),
            "attestationObject": bytes_to_base64url(attestation["response"]["attestationObject"]),
        },
    }


def build_authentication_credential(device: SoftWebauthnDevice, public_key: dict) -> dict:
    get_options = {
        "publicKey": {
            **public_key,
            "challenge": base64url_to_bytes(public_key["challenge"]),
        }
    }
    assertion = device.get(get_options, TEST_ORIGIN)
    raw_id = bytes_to_base64url(assertion["rawId"])
    response = {
        "clientDataJSON": bytes_to_base64url(assertion["response"]["clientDataJSON"]),
        "authenticatorData": bytes_to_base64url(assertion["response"]["authenticatorData"]),
        "signature": bytes_to_base64url(assertion["response"]["signature"]),
    }
    user_handle = assertion["response"].get("userHandle")
    if user_handle:
        response["userHandle"] = bytes_to_base64url(user_handle)
    return {
        "id": raw_id,
        "rawId": raw_id,
        "type": "public-key",
        "clientExtensionResults": {},
        "response": response,
    }


def register(client, device: SoftWebauthnDevice, *, label: str = "Prueba"):
    """Registra una passkey nueva y devuelve la respuesta de `verify`."""
    options = client.post(REGISTRATION_OPTIONS, json={"label": label})
    assert options.status_code == 200, options.text
    body = options.json()
    credential = build_registration_credential(device, body["public_key"])
    return client.post(
        REGISTRATION_VERIFY,
        json={"challenge_token": body["challenge_token"], "credential": credential},
    )


def authenticate(client, device: SoftWebauthnDevice):
    """Inicia sesión con una passkey ya registrada."""
    options = client.post(AUTHENTICATION_OPTIONS, json={})
    assert options.status_code == 200, options.text
    body = options.json()
    credential = build_authentication_credential(device, body["public_key"])
    return client.post(
        AUTHENTICATION_VERIFY,
        json={"challenge_token": body["challenge_token"], "credential": credential},
    )
