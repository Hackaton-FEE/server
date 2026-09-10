"""El reto público nunca sustituye la verificación de una passkey."""

import hashlib
import json

import pytest
from fido2 import cbor
from sqlalchemy import func, select
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from fee_server.db.models import Credential, RefreshToken, User
from fee_server.db.session import session_scope
from tests import passkey_helpers as pk


@pytest.mark.parametrize("invalid_response", ["fake-none", "missing-attestation", "missing-uv"])
def test_valid_registration_challenge_without_valid_attestation_is_rejected(
    client, invalid_response
):
    options = client.post(pk.REGISTRATION_OPTIONS, json={}).json()
    credential = pk.build_registration_credential(pk.new_device(), options["public_key"])
    response = credential["response"]
    if invalid_response == "fake-none":
        response["attestationObject"] = bytes_to_base64url(b"none")
    elif invalid_response == "missing-attestation":
        del response["attestationObject"]
    else:
        attestation = cbor.decode(base64url_to_bytes(response["attestationObject"]))
        auth_data = bytearray(attestation["authData"])
        auth_data[32] &= ~0x04
        attestation["authData"] = bytes(auth_data)
        response["attestationObject"] = bytes_to_base64url(cbor.encode(attestation))

    result = client.post(
        pk.REGISTRATION_VERIFY,
        json={"challenge_token": options["challenge_token"], "credential": credential},
    )

    assert result.status_code == 400
    assert result.json()["type"].endswith("/invalid-credential")
    with session_scope() as session:
        for model in (User, Credential, RefreshToken):
            assert session.scalar(select(func.count()).select_from(model)) == 0


@pytest.mark.parametrize(
    "invalid_response", ["fake-signature", "missing-signature", "wrong-origin"]
)
def test_valid_login_challenge_without_valid_signature_is_rejected(client, invalid_response):
    device = pk.new_device()
    registered = pk.register(client, device)
    assert registered.status_code == 201
    existing_session = registered.json()
    options = client.post(pk.AUTHENTICATION_OPTIONS, json={}).json()
    credential = pk.build_authentication_credential(device, options["public_key"])
    response = credential["response"]
    if invalid_response == "fake-signature":
        response["signature"] = bytes_to_base64url(b"sig_fee")
    elif invalid_response == "missing-signature":
        del response["signature"]
    else:
        client_data = json.loads(base64url_to_bytes(response["clientDataJSON"]))
        client_data["origin"] = "https://untrusted.invalid"
        response["clientDataJSON"] = bytes_to_base64url(json.dumps(client_data).encode())

    with session_scope() as session:
        stored = session.scalar(select(Credential))
        original_count = stored.sign_count
        original_last_used = stored.last_used_at

    result = client.post(
        pk.AUTHENTICATION_VERIFY,
        json={"challenge_token": options["challenge_token"], "credential": credential},
    )

    assert result.status_code == 400
    assert result.json()["type"].endswith("/invalid-credential")
    with session_scope() as session:
        stored = session.scalar(select(Credential))
        assert stored.sign_count == original_count
        assert stored.last_used_at == original_last_used
        assert session.scalar(select(func.count()).select_from(RefreshToken)) == 1

    # El rechazo conserva la cuenta y la sesión previa; una firma válida aún funciona.
    me = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {existing_session['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["id"] == existing_session["user"]["id"]
    assert pk.authenticate(client, device).status_code == 200


def test_legacy_software_key_cannot_login_but_keeps_existing_session(client):
    device = pk.new_device()
    registered = pk.register(client, device).json()
    with session_scope() as session:
        stored = session.scalar(select(Credential))
        # Reproduce solo en la BD temporal el formato que guardaba el fallback.
        stored.public_key = hashlib.sha256(b"fee_soft_pubkey:" + stored.credential_id).digest()

    rejected = pk.authenticate(client, device)
    assert rejected.status_code == 400
    assert rejected.json()["type"].endswith("/invalid-credential")
    with session_scope() as session:
        assert session.scalar(select(func.count()).select_from(User)) == 1
        assert session.scalar(select(func.count()).select_from(Credential)) == 1
        assert session.scalar(select(func.count()).select_from(RefreshToken)) == 1

    me = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {registered['access_token']}"}
    )
    assert me.status_code == 200
    assert me.json()["id"] == registered["user"]["id"]
    refreshed = client.post(
        "/api/v1/auth/token/refresh", json={"refresh_token": registered["refresh_token"]}
    )
    assert refreshed.status_code == 200
    assert refreshed.json()["user"]["id"] == registered["user"]["id"]
