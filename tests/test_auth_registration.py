"""Registro de una passkey nueva (crea la cuenta)."""

from tests import passkey_helpers as pk


def test_options_ask_for_a_discoverable_verified_passkey(client):
    response = client.post(pk.REGISTRATION_OPTIONS, json={"label": "Mi bóveda"})

    assert response.status_code == 200
    public_key = response.json()["public_key"]
    assert public_key["rp"]["id"] == "localhost"
    selection = public_key["authenticatorSelection"]
    assert selection["residentKey"] == "required"
    assert selection["userVerification"] == "required"


def test_verify_creates_the_account_and_opens_a_session(client):
    device = pk.new_device()

    response = pk.register(client, device, label="Mi bóveda")

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["user"]["label"] == "Mi bóveda"


def test_control_characters_are_stripped_from_the_label(client):
    device = pk.new_device()

    body = pk.register(client, device, label="Hola\x00\x07mundo").json()

    assert body["user"]["label"] == "Holamundo"


def test_bad_challenge_token_is_rejected(client):
    device = pk.new_device()
    options = client.post(pk.REGISTRATION_OPTIONS, json={}).json()
    credential = pk.build_registration_credential(device, options["public_key"])

    response = client.post(
        pk.REGISTRATION_VERIFY,
        json={"challenge_token": "garbage.deadbeef", "credential": credential},
    )

    assert response.status_code == 400
    assert response.json()["type"].endswith("/invalid-challenge")


def test_same_passkey_cannot_register_twice(client):
    device = pk.new_device()
    options = client.post(pk.REGISTRATION_OPTIONS, json={}).json()
    credential = pk.build_registration_credential(device, options["public_key"])
    payload = {"challenge_token": options["challenge_token"], "credential": credential}

    assert client.post(pk.REGISTRATION_VERIFY, json=payload).status_code == 201
    second = client.post(pk.REGISTRATION_VERIFY, json=payload)

    assert second.status_code in (400, 409)


def test_oversized_body_is_rejected(client):
    huge = "x" * 20_000
    response = client.post(pk.REGISTRATION_VERIFY, json={"challenge_token": huge, "credential": {}})

    assert response.status_code in (400, 413)
