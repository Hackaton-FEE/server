"""Inicio de sesión con una passkey ya registrada (sin usuario ni contraseña)."""

from tests import passkey_helpers as pk


def test_register_then_login_returns_a_fresh_session(client):
    device = pk.new_device()
    registered = pk.register(client, device).json()

    logged_in = pk.authenticate(client, device)

    assert logged_in.status_code == 200, logged_in.text
    body = logged_in.json()
    assert body["user"]["id"] == registered["user"]["id"]
    assert body["access_token"] != registered["access_token"]


def test_authentication_options_have_no_allowed_credentials(client):
    response = client.post(pk.AUTHENTICATION_OPTIONS, json={})

    assert response.status_code == 200
    assert response.json()["public_key"].get("allowCredentials") in (None, [])


def test_unknown_passkey_is_rejected(client):
    pk.register(client, pk.new_device())  # hay al menos una cuenta

    # Un dispositivo con una passkey creada localmente pero nunca registrada.
    never_registered = pk.new_device()
    never_registered.create(
        {
            "publicKey": {
                "rp": {"id": "localhost", "name": "x"},
                "user": {"id": b"x", "name": "x", "displayName": "x"},
                "challenge": b"0123456789012345",
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            }
        },
        pk.TEST_ORIGIN,
    )
    options = client.post(pk.AUTHENTICATION_OPTIONS, json={}).json()
    credential = pk.build_authentication_credential(never_registered, options["public_key"])

    response = client.post(
        pk.AUTHENTICATION_VERIFY,
        json={"challenge_token": options["challenge_token"], "credential": credential},
    )

    assert response.status_code == 401
    assert response.json()["type"].endswith("/unknown-credential")


def test_login_challenge_cannot_be_used_for_registration(client):
    device = pk.new_device()
    pk.register(client, device)
    options = client.post(pk.AUTHENTICATION_OPTIONS, json={}).json()
    credential = pk.build_authentication_credential(device, options["public_key"])

    response = client.post(
        pk.REGISTRATION_VERIFY,
        json={"challenge_token": options["challenge_token"], "credential": credential},
    )

    assert response.status_code == 400
    assert response.json()["type"].endswith("/invalid-challenge")
