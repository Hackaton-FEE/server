"""Contrato HTTP de la verificación de correo (código estático `"1234"`)."""

REQUEST = "/api/v1/verification/email/request"
CONFIRM = "/api/v1/verification/email/confirm"

EMAIL = "titular@example.com"


def _request_token(client, headers, email: str = EMAIL) -> str:
    response = client.post(REQUEST, json={"email": email}, headers=headers)
    assert response.status_code == 200
    return response.json()["verification_token"]


def test_request_then_confirm_returns_a_consent_token(client, headers):
    token = _request_token(client, headers)

    confirmed = client.post(
        CONFIRM, json={"verification_token": token, "code": "1234"}, headers=headers
    )

    assert confirmed.status_code == 200
    body = confirmed.json()
    assert body["consent_token"]
    assert body["expires_in"] > 0


def test_wrong_code_is_rejected(client, headers):
    token = _request_token(client, headers)

    response = client.post(
        CONFIRM, json={"verification_token": token, "code": "0000"}, headers=headers
    )

    assert response.status_code == 400
    assert response.json()["type"].endswith("invalid-verification-code")


def test_tampered_verification_token_is_rejected(client, headers):
    token = _request_token(client, headers)
    body, signature = token.split(".")
    tampered = f"{body[:-2]}00.{signature}"

    response = client.post(
        CONFIRM, json={"verification_token": tampered, "code": "1234"}, headers=headers
    )

    assert response.status_code == 400
    assert response.json()["type"].endswith("invalid-verification-token")


def test_invalid_email_is_rejected(client, headers):
    response = client.post(REQUEST, json={"email": "no-arroba"}, headers=headers)

    assert response.status_code == 400


def test_endpoints_require_authentication(client):
    assert client.post(REQUEST, json={"email": EMAIL}).status_code == 401
    assert (
        client.post(CONFIRM, json={"verification_token": "x.y", "code": "1234"}).status_code == 401
    )
