"""Sesión: `me`, rotación de refresh token y cierre de sesión."""

from tests import passkey_helpers as pk

ME = "/api/v1/auth/me"
REFRESH = "/api/v1/auth/token/refresh"
LOGOUT = "/api/v1/auth/logout"


def _session(client):
    return pk.register(client, pk.new_device()).json()


def test_me_requires_a_bearer_token(client):
    assert client.get(ME).status_code == 401


def test_me_rejects_a_garbage_token(client):
    response = client.get(ME, headers={"Authorization": "Bearer not-a-real-token"})

    assert response.status_code == 401
    assert response.json()["type"].endswith("/invalid-session")


def test_me_returns_the_account_summary(client):
    session = _session(client)

    response = client.get(ME, headers={"Authorization": f"Bearer {session['access_token']}"})

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == session["user"]["id"]
    assert body["credentials_count"] == 1


def test_refresh_rotates_and_revokes_the_previous_token(client):
    session = _session(client)
    old_refresh = session["refresh_token"]

    rotated = client.post(REFRESH, json={"refresh_token": old_refresh})
    assert rotated.status_code == 200
    new_refresh = rotated.json()["refresh_token"]
    assert new_refresh != old_refresh

    reused = client.post(REFRESH, json={"refresh_token": old_refresh})
    assert reused.status_code == 401

    # El reuso del token viejo invalida también al nuevo (posible robo).
    assert client.post(REFRESH, json={"refresh_token": new_refresh}).status_code == 401


def test_logout_revokes_the_refresh_token(client):
    session = _session(client)

    assert client.post(LOGOUT, json={"refresh_token": session["refresh_token"]}).status_code == 204
    assert client.post(REFRESH, json={"refresh_token": session["refresh_token"]}).status_code == 401
