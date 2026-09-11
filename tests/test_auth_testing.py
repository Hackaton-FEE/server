"""Acceso de pruebas: sesión individual y OSINT sin llamadas WebAuthn ni red."""

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from fee_server.core.config import Settings
from fee_server.core.rate_limit import limiter
from fee_server.db.models import Credential, RefreshToken, User
from fee_server.db.session import session_scope
from fee_server.domain.auth import repository, webauthn_gateway
from tests import passkey_helpers as pk
from tests.osint.conftest import VALID_USERNAME_SCAN

TESTING = "/api/v1/auth/testing/session"
ME = "/api/v1/auth/me"
REFRESH = "/api/v1/auth/token/refresh"
LOGOUT = "/api/v1/auth/logout"
SCANS = "/api/v1/osint/scans"


@pytest.fixture
def no_webauthn(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("El acceso de pruebas no debe invocar WebAuthn")

    for name in (
        "registration_options",
        "verify_registration",
        "authentication_options",
        "verify_authentication",
    ):
        monkeypatch.setattr(webauthn_gateway, name, unexpected)


@pytest.fixture
def testing_client(client, no_webauthn):
    client.app.state.settings = client.app.state.settings.model_copy(
        update={"auth_mode": "testing"}
    )
    return client


def _headers(session):
    return {"Authorization": f"Bearer {session['access_token']}"}


def _session(client):
    response = client.post(TESTING, json={})
    assert response.status_code == 201
    return response.json()


def test_default_auth_mode_does_not_allow_testing_sessions(client, monkeypatch):
    monkeypatch.delenv("FEE_AUTH_MODE", raising=False)
    assert Settings().auth_mode == "passkey"

    response = client.post(TESTING, json={})
    assert response.status_code == 403
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["type"].endswith("/testing-access-disabled")
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 0
        assert db.scalar(select(func.count()).select_from(RefreshToken)) == 0


def test_auth_mode_is_loaded_from_env_and_rejects_typos(monkeypatch):
    monkeypatch.setenv("FEE_AUTH_MODE", "testing")
    assert Settings().auth_mode == "testing"
    monkeypatch.setenv("FEE_AUTH_MODE", "testng")
    with pytest.raises(ValidationError, match="auth_mode"):
        Settings()


def test_testing_session_creates_a_new_account_without_credentials(testing_client):
    first = _session(testing_client)
    second = _session(testing_client)

    assert first["user"]["id"] != second["user"]["id"]
    assert first["refresh_token"] != second["refresh_token"]
    assert first["token_type"] == "bearer"
    assert first["expires_in"] == 3600
    for session in (first, second):
        assert session["user"]["label"] == "Pruebas"
        me = testing_client.get(ME, headers=_headers(session))
        assert me.status_code == 200
        assert me.json()["id"] == session["user"]["id"]
        assert me.json()["credentials_count"] == 0
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 2
        assert db.scalar(select(func.count()).select_from(Credential)) == 0
        assert len(set(db.scalars(select(User.handle)))) == 2


@pytest.mark.parametrize("field", ["id", "user_id", "handle", "label", "credential"])
def test_testing_session_cannot_select_or_link_an_existing_account(testing_client, field):
    existing = _session(testing_client)
    response = testing_client.post(TESTING, json={field: existing["user"]["id"]})
    assert response.status_code == 422
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 1


def test_testing_session_requires_an_empty_json_object(testing_client):
    assert testing_client.post(TESTING).status_code == 422
    assert testing_client.post(TESTING, json=[]).status_code == 422


@pytest.mark.parametrize(
    "path,payload",
    [
        ("registration/options", {}),
        ("registration/verify", {"challenge_token": "unused", "credential": {}}),
        ("authentication/options", {}),
        ("authentication/verify", {"challenge_token": "unused", "credential": {}}),
    ],
)
def test_testing_mode_disables_all_passkey_steps(testing_client, path, payload):
    response = testing_client.post(f"/api/v1/auth/passkey/{path}", json=payload)
    assert response.status_code == 403
    assert response.json()["type"].endswith("/passkey-disabled")


def test_testing_mode_preserves_existing_passkey_credentials(testing_client):
    with session_scope() as db:
        existing = repository.create_user_with_credential(
            db,
            handle=b"existing-passkey",
            label="Cuenta existente",
            credential_id=b"credential-id",
            public_key=b"public-key",
            sign_count=12,
        )
        existing_id = existing.id
    created = _session(testing_client)
    assert created["user"]["id"] != existing_id
    with session_scope() as db:
        credential = repository.get_credential(db, b"credential-id")
        assert credential.user_id == existing_id
        assert credential.public_key == b"public-key"
        assert credential.sign_count == 12
        assert credential.user.label == "Cuenta existente"
        assert repository.count_credentials(db, existing_id) == 1


def test_testing_refresh_rotates_and_logout_revokes(testing_client):
    session = _session(testing_client)
    rotated = testing_client.post(REFRESH, json={"refresh_token": session["refresh_token"]})
    assert rotated.status_code == 200
    fresh = rotated.json()
    assert fresh["user"] == session["user"]
    assert fresh["refresh_token"] != session["refresh_token"]
    assert testing_client.get(ME, headers=_headers(fresh)).status_code == 200
    assert (
        testing_client.post(LOGOUT, json={"refresh_token": fresh["refresh_token"]}).status_code
        == 204
    )
    assert (
        testing_client.post(REFRESH, json={"refresh_token": fresh["refresh_token"]}).status_code
        == 401
    )


def test_reused_refresh_only_revokes_the_same_testing_account(testing_client):
    first = _session(testing_client)
    second = _session(testing_client)
    fresh = testing_client.post(REFRESH, json={"refresh_token": first["refresh_token"]}).json()
    assert (
        testing_client.post(REFRESH, json={"refresh_token": first["refresh_token"]}).status_code
        == 401
    )
    assert (
        testing_client.post(REFRESH, json={"refresh_token": fresh["refresh_token"]}).status_code
        == 401
    )
    assert (
        testing_client.post(REFRESH, json={"refresh_token": second["refresh_token"]}).status_code
        == 200
    )


def test_full_fake_scan_with_testing_tokens_remains_private(testing_client):
    owner = _session(testing_client)
    other = _session(testing_client)
    headers = _headers(owner)
    other_headers = _headers(other)
    assert testing_client.post(SCANS, json=VALID_USERNAME_SCAN).status_code == 401
    accepted = testing_client.post(SCANS, json=VALID_USERNAME_SCAN, headers=headers)
    assert accepted.status_code == 202
    path = f"{SCANS}/{accepted.json()['scan_id']}"

    status = testing_client.get(path, headers=headers)
    assert status.status_code == 200
    assert status.json()["status"] == "COMPLETED"
    assert status.json()["progress_percentage"] == 100
    results = testing_client.get(f"{path}/results", headers=headers)
    assert results.status_code == 200
    assert results.json()["summary"]["platforms_found"] >= 1
    assert "event: done" in testing_client.get(f"{path}/events", headers=headers).text

    for endpoint in (path, f"{path}/results", f"{path}/events"):
        assert testing_client.get(endpoint, headers=other_headers).status_code == 404
    # El borrado ajeno es idempotente, pero debe dejar intacto el escaneo.
    testing_client.delete(path, headers=other_headers)
    assert testing_client.get(path, headers=headers).status_code == 200

    fresh = testing_client.post(REFRESH, json={"refresh_token": owner["refresh_token"]}).json()
    assert testing_client.get(f"{path}/results", headers=_headers(fresh)).status_code == 200
    assert testing_client.delete(path, headers=_headers(fresh)).status_code == 204
    assert testing_client.get(path, headers=_headers(fresh)).status_code == 404


def test_testing_session_creation_is_rate_limited(testing_client, monkeypatch):
    monkeypatch.setattr(limiter, "enabled", True)
    limiter.reset()
    try:
        for _ in range(10):
            assert testing_client.post(TESTING, json={}).status_code == 201
        limited = testing_client.post(TESTING, json={})
        assert limited.status_code == 429
        assert limited.json()["type"].endswith("/rate-limited")
    finally:
        limiter.reset()


def test_returning_to_passkey_blocks_testing_tokens_and_preserves_existing_accounts(client):
    device = pk.new_device()
    existing = pk.register(client, device, label="Cuenta existente").json()
    passkey_settings = client.app.state.settings
    client.app.state.settings = passkey_settings.model_copy(update={"auth_mode": "testing"})
    guest = _session(client)
    assert client.get(ME, headers=_headers(guest)).status_code == 200
    assert client.get(ME, headers=_headers(existing)).status_code == 200

    client.app.state.settings = passkey_settings
    assert client.get(ME, headers=_headers(guest)).status_code == 401
    assert client.post(REFRESH, json={"refresh_token": guest["refresh_token"]}).status_code == 401
    assert client.post(TESTING, json={}).status_code == 403
    assert client.post(SCANS, json=VALID_USERNAME_SCAN, headers=_headers(guest)).status_code == 401

    me = client.get(ME, headers=_headers(existing))
    assert me.status_code == 200
    assert me.json()["credentials_count"] == 1
    assert (
        client.post(REFRESH, json={"refresh_token": existing["refresh_token"]}).status_code == 200
    )
    assert pk.authenticate(client, device).status_code == 200
