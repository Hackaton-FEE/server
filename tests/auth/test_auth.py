from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event
from uuid import UUID, uuid4

import jwt
import pytest
from sqlalchemy import event, select, update

from fee_server.modules.auth.models import AuthSession, RefreshToken, User, as_utc, utcnow

EMAIL = "demo@example.com"
PASSWORD = "a long demo passphrase"
NEW_PASSWORD = "a different demo passphrase"


def register(client, *, email=EMAIL, password=PASSWORD):
    return client.post("/api/v1/auth/register", json={"email": email, "password": password})


def login(client, *, email=EMAIL, password=PASSWORD):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def bearer(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


@pytest.fixture
def tokens(client):
    assert register(client).status_code == 201
    response = login(client)
    assert response.status_code == 200
    return response.json()


def test_register_normalizes_email_and_never_exposes_passwords(client, app):
    response = register(client, email="  Demo@EXAMPLE.com  ")
    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"id", "email", "is_active", "created_at"}
    assert body["email"] == EMAIL
    assert body["is_active"] is True
    assert body["created_at"].endswith("Z")
    assert UUID(body["id"])
    with app.state.database.session_factory() as db:
        user = db.get(User, UUID(body["id"]))
        assert user.password_hash.startswith("$argon2id$")
        assert PASSWORD not in user.password_hash
        assert app.state.token_service.verify_password(PASSWORD, user.password_hash)
    conflict = register(client, email="DEMO@example.com")
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "registration_conflict"
    assert EMAIL not in conflict.text


@pytest.mark.parametrize(
    "payload",
    [
        {"email": EMAIL, "password": "abcde"},
        {"email": EMAIL, "password": "x" * 129},
        {"email": "invalid-address", "password": PASSWORD},
        {"email": "x" * 255 + "@example.com", "password": PASSWORD},
        {"email": EMAIL, "password": PASSWORD, "is_active": True},
        {"email": EMAIL, "password": PASSWORD, "role": "admin"},
    ],
)
def test_invalid_registration_is_bounded_and_redacted(client, payload):
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422
    assert payload["password"] not in response.text
    assert payload["email"] not in response.text
    assert '"input"' not in response.text


def test_passphrase_does_not_require_composition_rules(client):
    assert register(client, password="abcdefghijkl").status_code == 201


def test_login_me_and_refresh_persist_only_token_hashes(client, app, tokens):
    assert tokens["token_type"] == "bearer"
    assert tokens["expires_in"] == 900
    assert 0 < tokens["refresh_expires_in"] <= 2_592_000
    response = client.get("/api/v1/auth/me", headers=bearer(tokens))
    assert response.status_code == 200
    assert response.json()["email"] == EMAIL
    assert "password_hash" not in response.text
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    assert set(claims) == {"sub", "sid", "jti", "iat", "exp", "iss", "aud", "type"}
    assert claims["sid"] == tokens["session_id"]
    with app.state.database.session_factory() as db:
        original_session = db.get(AuthSession, UUID(tokens["session_id"]))
        expires_at = as_utc(original_session.expires_at)
        stored = db.scalar(select(RefreshToken))
        assert stored.token_hash != tokens["refresh_token"]
        assert stored.token_hash == app.state.token_service.hash_refresh_token(
            tokens["refresh_token"]
        )
    response = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    replacement = response.json()
    assert replacement["session_id"] == tokens["session_id"]
    assert replacement["refresh_token"] != tokens["refresh_token"]
    assert replacement["access_token"] != tokens["access_token"]
    with app.state.database.session_factory() as db:
        stored_tokens = db.scalars(select(RefreshToken)).all()
        assert len(stored_tokens) == 2
        assert sum(token.consumed_at is not None for token in stored_tokens) == 1
        assert all(as_utc(token.expires_at) == expires_at for token in stored_tokens)
        assert as_utc(db.get(AuthSession, original_session.id).expires_at) == expires_at
    assert client.get("/api/v1/auth/me", headers=bearer(replacement)).status_code == 200


def test_refresh_replay_revokes_the_whole_session_but_not_other_sessions(client, tokens):
    other = login(client).json()
    replacement = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    ).json()
    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 401
    assert replay.json()["detail"]["code"] == "invalid_refresh_token"
    assert client.get("/api/v1/auth/me", headers=bearer(tokens)).status_code == 401
    assert client.get("/api/v1/auth/me", headers=bearer(replacement)).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/refresh", json={"refresh_token": replacement["refresh_token"]}
        ).status_code
        == 401
    )
    assert client.get("/api/v1/auth/me", headers=bearer(other)).status_code == 200


def test_logout_revokes_access_and_refresh_immediately(client, tokens):
    response = client.post("/api/v1/auth/logout", headers=bearer(tokens))
    assert response.status_code == 204
    assert response.content == b""
    assert client.get("/api/v1/auth/me", headers=bearer(tokens)).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        ).status_code
        == 401
    )


def test_sessions_are_private_and_owned_sessions_can_be_revoked(client, tokens):
    second = login(client).json()
    assert register(client, email="another@example.com").status_code == 201
    foreign = login(client, email="another@example.com").json()
    response = client.get("/api/v1/auth/sessions", headers=bearer(tokens))
    assert response.status_code == 200
    sessions = response.json()
    assert {session["id"] for session in sessions} == {tokens["session_id"], second["session_id"]}
    assert sum(session["is_current"] for session in sessions) == 1
    assert all("token_hash" not in session for session in sessions)
    for session_id in [foreign["session_id"], str(uuid4())]:
        response = client.delete(f"/api/v1/auth/sessions/{session_id}", headers=bearer(tokens))
        assert response.status_code == 404
        assert response.json()["detail"]["code"] == "session_not_found"
    response = client.delete(
        f"/api/v1/auth/sessions/{second['session_id']}", headers=bearer(tokens)
    )
    assert response.status_code == 204
    assert client.get("/api/v1/auth/me", headers=bearer(second)).status_code == 401
    assert client.get("/api/v1/auth/me", headers=bearer(foreign)).status_code == 200
    assert len(client.get("/api/v1/auth/sessions", headers=bearer(tokens)).json()) == 1


def test_password_change_requires_current_password_and_revokes_all_sessions(client, tokens):
    second = login(client).json()
    wrong = client.post(
        "/api/v1/auth/change-password",
        headers=bearer(tokens),
        json={"current_password": "wrong", "new_password": NEW_PASSWORD},
    )
    assert wrong.status_code == 401
    assert client.get("/api/v1/auth/me", headers=bearer(tokens)).status_code == 200
    response = client.post(
        "/api/v1/auth/change-password",
        headers=bearer(tokens),
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
    )
    assert response.status_code == 204
    for old in [tokens, second]:
        assert client.get("/api/v1/auth/me", headers=bearer(old)).status_code == 401
        assert (
            client.post(
                "/api/v1/auth/refresh", json={"refresh_token": old["refresh_token"]}
            ).status_code
            == 401
        )
    assert login(client).status_code == 401
    assert login(client, password=NEW_PASSWORD).status_code == 200


def test_unknown_wrong_and_disabled_credentials_have_identical_errors(client, app, tokens):
    wrong = login(client, password="wrong").json()
    unknown = login(client, email="unknown@example.com").json()
    assert wrong == unknown
    with app.state.database.session_factory() as db:
        db.execute(update(User).where(User.email == EMAIL).values(is_active=False))
        db.commit()
    disabled = login(client)
    assert disabled.status_code == 401
    assert disabled.json() == wrong
    assert client.get("/api/v1/auth/me", headers=bearer(tokens)).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        ).status_code
        == 401
    )


def test_failed_login_lockout_expires_and_success_resets_counter(client, app, tokens, settings):
    for _ in range(settings.auth_login_max_attempts):
        assert login(client, password="wrong").status_code == 401
    assert login(client).status_code == 401
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.email == EMAIL))
        assert user.failed_login_attempts == settings.auth_login_max_attempts
        assert as_utc(user.locked_until) > utcnow()
        user.locked_until = utcnow() - timedelta(seconds=1)
        db.commit()
    assert login(client, password="wrong").status_code == 401
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.email == EMAIL))
        assert user.failed_login_attempts == 1
        assert user.locked_until is None
    assert login(client).status_code == 200
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.email == EMAIL))
        assert user.failed_login_attempts == 0


@pytest.mark.parametrize(
    "authorization", [None, "Basic abc", "Bearer invalid", "Bearer " + "x" * 4097]
)
def test_protected_endpoints_require_valid_bearer(client, authorization):
    headers = {"Authorization": authorization} if authorization else {}
    for path in ["/api/v1/auth/me", "/api/v1/auth/sessions"]:
        response = client.get(path, headers=headers)
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert response.json()["detail"]["code"] == "invalid_access_token"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda claims: claims.update(iss="other-issuer"),
        lambda claims: claims.update(aud="other-audience"),
        lambda claims: claims.update(type="refresh"),
        lambda claims: claims.update(exp=int(utcnow().timestamp()) - 1),
        lambda claims: claims.update(iat=int(utcnow().timestamp()) + 3600),
        lambda claims: claims.update(sub=str(uuid4())),
        lambda claims: claims.update(sid=str(uuid4())),
        lambda claims: claims.update(sid="not-a-uuid"),
        lambda claims: claims.update(jti=None),
        lambda claims: claims.update(iat=True),
        lambda claims: claims.pop("exp"),
        lambda claims: claims.pop("iat"),
        lambda claims: claims.pop("sid"),
        lambda claims: claims.pop("jti"),
        lambda claims: claims.pop("type"),
    ],
)
def test_invalid_or_missing_jwt_claims_fail_closed(client, tokens, settings, mutate):
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    mutate(claims)
    invalid = jwt.encode(claims, settings.auth_secret_key.get_secret_value(), algorithm="HS256")
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {invalid}"})
    assert response.status_code == 401


@pytest.mark.parametrize("algorithm", ["none", "HS384"])
def test_only_hs256_is_accepted(client, tokens, settings, algorithm):
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    key = "" if algorithm == "none" else settings.auth_secret_key.get_secret_value()
    invalid = jwt.encode(claims, key, algorithm=algorithm)
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {invalid}"}).status_code
        == 401
    )


def test_forged_signature_is_rejected(client, tokens):
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    invalid = jwt.encode(claims, "another-key-for-tests-only-0123456789", algorithm="HS256")
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {invalid}"}).status_code
        == 401
    )


def test_expired_session_invalidates_unexpired_access_and_refresh(client, app, tokens):
    with app.state.database.session_factory() as db:
        db.execute(
            update(AuthSession)
            .where(AuthSession.id == UUID(tokens["session_id"]))
            .values(expires_at=utcnow() - timedelta(seconds=1))
        )
        db.commit()
    assert client.get("/api/v1/auth/me", headers=bearer(tokens)).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        ).status_code
        == 401
    )


def test_refresh_with_less_than_one_jwt_second_remaining_fails_closed(
    client, app, tokens, monkeypatch
):
    now = utcnow().replace(microsecond=0)
    monkeypatch.setattr("fee_server.modules.auth.service.utcnow", lambda: now)
    monkeypatch.setattr("fee_server.modules.auth.security.utcnow", lambda: now)
    with app.state.database.session_factory() as db:
        db.execute(
            update(AuthSession)
            .where(AuthSession.id == UUID(tokens["session_id"]))
            .values(expires_at=now + timedelta(milliseconds=500))
        )
        db.commit()
    response = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert response.status_code == 401
    with app.state.database.session_factory() as db:
        assert db.scalar(select(RefreshToken)).consumed_at is None


def test_refresh_token_inputs_are_bounded_and_unknown_token_is_rejected(client):
    for raw in ["too-short", "x" * 257]:
        response = client.post("/api/v1/auth/refresh", json={"refresh_token": raw})
        assert response.status_code == 422
        assert raw not in response.text
    assert (
        client.post(
            "/api/v1/auth/refresh", json={"refresh_token": "fee_rt_" + "x" * 64}
        ).status_code
        == 401
    )


def test_concurrent_refresh_is_single_use_and_replay_revocation_persists(client, app, tokens):
    barrier = Barrier(2)

    def synchronize_consumption(_conn, _cursor, statement, _parameters, _context, _executemany):
        if statement.startswith("UPDATE auth_sessions SET last_used_at"):
            barrier.wait(timeout=10)

    engine = app.state.database.engine
    event.listen(engine, "before_cursor_execute", synchronize_consumption)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(
                    client.post,
                    "/api/v1/auth/refresh",
                    json={"refresh_token": tokens["refresh_token"]},
                )
                for _ in range(2)
            ]
            responses = [future.result(timeout=20) for future in futures]
    finally:
        event.remove(engine, "before_cursor_execute", synchronize_consumption)
    assert sorted(response.status_code for response in responses) == [200, 401]
    replacement = next(response.json() for response in responses if response.status_code == 200)
    assert client.get("/api/v1/auth/me", headers=bearer(replacement)).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/refresh", json={"refresh_token": replacement["refresh_token"]}
        ).status_code
        == 401
    )
    with app.state.database.session_factory() as db:
        assert len(db.scalars(select(RefreshToken)).all()) == 2
        assert db.get(AuthSession, UUID(tokens["session_id"])).revoked_at is not None


def test_concurrent_failed_logins_do_not_lose_attempts(client, app, tokens, settings):
    for _ in range(settings.auth_login_max_attempts - 2):
        assert login(client, password="wrong").status_code == 401
    barrier = Barrier(2)

    def synchronize_attempts(_conn, _cursor, statement, _parameters, _context, _executemany):
        if statement.startswith("UPDATE auth_users"):
            barrier.wait(timeout=10)

    engine = app.state.database.engine
    event.listen(engine, "before_cursor_execute", synchronize_attempts)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(login, client, password="wrong") for _ in range(2)]
            responses = [future.result(timeout=20) for future in futures]
    finally:
        event.remove(engine, "before_cursor_execute", synchronize_attempts)
    assert all(response.status_code == 401 for response in responses)
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.email == EMAIL))
        assert user.failed_login_attempts == settings.auth_login_max_attempts
        assert user.locked_until is not None
    assert login(client).status_code == 401


def test_password_change_blocks_a_login_that_already_verified_the_old_password(client, app, tokens):
    login_verified = Event()
    password_changed = Event()

    def delay_admission(_conn, _cursor, statement, _parameters, _context, _executemany):
        if statement.startswith("UPDATE auth_users SET failed_login_attempts"):
            login_verified.set()
            assert password_changed.wait(timeout=10)

    engine = app.state.database.engine
    event.listen(engine, "before_cursor_execute", delay_admission)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending_login = pool.submit(login, client)
            try:
                assert login_verified.wait(timeout=10)
                changed = client.post(
                    "/api/v1/auth/change-password",
                    headers=bearer(tokens),
                    json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
                )
                assert changed.status_code == 204
            finally:
                password_changed.set()
            assert pending_login.result(timeout=10).status_code == 401
    finally:
        event.remove(engine, "before_cursor_execute", delay_admission)
    assert login(client, password=NEW_PASSWORD).status_code == 200
