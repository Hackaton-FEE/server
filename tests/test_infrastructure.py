from collections import deque

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.engine import Engine

from fee_server.core.config import Settings
from fee_server.core.database import Base
from fee_server.core.http import PrivateAPIHeadersMiddleware
from fee_server.main import create_app

TEST_SECRET = "infrastructure-test-only-0123456789-abcdefghijklmnopqrstuvwxyz"
POSTGRES_URL = "postgresql+psycopg://unused:unused@localhost/unused"


@pytest.mark.parametrize("secret", [None, "short-secret", "x" * 64])
def test_production_rejects_missing_or_weak_signing_secret(secret):
    with pytest.raises(ValidationError, match="auth_secret_key"):
        Settings(
            environment="production",
            database_url=POSTGRES_URL,
            auth_secret_key=secret,
        )


def test_production_requires_postgresql():
    with pytest.raises(ValidationError, match="production requires PostgreSQL"):
        Settings(
            environment="production",
            database_url="sqlite:///:memory:",
            auth_secret_key=TEST_SECRET,
        )


@pytest.mark.parametrize("url", ["not-a-database-url", "mysql://localhost/fee"])
def test_invalid_or_unsupported_database_url_is_rejected(url):
    with pytest.raises(ValidationError, match="database_url"):
        Settings(environment="test", database_url=url)


def test_production_accepts_explicit_secret_database_and_https_origin():
    settings = Settings(
        environment="production",
        database_url=POSTGRES_URL,
        auth_secret_key=TEST_SECRET,
        cors_origins=["https://app.example.com"],
    )

    assert settings.docs_enabled is False
    assert TEST_SECRET not in repr(settings)
    assert POSTGRES_URL not in repr(settings)


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "https://*.example.com",
        "https://example.com:bad",
        "https://example.com/path",
        "https://example.com?token=private",
        "https://user:password@example.com",
    ],
)
def test_cors_configuration_requires_exact_valid_origins(origin):
    with pytest.raises(ValidationError, match="cors_origins"):
        Settings(environment="test", cors_origins=[origin])


def test_production_cors_requires_https():
    with pytest.raises(ValidationError, match="cors_origins"):
        Settings(
            environment="production",
            database_url=POSTGRES_URL,
            auth_secret_key=TEST_SECRET,
            cors_origins=["http://app.example.com"],
        )


def test_cors_allows_only_the_configured_origin(settings):
    application = create_app(
        settings.model_copy(update={"cors_origins": ["https://app.example.com"]})
    )
    with TestClient(application) as client:
        allowed = client.options(
            "/api/v1/auth/login",
            headers={
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )
        denied = client.options(
            "/api/v1/auth/login",
            headers={
                "Origin": "https://app.example.com.attacker.example",
                "Access-Control-Request-Method": "POST",
            },
        )

    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "https://app.example.com"
    assert "access-control-allow-credentials" not in allowed.headers
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers


def test_factory_and_health_do_not_connect_to_or_initialize_database(monkeypatch, tmp_path):
    database_path = tmp_path / "not-initialized.db"

    def reject_database_connection(*_args, **_kwargs):
        pytest.fail("Application construction and liveness must not connect to the database")

    monkeypatch.setattr(Engine, "connect", reject_database_connection)
    application = create_app(
        Settings(
            environment="test",
            database_url=f"sqlite:///{database_path}",
            auth_secret_key=TEST_SECRET,
        )
    )
    with TestClient(application) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert not database_path.exists()


@pytest.mark.parametrize("password", ["short-key", {"value": "private-password-value"}])
def test_validation_errors_do_not_echo_password_or_email(client, password):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "private-person@example.com", "password": password},
    )

    assert response.status_code == 422
    assert "private-person@example.com" not in response.text
    assert "short-key" not in response.text
    assert "private-password-value" not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert all(set(error) == {"loc", "type", "msg"} for error in response.json()["detail"])


def test_malformed_json_does_not_echo_request_body(client):
    response = client.post(
        "/api/v1/auth/login",
        content='{"password":"private-password-value",',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert "private-password-value" not in response.text


def test_body_limit_uses_actual_bytes_and_does_not_echo_sensitive_input(client, settings):
    response = client.post(
        "/api/v1/auth/register",
        content=b"private-password-value" + b"x" * settings.max_request_body_bytes,
        headers={"Content-Type": "application/json", "Content-Length": "1"},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "request_too_large"
    assert "private-password-value" not in response.text
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_chunked_body_limit_rejects_before_the_endpoint_runs():
    messages = deque(
        [
            {"type": "http.request", "body": b"x" * 800, "more_body": True},
            {"type": "http.request", "body": b"y" * 800, "more_body": False},
        ]
    )
    sent = []

    async def endpoint(_scope, _receive, _send):
        pytest.fail("An oversized chunked request must not reach the endpoint")

    async def receive():
        return messages.popleft()

    async def send(message):
        sent.append(message)

    middleware = PrivateAPIHeadersMiddleware(endpoint, max_body_bytes=1024)
    await middleware(
        {"type": "http", "method": "POST", "path": "/api/v1/auth/register", "headers": []},
        receive,
        send,
    )

    assert sent[0]["status"] == 413
    assert (b"cache-control", b"no-store") in sent[0]["headers"]


def test_auth_storage_failure_is_generic_and_does_not_initialize_tables(settings):
    application = create_app(settings)
    with TestClient(application) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "private-person@example.com", "password": "private-password-value"},
        )

    assert response.status_code == 503
    assert response.json() == {
        "detail": {"code": "storage_unavailable", "message": "Storage unavailable"}
    }
    assert "private-person@example.com" not in response.text
    assert "private-password-value" not in response.text
    assert "cache-control" in response.headers


def test_auth_rate_limit_is_shared_by_apps_and_cannot_be_reset_by_forwarded_headers(
    settings, monkeypatch
):
    monkeypatch.setattr("fee_server.core.rate_limit.time.time", lambda: 1_700_000_000)
    limited_settings = settings.model_copy(update={"auth_request_limit": 2})
    first_app = create_app(limited_settings)
    second_app = create_app(limited_settings)
    Base.metadata.create_all(first_app.state.database.engine)

    with TestClient(first_app) as first, TestClient(second_app) as second:
        initial = first.post(
            "/api/v1/auth/login", json={}, headers={"X-Forwarded-For": "192.0.2.1"}
        )
        next_request = second.post(
            "/api/v1/auth/login", json={}, headers={"X-Forwarded-For": "192.0.2.2"}
        )
        limited = first.post(
            "/api/v1/auth/login", json={}, headers={"X-Forwarded-For": "192.0.2.3"}
        )

        assert initial.status_code == 422
        assert next_request.status_code == 422
        assert limited.status_code == 429
        assert limited.json()["detail"]["code"] == "rate_limited"
        assert 1 <= int(limited.headers["retry-after"]) <= settings.auth_request_window_seconds
        assert first.get("/api/v1/health").status_code == 200

        with TestClient(second_app, client=("192.0.2.4", 50000)) as other_peer:
            assert other_peer.post("/api/v1/auth/login", json={}).status_code == 422

        monkeypatch.setattr("fee_server.core.rate_limit.time.time", lambda: 1_700_000_060)
        assert first.post("/api/v1/auth/login", json={}).status_code == 422
