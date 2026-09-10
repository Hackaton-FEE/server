import pytest
from pydantic import ValidationError

from fee_server.core.config import DEV_INSECURE_JWT_SECRET, Settings


def test_unknown_environment_fails_at_startup(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "prodution")

    with pytest.raises(ValidationError, match="environment"):
        Settings()


def test_defaults_are_usable_for_local_development():
    settings = Settings()

    assert settings.database_url.startswith("sqlite")
    assert settings.challenge_ttl_seconds == 120
    assert settings.docs_enabled is True


def test_short_jwt_secret_is_rejected(monkeypatch):
    monkeypatch.setenv("FEE_JWT_SECRET", "too-short")

    with pytest.raises(ValidationError, match="JWT_SECRET"):
        Settings()


def test_production_refuses_the_insecure_default_secret(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "production")
    monkeypatch.setenv("FEE_JWT_SECRET", DEV_INSECURE_JWT_SECRET)

    with pytest.raises(ValidationError, match="producción"):
        Settings()


def test_osint_defaults_to_simulated_engines():
    settings = Settings()

    assert settings.osint_engine_mode == "fake"
    assert settings.osint_uses_real_engines is False


def test_osint_real_mode_is_disabled_under_test_environment(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "test")
    monkeypatch.setenv("FEE_OSINT_ENGINE_MODE", "real")

    assert Settings().osint_uses_real_engines is False


def test_production_accepts_a_real_secret(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "production")
    monkeypatch.setenv("FEE_JWT_SECRET", "a-proper-production-secret-value-32chars")

    settings = Settings()

    assert settings.environment == "production"
    assert settings.docs_enabled is False


def test_assistant_defaults_to_simulated_gateway():
    settings = Settings()

    assert settings.assistant_mode == "fake"
    assert settings.assistant_uses_real_gateway is False


def test_assistant_real_mode_is_disabled_under_test_environment(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "test")
    monkeypatch.setenv("FEE_ASSISTANT_MODE", "real")

    assert Settings().assistant_uses_real_gateway is False


def test_production_refuses_real_assistant_without_an_api_key(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "production")
    monkeypatch.setenv("FEE_JWT_SECRET", "a-proper-production-secret-value-32chars")
    monkeypatch.setenv("FEE_ASSISTANT_MODE", "real")

    with pytest.raises(ValidationError, match="ASSISTANT_API_KEY"):
        Settings()


def test_production_accepts_real_assistant_with_an_api_key(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "production")
    monkeypatch.setenv("FEE_JWT_SECRET", "a-proper-production-secret-value-32chars")
    monkeypatch.setenv("FEE_ASSISTANT_MODE", "real")
    monkeypatch.setenv("FEE_ASSISTANT_API_KEY", "nvapi-test-key")

    settings = Settings()

    assert settings.assistant_uses_real_gateway is True
