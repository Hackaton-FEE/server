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


def test_proxy_credentials_are_loaded_without_exposing_them(monkeypatch):
    proxy = "http://example-user:example-password@gate.decodo.com:7000"
    monkeypatch.setenv("FEE_OSINT_PROXY_URL", proxy)

    settings = Settings()

    assert settings.osint_proxy_url.get_secret_value() == proxy
    assert "example-password" not in repr(settings)
    assert "example-password" not in settings.model_dump_json()


@pytest.mark.parametrize(
    "proxy",
    [
        "https://example-user:example-password@proxy.example:7000",
        "socks5://example-user:example-password@proxy.example:7000",
        "http://example-user:example-password@proxy.example:99999",
        "http://example-user:example-password@proxy.example:7000/path",
        "http://example-user:example-password@proxy.example:7000?query=secret",
        "http://example-user:example-password@proxy.example:7000\n",
        "http://example-user@proxy.example:7000",
        "proxy.example:7000",
    ],
)
def test_invalid_proxy_fails_at_startup_without_exposing_credentials(proxy):
    with pytest.raises(ValidationError, match="FEE_OSINT_PROXY_URL") as error:
        Settings(osint_proxy_url=proxy)

    assert "example-password" not in str(error.value)


def test_proxy_can_be_disabled_or_use_ip_allowlisting():
    assert Settings(osint_proxy_url="").osint_proxy_url.get_secret_value() == ""
    proxy = "http://proxy.example:7000"
    assert Settings(osint_proxy_url=proxy).osint_proxy_url.get_secret_value() == proxy
