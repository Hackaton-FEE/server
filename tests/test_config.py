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


@pytest.mark.parametrize("limit", [-1, 11])
def test_pivot_candidate_limit_is_bounded(limit):
    with pytest.raises(ValidationError, match="osint_max_pivot_candidates"):
        Settings(osint_max_pivot_candidates=limit)


def test_osint_real_mode_is_disabled_under_test_environment(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "test")
    monkeypatch.setenv("FEE_OSINT_ENGINE_MODE", "real")

    assert Settings().osint_uses_real_engines is False


def _minimal_production_env(monkeypatch) -> None:
    """Variables sin las que producción no arranca, más allá del JWT secret."""
    monkeypatch.setenv("FEE_RATE_LIMIT_ENABLED", "1")
    monkeypatch.setenv("FEE_VERIFICATION_STATIC_CODE", "")


def test_production_accepts_a_real_secret(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "production")
    monkeypatch.setenv("FEE_JWT_SECRET", "a-proper-production-secret-value-32chars")
    _minimal_production_env(monkeypatch)

    settings = Settings()

    assert settings.environment == "production"
    assert settings.docs_enabled is False


def test_production_refuses_to_start_without_rate_limiting(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "production")
    monkeypatch.setenv("FEE_JWT_SECRET", "a-proper-production-secret-value-32chars")
    monkeypatch.setenv("FEE_VERIFICATION_STATIC_CODE", "")

    with pytest.raises(ValidationError, match="RATE_LIMIT_ENABLED"):
        Settings()


def test_production_refuses_the_default_static_verification_code(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "production")
    monkeypatch.setenv("FEE_JWT_SECRET", "a-proper-production-secret-value-32chars")
    monkeypatch.setenv("FEE_RATE_LIMIT_ENABLED", "1")

    with pytest.raises(ValidationError, match="VERIFICATION_STATIC_CODE"):
        Settings()


def test_production_accepts_an_empty_static_verification_code(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "production")
    monkeypatch.setenv("FEE_JWT_SECRET", "a-proper-production-secret-value-32chars")
    monkeypatch.setenv("FEE_RATE_LIMIT_ENABLED", "1")
    monkeypatch.setenv("FEE_VERIFICATION_STATIC_CODE", "")

    assert Settings().verification_static_code == ""


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
    _minimal_production_env(monkeypatch)

    with pytest.raises(ValidationError, match="ASSISTANT_API_KEY"):
        Settings()


def test_production_accepts_real_assistant_with_an_api_key(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "production")
    monkeypatch.setenv("FEE_JWT_SECRET", "a-proper-production-secret-value-32chars")
    monkeypatch.setenv("FEE_ASSISTANT_MODE", "real")
    monkeypatch.setenv("FEE_ASSISTANT_API_KEY", "nvapi-test-key")
    _minimal_production_env(monkeypatch)

    settings = Settings()

    assert settings.assistant_uses_real_gateway is True
    assert settings.assistant_api_key.get_secret_value() == "nvapi-test-key"
    assert "nvapi-test-key" not in repr(settings)


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


def test_differentiated_proxies_fallback_and_effective_values(monkeypatch):
    legacy = "http://legacy-user:legacy-pass@proxy.example:7000"
    res = "http://res-user:res-pass@residential.example:7000"
    norm = "http://norm-user:norm-pass@datacenter.example:8080"

    # Caso 1: Solo legacy
    monkeypatch.setenv("FEE_OSINT_PROXY_URL", legacy)
    monkeypatch.delenv("FEE_OSINT_RESIDENTIAL_PROXY_URL", raising=False)
    monkeypatch.delenv("FEE_OSINT_NORMAL_PROXY_URL", raising=False)
    s1 = Settings()
    assert s1.effective_osint_residential_proxy == legacy
    assert s1.effective_osint_normal_proxy == ""

    # Caso 2: Residencial explícito tiene prioridad sobre legacy
    monkeypatch.setenv("FEE_OSINT_RESIDENTIAL_PROXY_URL", res)
    monkeypatch.setenv("FEE_OSINT_NORMAL_PROXY_URL", norm)
    s2 = Settings()
    assert s2.effective_osint_residential_proxy == res
    assert s2.effective_osint_normal_proxy == norm
    assert "res-pass" not in repr(s2)
    assert "norm-pass" not in repr(s2)

