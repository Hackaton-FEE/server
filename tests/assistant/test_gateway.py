"""Selección de gateway simulado/real según `Settings`."""

from fee_server.core.config import Settings
from fee_server.domain.assistant.fake import FakeAssistantGateway
from fee_server.domain.assistant.gateway import build_gateway
from fee_server.domain.assistant.real import NvidiaAssistantGateway


def test_build_gateway_uses_the_fake_gateway_by_default():
    gateway = build_gateway(Settings(environment="test"))

    assert isinstance(gateway, FakeAssistantGateway)


def test_build_gateway_returns_the_real_gateway_in_real_mode():
    settings = Settings(
        environment="development",
        jwt_secret="a-proper-production-secret-value-32chars",
        assistant_mode="real",
        assistant_api_key="nvapi-test-key",
    )

    gateway = build_gateway(settings)

    assert isinstance(gateway, NvidiaAssistantGateway)
