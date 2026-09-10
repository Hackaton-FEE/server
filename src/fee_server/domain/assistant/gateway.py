"""Puerto del proveedor de LLM: contrato común, sin detalle de transporte."""

from collections.abc import AsyncIterator, Mapping
from typing import Protocol

from fee_server.core.config import Settings
from fee_server.domain.assistant.fake import FakeAssistantGateway
from fee_server.domain.assistant.real import NvidiaAssistantGateway


class AssistantGateway(Protocol):
    def stream_reply(self, messages: list[Mapping[str, str]]) -> AsyncIterator[str]:
        """Cede fragmentos de texto de la respuesta a medida que llegan."""
        ...


def build_gateway(settings: Settings) -> AssistantGateway:
    if settings.assistant_uses_real_gateway:
        return NvidiaAssistantGateway(settings)
    return FakeAssistantGateway()
