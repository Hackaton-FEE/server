"""Validación de la conversación y construcción de los mensajes a enviar."""

from fee_server.core.config import Settings
from fee_server.core.problem import InvalidConversationError
from fee_server.domain.assistant.prompts import SYSTEM_PROMPT
from fee_server.domain.assistant.schemas import ChatRequest


class AssistantService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def validate(self, request: ChatRequest) -> None:
        if len(request.messages) > self._settings.assistant_max_messages:
            raise InvalidConversationError()
        if request.messages[-1].role != "user":
            raise InvalidConversationError()
        max_chars = self._settings.assistant_max_message_chars
        if any(len(message.content) > max_chars for message in request.messages):
            raise InvalidConversationError()

    def build_messages(self, request: ChatRequest) -> list[dict[str, str]]:
        """Antepone el `system prompt` fijo; el cliente no puede sustituirlo."""
        history = [{"role": m.role, "content": m.content} for m in request.messages]
        return [{"role": "system", "content": SYSTEM_PROMPT}, *history]
