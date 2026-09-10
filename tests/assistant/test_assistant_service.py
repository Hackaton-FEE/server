"""AssistantService: validación de la conversación y construcción de mensajes."""

import pytest

from fee_server.core.config import Settings
from fee_server.core.problem import InvalidConversationError
from fee_server.domain.assistant.prompts import SYSTEM_PROMPT
from fee_server.domain.assistant.schemas import ChatMessage, ChatRequest
from fee_server.domain.assistant.service import AssistantService


def _service(**overrides) -> AssistantService:
    return AssistantService(Settings(environment="test", **overrides))


def _request(*pairs: tuple[str, str]) -> ChatRequest:
    return ChatRequest(messages=[ChatMessage(role=r, content=c) for r, c in pairs])


def test_valid_conversation_passes():
    _service().validate(_request(("user", "¿cómo reduzco mi huella digital?")))


def test_too_many_messages_is_rejected():
    request = _request(*[("user", "hola")] * 5)

    with pytest.raises(InvalidConversationError):
        _service(assistant_max_messages=4).validate(request)


def test_message_too_long_is_rejected():
    request = _request(("user", "x" * 100))

    with pytest.raises(InvalidConversationError):
        _service(assistant_max_message_chars=10).validate(request)


def test_last_message_must_be_from_the_user():
    request = _request(("user", "hola"), ("assistant", "hola, ¿en qué ayudo?"))

    with pytest.raises(InvalidConversationError):
        _service().validate(request)


def test_build_messages_prepends_the_fixed_system_prompt():
    request = _request(("user", "hola"))

    messages = _service().build_messages(request)

    assert messages[0] == {"role": "system", "content": SYSTEM_PROMPT}
    assert messages[1] == {"role": "user", "content": "hola"}
