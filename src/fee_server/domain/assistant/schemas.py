"""Modelos de petición del chat del asistente."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Solo `user`/`assistant`: el cliente nunca puede enviar un rol `system` y
    # así sustituir la persona fija del asistente.
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Cotas de tamaño (nº de mensajes, caracteres por mensaje) las aplica
    # `AssistantService.validate` según `Settings` — configurables por entorno.
    messages: list[ChatMessage] = Field(min_length=1)
