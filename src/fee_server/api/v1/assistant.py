"""Ruta del asistente de higiene de privacidad (chat por streaming).

Sin persistencia: el cliente reenvía el historial de la conversación actual en
cada petición; el servidor antepone su `system prompt` fijo y transmite la
respuesta por SSE a medida que el proveedor la genera. Ver
`docs/osint-architecture.md`.
"""

import logging
from collections.abc import AsyncIterator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from fee_server.api.dependencies import AssistantServiceDep, CurrentUserDep, SettingsDep
from fee_server.core.config import Settings
from fee_server.core.rate_limit import limiter
from fee_server.core.sse import format_event
from fee_server.domain.assistant.gateway import build_gateway
from fee_server.domain.assistant.schemas import ChatRequest

router = APIRouter(prefix="/assistant", tags=["assistant"])
logger = logging.getLogger("fee_server.assistant")


@router.post("/chat")
@limiter.limit("15/minute")
def chat(
    request: Request,
    body: ChatRequest,
    user: CurrentUserDep,
    service: AssistantServiceDep,
    settings: SettingsDep,
) -> StreamingResponse:
    # Validación antes de abrir el stream: si falla, se devuelve un error RFC
    # 7807 normal en vez de un evento `error` a mitad de una respuesta 200.
    service.validate(body)
    messages = service.build_messages(body)
    return StreamingResponse(
        _stream(messages, settings),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store"},
    )


async def _stream(messages: list[dict[str, str]], settings: Settings) -> AsyncIterator[str]:
    gateway = build_gateway(settings)
    try:
        async for chunk in gateway.stream_reply(messages):
            yield format_event("token", {"content": chunk})
    except Exception:  # noqa: BLE001 - el proveedor ya empezó a responder (200)
        logger.exception("assistant: el proveedor falló durante el streaming")
        yield format_event("error", {"detail": "assistant-unavailable"})
        return
    yield format_event("done", {})
