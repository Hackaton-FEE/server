"""Gateway simulado: respuesta determinista, sin red.

Modo por defecto y forzado en `test` (ver `Settings.assistant_uses_real_gateway`).
"""

import asyncio
from collections.abc import AsyncIterator, Mapping

_REPLY_CHUNKS = (
    "Para reducir tu huella digital, ",
    "empieza por lo más expuesto: ",
    "revisa las cuentas con tu nombre real o ubicación visibles ",
    "y ponlas en privado o bórralas si ya no las usas.",
)


class FakeAssistantGateway:
    name = "fake"

    async def stream_reply(self, messages: list[Mapping[str, str]]) -> AsyncIterator[str]:
        for chunk in _REPLY_CHUNKS:
            await asyncio.sleep(0)
            yield chunk
