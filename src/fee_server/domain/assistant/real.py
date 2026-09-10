"""Gateway real: proveedor compatible con la API de OpenAI (NVIDIA por defecto)."""

from collections.abc import AsyncIterator, Mapping

from openai import AsyncOpenAI

from fee_server.core.config import Settings


class NvidiaAssistantGateway:
    name = "nvidia"

    def __init__(self, settings: Settings) -> None:
        self._client = AsyncOpenAI(
            base_url=settings.assistant_base_url,
            api_key=settings.assistant_api_key,
            timeout=settings.assistant_timeout_seconds,
        )
        self._model = settings.assistant_model
        self._max_output_tokens = settings.assistant_max_output_tokens

    async def stream_reply(self, messages: list[Mapping[str, str]]) -> AsyncIterator[str]:
        stream = await self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            temperature=1,
            top_p=0.95,
            max_tokens=self._max_output_tokens,
            stream=True,
        )
        async for chunk in stream:
            delta = chunk.choices[0].delta.content
            if delta:
                yield delta
