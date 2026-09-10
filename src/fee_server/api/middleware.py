"""Middlewares pequeños de seguridad para el transporte HTTP."""

from starlette.types import ASGIApp, Message, Receive, Scope, Send


class MaxBodySizeMiddleware:
    """Rechaza cuerpos mayores a `max_bytes` (por `Content-Length` o al leer).

    Los payloads WebAuthn son de unos pocos KB; un cuerpo grande solo sirve para
    forzar trabajo criptográfico o de parseo.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self._app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        content_length = _header(scope, b"content-length")
        if content_length and content_length.isdigit() and int(content_length) > self._max_bytes:
            await _reject(send)
            return

        received = 0

        async def guarded_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self._max_bytes:
                    return {"type": "http.disconnect"}
            return message

        await self._app(scope, guarded_receive, send)


_NO_STORE_PREFIXES = ("/api/v1/auth", "/api/v1/osint")


class SecurityHeadersMiddleware:
    """Añade cabeceras defensivas; `no-store` en respuestas con datos sensibles."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        is_sensitive = scope["path"].startswith(_NO_STORE_PREFIXES)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                headers.append((b"x-content-type-options", b"nosniff"))
                headers.append((b"referrer-policy", b"no-referrer"))
                if is_sensitive:
                    headers.append((b"cache-control", b"no-store"))
            await send(message)

        await self._app(scope, receive, send_with_headers)


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return value.decode("latin-1")
    return None


async def _reject(send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/problem+json")],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": b'{"type":"https://api.fee.local/errors/payload-too-large",'
            b'"title":"Payload Too Large","status":413,'
            b'"detail":"La petici\\u00f3n excede el tama\\u00f1o permitido."}',
        }
    )
