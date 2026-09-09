"""Request limits and error responses that do not echo personal information."""

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.types import ASGIApp, Message, Receive, Scope, Send


async def validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {"loc": error["loc"], "type": error["type"], "msg": error["msg"]}
                for error in exc.errors()
            ]
        },
    )


async def database_error(_request: Request, _exc: SQLAlchemyError) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": {"code": "storage_unavailable", "message": "Storage unavailable"}},
    )


class PrivateAPIHeadersMiddleware:
    """Bound bodies, including chunked requests, before JSON parsing/hashing."""

    def __init__(self, app: ASGIApp, max_body_bytes: int):
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def private_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).extend(
                    [(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff")]
                )
            await send(message)

        # Buffer a bounded body so downstream error handling cannot turn a size
        # failure into a parser error or begin hashing before the limit is known.
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > self.max_body_bytes:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": {"code": "request_too_large", "message": "Body too large"}},
                )
                await response(scope, receive, private_send)
                return
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        delivered = False

        async def bounded_receive() -> Message:
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": b"".join(chunks), "more_body": False}

        await self.app(scope, bounded_receive, private_send)
