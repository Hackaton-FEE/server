"""Comprobación de vida del proceso; no comprueba servicios externos."""

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

from fee_server import __version__

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: Literal["fee-server"] = "fee-server"
    version: str = __version__


@router.get("/health", response_model=HealthResponse, summary="Estado del proceso")
async def get_health() -> HealthResponse:
    return HealthResponse()
