"""Authenticated discovery metadata; execution is not an HTTP contract yet."""

from fastapi import APIRouter, Request

from fee_server.modules.auth.dependencies import CurrentActor
from fee_server.modules.scans.models import CapabilitiesResponse
from fee_server.modules.scans.registry import ScanRegistry

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get(
    "/capabilities",
    response_model=CapabilitiesResponse,
    responses={401: {"description": "A valid, active session is required"}},
)
def get_capabilities(request: Request, actor: CurrentActor) -> CapabilitiesResponse:
    registry: ScanRegistry = request.app.state.scan_registry
    return CapabilitiesResponse(providers=registry.catalog())
