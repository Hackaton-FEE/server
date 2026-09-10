"""Rutas del motor OSINT de huella digital.

Escaneo asíncrono de la propia identidad del usuario: `POST /scans` responde
`202` y encola el trabajo; el cliente sigue el avance por polling (`GET .../{id}`)
o por el stream SSE (`GET .../{id}/events`). Ver `docs/osint-architecture.md`.
"""

import asyncio
import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, BackgroundTasks, Request, Response, status
from fastapi.responses import StreamingResponse

from fee_server.api.dependencies import CurrentUserDep, OsintServiceDep, SettingsDep
from fee_server.core.rate_limit import limiter
from fee_server.db.models import OsintScan
from fee_server.db.session import session_scope
from fee_server.domain.osint import repository
from fee_server.domain.osint.runner import TERMINAL_STATUSES, run_scan
from fee_server.domain.osint.schemas import (
    DashboardResult,
    ScanAccepted,
    ScanRequest,
    ScanStatusResponse,
)

router = APIRouter(prefix="/osint", tags=["osint"])

_ESTIMATED_DURATION_SECONDS = 90
_SSE_POLL_SECONDS = 1.0
_SSE_MAX_POLLS = 300  # ~5 min de vida máxima del stream


def _base_path(scan_id: str) -> str:
    return f"/api/v1/osint/scans/{scan_id}"


@router.post("/scans", response_model=ScanAccepted, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/hour")
def create_scan(
    request: Request,
    body: ScanRequest,
    user: CurrentUserDep,
    service: OsintServiceDep,
    settings: SettingsDep,
    background: BackgroundTasks,
) -> ScanAccepted:
    scan, engine_request = service.create_scan(body, user)
    background.add_task(
        run_scan,
        scan_id=scan.id,
        engine_request=engine_request,
        settings=settings,
    )
    return ScanAccepted(
        scan_id=scan.id,
        status=scan.status,
        estimated_duration_seconds=_ESTIMATED_DURATION_SECONDS,
        polling_url=_base_path(scan.id),
        events_url=f"{_base_path(scan.id)}/events",
    )


@router.get("/scans/{scan_id}", response_model=ScanStatusResponse)
@limiter.limit("120/minute")
def get_scan_status(
    request: Request, scan_id: str, user: CurrentUserDep, service: OsintServiceDep
) -> ScanStatusResponse:
    scan = service.owned_scan(scan_id, user)
    return service.build_status(scan)


@router.get("/scans/{scan_id}/results", response_model=DashboardResult)
@limiter.limit("120/minute")
def get_scan_results(
    request: Request, scan_id: str, user: CurrentUserDep, service: OsintServiceDep
) -> DashboardResult:
    scan = service.owned_scan(scan_id, user)
    return service.build_results(scan)


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("60/minute")
def delete_scan(
    request: Request, scan_id: str, user: CurrentUserDep, service: OsintServiceDep
) -> Response:
    service.delete_scan(scan_id, user)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/scans/{scan_id}/events")
async def stream_scan_events(
    request: Request, scan_id: str, user: CurrentUserDep, service: OsintServiceDep
) -> StreamingResponse:
    # Comprobación de propiedad con la sesión de la petición (404 si no es suya).
    service.owned_scan(scan_id, user)
    return StreamingResponse(
        _event_stream(scan_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store"},
    )


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _snapshot(scan_id: str) -> dict | None:
    with session_scope() as session:
        scan: OsintScan | None = repository.get_scan(session, scan_id)
        if scan is None:
            return None
        return {
            "scan_id": scan.id,
            "status": scan.status,
            "progress_percentage": scan.progress,
            "findings_count": len(repository.list_findings(session, scan_id)),
        }


async def _event_stream(scan_id: str) -> AsyncIterator[str]:
    last: dict | None = None
    for _ in range(_SSE_MAX_POLLS):
        snapshot = _snapshot(scan_id)
        if snapshot is None:
            yield _sse("error", {"detail": "scan-not-found"})
            return
        if snapshot != last:
            yield _sse("progress", snapshot)
            last = snapshot
        if snapshot["status"] in TERMINAL_STATUSES:
            yield _sse("done", snapshot)
            return
        await asyncio.sleep(_SSE_POLL_SECONDS)
    yield _sse("error", {"detail": "stream-timeout"})
