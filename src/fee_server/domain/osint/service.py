"""Casos de uso del módulo OSINT, aislados del transporte HTTP."""

import hashlib
from datetime import timedelta

from sqlalchemy.orm import Session

from fee_server.core.config import Settings
from fee_server.core.problem import (
    ConsentRequiredError,
    InvalidIdentifierError,
    ScanNotFoundError,
    ScanNotReadyError,
    UnsupportedTargetTypeError,
)
from fee_server.db.models import OsintScan, User
from fee_server.domain.osint import repository
from fee_server.domain.osint.catalog import is_valid_identifier
from fee_server.domain.osint.engines import EngineRequest
from fee_server.domain.osint.findings import Finding
from fee_server.domain.osint.schemas import (
    TARGET_TYPES,
    DashboardResult,
    ScanRequest,
    ScanStatusResponse,
)
from fee_server.domain.osint.scoring import build_dashboard
from fee_server.util.time import utcnow

_TERMINAL = frozenset({"COMPLETED", "FAILED", "EXPIRED"})
_HINT_CHARS = 4


def _hint(identifier: str) -> str:
    head = identifier[:_HINT_CHARS]
    return f"{head}…" if len(identifier) > _HINT_CHARS else head


def _digest(identifier: str) -> str:
    return hashlib.sha256(identifier.encode("utf-8")).hexdigest()


class ScanService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # --- creación ---------------------------------------------------------

    def create_scan(self, request: ScanRequest, user: User) -> tuple[OsintScan, EngineRequest]:
        self._validate(request)

        scan = OsintScan(
            user_id=user.id,
            target_type=request.target_type,
            identifier_hint=_hint(request.identifier),
            identifier_sha256=_digest(request.identifier),
            consent_at=utcnow(),
            status="QUEUED",
            progress=0,
            engines={},
            expires_at=utcnow() + timedelta(days=self._settings.osint_retention_days),
        )
        repository.add_scan(self._session, scan)
        # Commit explícito: la tarea de fondo abre su propia sesión y necesita
        # ver el escaneo ya persistido.
        self._session.commit()
        return scan, self._engine_request(request)

    def _validate(self, request: ScanRequest) -> None:
        if request.target_type not in TARGET_TYPES:
            raise UnsupportedTargetTypeError()
        if not request.consent_self_audit:
            raise ConsentRequiredError()
        if not is_valid_identifier(request.target_type, request.identifier):
            raise InvalidIdentifierError()
        for username in request.associated_usernames:
            if not is_valid_identifier("username", username):
                raise InvalidIdentifierError()
        if request.associated_email and not is_valid_identifier("email", request.associated_email):
            raise InvalidIdentifierError()

    def _engine_request(self, request: ScanRequest) -> EngineRequest:
        usernames: list[str] = list(request.associated_usernames)
        email = request.associated_email
        if request.target_type == "username":
            usernames.insert(0, request.identifier)
        else:
            email = request.identifier
        # Sin duplicados, preservando el orden.
        ordered = tuple(dict.fromkeys(usernames))
        return EngineRequest(usernames=ordered, email=email)

    # --- consulta --------------------------------------------------------

    def owned_scan(self, scan_id: str, user: User) -> OsintScan:
        scan = repository.get_owned_scan(self._session, scan_id, user.id)
        if scan is None:
            raise ScanNotFoundError()
        return scan

    def build_status(self, scan: OsintScan) -> ScanStatusResponse:
        engines = scan.engines or {}
        completed = [name for name, state in engines.items() if state.get("finished_at")]
        running = (
            [name for name in ("blackbird", "maigret", "holehe") if name not in completed]
            if scan.status == "RUNNING"
            else []
        )
        return ScanStatusResponse(
            scan_id=scan.id,
            status=scan.status,
            progress_percentage=scan.progress,
            completed_engines=completed,
            running_engines=running,
            partial_findings_count=len(repository.list_findings(self._session, scan.id)),
        )

    def build_results(self, scan: OsintScan) -> DashboardResult:
        if scan.status == "QUEUED":
            raise ScanNotReadyError()

        rows = repository.list_findings(self._session, scan.id)
        findings = [
            Finding(
                platform=row.platform,
                category=row.category,
                url=row.url,
                username=row.username,
                status=row.status,
                confidence=row.confidence,
                sources=tuple(row.sources or ()),
                details=dict(row.details or {}),
            )
            for row in rows
        ]
        engines_run = [
            name for name, state in (scan.engines or {}).items() if state.get("finished_at")
        ]
        return build_dashboard(
            scan_id=scan.id,
            findings=findings,
            engines_run=engines_run,
            score=scan.exposure_score or 0,
            partial=scan.status not in _TERMINAL,
        )

    # --- borrado y limpieza --------------------------------------------

    def delete_scan(self, scan_id: str, user: User) -> None:
        scan = repository.get_owned_scan(self._session, scan_id, user.id)
        if scan is not None:
            repository.delete_scan(self._session, scan)

    def purge_expired(self) -> int:
        return repository.purge_expired(self._session)
