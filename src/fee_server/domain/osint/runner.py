"""Orquestación de la cascada de motores para un escaneo.

Ejecución secuencial de los motores desde una tarea de fondo de FastAPI. El
contrato HTTP (202 + polling) es el mismo que tendría un worker externo; ver
ADR-OSINT-01 en `docs/osint-architecture.md`. Los motores son simulados o reales
según `FEE_OSINT_ENGINE_MODE`; un motor que falla no aborta el escaneo.
"""

import logging

from fee_server.core.config import Settings
from fee_server.db.models import OsintScan
from fee_server.db.session import session_scope
from fee_server.domain.osint import repository
from fee_server.domain.osint.correlation import correlate
from fee_server.domain.osint.engines import (
    ENGINE_ERROR,
    EngineRequest,
    build_engines,
)
from fee_server.domain.osint.normalize import merge_findings
from fee_server.domain.osint.scoring import exposure_score, risk_level
from fee_server.util.time import utcnow

logger = logging.getLogger("fee_server.osint")

TERMINAL_STATUSES = frozenset({"COMPLETED", "FAILED", "EXPIRED"})


def run_scan(*, scan_id: str, engine_request: EngineRequest, settings: Settings) -> None:
    """Ejecuta la cascada y persiste el resultado. No propaga excepciones."""
    try:
        engines = build_engines(settings)
    except Exception:  # noqa: BLE001 - sin motores no hay escaneo posible
        logger.exception("osint scan %s: no se pudieron construir los motores", scan_id)
        _fail(scan_id, "engines-unavailable")
        return

    if not _mark_running(scan_id):
        return

    all_findings: list = []
    engine_state: dict[str, dict] = {}
    step = 90 // max(len(engines), 1)

    for index, engine in enumerate(engines, start=1):
        started = utcnow().isoformat()
        try:
            result = engine.run(engine_request)
            engine_state[engine.name] = {
                "status": result.status,
                "started_at": started,
                "finished_at": utcnow().isoformat(),
                "findings": len(result.findings),
            }
            all_findings.extend(result.findings)
        except Exception:  # noqa: BLE001 - un motor no puede tumbar el escaneo
            logger.exception("osint scan %s: motor %s falló", scan_id, engine.name)
            engine_state[engine.name] = {
                "status": ENGINE_ERROR,
                "started_at": started,
                "finished_at": utcnow().isoformat(),
                "error_category": "engine-exception",
            }
        _checkpoint(scan_id, progress=min(90, index * step), engines=engine_state)

    try:
        merged = merge_findings(all_findings)
        score = exposure_score(merged)
        correlation = correlate(merged, provided_email=engine_request.email).to_dict()
    except Exception:  # noqa: BLE001 - la normalización no debe dejar el escaneo colgado
        logger.exception("osint scan %s: fallo al consolidar resultados", scan_id)
        _fail(scan_id, "result-consolidation-failed")
        return
    _complete(scan_id, merged, score, engine_state, correlation)


def _mark_running(scan_id: str) -> bool:
    with session_scope() as session:
        scan = repository.get_scan(session, scan_id)
        if scan is None or scan.status != "QUEUED":
            return False
        scan.status = "RUNNING"
        return True


def _checkpoint(scan_id: str, *, progress: int, engines: dict) -> None:
    with session_scope() as session:
        scan = repository.get_scan(session, scan_id)
        if scan is None or scan.status in TERMINAL_STATUSES:
            return
        scan.progress = progress
        scan.engines = dict(engines)


def _complete(scan_id: str, findings: list, score: int, engines: dict, correlation: dict) -> None:
    with session_scope() as session:
        scan = repository.get_scan(session, scan_id)
        if scan is None or scan.status in TERMINAL_STATUSES:
            return
        repository.replace_findings(session, scan_id, findings)
        scan.status = "COMPLETED"
        scan.progress = 100
        scan.exposure_score = score
        scan.risk_level = risk_level(score)
        scan.engines = dict(engines)
        scan.correlation = correlation
        scan.completed_at = utcnow()


def _fail(scan_id: str, error_category: str) -> None:
    with session_scope() as session:
        scan: OsintScan | None = repository.get_scan(session, scan_id)
        if scan is None or scan.status in TERMINAL_STATUSES:
            return
        scan.status = "FAILED"
        scan.progress = 100
        scan.engines = {"error_category": error_category}
        scan.completed_at = utcnow()
