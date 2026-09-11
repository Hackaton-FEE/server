"""Orquestación de la cascada de motores para un escaneo, con pivoteo.

Ejecución secuencial de los motores desde una tarea de fondo de FastAPI. El
contrato HTTP (202 + polling) es el mismo que tendría un worker externo; ver
ADR-OSINT-01 en `docs/osint-architecture.md`. Los motores son simulados o reales
según `FEE_OSINT_ENGINE_MODE`; un motor que falla no aborta el escaneo.

Dos fases, sin recursión encadenada (§8): la Fase 1 corre los 4 motores sobre
el identificador original; si alguno descubrió alias relacionados
(`linked_usernames`), una Fase 2 acotada vuelve a correr los motores basados
en username sobre esos candidatos. Los hallazgos de la Fase 2 nunca se
inspeccionan para sacar más candidatos — no hay un tercer bucle que alguien
pueda añadir por accidente; la profundidad 1 está en la forma del código, no
en un contador que se pueda subir sin querer.
"""

import logging
from threading import Condition

from fee_server.core.config import Settings
from fee_server.db.models import OsintScan
from fee_server.db.session import session_scope
from fee_server.domain.osint import repository
from fee_server.domain.osint.correlation import build_identity_graph, correlate
from fee_server.domain.osint.engines import (
    ENGINE_ERROR,
    Engine,
    EngineRequest,
    build_engines,
)
from fee_server.domain.osint.findings import Finding
from fee_server.domain.osint.noise import demote_unlinked_common_usernames
from fee_server.domain.osint.normalize import merge_findings
from fee_server.domain.osint.pivot import extract_pivot_candidates
from fee_server.domain.osint.scoring import exposure_score, risk_level
from fee_server.util.time import utcnow

logger = logging.getLogger("fee_server.osint")

TERMINAL_STATUSES = frozenset({"COMPLETED", "FAILED", "EXPIRED"})

# Presupuesto de progreso: Fase 1 hasta 70, Fase 2 (si hay candidatos) de 70 a
# 95, consolidación final a 100. Sin candidatos se salta de 70 a 100.
_PHASE1_PROGRESS_BUDGET = 70
_PHASE2_PROGRESS_BUDGET = 25
# Solo estos motores buscan por username; Holehe/Ignorant son de correo/teléfono.
_USERNAME_ENGINE_NAMES = frozenset({"blackbird", "maigret"})


# La API desplegada usa un único worker. El cupo limita las tareas de fondo
# dentro del proceso; QUEUED espera sin lanzar herramientas ni gastar proxy.
_SCAN_SLOTS = Condition()
_active_scans = 0


def run_scan(*, scan_id: str, engine_request: EngineRequest, settings: Settings) -> None:
    global _active_scans
    with _SCAN_SLOTS:
        _SCAN_SLOTS.wait_for(lambda: _active_scans < settings.osint_max_concurrent_scans)
        _active_scans += 1
    try:
        _run_scan(scan_id=scan_id, engine_request=engine_request, settings=settings)
    finally:
        with _SCAN_SLOTS:
            _active_scans -= 1
            _SCAN_SLOTS.notify_all()


def _run_scan(*, scan_id: str, engine_request: EngineRequest, settings: Settings) -> None:
    """Ejecuta la cascada (con pivoteo) y persiste el resultado. No propaga excepciones."""
    try:
        engines = build_engines(settings)
    except Exception:  # noqa: BLE001 - sin motores no hay escaneo posible
        logger.exception("osint scan %s: no se pudieron construir los motores", scan_id)
        _fail(scan_id, "engines-unavailable")
        return

    if not _mark_running(scan_id):
        return

    all_findings: list[Finding] = []
    engine_state: dict[str, dict] = {}

    step1 = _PHASE1_PROGRESS_BUDGET // max(len(engines), 1)
    for index, engine in enumerate(engines, start=1):
        if not _is_active(scan_id):
            return
        all_findings.extend(_run_engine(scan_id, engine, engine_request, engine_state))
        progress = min(_PHASE1_PROGRESS_BUDGET, index * step1)
        _checkpoint(scan_id, progress=progress, engines=engine_state)

    candidates = _extract_candidates(scan_id, all_findings, engine_request, settings)
    if candidates:
        pivot_request = EngineRequest(usernames=candidates)
        pivot_engines = [e for e in engines if e.name in _USERNAME_ENGINE_NAMES]
        step2 = _PHASE2_PROGRESS_BUDGET // max(len(pivot_engines), 1)
        for index, engine in enumerate(pivot_engines, start=1):
            if not _is_active(scan_id):
                return
            all_findings.extend(_run_engine(scan_id, engine, pivot_request, engine_state))
            progress = _PHASE1_PROGRESS_BUDGET + min(_PHASE2_PROGRESS_BUDGET, index * step2)
            _checkpoint(scan_id, progress=progress, engines=engine_state)

    try:
        merged = merge_findings(all_findings)
        # Dos grafos con propósitos distintos, no un cálculo duplicado: este se
        # construye sobre el conjunto crudo (antes de degradar) para que un
        # hallazgo de ruido pueda salvarse si otra cuenta lo corrobora;
        # `correlate()` abajo recalcula el grafo sobre el conjunto ya limpio,
        # que es el que se persiste. No reusar este primer grafo para la
        # correlación final: seguiría incluyendo nodos que la degradación
        # dejó fuera de `CONFIRMED` (y por tanto fuera de `build_identity_graph`).
        graph = build_identity_graph(merged)
        merged = demote_unlinked_common_usernames(merged, graph)
        score = exposure_score(merged)
        correlation = correlate(merged, provided_email=engine_request.email).to_dict()
    except Exception:  # noqa: BLE001 - la normalización no debe dejar el escaneo colgado
        logger.exception("osint scan %s: fallo al consolidar resultados", scan_id)
        _fail(scan_id, "result-consolidation-failed")
        return
    _complete(scan_id, merged, score, engine_state, correlation)


def _run_engine(
    scan_id: str, engine: Engine, request: EngineRequest, engine_state: dict[str, dict]
) -> list[Finding]:
    """Corre un motor y actualiza `engine_state` in place. Nunca lanza."""
    started = utcnow().isoformat()
    try:
        result = engine.run(request)
        count = len(result.findings)
        _record_engine_result(
            engine_state,
            engine.name,
            result.status,
            started,
            count,
            error_category=result.error_category,
        )
        return list(result.findings)
    except Exception:  # noqa: BLE001 - un motor no puede tumbar el escaneo
        logger.exception("osint scan %s: motor %s falló", scan_id, engine.name)
        _record_engine_result(
            engine_state,
            engine.name,
            ENGINE_ERROR,
            started,
            0,
            error_category="engine-exception",
        )
        return []


def _record_engine_result(
    engine_state: dict[str, dict],
    name: str,
    status: str,
    started_at: str,
    findings_count: int,
    *,
    error_category: str | None = None,
) -> None:
    """Registra el resultado de un motor; si ya corrió antes (pivoteo), agrega.

    `scan.engines` conserva siempre las 4 claves canónicas — nunca se inventan
    pseudo-motores tipo `"blackbird_pivot"` — así el contrato de
    `ScanStatusResponse` no cambia de forma entre fases.
    """
    previous = engine_state.get(name)
    if previous:
        severity = {"skipped": 0, "ok": 1, "degraded": 2, "error": 3}
        if severity.get(previous["status"], 0) > severity.get(status, 0):
            status = previous["status"]
    total_findings = findings_count + int(previous["findings"]) if previous else findings_count
    entry: dict[str, object] = {
        "status": status,
        "started_at": previous["started_at"] if previous else started_at,
        "finished_at": utcnow().isoformat(),
        "findings": total_findings,
        "runs": int(previous.get("runs", 1)) + 1 if previous else 1,
    }
    if error_category:
        entry["error_category"] = error_category
    elif previous and previous.get("error_category"):
        entry["error_category"] = previous["error_category"]
    engine_state[name] = entry


def _extract_candidates(
    scan_id: str, findings: list[Finding], engine_request: EngineRequest, settings: Settings
) -> tuple[str, ...]:
    """Candidatos de pivoteo; un fallo aquí no debe tumbar el escaneo."""
    try:
        return extract_pivot_candidates(
            findings, engine_request.usernames, settings.osint_max_pivot_candidates
        )
    except Exception:  # noqa: BLE001 - sin candidatos, el escaneo sigue sin pivotear
        logger.exception("osint scan %s: fallo al extraer candidatos de pivoteo", scan_id)
        return ()


def _mark_running(scan_id: str) -> bool:
    with session_scope() as session:
        scan = repository.get_scan(session, scan_id)
        if scan is None or scan.status != "QUEUED":
            return False
        scan.status = "RUNNING"
        return True


def _is_active(scan_id: str) -> bool:
    with session_scope() as session:
        scan = repository.get_scan(session, scan_id)
        return scan is not None and scan.status == "RUNNING"


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
