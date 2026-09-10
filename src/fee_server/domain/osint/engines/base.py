"""Puertos de los motores OSINT: contrato común, sin lógica de red."""

from dataclasses import dataclass, field
from typing import Protocol

from fee_server.domain.osint.findings import Finding

# Estado de ejecución de un motor dentro de un escaneo.
ENGINE_OK = "ok"
ENGINE_DEGRADED = "degraded"
ENGINE_ERROR = "error"
ENGINE_SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class EngineRequest:
    usernames: tuple[str, ...]
    email: str | None = None
    phone: str | None = None


@dataclass(frozen=True, slots=True)
class EngineResult:
    engine: str
    status: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    error_category: str | None = None


class Engine(Protocol):
    name: str

    def run(self, request: EngineRequest) -> EngineResult: ...
