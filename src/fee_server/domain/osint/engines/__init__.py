"""Motores OSINT: puertos, motores simulados y adaptadores reales.

`build_engines` devuelve la cascada en orden (rápido → profundo → vector correo →
vector teléfono), simulada o real según `FEE_OSINT_ENGINE_MODE` (y siempre
simulada bajo `test`).
"""

from fee_server.core.config import Settings
from fee_server.domain.osint.engines.base import (
    ENGINE_DEGRADED,
    ENGINE_ERROR,
    ENGINE_OK,
    ENGINE_SKIPPED,
    Engine,
    EngineRequest,
    EngineResult,
)
from fee_server.domain.osint.engines.fake import (
    FakeBlackbird,
    FakeHolehe,
    FakeIgnorant,
    FakeMaigret,
)
from fee_server.domain.osint.engines.process import ToolExecutionError, ToolRun, run_tool
from fee_server.domain.osint.engines.real import (
    BlackbirdEngine,
    HoleheEngine,
    IgnorantEngine,
    MaigretEngine,
)

__all__ = [
    "ENGINE_DEGRADED",
    "ENGINE_ERROR",
    "ENGINE_OK",
    "ENGINE_SKIPPED",
    "BlackbirdEngine",
    "Engine",
    "EngineRequest",
    "EngineResult",
    "FakeBlackbird",
    "FakeHolehe",
    "FakeIgnorant",
    "FakeMaigret",
    "HoleheEngine",
    "IgnorantEngine",
    "MaigretEngine",
    "ToolExecutionError",
    "ToolRun",
    "build_engines",
    "run_tool",
]


def build_engines(settings: Settings) -> tuple[Engine, ...]:
    if settings.osint_uses_real_engines:
        return (
            BlackbirdEngine(settings),
            MaigretEngine(settings),
            HoleheEngine(settings),
            IgnorantEngine(settings),
        )
    return (FakeBlackbird(), FakeMaigret(), FakeHolehe(), FakeIgnorant())
