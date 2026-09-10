"""Puertos de los motores OSINT y su implementación simulada.

Fase inicial: solo motores `Fake*` con salidas deterministas derivadas de la
entrada. No tocan la red. Los adaptadores reales (subprocess a las herramientas
vendorizadas) llegan en una fase posterior y se ubicarán en `engines/`.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

from fee_server.core.config import Settings
from fee_server.domain.osint.findings import (
    CONFIRMED,
    POTENTIAL_MATCH,
    RATE_LIMITED,
    Finding,
)

# Estado de ejecución de un motor dentro de un escaneo.
ENGINE_OK = "ok"
ENGINE_DEGRADED = "degraded"
ENGINE_ERROR = "error"
ENGINE_SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class EngineRequest:
    usernames: tuple[str, ...]
    email: str | None = None


@dataclass(frozen=True, slots=True)
class EngineResult:
    engine: str
    status: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    error_category: str | None = None


class Engine(Protocol):
    name: str

    def run(self, request: EngineRequest) -> EngineResult: ...


class _FakeUsernameEngine:
    """Base de los motores simulados que parten de un username."""

    name = "fake"

    def _findings_for(self, username: str) -> Iterable[Finding]:  # pragma: no cover
        raise NotImplementedError

    def run(self, request: EngineRequest) -> EngineResult:
        if not request.usernames:
            return EngineResult(self.name, ENGINE_SKIPPED)
        findings: list[Finding] = []
        for username in request.usernames:
            findings.extend(self._findings_for(username))
        return EngineResult(self.name, ENGINE_OK, tuple(findings))


class FakeBlackbird(_FakeUsernameEngine):
    name = "blackbird"

    def _findings_for(self, username: str) -> Iterable[Finding]:
        return (
            Finding(
                platform="GitHub",
                category="coding",
                url=f"https://github.com/{username}",
                username=username,
                status=CONFIRMED,
                confidence=80,
                sources=("blackbird",),
                details={},
            ),
            Finding(
                platform="Reddit",
                category="social",
                url=f"https://www.reddit.com/user/{username}",
                username=username,
                status=CONFIRMED,
                confidence=80,
                sources=("blackbird",),
                details={},
            ),
            Finding(
                platform="SoundCloud",
                category="music",
                url=f"https://soundcloud.com/{username}",
                username=username,
                status=CONFIRMED,
                confidence=90,
                sources=("blackbird",),
                details={"avatar_url": f"https://cdn.example/{username}.png"},
            ),
        )


class FakeMaigret(_FakeUsernameEngine):
    name = "maigret"

    def _findings_for(self, username: str) -> Iterable[Finding]:
        return (
            Finding(
                platform="GitHub",
                category="coding",
                url=f"https://github.com/{username}",
                username=username,
                status=CONFIRMED,
                confidence=95,
                sources=("maigret",),
                details={
                    "account_id": "1024025",
                    "full_name": "Perfil De Prueba",
                    "creation_date": "2011-09-03T15:26:22Z",
                    "location": "Portland, OR",
                    "followers": 321694,
                },
            ),
            Finding(
                platform="Wattpad",
                category="social",
                url=f"https://www.wattpad.com/user/{username}",
                username=username,
                status=POTENTIAL_MATCH,
                confidence=50,
                sources=("maigret",),
                details={},
            ),
        )


class FakeHolehe:
    name = "holehe"

    def run(self, request: EngineRequest) -> EngineResult:
        if not request.email:
            return EngineResult(self.name, ENGINE_SKIPPED)
        findings = (
            Finding(
                platform="Adobe",
                category="other",
                url=None,
                username=None,
                status=CONFIRMED,
                confidence=75,
                sources=("holehe",),
                details={"masked_email": "j***@e***.com"},
            ),
            Finding(
                platform="Spotify",
                category="music",
                url=None,
                username=None,
                status=RATE_LIMITED,
                confidence=0,
                sources=("holehe",),
                details={},
            ),
        )
        return EngineResult(self.name, ENGINE_DEGRADED, findings)


def build_engines(settings: Settings) -> tuple[Engine, ...]:
    """Cascada de motores en orden: rápido, profundo, vector correo."""
    if settings.osint_uses_real_engines:
        raise NotImplementedError(
            "Los motores reales se implementan en una fase posterior; "
            "usa FEE_OSINT_ENGINE_MODE=fake"
        )
    return (FakeBlackbird(), FakeMaigret(), FakeHolehe())
