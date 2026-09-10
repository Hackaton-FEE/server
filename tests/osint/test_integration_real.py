"""Integración real de las tres herramientas: NO se ejecuta en CI.

Requiere haber corrido `vendor/osint/setup.sh` y luego:

    FEE_OSINT_INTEGRATION=1 uv run --frozen pytest tests/osint/test_integration_real.py

Hace peticiones de red reales a cientos de sitios y tarda ~1-2 minutos.
"""

import os

import pytest

from fee_server.core.config import Settings
from fee_server.domain.osint.engines import build_engines
from fee_server.domain.osint.engines.base import EngineRequest
from fee_server.domain.osint.normalize import merge_findings
from fee_server.domain.osint.scoring import exposure_score

pytestmark = pytest.mark.skipif(
    os.environ.get("FEE_OSINT_INTEGRATION") != "1",
    reason="integración real: define FEE_OSINT_INTEGRATION=1 tras vendor/osint/setup.sh",
)

_PUBLIC_ALIAS = "torvalds"


def _real_settings() -> Settings:
    return Settings(
        environment="development",
        jwt_secret="a-proper-production-secret-value-32chars",
        osint_engine_mode="real",
    )


def test_real_cascade_discovers_and_corroborates_a_public_alias():
    engines = build_engines(_real_settings())
    request = EngineRequest(usernames=(_PUBLIC_ALIAS,), email=None)

    statuses: dict[str, str] = {}
    all_findings = []
    for engine in engines:
        result = engine.run(request)
        statuses[engine.name] = result.status
        all_findings += list(result.findings)

    # Blackbird puede degradarse por rate-limit pero debe ejecutarse.
    assert statuses["blackbird"] in {"ok", "degraded"}
    assert statuses["maigret"] == "ok"
    # Holehe sin proxy residencial casi siempre queda "degraded".
    assert statuses["holehe"] in {"ok", "degraded", "skipped"}
    # Ignorant es el vector de teléfono: sin `phone` en la petición se omite.
    assert statuses["ignorant"] == "skipped"

    merged = merge_findings(all_findings)
    assert len(merged) > 20

    corroborated = [f for f in merged if len(f.sources) >= 2]
    assert corroborated, "la deduplicación entre motores no cruzó ningún hallazgo"

    assert 0 <= exposure_score(merged) <= 100


def test_real_phone_vector_runs_ignorant():
    from fee_server.domain.osint.engines.real import IgnorantEngine

    engine = IgnorantEngine(_real_settings())
    # Número de ejemplo del propio proyecto Ignorant; sin proxy suele dar rate-limit.
    result = engine.run(EngineRequest(usernames=(), phone="+33644637111"))

    assert result.status in {"ok", "degraded"}
    assert {f.platform for f in result.findings} <= {"amazon", "instagram", "snapchat"}
