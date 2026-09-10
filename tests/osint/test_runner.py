"""Orquestación de la cascada: selección de motores y tolerancia a fallos."""

from fee_server.core.config import Settings
from fee_server.db.models import OsintScan, User
from fee_server.db.session import session_scope
from fee_server.domain.osint import engines as engines_module
from fee_server.domain.osint import runner
from fee_server.domain.osint.engines import ENGINE_ERROR, EngineRequest
from fee_server.domain.osint.schemas import ScanRequest
from fee_server.domain.osint.service import ScanService


def _make_scan(settings) -> str:
    with session_scope() as session:
        user = User(handle=b"runner-tests-handle", label="R")
        session.add(user)
        session.flush()
        service = ScanService(session, settings)
        scan, _ = service.create_scan(
            ScanRequest(
                target_type="username", identifier="alias_de_prueba", consent_self_audit=True
            ),
            user,
        )
        return scan.id


class _BoomEngine:
    name = "maigret"

    def run(self, request: EngineRequest):
        raise RuntimeError("motor caído")


def test_build_engines_uses_fake_engines_by_default():
    engines = engines_module.build_engines(Settings(environment="test"))

    assert [engine.name for engine in engines] == ["blackbird", "maigret", "holehe", "ignorant"]
    assert all(type(engine).__name__.startswith("Fake") for engine in engines)


def test_build_engines_returns_real_adapters_in_real_mode():
    real = Settings(
        environment="development",
        jwt_secret="a-proper-production-secret-value-32chars",
        osint_engine_mode="real",
    )

    engines = engines_module.build_engines(real)

    assert [engine.name for engine in engines] == ["blackbird", "maigret", "holehe", "ignorant"]
    assert isinstance(engines[0], engines_module.BlackbirdEngine)


def test_a_failing_engine_does_not_abort_the_scan(client, settings, monkeypatch):
    scan_id = _make_scan(settings)
    monkeypatch.setattr(runner, "build_engines", lambda _s: (_BoomEngine(),))

    runner.run_scan(
        scan_id=scan_id,
        engine_request=EngineRequest(usernames=("alias_de_prueba",)),
        settings=settings,
    )

    with session_scope() as session:
        scan = session.get(OsintScan, scan_id)
        assert scan.status == "COMPLETED"
        assert scan.engines["maigret"]["status"] == ENGINE_ERROR


def test_completed_scan_stores_a_correlation(client, settings, monkeypatch):
    scan_id = _make_scan(settings)
    monkeypatch.setattr(runner, "build_engines", lambda _s: engines_module.build_engines(settings))

    runner.run_scan(
        scan_id=scan_id,
        engine_request=EngineRequest(usernames=("alias_de_prueba",)),
        settings=settings,
    )

    with session_scope() as session:
        scan = session.get(OsintScan, scan_id)
        assert scan.status == "COMPLETED"
        assert scan.correlation["identity_graph"]["nodes"]
        assert "timeline" in scan.correlation


def test_scan_fails_when_result_consolidation_raises(client, settings, monkeypatch):
    scan_id = _make_scan(settings)
    monkeypatch.setattr(runner, "build_engines", lambda _s: engines_module.build_engines(settings))

    def _boom(*_args, **_kwargs):
        raise RuntimeError("normalización rota")

    monkeypatch.setattr(runner, "correlate", _boom)

    runner.run_scan(
        scan_id=scan_id,
        engine_request=EngineRequest(usernames=("alias_de_prueba",)),
        settings=settings,
    )

    with session_scope() as session:
        scan = session.get(OsintScan, scan_id)
        assert scan.status == "FAILED"
        assert scan.completed_at is not None


def test_scan_fails_when_engines_are_unavailable(client, settings, monkeypatch):
    scan_id = _make_scan(settings)

    def _unavailable(_settings):
        raise NotImplementedError

    monkeypatch.setattr(runner, "build_engines", _unavailable)

    runner.run_scan(
        scan_id=scan_id,
        engine_request=EngineRequest(usernames=("alias_de_prueba",)),
        settings=settings,
    )

    with session_scope() as session:
        scan = session.get(OsintScan, scan_id)
        assert scan.status == "FAILED"
