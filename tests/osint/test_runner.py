"""Orquestación de la cascada: selección de motores y tolerancia a fallos."""

from fee_server.core.config import Settings
from fee_server.db.models import OsintScan, User
from fee_server.db.session import session_scope
from fee_server.domain.osint import engines as engines_module
from fee_server.domain.osint import repository, runner
from fee_server.domain.osint.engines import ENGINE_ERROR, ENGINE_OK, EngineRequest, EngineResult
from fee_server.domain.osint.findings import CONFIRMED, POTENTIAL_MATCH, Finding
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


class _NoiseEngine:
    """Devuelve un hallazgo con un alias común, sin datos ricos y sin par."""

    name = "blackbird"

    def run(self, request: EngineRequest) -> EngineResult:
        finding = Finding("Site", "other", None, "test", CONFIRMED, 80, ("blackbird",), {})
        return EngineResult(self.name, ENGINE_OK, (finding,))


def test_common_alias_without_corroboration_is_demoted_end_to_end(client, settings, monkeypatch):
    scan_id = _make_scan(settings)
    monkeypatch.setattr(runner, "build_engines", lambda _s: (_NoiseEngine(),))

    runner.run_scan(
        scan_id=scan_id,
        engine_request=EngineRequest(usernames=("alias_de_prueba",)),
        settings=settings,
    )

    with session_scope() as session:
        scan = session.get(OsintScan, scan_id)
        assert scan.status == "COMPLETED"
        assert scan.exposure_score == 0  # ningún CONFIRMED sobrevive
        findings = repository.list_findings(session, scan_id)
        assert findings[0].status == POTENTIAL_MATCH


class _LinkDiscoveryEngine:
    """Fase 1: encuentra el alias original y descubre uno relacionado."""

    name = "maigret"

    def run(self, request: EngineRequest) -> EngineResult:
        if "origin_alias" not in request.usernames:
            return EngineResult(self.name, ENGINE_OK, ())
        finding = Finding(
            "GitHub",
            "coding",
            None,
            "origin_alias",
            CONFIRMED,
            90,
            ("maigret",),
            {"full_name": "Ada Lovelace", "linked_usernames": ["pivot_target_99"]},
        )
        return EngineResult(self.name, ENGINE_OK, (finding,))


class _PivotAwareEngine:
    """Solo encuentra algo cuando se le consulta el alias pivotado (Fase 2)."""

    name = "blackbird"

    def run(self, request: EngineRequest) -> EngineResult:
        if "pivot_target_99" not in request.usernames:
            return EngineResult(self.name, ENGINE_OK, ())
        finding = Finding(
            "GitLab", "coding", None, "pivot_target_99", CONFIRMED, 80, ("blackbird",), {}
        )
        return EngineResult(self.name, ENGINE_OK, (finding,))


def test_pivoting_scans_a_username_linked_in_phase_one(client, settings, monkeypatch):
    scan_id = _make_scan(settings)
    monkeypatch.setattr(
        runner, "build_engines", lambda _s: (_LinkDiscoveryEngine(), _PivotAwareEngine())
    )

    runner.run_scan(
        scan_id=scan_id,
        engine_request=EngineRequest(usernames=("origin_alias",)),
        settings=settings,
    )

    with session_scope() as session:
        scan = session.get(OsintScan, scan_id)
        assert scan.status == "COMPLETED"
        # Solo las claves canónicas: la Fase 2 no inventa pseudo-motores.
        assert set(scan.engines.keys()) == {"maigret", "blackbird"}
        platforms = {f.platform for f in repository.list_findings(session, scan_id)}
        assert "GitLab" in platforms  # el hallazgo de la Fase 2 llegó


class _BoomInPhaseTwoEngine:
    """Falla solo cuando se le consulta el alias pivotado (Fase 2)."""

    name = "blackbird"

    def run(self, request: EngineRequest) -> EngineResult:
        if "pivot_target_99" in request.usernames:
            raise RuntimeError("motor de pivoteo caído")
        return EngineResult(self.name, ENGINE_OK, ())


def test_a_failing_pivot_engine_does_not_abort_the_scan(client, settings, monkeypatch):
    scan_id = _make_scan(settings)
    monkeypatch.setattr(
        runner, "build_engines", lambda _s: (_LinkDiscoveryEngine(), _BoomInPhaseTwoEngine())
    )

    runner.run_scan(
        scan_id=scan_id,
        engine_request=EngineRequest(usernames=("origin_alias",)),
        settings=settings,
    )

    with session_scope() as session:
        scan = session.get(OsintScan, scan_id)
        assert scan.status == "COMPLETED"
        assert scan.engines["blackbird"]["status"] == ENGINE_ERROR


def test_no_pivot_candidates_means_no_second_phase(client, settings, monkeypatch):
    """Sin `linked_usernames`, la cascada se comporta exactamente como antes."""
    calls: list[tuple[str, ...]] = []

    class _PlainEngine:
        name = "maigret"

        def run(self, request: EngineRequest) -> EngineResult:
            calls.append(request.usernames)
            return EngineResult(self.name, ENGINE_OK, ())

    scan_id = _make_scan(settings)
    monkeypatch.setattr(runner, "build_engines", lambda _s: (_PlainEngine(),))

    runner.run_scan(
        scan_id=scan_id,
        engine_request=EngineRequest(usernames=("alias_de_prueba",)),
        settings=settings,
    )

    assert calls == [("alias_de_prueba",)]  # una sola llamada: sin Fase 2


def test_deleted_scan_stops_before_next_engine(client, settings, monkeypatch):
    scan_id = _make_scan(settings)
    calls = []

    class DeleteEngine:
        name = "blackbird"

        def run(self, request):
            calls.append(self.name)
            with session_scope() as session:
                repository.delete_scan(session, repository.get_scan(session, scan_id))
            return EngineResult(self.name, ENGINE_OK, ())

    class NextEngine:
        name = "holehe"

        def run(self, request):
            calls.append(self.name)
            return EngineResult(self.name, ENGINE_OK, ())

    monkeypatch.setattr(runner, "build_engines", lambda _: [DeleteEngine(), NextEngine()])
    runner.run_scan(
        scan_id=scan_id, engine_request=EngineRequest(usernames=("alias",)), settings=settings
    )
    assert calls == ["blackbird"]


class _AvatarEngine:
    """Aporta un `avatar_url` para ejercitar el enriquecimiento de imágenes."""

    name = "blackbird"

    def run(self, request: EngineRequest) -> EngineResult:
        finding = Finding(
            "GitHub",
            "coding",
            None,
            "alias_de_prueba",
            CONFIRMED,
            90,
            ("blackbird",),
            {"full_name": "Ada Lovelace", "avatar_url": "https://cdn.example/ada.png"},
        )
        return EngineResult(self.name, ENGINE_OK, (finding,))


def test_a_finding_with_an_avatar_gains_image_metadata_end_to_end(client, settings, monkeypatch):
    scan_id = _make_scan(settings)
    monkeypatch.setattr(runner, "build_engines", lambda _s: (_AvatarEngine(),))

    runner.run_scan(
        scan_id=scan_id,
        engine_request=EngineRequest(usernames=("alias_de_prueba",)),
        settings=settings,
    )

    with session_scope() as session:
        scan = session.get(OsintScan, scan_id)
        assert scan.status == "COMPLETED"
        findings = repository.list_findings(session, scan_id)
        github = next(f for f in findings if f.platform == "GitHub")
        assert "image_camera_model" in github.details


def test_image_metadata_disabled_leaves_the_scan_unaffected(client, settings, monkeypatch):
    scan_id = _make_scan(settings)
    monkeypatch.setattr(runner, "build_engines", lambda _s: (_AvatarEngine(),))
    disabled_settings = settings.model_copy(update={"osint_image_metadata_enabled": False})

    runner.run_scan(
        scan_id=scan_id,
        engine_request=EngineRequest(usernames=("alias_de_prueba",)),
        settings=disabled_settings,
    )

    with session_scope() as session:
        scan = session.get(OsintScan, scan_id)
        assert scan.status == "COMPLETED"
        findings = repository.list_findings(session, scan_id)
        github = next(f for f in findings if f.platform == "GitHub")
        assert "image_camera_model" not in github.details


def test_concurrent_scan_limit_and_slot_release(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event, Lock

    import pytest

    settings = Settings(environment="test", osint_max_concurrent_scans=1)
    started = Event()
    release = Event()
    lock = Lock()
    active = peak = 0

    def fake_scan(**kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        started.set()
        assert release.wait(timeout=5)
        with lock:
            active -= 1
        if kwargs["scan_id"] == "first":
            raise RuntimeError("simulated failure")

    monkeypatch.setattr(runner, "_run_scan", fake_scan)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(
            runner.run_scan, scan_id="first", engine_request=EngineRequest(()), settings=settings
        )
        assert started.wait(timeout=5)
        second = pool.submit(
            runner.run_scan, scan_id="second", engine_request=EngineRequest(()), settings=settings
        )
        release.set()
        with pytest.raises(RuntimeError):
            first.result(timeout=5)
        second.result(timeout=5)
    assert peak == 1
    assert runner._active_scans == 0
