import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

import pytest
from pydantic import SecretStr, ValidationError

from fee_server.modules.scans.models import Capability, Finding, ProviderDefinition, ScanTarget
from fee_server.modules.scans.orchestrator import ScanOrchestrator
from fee_server.modules.scans.registry import ScanRegistry, build_registry

TARGET = ScanTarget(kind="username", value=SecretStr("sample_handle"))
FINDING = Finding(kind="account", service="example", url="https://example.test")


@dataclass
class FakeProvider:
    definition: ProviderDefinition
    callback: Callable[[], Awaitable[Sequence[Finding]]]

    async def scan(self, target: ScanTarget, capability: Capability) -> Sequence[Finding]:
        return await self.callback()


def provider(provider_id, callback, capability=Capability.USERNAME):
    return FakeProvider(
        ProviderDefinition(
            provider_id=provider_id, name="Test adapter", capabilities=(capability,)
        ),
        callback,
    )


async def empty_results():
    return []


def test_catalog_is_unavailable_until_an_adapter_is_explicitly_registered():
    registry = build_registry()
    assert {item.provider_id for item in registry.catalog()} == {
        "sherlock",
        "holehe",
        "maigret",
        "hibp",
    }
    assert all(not item.available for item in registry.catalog())
    registry.register(provider("sherlock", empty_results))
    assert {item.provider_id for item in registry.catalog() if item.available} == {"sherlock"}
    assert all(not item.available for item in build_registry().catalog())


def test_registry_rejects_duplicates_and_mismatched_catalog_capabilities():
    adapter = provider("sherlock", empty_results)
    registry = build_registry((adapter,))
    with pytest.raises(ValueError, match="unique"):
        registry.register(adapter)
    with pytest.raises(ValueError, match="unique"):
        ScanRegistry((adapter.definition, adapter.definition))
    with pytest.raises(ValueError, match="match"):
        build_registry((provider("holehe", empty_results),))
    with pytest.raises(ValueError, match="Unknown scan provider"):
        registry.adapter("unknown")


def test_provider_metadata_rejects_invalid_ids_and_duplicate_capabilities():
    with pytest.raises(ValidationError):
        ProviderDefinition(provider_id="a/b", name="Example", capabilities=(Capability.EMAIL,))
    with pytest.raises(ValidationError):
        ProviderDefinition(
            provider_id="example", name="Example", capabilities=(Capability.EMAIL, Capability.EMAIL)
        )


def test_mixed_outcomes_keep_empty_success_failures_and_timeouts_distinct(caplog):
    async def exercise():
        timed_out_cancelled = False

        async def successful():
            return [FINDING, FINDING, Finding(kind="account", service="another")]

        async def broken():
            raise RuntimeError(
                "sample_handle https://example.test/private?email=sample@example.test"
            )

        async def timeout():
            nonlocal timed_out_cancelled
            try:
                await asyncio.Event().wait()
            finally:
                timed_out_cancelled = True

        registry = build_registry(
            (
                provider("test_success", successful),
                provider("test_empty", empty_results),
                provider("test_failed", broken),
                provider("test_timeout", timeout),
            )
        )
        result = await ScanOrchestrator(registry, timeout_seconds=0.02).run(
            TARGET, Capability.USERNAME
        )
        statuses = {item.provider_id: item.status for item in result.providers}
        assert statuses == {
            "sherlock": "unavailable",
            "maigret": "unavailable",
            "test_success": "completed",
            "test_empty": "completed",
            "test_failed": "failed",
            "test_timeout": "timed_out",
        }
        success = next(item for item in result.providers if item.provider_id == "test_success")
        assert success.findings == (FINDING, Finding(kind="account", service="another"))
        assert str(success.findings[0].url) == "https://example.test/"
        assert all(not item.findings for item in result.providers if item != success)
        assert timed_out_cancelled
        assert "sample_handle" not in result.model_dump_json()
        assert "private?email" not in result.model_dump_json()
        assert "sample_handle" not in caplog.text

    asyncio.run(exercise())


def test_concurrency_limit_is_shared_by_simultaneous_runs():
    async def exercise():
        active = peak = 0

        async def work():
            nonlocal active, peak
            active += 1
            peak = max(active, peak)
            try:
                await asyncio.sleep(0.005)
                return []
            finally:
                active -= 1

        registry = ScanRegistry()
        for index in range(4):
            registry.register(provider(f"test_{index}", work))
        orchestrator = ScanOrchestrator(registry, max_concurrency=2)
        reports = await asyncio.gather(
            *(orchestrator.run(TARGET, Capability.USERNAME) for _ in range(2))
        )
        assert peak == 2
        assert active == 0
        assert all(item.status == "completed" for report in reports for item in report.providers)

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "payload",
    [
        [Finding.model_construct(kind="account", service="invalid service")],
        [Finding(kind="breach", service="example")],
        [FINDING] * 3,
        {"unexpected": "payload"},
    ],
)
def test_invalid_or_oversized_provider_results_fail_without_partial_findings(payload):
    async def malformed():
        return payload

    registry = build_registry((provider("test_invalid", malformed),))
    result = asyncio.run(
        ScanOrchestrator(registry, max_findings=2).run(
            TARGET, Capability.USERNAME, ["test_invalid"]
        )
    )
    assert result.providers[0].status == "failed"
    assert result.providers[0].findings == ()


@pytest.mark.parametrize("provider_ids", [[], ["sherlock", "sherlock"], ["unknown"], ["holehe"]])
def test_bad_provider_selection_is_rejected_before_any_execution(provider_ids):
    with pytest.raises(ValueError):
        asyncio.run(
            ScanOrchestrator(build_registry()).run(TARGET, Capability.USERNAME, provider_ids)
        )


def test_incompatible_target_type_is_rejected():
    with pytest.raises(ValueError, match="Target kind"):
        asyncio.run(ScanOrchestrator(build_registry()).run(TARGET, Capability.BREACHES))


def test_unknown_capability_rejects_raw_input_without_echoing_it():
    with pytest.raises(ValueError, match="^Unknown scan capability$"):
        asyncio.run(ScanOrchestrator(build_registry()).run(TARGET, "sample_private_value"))


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.test/data",
        "https://user:password@example.test/",
        "https://user@example.test/",
        "https://example.test/" + "a" * 2084,
    ],
)
def test_finding_urls_are_bounded_http_urls_without_credentials(url):
    with pytest.raises(ValidationError):
        Finding(kind="account", service="example", url=url)


@pytest.mark.parametrize(
    "capability, finding_kind", [(Capability.EMAIL, "account"), (Capability.BREACHES, "breach")]
)
def test_email_and_breach_features_accept_email_targets(capability, finding_kind):
    async def successful():
        return [Finding(kind=finding_kind, service="example")]

    target = ScanTarget(kind="email", value="sample@example.test")
    registry = ScanRegistry()
    registry.register(provider("test_email", successful, capability))
    result = asyncio.run(ScanOrchestrator(registry).run(target, capability))
    assert result.capability == capability
    assert result.providers[0].status == "completed"
    assert result.providers[0].findings[0].kind == finding_kind
    assert "sample@example.test" not in result.model_dump_json()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_concurrency": 0},
        {"max_concurrency": 1.5},
        {"max_findings": 0},
        {"timeout_seconds": 0},
        {"timeout_seconds": float("inf")},
        {"timeout_seconds": float("nan")},
    ],
)
def test_execution_limits_are_validated(kwargs):
    with pytest.raises(ValueError):
        ScanOrchestrator(build_registry(), **kwargs)


def test_caller_cancellation_propagates_to_the_adapter():
    async def exercise():
        started = asyncio.Event()
        cancelled = False

        async def wait():
            nonlocal cancelled
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled = True

        registry = build_registry((provider("test_cancel", wait),))
        task = asyncio.create_task(
            ScanOrchestrator(registry).run(TARGET, Capability.USERNAME, ["test_cancel"])
        )
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cancelled

    asyncio.run(exercise())


def test_target_representation_is_redacted_and_blank_targets_are_invalid():
    assert "sample_handle" not in repr(TARGET)
    assert "sample_handle" not in TARGET.model_dump_json()
    with pytest.raises(ValidationError):
        ScanTarget(kind="username", value="   ")
