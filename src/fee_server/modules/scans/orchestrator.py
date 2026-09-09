"""In-memory execution primitive for a future authorized worker entrypoint."""

import asyncio
import math
from collections.abc import Sequence

from fee_server.modules.scans.models import (
    Capability,
    Finding,
    ProviderResult,
    ScanResult,
    ScanTarget,
)
from fee_server.modules.scans.registry import ScanRegistry


class ScanOrchestrator:
    def __init__(
        self,
        registry: ScanRegistry,
        *,
        max_concurrency: int = 3,
        timeout_seconds: float = 20,
        max_findings: int = 1000,
    ) -> None:
        if any(type(limit) is not int or limit < 1 for limit in (max_concurrency, max_findings)):
            raise ValueError("Concurrency and finding limits must be positive integers")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("Provider timeout must be finite and positive")
        self._registry = registry
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._timeout = timeout_seconds
        self._max_findings = max_findings

    async def run(
        self,
        target: ScanTarget,
        capability: Capability,
        provider_ids: Sequence[str] | None = None,
    ) -> ScanResult:
        try:
            capability = Capability(capability)
        except (ValueError, TypeError):
            raise ValueError("Unknown scan capability") from None
        expected_kind = "username" if capability == Capability.USERNAME else "email"
        if target.kind != expected_kind:
            raise ValueError("Target kind is incompatible with the requested capability")
        selected = (
            tuple(provider_ids)
            if provider_ids is not None
            else tuple(
                item.provider_id
                for item in self._registry.catalog()
                if capability in item.capabilities
            )
        )
        if not selected or len(set(selected)) != len(selected):
            raise ValueError("Select one or more unique providers")
        for provider_id in selected:
            if capability not in self._registry.definition(provider_id).capabilities:
                raise ValueError("Provider does not support the requested capability")
        results = await asyncio.gather(
            *(self._run_one(provider_id, target, capability) for provider_id in selected)
        )
        return ScanResult(capability=capability, providers=tuple(results))

    async def _run_one(
        self, provider_id: str, target: ScanTarget, capability: Capability
    ) -> ProviderResult:
        provider = self._registry.adapter(provider_id)
        if provider is None:
            return ProviderResult(provider_id=provider_id, status="unavailable")
        async with self._semaphore:
            try:
                async with asyncio.timeout(self._timeout):
                    raw = await provider.scan(target, capability)
                    if not isinstance(raw, Sequence) or len(raw) > self._max_findings:
                        raise ValueError("Invalid provider results")
                    findings = tuple(dict.fromkeys(Finding.model_validate(item) for item in raw))
                    expected_kind = "breach" if capability == Capability.BREACHES else "account"
                    if any(finding.kind != expected_kind for finding in findings):
                        raise ValueError("Provider result kind is incompatible with capability")
                return ProviderResult(
                    provider_id=provider_id, status="completed", findings=findings
                )
            except TimeoutError:
                return ProviderResult(provider_id=provider_id, status="timed_out")
            except Exception:
                # Third-party exceptions may contain targets, credentials or response bodies.
                return ProviderResult(provider_id=provider_id, status="failed")
