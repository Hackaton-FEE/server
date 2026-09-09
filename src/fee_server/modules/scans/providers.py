"""Adapters own third-party I/O and translate it into the shared finding model."""

from collections.abc import Sequence
from typing import Protocol

from fee_server.modules.scans.models import Capability, Finding, ProviderDefinition, ScanTarget


class ScanProvider(Protocol):
    @property
    def definition(self) -> ProviderDefinition: ...

    async def scan(self, target: ScanTarget, capability: Capability) -> Sequence[Finding]: ...
