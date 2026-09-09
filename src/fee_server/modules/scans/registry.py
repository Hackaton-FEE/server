"""Explicit registration: a roadmap entry alone never enables execution."""

from collections.abc import Iterable

from fee_server.modules.scans.models import Capability, ProviderCapability, ProviderDefinition
from fee_server.modules.scans.providers import ScanProvider

PLANNED_PROVIDERS = (
    ProviderDefinition(
        provider_id="sherlock", name="Sherlock", capabilities=(Capability.USERNAME,)
    ),
    ProviderDefinition(provider_id="holehe", name="Holehe", capabilities=(Capability.EMAIL,)),
    ProviderDefinition(provider_id="maigret", name="Maigret", capabilities=(Capability.USERNAME,)),
    ProviderDefinition(
        provider_id="hibp", name="Have I Been Pwned", capabilities=(Capability.BREACHES,)
    ),
)


class ScanRegistry:
    def __init__(self, planned: Iterable[ProviderDefinition] = ()) -> None:
        self._definitions: dict[str, ProviderDefinition] = {}
        self._providers: dict[str, ScanProvider] = {}
        for definition in planned:
            if definition.provider_id in self._definitions:
                raise ValueError("Provider IDs must be unique")
            self._definitions[definition.provider_id] = definition

    def register(self, provider: ScanProvider) -> None:
        definition = ProviderDefinition.model_validate(provider.definition)
        if definition.provider_id in self._providers:
            raise ValueError("Provider IDs must be unique")
        planned = self._definitions.get(definition.provider_id)
        if planned is not None and set(planned.capabilities) != set(definition.capabilities):
            raise ValueError("Adapter capabilities must match the provider catalog")
        self._definitions[definition.provider_id] = definition
        self._providers[definition.provider_id] = provider

    def catalog(self) -> tuple[ProviderCapability, ...]:
        return tuple(
            ProviderCapability(**definition.model_dump(), available=provider_id in self._providers)
            for provider_id, definition in self._definitions.items()
        )

    def definition(self, provider_id: str) -> ProviderDefinition:
        try:
            return self._definitions[provider_id]
        except KeyError:
            raise ValueError("Unknown scan provider") from None

    def adapter(self, provider_id: str) -> ScanProvider | None:
        self.definition(provider_id)
        return self._providers.get(provider_id)


def build_registry(providers: Iterable[ScanProvider] = ()) -> ScanRegistry:
    registry = ScanRegistry(PLANNED_PROVIDERS)
    for provider in providers:
        registry.register(provider)
    return registry
