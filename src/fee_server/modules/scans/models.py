"""Small, provider-independent contracts; no raw third-party payloads."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, SecretStr, field_validator


class ScanModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)


class Capability(StrEnum):
    USERNAME = "username"
    EMAIL = "email"
    BREACHES = "breaches"


class ScanTarget(ScanModel):
    kind: Literal["username", "email"]
    value: SecretStr = Field(min_length=1, max_length=320)

    @field_validator("value")
    @classmethod
    def nonblank_value(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("A nonblank target is required")
        return value


class Finding(ScanModel):
    """Candidate account or breach; presence does not prove the person's identity."""

    model_config = ConfigDict(revalidate_instances="always")

    kind: Literal["account", "breach"]
    service: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    url: HttpUrl | None = None

    @field_validator("url")
    @classmethod
    def no_url_credentials(cls, value: HttpUrl | None) -> HttpUrl | None:
        if value is not None and (value.username is not None or value.password is not None):
            raise ValueError("Finding URLs must not contain credentials")
        return value


class ProviderDefinition(ScanModel):
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    name: str = Field(min_length=1, max_length=80)
    capabilities: tuple[Capability, ...] = Field(min_length=1)

    @field_validator("capabilities")
    @classmethod
    def unique_capabilities(cls, value: tuple[Capability, ...]) -> tuple[Capability, ...]:
        if len(set(value)) != len(value):
            raise ValueError("Provider capabilities must be unique")
        return value


class ProviderCapability(ProviderDefinition):
    available: bool


class CapabilitiesResponse(ScanModel):
    providers: tuple[ProviderCapability, ...]


class ProviderResult(ScanModel):
    provider_id: str
    status: Literal["completed", "failed", "timed_out", "unavailable"]
    findings: tuple[Finding, ...] = ()


class ScanResult(ScanModel):
    capability: Capability
    providers: tuple[ProviderResult, ...]
