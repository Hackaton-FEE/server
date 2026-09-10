"""Modelos de petición y respuesta del módulo OSINT."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

TARGET_TYPES = ("username", "email")


class _StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanRequest(_StrictRequest):
    # El tipo se valida en el servicio para devolver `unsupported-target-type`
    # (RFC 7807) en lugar de un 422 genérico.
    target_type: str
    identifier: str = Field(min_length=2, max_length=120)
    associated_usernames: list[str] = Field(default_factory=list, max_length=10)
    associated_email: str | None = Field(default=None, max_length=254)
    consent_self_audit: bool = False


class ScanAccepted(BaseModel):
    scan_id: str
    status: str
    estimated_duration_seconds: int
    polling_url: str
    events_url: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    progress_percentage: int
    completed_engines: list[str]
    running_engines: list[str]
    partial_findings_count: int


class FindingItem(BaseModel):
    platform: str
    username: str | None
    url: str | None
    status: str
    confidence: int
    sources: list[str]
    details: dict


class DashboardCategory(BaseModel):
    name: str
    color_hex: str
    items_count: int
    items: list[FindingItem]


class DashboardSummary(BaseModel):
    platforms_found: int
    high_confidence: int
    potential_matches: int
    rate_limited: int
    engines_run: list[str]


class DashboardResult(BaseModel):
    scan_id: str
    generated_at: datetime
    partial: bool
    exposure_score: int
    risk_level: str
    summary: DashboardSummary
    categories: list[DashboardCategory]
