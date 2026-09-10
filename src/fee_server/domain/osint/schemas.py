"""Modelos de petición y respuesta del módulo OSINT."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

TARGET_TYPES = ("username", "email", "name", "phone")


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
    # Consentimiento del titular del correo para el camino de escaneo de terceros
    # (solo `target_type: "email"`). Lo emite `POST /verification/email/confirm`.
    consent_token: str | None = Field(default=None, max_length=4096)


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


class IdentityNodeModel(BaseModel):
    id: str
    platform: str
    username: str | None
    category: str


class IdentityEdgeModel(BaseModel):
    source: str
    target: str
    shared: list[str]
    weight: int


class IdentityGraphModel(BaseModel):
    nodes: list[IdentityNodeModel] = Field(default_factory=list)
    edges: list[IdentityEdgeModel] = Field(default_factory=list)
    clusters: list[list[str]] = Field(default_factory=list)


class TimelineEntryModel(BaseModel):
    platform: str
    username: str | None
    created_at: str
    age_years: float


class TimelineModel(BaseModel):
    entries: list[TimelineEntryModel] = Field(default_factory=list)
    oldest_platform: str | None = None
    oldest_date: str | None = None
    newest_platform: str | None = None
    newest_date: str | None = None
    span_years: float = 0.0
    dormant_old_accounts: list[str] = Field(default_factory=list)


class ReconstructedContactModel(BaseModel):
    kind: str
    pattern: str
    sources: list[str]
    count: int
    consistent_with_provided: bool | None = None


class CorrelationModel(BaseModel):
    identity_graph: IdentityGraphModel = Field(default_factory=IdentityGraphModel)
    timeline: TimelineModel = Field(default_factory=TimelineModel)
    reconstructed_contacts: list[ReconstructedContactModel] = Field(default_factory=list)


class DashboardResult(BaseModel):
    scan_id: str
    generated_at: datetime
    partial: bool
    exposure_score: int
    risk_level: str
    summary: DashboardSummary
    categories: list[DashboardCategory]
    correlation: CorrelationModel | None = None
