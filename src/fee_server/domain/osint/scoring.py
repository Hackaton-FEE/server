"""Exposure Score, nivel de riesgo y proyección para el dashboard.

Los pesos son constantes explícitas y ajustables; ver `docs/osint-architecture.md`
§9.4. Los `POTENTIAL_MATCH` y `RATE_LIMITED` se muestran pero apenas pesan.
"""

import math
from collections.abc import Iterable, Sequence
from datetime import datetime

from fee_server.domain.osint.catalog import category_color
from fee_server.domain.osint.findings import CONFIRMED, POTENTIAL_MATCH, RATE_LIMITED, Finding
from fee_server.domain.osint.schemas import (
    DashboardCategory,
    DashboardResult,
    DashboardSummary,
    FindingItem,
)
from fee_server.util.time import utcnow

_VOLUME_WEIGHT = 18
_VOLUME_CAP = 50
_DIVERSITY_PER_CATEGORY = 6
_DIVERSITY_CAP = 24
_HIGH_RISK_CATEGORY_POINTS = 8
_LOCATION_POINTS = 6
_FULL_NAME_POINTS = 5
_MASKED_CONTACT_POINTS = 4

_HIGH_RISK_CATEGORIES = {"finance", "adult"}

_RISK_THRESHOLDS = (
    (25, "LOW"),
    (50, "MODERATE"),
    (75, "ELEVATED"),
)


def _risk_signal_points(findings: Sequence[Finding]) -> int:
    points = 0
    for finding in findings:
        if finding.category in _HIGH_RISK_CATEGORIES:
            points += _HIGH_RISK_CATEGORY_POINTS
        if "location" in finding.details:
            points += _LOCATION_POINTS
        if "full_name" in finding.details:
            points += _FULL_NAME_POINTS
        if "masked_phone" in finding.details or "masked_email" in finding.details:
            points += _MASKED_CONTACT_POINTS
    return points


def exposure_score(findings: Iterable[Finding]) -> int:
    confirmed = [f for f in findings if f.status == CONFIRMED]
    if not confirmed:
        return 0

    volume = min(_VOLUME_CAP, round(_VOLUME_WEIGHT * math.log2(len(confirmed) + 1)))
    diversity = min(
        _DIVERSITY_CAP,
        len({f.category for f in confirmed}) * _DIVERSITY_PER_CATEGORY,
    )
    risk = _risk_signal_points(confirmed)
    return max(0, min(100, volume + diversity + risk))


def risk_level(score: int) -> str:
    for threshold, label in _RISK_THRESHOLDS:
        if score < threshold:
            return label
    return "HIGH"


def _to_item(finding: Finding) -> FindingItem:
    return FindingItem(
        platform=finding.platform,
        username=finding.username,
        url=finding.url,
        status=finding.status,
        confidence=finding.confidence,
        sources=list(finding.sources),
        details=dict(finding.details),
    )


def _summary(findings: Sequence[Finding], engines_run: Sequence[str]) -> DashboardSummary:
    return DashboardSummary(
        platforms_found=sum(1 for f in findings if f.status != RATE_LIMITED),
        high_confidence=sum(1 for f in findings if f.status == CONFIRMED and f.confidence >= 80),
        potential_matches=sum(1 for f in findings if f.status == POTENTIAL_MATCH),
        rate_limited=sum(1 for f in findings if f.status == RATE_LIMITED),
        engines_run=list(engines_run),
    )


def _categories(findings: Sequence[Finding]) -> list[DashboardCategory]:
    buckets: dict[str, list[Finding]] = {}
    for finding in findings:
        buckets.setdefault(finding.category, []).append(finding)

    categories = [
        DashboardCategory(
            name=name,
            color_hex=category_color(name),
            items_count=len(items),
            items=[_to_item(f) for f in items],
        )
        for name, items in buckets.items()
    ]
    categories.sort(key=lambda c: (-c.items_count, c.name))
    return categories


def build_dashboard(
    *,
    scan_id: str,
    findings: Sequence[Finding],
    engines_run: Sequence[str],
    score: int,
    partial: bool,
    generated_at: datetime | None = None,
) -> DashboardResult:
    return DashboardResult(
        scan_id=scan_id,
        generated_at=generated_at or utcnow(),
        partial=partial,
        exposure_score=score,
        risk_level=risk_level(score),
        summary=_summary(findings, engines_run),
        categories=_categories(findings),
    )
