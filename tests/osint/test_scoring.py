"""Exposure Score, nivel de riesgo y proyección para el dashboard."""

import pytest

from fee_server.domain.osint.findings import CONFIRMED, POTENTIAL_MATCH, RATE_LIMITED, Finding
from fee_server.domain.osint.schemas import CorrelationModel
from fee_server.domain.osint.scoring import build_dashboard, exposure_score, risk_level


def _confirmed(platform: str, category: str, **details) -> Finding:
    return Finding(
        platform=platform,
        category=category,
        url=None,
        username="x",
        status=CONFIRMED,
        confidence=90,
        sources=("maigret",),
        details=details,
    )


def test_score_is_zero_without_confirmed_findings():
    only_weak = [
        Finding("W", "social", None, "x", POTENTIAL_MATCH, 50, ("maigret",), {}),
        Finding("S", "music", None, "x", RATE_LIMITED, 0, ("holehe",), {}),
    ]
    assert exposure_score(only_weak) == 0


def test_score_does_not_decrease_when_more_accounts_appear():
    one = [_confirmed("GitHub", "coding")]
    many = one + [
        _confirmed("Reddit", "social"),
        _confirmed("SoundCloud", "music"),
        _confirmed("Steam", "gaming"),
    ]
    assert exposure_score(many) >= exposure_score(one)


def test_risk_signals_add_points():
    plain = [_confirmed("GitHub", "coding")]
    risky = [_confirmed("GitHub", "coding", location="Portland, OR", full_name="Real Name")]
    assert exposure_score(risky) > exposure_score(plain)


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0, "LOW"), (24, "LOW"), (25, "MODERATE"), (74, "ELEVATED"), (75, "HIGH"), (100, "HIGH")],
)
def test_risk_level_thresholds(score, expected):
    assert risk_level(score) == expected


def test_build_dashboard_groups_categories_and_counts():
    findings = [
        _confirmed("GitHub", "coding"),
        _confirmed("GitLab", "coding"),
        Finding("Wattpad", "social", None, "x", POTENTIAL_MATCH, 50, ("maigret",), {}),
        Finding("Spotify", "music", None, "", RATE_LIMITED, 0, ("holehe",), {}),
    ]

    dashboard = build_dashboard(
        scan_id="s1",
        findings=findings,
        engines_run=["blackbird", "maigret"],
        score=40,
        partial=False,
    )

    coding = next(c for c in dashboard.categories if c.name == "coding")
    assert coding.items_count == 2
    assert coding.color_hex == "#8B5CF6"
    assert dashboard.summary.platforms_found == 3
    assert dashboard.summary.potential_matches == 1
    assert dashboard.summary.rate_limited == 1


def test_build_dashboard_propagates_correlation():
    correlation = CorrelationModel.model_validate(
        {"timeline": {"oldest_platform": "GitHub", "span_years": 12.0}}
    )

    dashboard = build_dashboard(
        scan_id="s1",
        findings=[_confirmed("GitHub", "coding")],
        engines_run=["maigret"],
        score=30,
        partial=False,
        correlation=correlation,
    )

    assert dashboard.correlation is not None
    assert dashboard.correlation.timeline.oldest_platform == "GitHub"


def test_build_dashboard_correlation_defaults_to_none():
    dashboard = build_dashboard(
        scan_id="s1",
        findings=[_confirmed("GitHub", "coding")],
        engines_run=["maigret"],
        score=30,
        partial=False,
    )

    assert dashboard.correlation is None
