"""Normalización y deduplicación entre motores."""

from fee_server.domain.osint.findings import CONFIRMED, POTENTIAL_MATCH, RATE_LIMITED, Finding
from fee_server.domain.osint.normalize import merge_findings, normalize


def _finding(**overrides) -> Finding:
    base = dict(
        platform="GitHub",
        category="coding",
        url="https://github.com/x",
        username="x",
        status=CONFIRMED,
        confidence=80,
        sources=("blackbird",),
        details={},
    )
    return Finding(**{**base, **overrides})


def test_normalize_canonicalizes_platform_and_filters_details():
    raw = _finding(
        platform="git-hub",
        category="business",
        details={"location": "Lima", "secret_token": "nope", "followers": 3},
    )

    result = normalize(raw)

    assert result.platform == "GitHub"
    assert result.category == "coding"
    assert result.details == {"location": "Lima", "followers": 3}


def test_merge_corroborated_finding_raises_confidence_and_unions_sources():
    blackbird = _finding(confidence=80, sources=("blackbird",))
    maigret = _finding(confidence=95, sources=("maigret",), details={"location": "Portland, OR"})

    merged = merge_findings([blackbird, maigret])

    assert len(merged) == 1
    assert sorted(merged[0].sources) == ["blackbird", "maigret"]
    assert merged[0].confidence == 98
    assert merged[0].details["location"] == "Portland, OR"


def test_potential_match_does_not_merge_with_confirmed_other_username():
    a = _finding(username="alice", status=CONFIRMED)
    b = _finding(username="bob", status=POTENTIAL_MATCH, confidence=50)

    merged = merge_findings([a, b])

    assert len(merged) == 2


def test_rate_limited_is_dropped_when_another_engine_confirms():
    confirmed = _finding(platform="Spotify", username="x", status=CONFIRMED)
    limited = _finding(
        platform="Spotify", username="", status=RATE_LIMITED, confidence=0, sources=("holehe",)
    )

    merged = merge_findings([confirmed, limited])

    assert [f.status for f in merged] == [CONFIRMED]


def test_rate_limited_is_kept_when_it_is_the_only_signal():
    limited = _finding(
        platform="Spotify", username="", status=RATE_LIMITED, confidence=0, sources=("holehe",)
    )

    merged = merge_findings([limited])

    assert [f.status for f in merged] == [RATE_LIMITED]


def test_results_are_sorted_by_confidence_desc():
    low = _finding(platform="Reddit", username="x", confidence=60)
    high = _finding(platform="GitHub", username="x", confidence=95)

    merged = merge_findings([low, high])

    assert [f.platform for f in merged] == ["GitHub", "Reddit"]
