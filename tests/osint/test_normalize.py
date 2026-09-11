"""Normalización y deduplicación entre motores."""

import pytest

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
    url = "https://github.com/alice"
    a = _finding(username="alice", url=url, status=CONFIRMED)
    b = _finding(username="bob", url=url, status=POTENTIAL_MATCH, confidence=50)

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


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("path", ["/client_seed", "/user/client_page", "/@client_page"])
def test_same_profile_url_keeps_the_username_from_maigret(reverse, path):
    url = f"https://example.invalid{path}"
    blackbird = _finding(username="client_seed", url=url)
    maigret = _finding(
        username="client_page",
        url=url,
        sources=("maigret",),
        confidence=95,
        details={"account_id": "account-123"},
    )
    findings = [blackbird, maigret]
    merged = merge_findings(list(reversed(findings)) if reverse else findings)

    assert len(merged) == 1
    assert merged[0].username == "client_page"
    assert merged[0].url == url
    assert merged[0].sources == ("blackbird", "maigret")
    assert merged[0].details["account_id"] == "account-123"
    assert merged[0].confidence == 98


def test_different_profile_urls_do_not_merge_different_usernames():
    findings = [
        _finding(username="client_seed", url="https://example.invalid/client_seed"),
        _finding(
            username="client_page",
            url="https://example.invalid/client_page",
            sources=("maigret",),
        ),
    ]
    assert len(merge_findings(findings)) == 2


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "https://example.invalid",
        "https://example.invalid/",
        "https://example.invalid/?username=client_seed",
        "https://example.invalid/login",
        "https://example.invalid/users",
        "https://example.invalid/client_seed_extra",
        "ftp://example.invalid/client_seed",
        "https://user:pass@example.invalid/client_seed",
        "https://[invalid/client_seed",
    ],
)
def test_generic_or_invalid_url_does_not_merge_different_usernames(url):
    findings = [
        _finding(username="client_seed", url=url),
        _finding(username="client_page", url=url, sources=("maigret",)),
    ]
    assert len(merge_findings(findings)) == 2


def test_same_profile_url_does_not_merge_different_platforms_or_contact_checks():
    findings = [
        _finding(username="client_seed", url="https://example.invalid/client_seed"),
        _finding(
            username="client_page",
            url="https://example.invalid/client_seed",
            platform="Other",
            sources=("maigret",),
        ),
        _finding(username=None, url="https://example.invalid/client_seed", sources=("holehe",)),
    ]
    assert len(merge_findings(findings)) == 3


def test_existing_username_key_still_merges_reports_with_different_urls():
    findings = [
        _finding(username="client_page", url="https://example.invalid/client_page"),
        _finding(
            username="client_page",
            url="https://api.example.invalid/users/client_page",
            sources=("maigret",),
        ),
    ]
    assert len(merge_findings(findings)) == 1
