"""Capa de correlación: grafo de identidad, timeline y contactos reconstruidos."""

from datetime import UTC, datetime

from fee_server.domain.osint.correlation import (
    build_identity_graph,
    build_timeline,
    correlate,
    reconstruct_contacts,
)
from fee_server.domain.osint.findings import CONFIRMED, POTENTIAL_MATCH, Finding

_NOW = datetime(2024, 1, 1, tzinfo=UTC)


def _finding(platform: str, username: str | None = "alias", **details) -> Finding:
    return Finding(
        platform=platform,
        category="social",
        url=None,
        username=username,
        status=CONFIRMED,
        confidence=90,
        sources=("maigret",),
        details=details,
    )


# --- Grafo de identidad ------------------------------------------------


def test_shared_full_name_links_two_accounts():
    findings = [
        _finding("GitHub", username="gh", full_name="Ada Lovelace"),
        _finding("GitLab", username="gl", full_name="ada lovelace"),
    ]

    graph = build_identity_graph(findings)

    assert len(graph.edges) == 1
    assert graph.edges[0].shared == ("full_name",)
    assert graph.edges[0].weight == 1
    assert len(graph.clusters) == 1
    assert set(graph.clusters[0]) == {"GitHub:gh", "GitLab:gl"}


def test_accounts_without_common_attributes_are_not_linked():
    findings = [
        _finding("GitHub", username="one", full_name="Ada Lovelace"),
        _finding("Reddit", username="two", location="Portland"),
    ]

    graph = build_identity_graph(findings)

    assert graph.edges == ()
    assert graph.clusters == ()


def test_potential_matches_are_excluded_from_the_graph():
    findings = [
        _finding("GitHub", username="gh", full_name="Ada"),
        Finding("Wattpad", "social", None, "gh", POTENTIAL_MATCH, 50, ("maigret",), {}),
    ]

    graph = build_identity_graph(findings)

    assert [node.platform for node in graph.nodes] == ["GitHub"]


# --- Timeline --------------------------------------------------------


def test_timeline_orders_entries_and_computes_span():
    findings = [
        _finding("GitHub", creation_date="2011-09-03T15:26:22Z"),
        _finding("Reddit", creation_date="2020-01-01T00:00:00Z"),
    ]

    timeline = build_timeline(findings, now=_NOW)

    assert [entry.platform for entry in timeline.entries] == ["GitHub", "Reddit"]
    assert timeline.oldest_platform == "GitHub"
    assert timeline.newest_platform == "Reddit"
    assert timeline.span_years == 8.3
    assert timeline.dormant_old_accounts == ("GitHub",)


def test_timeline_ignores_unparseable_dates():
    findings = [
        _finding("GitHub", creation_date="2011-09-03T15:26:22Z"),
        _finding("Reddit", creation_date="hace mucho"),
        _finding("Steam"),
    ]

    timeline = build_timeline(findings, now=_NOW)

    assert [entry.platform for entry in timeline.entries] == ["GitHub"]


def test_timeline_is_empty_without_dates():
    assert build_timeline([_finding("GitHub")], now=_NOW) == build_timeline([], now=_NOW)


# --- Contactos reconstruidos ---------------------------------------


def test_masked_emails_from_two_sites_form_one_group():
    findings = [
        Finding(
            "Adobe",
            "other",
            None,
            None,
            CONFIRMED,
            75,
            ("holehe",),
            {"masked_email": "a***@e***.com"},
        ),
        Finding(
            "Spotify",
            "music",
            None,
            None,
            CONFIRMED,
            75,
            ("blackbird",),
            {"masked_email": "a***@e***.com"},
        ),
    ]

    contacts = reconstruct_contacts(findings, provided_email=None)

    assert len(contacts) == 1
    assert contacts[0].kind == "email"
    assert contacts[0].sources == ("blackbird", "holehe")
    assert contacts[0].count == 2
    assert contacts[0].consistent_with_provided is None


def test_provided_email_consistency_is_flagged():
    findings = [
        Finding(
            "Adobe",
            "other",
            None,
            None,
            CONFIRMED,
            75,
            ("holehe",),
            {"masked_email": "a***@example.com"},
        ),
    ]

    consistent = reconstruct_contacts(findings, provided_email="ada@example.com")
    inconsistent = reconstruct_contacts(findings, provided_email="bob@other.com")

    assert consistent[0].consistent_with_provided is True
    assert inconsistent[0].consistent_with_provided is False


def test_consistency_check_handles_non_length_preserving_masks():
    findings = [
        Finding(
            "Adobe",
            "other",
            None,
            None,
            CONFIRMED,
            75,
            ("holehe",),
            {"masked_email": "a***@e***.com"},
        ),
    ]

    match = reconstruct_contacts(findings, provided_email="ada@example.com")
    no_match = reconstruct_contacts(findings, provided_email="ada@example.org")

    assert match[0].consistent_with_provided is True
    assert no_match[0].consistent_with_provided is False


def test_malformed_provided_email_is_treated_as_inconsistent():
    findings = [
        Finding(
            "Adobe",
            "other",
            None,
            None,
            CONFIRMED,
            75,
            ("holehe",),
            {"masked_email": "a***@example.com"},
        ),
    ]

    contacts = reconstruct_contacts(findings, provided_email="not-an-email")

    assert contacts[0].consistent_with_provided is False


# --- Orquestación ---------------------------------------------------


def test_correlate_on_empty_findings_returns_empty_result():
    result = correlate([], now=_NOW)

    assert result.identity_graph.nodes == ()
    assert result.timeline.entries == ()
    assert result.reconstructed_contacts == ()
    assert result.to_dict()["timeline"]["span_years"] == 0.0
