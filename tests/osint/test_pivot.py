"""Extracción de candidatos de pivoteo a partir de `linked_usernames`."""

from fee_server.domain.osint.findings import CONFIRMED, POTENTIAL_MATCH, RATE_LIMITED, Finding
from fee_server.domain.osint.pivot import extract_pivot_candidates


def _finding(status=CONFIRMED, linked=None, username="origin_alias", platform="Site") -> Finding:
    details = {"linked_usernames": linked} if linked is not None else {}
    return Finding(platform, "other", None, username, status, 90, ("maigret",), details)


def test_no_findings_yields_no_candidates():
    assert extract_pivot_candidates([], already_queried=(), max_candidates=3) == ()


def test_findings_without_linked_usernames_yield_no_candidates():
    findings = [_finding()]
    assert extract_pivot_candidates(findings, already_queried=(), max_candidates=3) == ()


def test_candidates_are_deduplicated_case_insensitively():
    findings = [
        _finding(linked=["Ghost_Handle"]),
        _finding(linked=["ghost_handle"]),
    ]

    candidates = extract_pivot_candidates(findings, already_queried=(), max_candidates=3)

    assert candidates == ("Ghost_Handle",)


def test_already_queried_usernames_are_excluded():
    findings = [_finding(linked=["origin_alias", "new_handle"])]

    candidates = extract_pivot_candidates(
        findings, already_queried=("Origin_Alias",), max_candidates=3
    )

    assert candidates == ("new_handle",)


def test_invalid_username_format_is_rejected():
    findings = [_finding(linked=["has spaces", "valid_handle"])]

    candidates = extract_pivot_candidates(findings, already_queried=(), max_candidates=3)

    assert candidates == ("valid_handle",)


def test_result_is_capped_and_alphabetically_sorted():
    findings = [_finding(linked=["charlie_h", "alpha_h", "bravo_h", "delta_h"])]

    candidates = extract_pivot_candidates(findings, already_queried=(), max_candidates=2)

    assert candidates == ("alpha_h", "bravo_h")


def test_an_alias_already_confirmed_elsewhere_in_the_scan_is_not_repeated():
    """Si la Fase 1 ya resolvió esa cuenta por su cuenta, no vale la pena
    volver a consultarla en la Fase 2 solo porque otro perfil la menciona."""
    findings = [
        _finding(linked=["richprofile99"]),
        _finding(username="richprofile99", platform="OtherSite", linked=None),
    ]

    candidates = extract_pivot_candidates(findings, already_queried=(), max_candidates=3)

    assert candidates == ()


def test_non_confirmed_findings_are_ignored():
    findings = [
        _finding(status=POTENTIAL_MATCH, linked=["from_potential"]),
        _finding(status=RATE_LIMITED, linked=["from_rate_limited"]),
    ]

    assert extract_pivot_candidates(findings, already_queried=(), max_candidates=3) == ()
