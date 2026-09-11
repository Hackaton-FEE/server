"""Reducción de ruido: degradar `CONFIRMED` solo cuando fallan las tres
condiciones a la vez (alias común, sin datos ricos, sin corroboración)."""

import pytest

from fee_server.domain.osint.correlation import build_identity_graph
from fee_server.domain.osint.findings import CONFIRMED, POTENTIAL_MATCH, Finding
from fee_server.domain.osint.noise import demote_unlinked_common_usernames, is_common_username


def _finding(username: str, **details) -> Finding:
    return Finding(
        platform="Site",
        category="other",
        url=None,
        username=username,
        status=CONFIRMED,
        confidence=80,
        sources=("blackbird",),
        details=details,
    )


@pytest.mark.parametrize(
    ("username", "expected"),
    [
        ("admin", True),
        ("test", True),
        ("mike12", True),  # < 8 caracteres
        ("mikemiller", True),  # sin dígitos ni separadores
        ("mike_miller_92", False),
        ("gh0stx92_zzt", False),
    ],
)
def test_is_common_username(username, expected):
    assert is_common_username(username) is expected


def test_common_alias_without_evidence_is_demoted():
    findings = [_finding("mikemiller")]
    graph = build_identity_graph(findings)

    result = demote_unlinked_common_usernames(findings, graph)

    assert result[0].status == POTENTIAL_MATCH


def test_common_alias_with_rich_details_is_not_demoted():
    findings = [_finding("mikemiller", full_name="Mike Miller")]
    graph = build_identity_graph(findings)

    result = demote_unlinked_common_usernames(findings, graph)

    assert result[0].status == CONFIRMED


def test_common_alias_referenced_by_another_accounts_bio_is_not_demoted():
    """B no tiene datos ricos propios, pero A lo enlaza explícitamente en su
    bio (`linked_usernames`) — eso sí es corroboración real, no circular."""
    a = _finding("richprofile99", linked_usernames=["mikemiller"])
    b = _finding("mikemiller")
    graph = build_identity_graph([a, b])

    result = demote_unlinked_common_usernames([a, b], graph)

    b_result = next(f for f in result if f.username == "mikemiller")
    assert b_result.status == CONFIRMED


def test_sharing_only_the_same_common_username_does_not_corroborate():
    """Dos hallazgos con el mismo alias común, sin ningún otro dato — la
    coincidencia de username por sí sola no debe "salvarse a sí misma"."""
    a = _finding("mikemiller")
    b = Finding("OtherSite", "other", None, "mikemiller", CONFIRMED, 80, ("maigret",), {})
    graph = build_identity_graph([a, b])

    result = demote_unlinked_common_usernames([a, b], graph)

    assert all(f.status == POTENTIAL_MATCH for f in result)


def test_claiming_a_link_to_nobody_in_the_scan_does_not_save_from_demotion():
    """`linked_usernames` es una afirmación propia del hallazgo, no evidencia:
    si el username referenciado no corresponde a ninguna otra cuenta real del
    escaneo, no cuenta como "perfil rico" ni como corroboración."""
    findings = [_finding("mikemiller", linked_usernames=["nonexistent_user_not_in_scan"])]
    graph = build_identity_graph(findings)

    result = demote_unlinked_common_usernames(findings, graph)

    assert result[0].status == POTENTIAL_MATCH


def test_distinctive_alias_without_evidence_is_not_demoted():
    findings = [_finding("gh0stx92_zzt")]
    graph = build_identity_graph(findings)

    result = demote_unlinked_common_usernames(findings, graph)

    assert result[0].status == CONFIRMED


def test_potential_match_findings_are_left_untouched():
    from fee_server.domain.osint.findings import POTENTIAL_MATCH as PM

    finding = Finding("Site", "other", None, "mike", PM, 50, ("maigret",), {})
    graph = build_identity_graph([finding])

    result = demote_unlinked_common_usernames([finding], graph)

    assert result[0].status == PM
