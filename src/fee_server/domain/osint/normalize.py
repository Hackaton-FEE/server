"""Normalización a esquema canónico y deduplicación entre motores."""

from collections.abc import Iterable

from fee_server.domain.osint.catalog import canonical_category, canonical_platform
from fee_server.domain.osint.findings import (
    CORROBORATION_BONUS,
    CORROBORATION_CEILING,
    RATE_LIMITED,
    Finding,
    clean_details,
    strongest_status,
)

# Prioridad al fusionar `details`: el motor más profundo gana ante un conflicto.
_ENGINE_DEPTH = {"maigret": 3, "blackbird": 2, "holehe": 1}


def normalize(finding: Finding) -> Finding:
    """Aplica nombres canónicos y filtra `details` a la allowlist."""
    return finding.with_changes(
        platform=canonical_platform(finding.platform),
        category=canonical_category(finding.category),
        sources=tuple(sorted(set(finding.sources))),
        details=clean_details(finding.details),
    )


def _merge_key(finding: Finding) -> tuple[str, str]:
    return (finding.platform.casefold(), (finding.username or "").casefold())


def _deepest_source(finding: Finding) -> int:
    return max((_ENGINE_DEPTH.get(source, 0) for source in finding.sources), default=0)


def _combine(existing: Finding, incoming: Finding) -> Finding:
    sources = tuple(sorted(set(existing.sources) | set(incoming.sources)))
    confidence = max(existing.confidence, incoming.confidence)
    if len(sources) >= 2:
        confidence = min(CORROBORATION_CEILING, confidence + CORROBORATION_BONUS)

    if _deepest_source(incoming) >= _deepest_source(existing):
        details = {**existing.details, **incoming.details}
    else:
        details = {**incoming.details, **existing.details}

    return existing.with_changes(
        status=strongest_status(existing.status, incoming.status),
        confidence=confidence,
        sources=sources,
        details=details,
        url=existing.url or incoming.url,
        category=existing.category if existing.category != "other" else incoming.category,
    )


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Fusiona hallazgos por (plataforma, username).

    Un hallazgo `RATE_LIMITED` se descarta si otro motor confirmó la misma
    plataforma; se conserva cuando es la única señal disponible.
    """
    merged: dict[tuple[str, str], Finding] = {}
    for raw in findings:
        finding = normalize(raw)
        key = _merge_key(finding)
        merged[key] = _combine(merged[key], finding) if key in merged else finding

    platforms_confirmed = {
        finding.platform.casefold() for finding in merged.values() if finding.status != RATE_LIMITED
    }
    result = [
        finding
        for finding in merged.values()
        if finding.status != RATE_LIMITED or finding.platform.casefold() not in platforms_confirmed
    ]
    result.sort(key=lambda f: (-f.confidence, f.platform.casefold()))
    return result
