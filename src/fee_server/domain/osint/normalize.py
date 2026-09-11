"""Normalización a esquema canónico y deduplicación entre motores."""

from collections.abc import Iterable
from urllib.parse import unquote, urlsplit

from fee_server.domain.osint.catalog import canonical_category, canonical_platform
from fee_server.domain.osint.findings import (
    CONFIRMED,
    CORROBORATION_BONUS,
    CORROBORATION_CEILING,
    RATE_LIMITED,
    Finding,
    clean_details,
    strongest_status,
)

# Prioridad al fusionar `details`: el motor más profundo gana ante un conflicto.
_ENGINE_DEPTH = {"maigret": 3, "blackbird": 2, "holehe": 1, "ignorant": 1}


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


def _profile_url(finding: Finding) -> tuple[str, str] | None:
    if finding.status != CONFIRMED or not finding.username or not finding.url:
        return None
    try:
        parts = urlsplit(finding.url)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.netloc
            or not parts.path.strip("/")
            or parts.username
            or parts.password
        ):
            return None
    except ValueError:
        return None
    # Solo URLs idénticas: no deducir redirecciones ni equivalencia de rutas.
    return finding.platform.casefold(), finding.url


def _merge_same_profile_urls(findings: Iterable[Finding]) -> list[Finding]:
    groups: dict[tuple[str, str], list[Finding]] = {}
    result: list[Finding] = []
    for finding in findings:
        key = _profile_url(finding)
        if key is None:
            result.append(finding)
        else:
            groups.setdefault(key, []).append(finding)
    for (_, url), accounts in groups.items():
        segments = {
            part.removeprefix("@").casefold() for part in unquote(urlsplit(url).path).split("/")
        }
        # Una ruta genérica no vincula dos alias. Exigir que la URL identifique
        # explícitamente al menos uno de ellos, como /user/alias o /@alias.
        if len(accounts) == 1 or not any(
            account.username.casefold() in segments for account in accounts
        ):
            result.extend(accounts)
            continue
        preferred = max(accounts, key=_deepest_source)
        combined = preferred
        for account in accounts:
            if account is not preferred:
                combined = _combine(combined, account)
        result.append(combined)
    return result


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

    profiles = _merge_same_profile_urls(merged.values())
    platforms_confirmed = {
        finding.platform.casefold() for finding in profiles if finding.status != RATE_LIMITED
    }
    result = [
        finding
        for finding in profiles
        if finding.status != RATE_LIMITED or finding.platform.casefold() not in platforms_confirmed
    ]
    result.sort(key=lambda f: (-f.confidence, f.platform.casefold()))
    return result
