"""Enriquece hallazgos `CONFIRMED` con metadatos EXIF de su `avatar_url`.

Un avatar que falla nunca degrada el hallazgo ni el escaneo.
"""

import logging
from collections.abc import Sequence

from fee_server.core.config import Settings
from fee_server.domain.osint.findings import CONFIRMED, Finding
from fee_server.domain.osint.image_fetch import ImageFetcher, build_image_fetcher
from fee_server.domain.osint.image_metadata import extract_image_metadata

logger = logging.getLogger("fee_server.osint")


def _fetch_details(fetcher: ImageFetcher, url: str, cache: dict[str, dict]) -> dict:
    if url in cache:
        return cache[url]
    details: dict[str, object] = {}
    try:
        image_bytes = fetcher.fetch(url)
        if image_bytes:
            details = extract_image_metadata(image_bytes)
    except Exception:  # noqa: BLE001 - un avatar no puede tumbar el enriquecimiento
        logger.warning("enrichment: image-processing-failed")
    cache[url] = details
    return details


def enrich_with_image_metadata(findings: Sequence[Finding], settings: Settings) -> list[Finding]:
    """Devuelve una lista nueva; nunca muta los `Finding` de entrada."""
    fetcher = build_image_fetcher(settings)
    if fetcher is None:
        return list(findings)

    cache: dict[str, dict] = {}
    enriched: list[Finding] = []
    for finding in findings:
        url = finding.details.get("avatar_url")
        if finding.status != CONFIRMED or not isinstance(url, str) or not url:
            enriched.append(finding)
            continue
        extra = _fetch_details(fetcher, url, cache)
        if not extra:
            enriched.append(finding)
            continue
        enriched.append(finding.with_changes(details={**finding.details, **extra}))
    return enriched
