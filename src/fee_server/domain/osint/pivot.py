"""Extracción de candidatos de pivoteo a partir de `linked_usernames`.

Los candidatos provienen de datos raspados de terceros, así que se validan con
el mismo patrón que un identificador recibido por la API.
"""

from collections.abc import Sequence

from fee_server.domain.osint.catalog import is_valid_identifier
from fee_server.domain.osint.findings import CONFIRMED, Finding


def extract_pivot_candidates(
    findings: Sequence[Finding],
    already_queried: Sequence[str],
    max_candidates: int,
) -> tuple[str, ...]:
    """Alias nuevos a consultar, deduplicados, validados y acotados.

    Solo considera hallazgos `CONFIRMED`; el orden alfabético hace el recorte
    determinista.
    """
    excluded = {alias.strip().casefold() for alias in already_queried if alias.strip()}
    # Tampoco se pivotea hacia alias que la Fase 1 ya confirmó.
    excluded |= {
        finding.username.strip().casefold()
        for finding in findings
        if finding.status == CONFIRMED and finding.username and finding.username.strip()
    }
    candidates: dict[str, str] = {}  # casefold -> forma original (para consultar el sitio)

    for finding in findings:
        if finding.status != CONFIRMED:
            continue
        linked = finding.details.get("linked_usernames")
        if not isinstance(linked, list):
            continue
        for raw in linked:
            if not isinstance(raw, str):
                continue
            candidate = raw.strip()
            # Algunos extractores exponen el token de plantilla como alias.
            if candidate.casefold() == "username":
                continue
            key = candidate.casefold()
            if not candidate or key in excluded or key in candidates:
                continue
            if not is_valid_identifier("username", candidate):
                continue
            candidates[key] = candidate

    ordered = sorted(candidates.values(), key=str.casefold)
    return tuple(ordered[:max_candidates])
