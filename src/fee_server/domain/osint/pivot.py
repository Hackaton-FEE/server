"""Extracción de candidatos de pivoteo a partir de `linked_usernames`.

Función pura, sin red: decide qué alias nuevos merece la pena consultar en una
segunda pasada, a partir de lo que los motores ya descubrieron en la primera.
Los candidatos vienen de datos raspados de un sitio de terceros (la bio de un
perfil) — una frontera de confianza distinta a la del propio usuario — así que
se validan con el mismo patrón estricto que un identificador enviado por API
antes de que lleguen a tocar un subproceso.
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

    Solo mira hallazgos `CONFIRMED` (un `POTENTIAL_MATCH`/`RATE_LIMITED` no es
    evidencia suficiente para gastar otro escaneo). Orden alfabético
    determinista antes de recortar al tope.
    """
    excluded = {alias.strip().casefold() for alias in already_queried if alias.strip()}
    # No pivotear hacia un alias que la Fase 1 ya confirmó por su cuenta —
    # sería repetir trabajo sobre una cuenta que el escaneo ya resolvió.
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
            # This is scraped metadata, not a client-supplied alias. Some
            # extractors expose the literal template token as a linked handle.
            # Never expand that token into a new, unrelated identity search.
            if not isinstance(raw, str):
                continue
            candidate = raw.strip()
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
