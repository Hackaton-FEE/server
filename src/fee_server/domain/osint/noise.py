"""Reducción de ruido: degrada `CONFIRMED` a `POTENTIAL_MATCH` cuando la única
evidencia es que un alias común existe en un sitio.

Un hallazgo se degrada solo si se cumplen las tres condiciones:

1. el alias es común (`is_common_username`);
2. no trae detalles que lo distingan (nombre real, ubicación, etc.);
3. no está enlazado a otra cuenta del escaneo en el grafo de identidad.
"""

from collections.abc import Sequence

from fee_server.domain.osint.correlation import IdentityGraph, node_id
from fee_server.domain.osint.findings import CONFIRMED, POTENTIAL_MATCH, Finding

# Heurística deliberadamente simple: el respaldo real es la corroboración.
_COMMON_USERNAME_STOPLIST: frozenset[str] = frozenset(
    {
        "admin",
        "administrator",
        "test",
        "test123",
        "user",
        "info",
        "support",
        "contact",
        "root",
        "guest",
        "demo",
        "default",
        "null",
        "anonymous",
        "unknown",
    }
)
_MIN_DISTINCTIVE_LENGTH = 8

# Detalles que distinguen un perfil. `linked_usernames` se excluye: es una
# afirmación del propio hallazgo y solo cuenta si el grafo la corrobora.
_RICH_DETAIL_KEYS = (
    "full_name",
    "location",
    "account_id",
    "company",
    "following_count",
    "repos_count",
    "bio_links",
    "image_gps_location",
    "image_camera_model",
    "image_taken_at",
)


def is_common_username(username: str) -> bool:
    """¿Es un alias con alta probabilidad de colisión entre personas distintas?"""
    normalized = username.strip().casefold()
    if not normalized or normalized in _COMMON_USERNAME_STOPLIST:
        return True
    if len(normalized) < _MIN_DISTINCTIVE_LENGTH:
        return True
    has_digit = any(ch.isdigit() for ch in normalized)
    has_separator = any(ch in "._-" for ch in normalized)
    return not (has_digit or has_separator)


def _has_rich_details(finding: Finding) -> bool:
    return any(key in finding.details for key in _RICH_DETAIL_KEYS)


# Compartir solo el `username` no corrobora: dos alias comunes idénticos se
# validarían entre sí.
_WEAK_LINK_ONLY_KEYS = frozenset({"username"})


def _strongly_linked_ids(graph: IdentityGraph) -> frozenset[str]:
    ids: set[str] = set()
    for edge in graph.edges:
        if set(edge.shared) - _WEAK_LINK_ONLY_KEYS:
            ids.add(edge.source)
            ids.add(edge.target)
    return frozenset(ids)


def demote_unlinked_common_usernames(
    findings: Sequence[Finding], graph: IdentityGraph
) -> list[Finding]:
    linked_ids = _strongly_linked_ids(graph)

    result: list[Finding] = []
    for finding in findings:
        if (
            finding.status == CONFIRMED
            and finding.username
            and is_common_username(finding.username)
            and not _has_rich_details(finding)
            and node_id(finding) not in linked_ids
        ):
            finding = finding.with_changes(status=POTENTIAL_MATCH)
        result.append(finding)
    return result
