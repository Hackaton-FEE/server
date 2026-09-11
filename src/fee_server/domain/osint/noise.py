"""Reducción de ruido: degrada `CONFIRMED` a `POTENTIAL_MATCH` cuando la única
evidencia es "un alias común existe en un sitio".

"La cuenta existe" no prueba "es tuya" cuando el alias es genérico — sitios
distintos pueden tener personas distintas con el mismo nombre de usuario. Un
hallazgo se degrada solo si fallan **las tres** condiciones a la vez (regla
conservadora, evita degradar de más):

1. el alias es común (heurística, ver `is_common_username`);
2. no trae ningún detalle que lo distinga (nombre real, ubicación, etc.);
3. no está enlazado a ninguna otra cuenta del escaneo en el grafo de identidad.

Si cualquiera de las tres falla (alias raro, o datos ricos, o corroborado por
otra cuenta), el hallazgo se queda `CONFIRMED`. Función pura: devuelve una
lista nueva, nunca muta las entradas.
"""

from collections.abc import Sequence

from fee_server.domain.osint.correlation import IdentityGraph, node_id
from fee_server.domain.osint.findings import CONFIRMED, POTENTIAL_MATCH, Finding

# Heurística conservadora y deliberadamente imperfecta: el respaldo real de
# esta regla es la corroboración (condiciones 2 y 3), no esta lista sola.
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

# Cualquiera de estas claves en `details` cuenta como "perfil rico": ya no es
# un simple "FOUND" pelón, hay algo específico que lo distingue.
#
# `linked_usernames` queda fuera a propósito: es una afirmación del propio
# hallazgo ("enlazo a esta otra cuenta"), no un dato autodescriptivo como
# `full_name`/`location` — sin verificar que el username referenciado exista
# de verdad en el escaneo, "digo que enlazo a alguien" no prueba nada. Esa
# verificación ya la hace la condición 3 (`_strongly_linked_ids`, que exige
# que el grafo haya formado una arista real); contarlo aquí también dejaría
# que cualquier hallazgo se auto-declarara "rico" sin corroboración genuina.
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


# Toda cuenta comparte el propio `username` como clave de enlace en el grafo
# (`correlation.py::_linking_values`), útil para mostrar "usas el mismo alias
# aquí y allá". Pero para la reducción de ruido esa coincidencia por sí sola
# es circular: dos alias comunes idénticos "se corroborarían" solo por serlo,
# justo lo que esta regla intenta filtrar. Una arista solo cuenta como
# corroboración real si trae evidencia además del username compartido.
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
