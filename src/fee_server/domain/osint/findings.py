"""El `Finding` canónico y sus valores permitidos.

Estructura inmutable: cada paso del pipeline (normalizar, deduplicar, puntuar)
devuelve nuevas instancias y nunca muta las anteriores.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Final

# Estado de un hallazgo.
CONFIRMED: Final = "CONFIRMED"
POTENTIAL_MATCH: Final = "POTENTIAL_MATCH"
RATE_LIMITED: Final = "RATE_LIMITED"

STATUS_STRENGTH: Final[dict[str, int]] = {
    RATE_LIMITED: 0,
    POTENTIAL_MATCH: 1,
    CONFIRMED: 2,
}

# Categorías de plataforma. `other` es el destino seguro ante lo desconocido.
CATEGORIES: Final[tuple[str, ...]] = (
    "social",
    "coding",
    "gaming",
    "music",
    "hobby",
    "finance",
    "adult",
    "other",
)

# Claves de `details` que circulan por el pipeline interno; el resto se descarta.
DETAIL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "account_id",
        "full_name",
        "avatar_url",
        "creation_date",
        "location",
        "followers",
        "following_count",
        "repos_count",
        "gists_count",
        "company",
        "masked_phone",
        "masked_email",
        "interests",
        "bio_links",
        "linked_usernames",
        "image_gps_location",
        "image_camera_model",
        "image_taken_at",
    }
)

# Solo para correlación y reducción de ruido; nunca se persisten ni se exponen.
_INTERNAL_ONLY_DETAIL_KEYS: Final[frozenset[str]] = frozenset({"linked_usernames"})

# Lo único que se persiste y se devuelve por HTTP.
PUBLIC_DETAIL_KEYS: Final[frozenset[str]] = DETAIL_KEYS - _INTERNAL_ONLY_DETAIL_KEYS

MAX_CONFIDENCE: Final = 100
CORROBORATION_BONUS: Final = 10
CORROBORATION_CEILING: Final = 98


@dataclass(frozen=True, slots=True)
class Finding:
    platform: str
    category: str
    url: str | None
    username: str | None
    status: str
    confidence: int
    sources: tuple[str, ...]
    details: Mapping[str, object] = field(default_factory=dict)

    def with_changes(self, **changes: object) -> "Finding":
        return replace(self, **changes)


def strongest_status(a: str, b: str) -> str:
    return a if STATUS_STRENGTH.get(a, 0) >= STATUS_STRENGTH.get(b, 0) else b


def clean_details(raw: Mapping[str, object]) -> dict[str, object]:
    """Filtra `details` a la allowlist interna y descarta valores vacíos."""
    return {
        key: value
        for key, value in raw.items()
        if key in DETAIL_KEYS and value not in (None, "", [], {})
    }


def project_public_details(details: Mapping[str, object]) -> dict[str, object]:
    """Recorta `details` a lo que puede salir del sistema (BD y respuesta HTTP)."""
    return {key: value for key, value in details.items() if key in PUBLIC_DETAIL_KEYS}
