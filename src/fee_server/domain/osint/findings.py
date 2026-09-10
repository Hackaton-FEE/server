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

# Claves permitidas dentro de `details`. Todo lo demás se descarta al normalizar.
DETAIL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "account_id",
        "full_name",
        "avatar_url",
        "creation_date",
        "location",
        "followers",
        "company",
        "masked_phone",
        "masked_email",
        "interests",
        "bio_links",
    }
)

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
    """Filtra `details` a la allowlist y descarta valores vacíos."""
    return {
        key: value
        for key, value in raw.items()
        if key in DETAIL_KEYS and value not in (None, "", [], {})
    }
