"""Normalización de nombres de plataforma y categorías, y validación de entrada.

En la fase inicial es una tabla pequeña. Al conectar los motores reales crecerá
o se sustituirá por el catálogo de WhatsMyName.
"""

import re
from typing import Final

from fee_server.domain.osint.findings import CATEGORIES

# username: letras, dígitos y `._-`; 2 a 64.
_USERNAME_RE: Final = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
# email: validación pragmática, no un parser RFC 5322 completo.
_EMAIL_RE: Final = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[A-Za-z]{2,}$")

# Nombre canónico por clave normalizada (minúsculas, sin separadores).
_PLATFORM_CANONICAL: Final[dict[str, str]] = {
    "github": "GitHub",
    "githubgist": "GitHub Gist",
    "gitlab": "GitLab",
    "gitea": "Gitea",
    "reddit": "Reddit",
    "instagram": "Instagram",
    "tiktok": "TikTok",
    "wattpad": "Wattpad",
    "soundcloud": "SoundCloud",
    "spotify": "Spotify",
    "steam": "Steam",
    "duolingo": "Duolingo",
    "tumblr": "Tumblr",
    "adobe": "Adobe",
}

_CATEGORY_ALIASES: Final[dict[str, str]] = {
    "social": "social",
    "media": "social",
    "networking": "social",
    "coding": "coding",
    "tech": "coding",
    "business": "coding",
    "gaming": "gaming",
    "games": "gaming",
    "music": "music",
    "hobby": "hobby",
    "sport": "hobby",
    "finance": "finance",
    "crypto": "finance",
    "adult": "adult",
    "porn": "adult",
}

CATEGORY_COLORS: Final[dict[str, str]] = {
    "social": "#3B82F6",
    "coding": "#8B5CF6",
    "gaming": "#10B981",
    "music": "#EC4899",
    "hobby": "#F59E0B",
    "finance": "#EF4444",
    "adult": "#6B7280",
    "other": "#9CA3AF",
}


def is_valid_identifier(target_type: str, identifier: str) -> bool:
    if target_type == "username":
        return bool(_USERNAME_RE.match(identifier))
    if target_type == "email":
        return bool(_EMAIL_RE.match(identifier))
    return False


def canonical_platform(name: str) -> str:
    key = re.sub(r"[^a-z0-9]", "", name.lower())
    return _PLATFORM_CANONICAL.get(key, name.strip() or "Desconocida")


def canonical_category(*candidates: str) -> str:
    """Primera categoría reconocida entre las etiquetas de un motor, o `other`."""
    for candidate in candidates:
        mapped = _CATEGORY_ALIASES.get(candidate.strip().lower())
        if mapped in CATEGORIES:
            return mapped
    return "other"


def category_color(category: str) -> str:
    return CATEGORY_COLORS.get(category, CATEGORY_COLORS["other"])
