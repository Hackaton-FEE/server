"""Conversión de la salida nativa de cada herramienta a `Finding[]`.

Funciones puras: reciben el texto crudo (JSON o CSV) y devuelven hallazgos sin
normalizar. La canonización de plataforma/categoría la hace `normalize`.
"""

import csv
import io
import json
import re
from collections.abc import Mapping

from fee_server.domain.osint.catalog import is_valid_identifier
from fee_server.domain.osint.findings import (
    CONFIRMED,
    POTENTIAL_MATCH,
    RATE_LIMITED,
    Finding,
)

_MAIGRET_SOURCE_SUFFIX = re.compile(r"\s*\[[^\]]*\]\s*$")

BLACKBIRD_BASE_CONFIDENCE = 80
BLACKBIRD_METADATA_BONUS = 10
MAIGRET_WITH_IDS = 95
MAIGRET_WITHOUT_IDS = 85
MAIGRET_SIMILAR = 50
HOLEHE_CONFIDENCE = 75
IGNORANT_CONFIDENCE = 70

# Ignorant solo cubre Amazon, Instagram y Snapchat; su categoría es conocida.
_IGNORANT_CATEGORY: Mapping[str, str] = {
    "instagram": "social",
    "snapchat": "social",
    "amazon": "other",
}
# Línea de resultado de Ignorant con `--no-color`: `[+] instagram.com`,
# `[-] amazon.com` (no usado) o `[x] snapchat.com` (rate-limit). El token debe
# tener forma de dominio para no confundir la línea-leyenda que también empieza
# por `[+] Phone number used, [-] ...`.
_IGNORANT_LINE = re.compile(r"^\s*\[([+\-x])\]\s+([a-z0-9.-]+\.[a-z]{2,})\b", re.IGNORECASE)

_MAIGRET_ID_MAP = {
    "uid": "account_id",
    "image": "avatar_url",
    "created_at": "creation_date",
    "location": "location",
    "fullname": "full_name",
    "company": "company",
}
# Campos numéricos de `ids`; se castean a `int` igual que `follower_count`.
_MAIGRET_COUNT_MAP = {
    "follower_count": "followers",
    "following_count": "following_count",
    "public_repos_count": "repos_count",
    "public_gists_count": "gists_count",
}


def _empty(value: object) -> bool:
    return value in (None, "", [], {})


# --- Blackbird -------------------------------------------------------------


def _blackbird_details(metadata: object) -> dict[str, object]:
    if not isinstance(metadata, list):
        return {}
    details: dict[str, object] = {}
    for item in metadata:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).lower()
        value = item.get("value")
        if _empty(value):
            continue
        if "avatar" in name or item.get("type") == "Image":
            details.setdefault("avatar_url", value)
        elif name in ("name", "full name", "fullname", "real name"):
            details.setdefault("full_name", value)
        elif "location" in name:
            details.setdefault("location", value)
        elif name in ("courses", "interests", "languages"):
            details.setdefault("interests", value if isinstance(value, list) else [value])
    return details


def parse_blackbird_json(text: str, *, username: str | None) -> list[Finding]:
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("blackbird: se esperaba una lista JSON")

    findings: list[Finding] = []
    for entry in data:
        if not isinstance(entry, dict) or entry.get("status") != "FOUND":
            continue
        details = _blackbird_details(entry.get("metadata"))
        confidence = BLACKBIRD_BASE_CONFIDENCE + (BLACKBIRD_METADATA_BONUS if details else 0)
        findings.append(
            Finding(
                platform=str(entry.get("name", "")).strip(),
                category=str(entry.get("category") or "other"),
                url=entry.get("url"),
                username=username,
                status=CONFIRMED,
                confidence=confidence,
                sources=("blackbird",),
                details=details,
            )
        )
    return findings


# --- Maigret --------------------------------------------------------------


def _maigret_details(ids: Mapping[str, object]) -> dict[str, object]:
    details: dict[str, object] = {}
    for source_key, dest_key in _MAIGRET_ID_MAP.items():
        value = ids.get(source_key)
        if not _empty(value):
            details[dest_key] = value
    for source_key, dest_key in _MAIGRET_COUNT_MAP.items():
        value = ids.get(source_key)
        if value in (None, ""):
            continue
        try:
            details[dest_key] = int(value)
        except (TypeError, ValueError):
            pass
    return details


def _maigret_links(entry: Mapping[str, object]) -> dict[str, object]:
    """Munición de pivoteo que Maigret ya calcula (`ids_links`/`ids_usernames`).

    `bio_links` es público (son enlaces que el propio perfil expone); las
    cuentas relacionadas (`linked_usernames`) son solo internas — alimentan el
    grafo de identidad, nunca se persisten tal cual (`findings.py:
    PUBLIC_DETAIL_KEYS`).
    """
    details: dict[str, object] = {}
    links = entry.get("ids_links")
    if isinstance(links, list):
        urls = sorted({str(url).strip() for url in links if str(url).strip()})
        if urls:
            details["bio_links"] = urls

    # Maigret 0.6.5 devuelve {identificador: tipo}, NO {sitio: alias}.
    # Los valores "username", "gaia_id", etc. describen el tipo de consulta.
    # Solo las claves de tipo username pueden alimentar los motores de alias.
    usernames_map = entry.get("ids_usernames")
    if isinstance(usernames_map, dict):
        usernames = sorted(
            {
                alias.strip()
                for alias, id_type in usernames_map.items()
                if id_type == "username"
                and isinstance(alias, str)
                and is_valid_identifier("username", alias.strip())
                and alias.strip().casefold() != "username"
            },
            key=str.casefold,
        )
        if usernames:
            details["linked_usernames"] = usernames
    return details


def _first_tag(*tag_lists: object) -> str:
    for tags in tag_lists:
        if isinstance(tags, list) and tags:
            return str(tags[0])
    return "other"


def _site_username(*values: object) -> str | None:
    """Alias observado del servicio, sin tokens de plantilla ni conversiones de IDs."""
    for value in values:
        if not isinstance(value, str):
            continue
        value = value.strip()
        if value and value.casefold() != "username" and not any(c in value for c in "{}<>\r\n\t"):
            return value
    return None


def parse_maigret_simple_json(text: str, *, username: str | None = None) -> list[Finding]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("maigret: se esperaba un objeto JSON")

    findings: list[Finding] = []
    for entry in data.values():
        if not isinstance(entry, dict):
            continue
        status = entry.get("status") or {}
        if status.get("status") != "Claimed":
            continue

        ids = status.get("ids") or {}
        site = entry.get("site") or {}
        if entry.get("is_similar"):
            state, confidence = POTENTIAL_MATCH, MAIGRET_SIMILAR
        else:
            state = CONFIRMED
            confidence = MAIGRET_WITH_IDS if ids else MAIGRET_WITHOUT_IDS

        details = {**_maigret_details(ids), **_maigret_links(entry)}
        findings.append(
            Finding(
                platform=_MAIGRET_SOURCE_SUFFIX.sub("", str(status.get("site_name") or "")).strip(),
                category=_first_tag(status.get("tags"), site.get("tags")),
                url=status.get("url") or entry.get("url_user"),
                # ids.username describe la cuenta extraída en esta página.
                # status/entry.username suelen repetir el alias consultado.
                # Nunca tomar un alias de ids_usernames: puede ser de otra página.
                username=_site_username(
                    ids.get("username"), status.get("username"), entry.get("username")
                )
                or username,
                status=state,
                confidence=confidence,
                sources=("maigret",),
                details=details,
            )
        )
    return findings


# --- Holehe --------------------------------------------------------------


def _holehe_details(row: Mapping[str, str]) -> dict[str, object]:
    details: dict[str, object] = {}
    recovery = (row.get("emailrecovery") or "").strip()
    phone = (row.get("phoneNumber") or "").strip()
    if recovery:
        details["masked_email"] = recovery
    if phone:
        details["masked_phone"] = phone
    return details


def _holehe_url(row: Mapping[str, str]) -> str | None:
    domain = (row.get("domain") or "").strip()
    return f"https://{domain}" if domain else None


# --- Ignorant ----------------------------------------------------------


def _ignorant_platform(domain: str) -> str:
    return domain.split(".", 1)[0].strip().lower()


def parse_ignorant_output(text: str) -> list[Finding]:
    """Parsea el stdout de Ignorant (no genera fichero; solo imprime)."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for line in text.splitlines():
        match = _IGNORANT_LINE.match(line)
        if match is None:
            continue
        marker, domain = match.group(1), match.group(2)
        platform = _ignorant_platform(domain)
        if not platform or platform in seen:
            continue
        seen.add(platform)
        if marker == "x":
            findings.append(
                Finding(platform, "other", None, None, RATE_LIMITED, 0, ("ignorant",), {})
            )
        elif marker == "+":
            findings.append(
                Finding(
                    platform,
                    _IGNORANT_CATEGORY.get(platform, "other"),
                    None,
                    None,
                    CONFIRMED,
                    IGNORANT_CONFIDENCE,
                    ("ignorant",),
                    {},
                )
            )
    return findings


def parse_holehe_csv(text: str) -> list[Finding]:
    reader = csv.DictReader(io.StringIO(text))
    findings: list[Finding] = []
    for row in reader:
        name = (row.get("name") or "").strip()
        if not name:
            continue
        rate_limited = (row.get("rateLimit") or "").strip().lower() == "true"
        exists = (row.get("exists") or "").strip().lower() == "true"
        if rate_limited:
            findings.append(Finding(name, "other", None, None, RATE_LIMITED, 0, ("holehe",), {}))
        elif exists:
            findings.append(
                Finding(
                    name,
                    "other",
                    _holehe_url(row),
                    None,
                    CONFIRMED,
                    HOLEHE_CONFIDENCE,
                    ("holehe",),
                    _holehe_details(row),
                )
            )
    return findings
