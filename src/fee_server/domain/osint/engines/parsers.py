"""Conversión de la salida nativa de cada herramienta a `Finding[]`.

Funciones puras: reciben el texto crudo (JSON o CSV) y devuelven hallazgos sin
normalizar. La canonización de plataforma/categoría la hace `normalize`.
"""

import csv
import io
import json
import re
from collections.abc import Mapping

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

_MAIGRET_ID_MAP = {
    "uid": "account_id",
    "image": "avatar_url",
    "created_at": "creation_date",
    "location": "location",
    "fullname": "full_name",
    "company": "company",
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
    followers = ids.get("follower_count")
    if followers not in (None, ""):
        try:
            details["followers"] = int(followers)
        except (TypeError, ValueError):
            pass
    return details


def _first_tag(*tag_lists: object) -> str:
    for tags in tag_lists:
        if isinstance(tags, list) and tags:
            return str(tags[0])
    return "other"


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

        findings.append(
            Finding(
                platform=_MAIGRET_SOURCE_SUFFIX.sub("", str(status.get("site_name") or "")).strip(),
                category=_first_tag(status.get("tags"), site.get("tags")),
                url=status.get("url") or entry.get("url_user"),
                username=status.get("username") or username or entry.get("username"),
                status=state,
                confidence=confidence,
                sources=("maigret",),
                details=_maigret_details(ids),
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
                    None,
                    None,
                    CONFIRMED,
                    HOLEHE_CONFIDENCE,
                    ("holehe",),
                    _holehe_details(row),
                )
            )
    return findings
