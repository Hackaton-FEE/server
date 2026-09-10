"""Parsers de salida nativa a Finding[], contra capturas reales de laboratorio."""

import json
from pathlib import Path

from fee_server.domain.osint.engines.parsers import (
    parse_blackbird_json,
    parse_holehe_csv,
    parse_maigret_simple_json,
)
from fee_server.domain.osint.findings import CONFIRMED, POTENTIAL_MATCH, RATE_LIMITED

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text("utf-8")


# --- Blackbird ----------------------------------------------------------


def test_blackbird_keeps_only_found_entries():
    findings = parse_blackbird_json(
        _fixture("blackbird_testuser12345.json"), username="testuser12345"
    )

    assert findings
    assert all(f.status == CONFIRMED for f in findings)
    assert all(f.sources == ("blackbird",) for f in findings)
    assert all(f.username == "testuser12345" for f in findings)
    platforms = {f.platform for f in findings}
    assert {"GitLab", "SoundCloud", "Wattpad"} <= platforms


def test_blackbird_metadata_raises_confidence():
    payload = json.dumps(
        [
            {
                "name": "Duolingo",
                "url": "https://duolingo.com/x",
                "category": "hobby",
                "status": "FOUND",
                "metadata": [{"type": "Image", "name": "Avatar", "value": "https://img/x.png"}],
            },
            {
                "name": "Reddit",
                "url": "https://reddit.com/u/x",
                "category": "social",
                "status": "FOUND",
                "metadata": None,
            },
        ]
    )

    by_platform = {f.platform: f for f in parse_blackbird_json(payload, username="x")}

    assert by_platform["Duolingo"].confidence == 90
    assert by_platform["Duolingo"].details["avatar_url"] == "https://img/x.png"
    assert by_platform["Reddit"].confidence == 80


# --- Maigret -----------------------------------------------------------


def test_maigret_simple_report_yields_confirmed_findings_with_ids():
    findings = {
        f.platform: f for f in parse_maigret_simple_json(_fixture("maigret_torvalds_simple.json"))
    }

    github = findings["GitHub"]
    assert github.status == CONFIRMED
    assert github.confidence == 95
    assert github.username == "torvalds"
    assert github.details["account_id"] == "1024025"
    assert github.details["full_name"] == "Linus Torvalds"
    assert github.details["location"] == "Portland, OR"
    assert github.details["followers"] == 321694

    # El segundo sitio no trae ids -> confianza menor y sufijo de fuente limpio.
    gist = findings["GitHubGist"]
    assert gist.confidence == 85
    assert gist.details == {}


def test_maigret_similar_match_is_a_potential_match():
    payload = json.dumps(
        {
            "SomeSite": {
                "is_similar": True,
                "status": {
                    "status": "Claimed",
                    "site_name": "SomeSite",
                    "url": "https://s/x",
                    "ids": {},
                    "username": "x",
                    "tags": ["social"],
                },
            }
        }
    )

    finding = parse_maigret_simple_json(payload)[0]

    assert finding.status == POTENTIAL_MATCH
    assert finding.confidence == 50


# --- Holehe ----------------------------------------------------------


def test_holehe_rate_limited_rows_become_rate_limited_findings():
    findings = parse_holehe_csv(_fixture("holehe_contact_github.csv"))

    assert findings
    assert all(f.status == RATE_LIMITED for f in findings)
    assert all(f.confidence == 0 for f in findings)


def test_holehe_confirmed_rows_extract_masked_contacts():
    findings = {f.platform: f for f in parse_holehe_csv(_fixture("holehe_confirmed.csv"))}

    assert findings["imgur"].status == CONFIRMED
    assert findings["imgur"].confidence == 75
    assert findings["lastpass"].details["masked_email"] == "jo****@gmail.com"
    assert findings["twitter"].details["masked_phone"] == "+1********89"
    assert "caringbridge" not in findings  # exists == False
    assert findings["spotify"].status == RATE_LIMITED
