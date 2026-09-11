"""Parsers de salida nativa a Finding[], contra capturas reales de laboratorio."""

import json
from pathlib import Path

from fee_server.domain.osint.engines.parsers import (
    IGNORANT_CONFIDENCE,
    parse_blackbird_json,
    parse_holehe_csv,
    parse_ignorant_output,
    parse_maigret_simple_json,
)
from fee_server.domain.osint.findings import CONFIRMED, POTENTIAL_MATCH, RATE_LIMITED

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text("utf-8")


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
    assert github.details["following_count"] == 0
    assert github.details["repos_count"] == 12
    assert github.details["gists_count"] == 1

    # El segundo sitio no trae ids -> confianza menor y sufijo de fuente limpio.
    gist = findings["GitHubGist"]
    assert gist.confidence == 85
    assert gist.details == {}


def test_maigret_extracts_pivoting_hints_from_ids_links_and_usernames():
    payload = json.dumps(
        {
            "SomeSite": {
                "ids_links": ["https://twitter.com/x", "https://twitter.com/x", ""],
                "ids_usernames": {"x_handle": "username", "123456": "gaia_id", "": "username"},
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

    assert finding.details["bio_links"] == ["https://twitter.com/x"]
    assert finding.details["linked_usernames"] == ["x_handle"]


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


def test_holehe_rate_limited_rows_become_rate_limited_findings():
    findings = parse_holehe_csv(_fixture("holehe_contact_github.csv"))

    assert findings
    assert all(f.status == RATE_LIMITED for f in findings)
    assert all(f.confidence == 0 for f in findings)


def test_holehe_confirmed_rows_extract_masked_contacts():
    findings = {f.platform: f for f in parse_holehe_csv(_fixture("holehe_confirmed.csv"))}

    assert findings["imgur"].status == CONFIRMED
    assert findings["imgur"].confidence == 75
    assert findings["imgur"].url == "https://imgur.com"
    assert findings["lastpass"].details["masked_email"] == "jo****@gmail.com"
    assert findings["twitter"].details["masked_phone"] == "+1********89"
    assert "caringbridge" not in findings  # exists == False
    assert findings["spotify"].status == RATE_LIMITED
    assert findings["spotify"].url is None


_IGNORANT_STDOUT = """\
Twitter : @palenath
*************************
   +34 611223344
*************************
[+] instagram.com
[-] amazon.com
[x] snapchat.com

[+] Phone number used, [-] Phone number not used, [x] Rate limit
3 websites checked in 0.03 seconds
"""


def test_ignorant_stdout_maps_markers_to_statuses():
    findings = {f.platform: f for f in parse_ignorant_output(_IGNORANT_STDOUT)}

    assert findings["instagram"].status == CONFIRMED
    assert findings["instagram"].confidence == IGNORANT_CONFIDENCE
    assert findings["instagram"].category == "social"
    assert findings["instagram"].sources == ("ignorant",)
    assert findings["snapchat"].status == RATE_LIMITED
    assert findings["snapchat"].confidence == 0
    assert "amazon" not in findings  # `[-]` no usado no genera hallazgo
    # La línea-leyenda `[+] Phone number used, [-] ...` no debe colarse.
    assert "phone" not in findings
    assert "rate" not in findings


def test_ignorant_ignores_noise_and_deduplicates():
    text = "cabecera irrelevante\n[+] instagram.com\n[+] instagram.com\n"

    findings = parse_ignorant_output(text)

    assert [f.platform for f in findings] == ["instagram"]


def test_ignorant_empty_output_yields_nothing():
    assert parse_ignorant_output("") == []


def test_maigret_preserves_the_account_username_of_each_service():
    payload = {
        "ServiceOne": {
            "username": "client_seed",
            "ids_usernames": {"external_link": "username"},
            "status": {
                "status": "Claimed",
                "site_name": "ServiceOne",
                "username": "client_seed",
                "ids": {"username": "client_on_one"},
            },
        },
        "ServiceTwo": {
            "status": {
                "status": "Claimed",
                "site_name": "ServiceTwo",
                "username": "client_seed",
                "ids": {"username": "client_on_two"},
            },
        },
    }
    findings = parse_maigret_simple_json(json.dumps(payload), username="client_seed")
    assert [(f.platform, f.username) for f in findings] == [
        ("ServiceOne", "client_on_one"),
        ("ServiceTwo", "client_on_two"),
    ]
    assert findings[0].details["linked_usernames"] == ["external_link"]


def test_maigret_uses_report_username_before_search_fallback():
    payload = {
        "Service": {
            "username": "reported_alias",
            "status": {"status": "Claimed", "site_name": "Service", "ids": {}},
        }
    }
    assert (
        parse_maigret_simple_json(json.dumps(payload), username="seed")[0].username
        == "reported_alias"
    )


def test_maigret_scraped_templates_do_not_replace_client_username():
    payload = {
        "Service": {
            "username": "{username}",
            "ids_usernames": {
                "actual_link": "username",
                "username": "username",
                "{username}": "username",
                "not_a_handle": "gaia_id",
                "wrong_shape": {"type": "username"},
            },
            "status": {
                "status": "Claimed",
                "site_name": "Service",
                "username": "username",
                "ids": {"username": "{username}"},
            },
        }
    }
    finding = parse_maigret_simple_json(json.dumps(payload), username="client_seed")[0]
    assert finding.username == "client_seed"
    assert finding.details["linked_usernames"] == ["actual_link"]
