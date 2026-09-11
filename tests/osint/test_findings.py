"""Las dos fronteras de `details`: qué no es basura vs. qué sale del sistema."""

from fee_server.domain.osint.findings import clean_details, project_public_details


def test_clean_details_keeps_the_widened_allowlist_and_drops_empty_values():
    raw = {
        "full_name": "Ada Lovelace",
        "following_count": 12,
        "linked_usernames": ["otra_cuenta"],
        "location": "",
        "unknown_field": "se descarta",
    }

    cleaned = clean_details(raw)

    assert cleaned == {
        "full_name": "Ada Lovelace",
        "following_count": 12,
        "linked_usernames": ["otra_cuenta"],
    }


def test_project_public_details_drops_internal_only_keys():
    details = {
        "full_name": "Ada Lovelace",
        "bio_links": ["https://ada.example"],
        "linked_usernames": ["otra_cuenta"],
    }

    public = project_public_details(details)

    assert public == {
        "full_name": "Ada Lovelace",
        "bio_links": ["https://ada.example"],
    }
    assert "linked_usernames" not in public
