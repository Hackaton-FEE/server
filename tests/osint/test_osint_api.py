"""Contrato HTTP del módulo OSINT con motores simulados (sin red)."""

from tests.osint.conftest import VALID_USERNAME_SCAN

SCANS = "/api/v1/osint/scans"


def _start(client, headers, **overrides):
    payload = {**VALID_USERNAME_SCAN, **overrides}
    return client.post(SCANS, json=payload, headers=headers)


def test_scan_requires_authentication(client):
    assert client.post(SCANS, json=VALID_USERNAME_SCAN).status_code == 401


def test_full_scan_flow_reaches_a_dashboard(client, headers):
    accepted = _start(client, headers)
    assert accepted.status_code == 202
    body = accepted.json()
    assert body["status"] == "QUEUED"
    scan_id = body["scan_id"]
    assert body["polling_url"] == f"{SCANS}/{scan_id}"
    assert body["events_url"] == f"{SCANS}/{scan_id}/events"

    status = client.get(f"{SCANS}/{scan_id}", headers=headers)
    assert status.status_code == 200
    status_body = status.json()
    assert status_body["status"] == "COMPLETED"
    assert status_body["progress_percentage"] == 100
    assert set(status_body["completed_engines"]) == {"blackbird", "maigret", "holehe", "ignorant"}

    results = client.get(f"{SCANS}/{scan_id}/results", headers=headers)
    assert results.status_code == 200
    dashboard = results.json()
    assert isinstance(dashboard["exposure_score"], int)
    assert dashboard["risk_level"] in {"LOW", "MODERATE", "ELEVATED", "HIGH"}
    assert dashboard["partial"] is False
    assert dashboard["summary"]["platforms_found"] >= 1
    assert dashboard["categories"]

    correlation = dashboard["correlation"]
    assert correlation is not None
    assert correlation["identity_graph"]["nodes"]
    assert correlation["timeline"]["oldest_platform"] == "GitHub"


def test_github_is_merged_across_engines(client, headers):
    scan_id = _start(client, headers).json()["scan_id"]
    dashboard = client.get(f"{SCANS}/{scan_id}/results", headers=headers).json()

    items = [item for cat in dashboard["categories"] for item in cat["items"]]
    github = next(item for item in items if item["platform"] == "GitHub")
    assert sorted(github["sources"]) == ["blackbird", "maigret"]
    assert github["confidence"] == 98
    assert github["details"]["location"] == "Portland, OR"


def test_email_target_runs_holehe(client, headers):
    scan_id = _start(client, headers, target_type="email", identifier="persona@example.com").json()[
        "scan_id"
    ]

    dashboard = client.get(f"{SCANS}/{scan_id}/results", headers=headers).json()
    assert "holehe" in dashboard["summary"]["engines_run"]
    platforms = {item["platform"] for cat in dashboard["categories"] for item in cat["items"]}
    assert "Adobe" in platforms

    contacts = dashboard["correlation"]["reconstructed_contacts"]
    assert any(c["kind"] == "email" for c in contacts)
    assert all(c["consistent_with_provided"] is False for c in contacts)


def test_phone_target_runs_ignorant(client, headers):
    scan_id = _start(
        client, headers, target_type="phone", identifier="+34611223344"
    ).json()["scan_id"]

    dashboard = client.get(f"{SCANS}/{scan_id}/results", headers=headers).json()
    assert "ignorant" in dashboard["summary"]["engines_run"]
    platforms = {item["platform"] for cat in dashboard["categories"] for item in cat["items"]}
    assert "Instagram" in platforms


def test_name_target_with_spaces_is_accepted(client, headers):
    response = _start(client, headers, target_type="name", identifier="Ada Lovelace")
    assert response.status_code == 202
    assert response.json()["status"] == "QUEUED"


def test_invalid_identifier_is_rejected(client, headers):
    response = _start(client, headers, identifier="tiene espacios y símbolos !!")
    assert response.status_code == 400
    assert response.json()["type"].endswith("/invalid-identifier")


def test_unsupported_target_type_is_rejected(client, headers):
    response = _start(client, headers, target_type="telefono")
    assert response.status_code == 400
    assert response.json()["type"].endswith("/unsupported-target-type")


def test_consent_is_required(client, headers):
    response = _start(client, headers, consent_self_audit=False)
    assert response.status_code == 400
    assert response.json()["type"].endswith("/consent-required")


def _consent_token(client, headers, email: str) -> str:
    token = client.post(
        "/api/v1/verification/email/request", json={"email": email}, headers=headers
    ).json()["verification_token"]
    return client.post(
        "/api/v1/verification/email/confirm",
        json={"verification_token": token, "code": "1234"},
        headers=headers,
    ).json()["consent_token"]


def test_third_party_email_scan_needs_a_consent_token(client, headers):
    response = _start(
        client, headers, target_type="email", identifier="tercero@example.com",
        consent_self_audit=False,
    )
    assert response.status_code == 400
    assert response.json()["type"].endswith("/consent-required")


def test_third_party_email_scan_with_valid_consent_token_runs(client, headers):
    email = "tercero@example.com"
    consent = _consent_token(client, headers, email)

    accepted = _start(
        client, headers, target_type="email", identifier=email,
        consent_self_audit=False, consent_token=consent,
    )
    assert accepted.status_code == 202
    scan_id = accepted.json()["scan_id"]
    assert client.get(f"{SCANS}/{scan_id}/results", headers=headers).status_code == 200


def test_consent_token_for_a_different_email_is_rejected(client, headers):
    consent = _consent_token(client, headers, "otro@example.com")

    response = _start(
        client, headers, target_type="email", identifier="victima@example.com",
        consent_self_audit=False, consent_token=consent,
    )
    assert response.status_code == 403
    assert response.json()["type"].endswith("/invalid-consent")


def test_consent_token_from_another_account_is_rejected(client, headers, other_headers):
    email = "tercero@example.com"
    consent = _consent_token(client, other_headers, email)

    response = _start(
        client, headers, target_type="email", identifier=email,
        consent_self_audit=False, consent_token=consent,
    )
    assert response.status_code == 403
    assert response.json()["type"].endswith("/invalid-consent")


def test_consent_token_is_only_valid_for_the_email_vector(client, headers):
    consent = _consent_token(client, headers, "tercero@example.com")

    response = _start(
        client, headers, target_type="username", identifier="algun_alias",
        consent_self_audit=False, consent_token=consent,
    )
    assert response.status_code == 400
    assert response.json()["type"].endswith("/invalid-identifier")


def test_tampered_consent_token_is_rejected(client, headers):
    consent = _consent_token(client, headers, "tercero@example.com")
    body, signature = consent.split(".")

    response = _start(
        client, headers, target_type="email", identifier="tercero@example.com",
        consent_self_audit=False, consent_token=f"{body[:-2]}00.{signature}",
    )
    assert response.status_code == 403


def test_scans_are_isolated_between_accounts(client, headers, other_headers):
    scan_id = _start(client, headers).json()["scan_id"]

    assert client.get(f"{SCANS}/{scan_id}", headers=other_headers).status_code == 404
    assert client.get(f"{SCANS}/{scan_id}/results", headers=other_headers).status_code == 404


def test_delete_is_idempotent(client, headers):
    scan_id = _start(client, headers).json()["scan_id"]

    assert client.delete(f"{SCANS}/{scan_id}", headers=headers).status_code == 204
    assert client.get(f"{SCANS}/{scan_id}", headers=headers).status_code == 404
    assert client.delete(f"{SCANS}/{scan_id}", headers=headers).status_code == 204


def test_results_are_not_cacheable(client, headers):
    scan_id = _start(client, headers).json()["scan_id"]
    results = client.get(f"{SCANS}/{scan_id}/results", headers=headers)
    assert results.headers["cache-control"] == "no-store"


def test_events_stream_emits_a_done_event(client, headers):
    scan_id = _start(client, headers).json()["scan_id"]

    response = client.get(f"{SCANS}/{scan_id}/events", headers=headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "event: done" in response.text


def test_unknown_scan_returns_404(client, headers):
    assert client.get(f"{SCANS}/does-not-exist", headers=headers).status_code == 404
