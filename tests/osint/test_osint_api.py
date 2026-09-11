"""Contrato HTTP del módulo OSINT con motores simulados (sin red)."""

import json

from fee_server.domain.osint import runner
from fee_server.domain.osint.engines import ENGINE_ERROR, ENGINE_OK, EngineResult
from fee_server.domain.osint.findings import CONFIRMED, Finding
from tests.osint.conftest import VALID_USERNAME_SCAN

SCANS = "/api/v1/osint/scans"


def test_failed_scan_remains_readable_without_claiming_complete_coverage(
    client, headers, monkeypatch
):
    def unavailable(_settings):
        raise RuntimeError("engines unavailable")

    monkeypatch.setattr(runner, "build_engines", unavailable)
    scan_id = _start(client, headers).json()["scan_id"]
    response = client.get(f"{SCANS}/{scan_id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "FAILED"
    assert response.json()["error_category"] == "engines-unavailable"
    dashboard = client.get(f"{SCANS}/{scan_id}/results", headers=headers)
    assert dashboard.status_code == 200
    assert dashboard.json()["coverage"] == "none"
    assert dashboard.json()["partial"] is True


def test_name_without_supported_inputs_reports_no_coverage(client, headers):
    scan_id = _start(client, headers, target_type="name", identifier="Persona Ejemplo").json()[
        "scan_id"
    ]
    body = client.get(f"{SCANS}/{scan_id}/results", headers=headers).json()
    assert body["coverage"] == "none"
    assert body["partial"] is True
    assert all(engine["status"] == "skipped" for engine in body["engines"].values())


def test_successful_pivot_does_not_hide_an_earlier_engine_failure(client, headers, monkeypatch):
    class RecoveringEngine:
        name = "blackbird"

        def run(self, request):
            if "pivot_target_99" in request.usernames:
                return EngineResult(self.name, ENGINE_OK, ())
            return EngineResult(self.name, ENGINE_ERROR, (), "timeout")

    monkeypatch.setattr(
        runner, "build_engines", lambda _s: (_DiscoveryEngine(), RecoveringEngine())
    )
    scan_id = _start(client, headers).json()["scan_id"]
    body = client.get(f"{SCANS}/{scan_id}/results", headers=headers).json()
    assert body["coverage"] == "partial"
    assert body["partial"] is True
    assert body["engines"]["blackbird"]["status"] == "error"
    assert body["engines"]["blackbird"]["runs"] == 2
    assert body["engines"]["blackbird"]["error_category"] == "timeout"


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


class _DiscoveryEngine:
    """Fase 1: encuentra el alias original y descubre uno relacionado."""

    name = "maigret"

    def run(self, request):
        if "alias_de_prueba" not in request.usernames:
            return EngineResult(self.name, ENGINE_OK, ())
        finding = Finding(
            "GitHub",
            "coding",
            None,
            "alias_de_prueba",
            CONFIRMED,
            90,
            ("maigret",),
            {"full_name": "Ada Lovelace", "linked_usernames": ["pivot_target_99"]},
        )
        return EngineResult(self.name, ENGINE_OK, (finding,))


class _PivotAwareEngine:
    """Solo encuentra algo cuando se le consulta el alias pivotado (Fase 2)."""

    name = "blackbird"

    def run(self, request):
        if "pivot_target_99" not in request.usernames:
            return EngineResult(self.name, ENGINE_OK, ())
        finding = Finding(
            "GitLab", "coding", None, "pivot_target_99", CONFIRMED, 80, ("blackbird",), {}
        )
        return EngineResult(self.name, ENGINE_OK, (finding,))


def test_pivoted_findings_reach_results_without_leaking_linked_usernames(
    client, headers, monkeypatch
):
    monkeypatch.setattr(
        runner, "build_engines", lambda _s: (_DiscoveryEngine(), _PivotAwareEngine())
    )

    scan_id = _start(client, headers).json()["scan_id"]
    dashboard = client.get(f"{SCANS}/{scan_id}/results", headers=headers).json()

    items = [item for cat in dashboard["categories"] for item in cat["items"]]
    platforms = {item["platform"] for item in items}
    assert "GitLab" in platforms  # el hallazgo pivotado llegó al dashboard

    # `linked_usernames` es interno: puede aparecer como *nombre* de evidencia
    # en la arista del grafo (documentado, esperado), pero nunca como campo
    # crudo dentro de ningún `details` de hallazgo.
    assert all("linked_usernames" not in item["details"] for item in items)

    edges = dashboard["correlation"]["identity_graph"]["edges"]
    assert any(edge["shared"] == ["linked_usernames"] for edge in edges)


class _LinkedUsernamesEngine:
    """Simula un motor que descubre `linked_usernames` (dato interno)."""

    name = "maigret"

    def run(self, request):
        finding = Finding(
            "GitHub",
            "coding",
            None,
            "alias_de_prueba",
            CONFIRMED,
            90,
            ("maigret",),
            {"full_name": "Ada Lovelace", "linked_usernames": ["otra_cuenta"]},
        )
        return EngineResult(self.name, ENGINE_OK, (finding,))


def test_internal_only_details_never_reach_the_api_response(client, headers, monkeypatch):
    monkeypatch.setattr(runner, "build_engines", lambda _s: (_LinkedUsernamesEngine(),))

    scan_id = _start(client, headers).json()["scan_id"]
    dashboard = client.get(f"{SCANS}/{scan_id}/results", headers=headers).json()

    # `linked_usernames` alimentó el grafo de identidad, pero nunca debe
    # aparecer como campo crudo en ningún `details` de la respuesta.
    assert "linked_usernames" not in json.dumps(dashboard)
    items = [item for cat in dashboard["categories"] for item in cat["items"]]
    github = next(item for item in items if item["platform"] == "GitHub")
    assert github["details"]["full_name"] == "Ada Lovelace"


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
    scan_id = _start(client, headers, target_type="phone", identifier="+34611223344").json()[
        "scan_id"
    ]

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
        client,
        headers,
        target_type="email",
        identifier="tercero@example.com",
        consent_self_audit=False,
    )
    assert response.status_code == 400
    assert response.json()["type"].endswith("/consent-required")


def test_third_party_email_scan_with_valid_consent_token_runs(client, headers):
    email = "tercero@example.com"
    consent = _consent_token(client, headers, email)

    accepted = _start(
        client,
        headers,
        target_type="email",
        identifier=email,
        consent_self_audit=False,
        consent_token=consent,
    )
    assert accepted.status_code == 202
    scan_id = accepted.json()["scan_id"]
    assert client.get(f"{SCANS}/{scan_id}/results", headers=headers).status_code == 200


def test_consent_token_for_a_different_email_is_rejected(client, headers):
    consent = _consent_token(client, headers, "otro@example.com")

    response = _start(
        client,
        headers,
        target_type="email",
        identifier="victima@example.com",
        consent_self_audit=False,
        consent_token=consent,
    )
    assert response.status_code == 403
    assert response.json()["type"].endswith("/invalid-consent")


def test_consent_token_from_another_account_is_rejected(client, headers, other_headers):
    email = "tercero@example.com"
    consent = _consent_token(client, other_headers, email)

    response = _start(
        client,
        headers,
        target_type="email",
        identifier=email,
        consent_self_audit=False,
        consent_token=consent,
    )
    assert response.status_code == 403
    assert response.json()["type"].endswith("/invalid-consent")


def test_consent_token_is_only_valid_for_the_email_vector(client, headers):
    consent = _consent_token(client, headers, "tercero@example.com")

    response = _start(
        client,
        headers,
        target_type="username",
        identifier="algun_alias",
        consent_self_audit=False,
        consent_token=consent,
    )
    assert response.status_code == 400
    assert response.json()["type"].endswith("/invalid-identifier")


def test_tampered_consent_token_is_rejected(client, headers):
    consent = _consent_token(client, headers, "tercero@example.com")
    body, signature = consent.split(".")

    response = _start(
        client,
        headers,
        target_type="email",
        identifier="tercero@example.com",
        consent_self_audit=False,
        consent_token=f"{body[:-2]}00.{signature}",
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


def test_client_identity_maps_to_per_service_usernames_without_session_label(client, monkeypatch):
    from fee_server.domain.osint.engines.parsers import parse_maigret_simple_json
    from tests import passkey_helpers as pk

    auth = pk.register(client, pk.new_device(), label="login_label").json()
    headers = {"Authorization": f"Bearer {auth['access_token']}"}
    requests = []

    class MaigretReportEngine:
        name = "maigret"

        def run(self, request):
            requests.append(request)
            if request.usernames == ("client_seed",):
                payload = {
                    "Primary": {
                        "username": "client_seed",
                        "ids_usernames": {"client_page_two": "username", "1234": "gaia_id"},
                        "status": {
                            "status": "Claimed",
                            "site_name": "Primary",
                            "username": "client_seed",
                            "url": "https://primary.example/client_page_one",
                            "ids": {"username": "client_page_one", "fullname": "Client Example"},
                        },
                    }
                }
            else:
                assert request.usernames == ("client_page_two",)
                payload = {
                    "Secondary": {
                        "status": {
                            "status": "Claimed",
                            "site_name": "Secondary",
                            "username": "client_page_two",
                            "ids": {},
                            "url": "https://secondary.example/client_page_two",
                        },
                    }
                }
            findings = parse_maigret_simple_json(json.dumps(payload), username=request.usernames[0])
            return EngineResult(self.name, ENGINE_OK, tuple(findings))

    class BlackbirdReportEngine:
        name = "blackbird"

        def run(self, request):
            if request.usernames != ("client_seed",):
                return EngineResult(self.name, ENGINE_OK, ())
            return EngineResult(
                self.name,
                ENGINE_OK,
                (
                    Finding(
                        "Primary",
                        "other",
                        "https://primary.example/client_page_one",
                        "client_seed",
                        CONFIRMED,
                        80,
                        (self.name,),
                        {},
                    ),
                ),
            )

    monkeypatch.setattr(
        runner, "build_engines", lambda _: (BlackbirdReportEngine(), MaigretReportEngine())
    )
    response = _start(
        client,
        headers,
        target_type="phone",
        identifier="+12025550123",
        associated_email="client@example.com",
        associated_usernames=["client_seed"],
    )
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]
    result = client.get(f"{SCANS}/{scan_id}/results", headers=headers).json()
    assert requests[0].usernames == ("client_seed",)
    assert requests[0].email == "client@example.com"
    assert requests[0].phone == "+12025550123"
    assert requests[1].usernames == ("client_page_two",)
    items = [item for category in result["categories"] for item in category["items"]]
    expected = {("Primary", "client_page_one"), ("Secondary", "client_page_two")}
    assert {(item["platform"], item["username"]) for item in items} == expected
    assert {
        (n["platform"], n["username"]) for n in result["correlation"]["identity_graph"]["nodes"]
    } == expected
    assert all("linked_usernames" not in item["details"] for item in items)
