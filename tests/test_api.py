import pytest
from fastapi.testclient import TestClient

from fee_server.core.config import Settings
from fee_server.main import create_app


@pytest.fixture
def client():
    with TestClient(create_app(Settings(environment="test"))) as test_client:
        yield test_client


def test_health_contract(client):
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {
        "status": "ok",
        "service": "fee-server",
        "version": "0.1.0",
    }


@pytest.mark.parametrize("method", ["get", "post"])
def test_unimplemented_cases_route_returns_404(client, method):
    response = getattr(client, method)("/api/v1/cases")

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


def test_health_is_read_only(client):
    assert client.post("/api/v1/health").status_code == 405


def test_openapi_describes_the_available_contract(client):
    response = client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["version"] == "0.1.0"
    assert set(schema["paths"]) == {"/api/v1/health"}
    success = schema["paths"]["/api/v1/health"]["get"]["responses"]["200"]
    assert success["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/HealthResponse"
    }


def test_production_hides_docs_and_preserves_health(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "production")

    with TestClient(create_app()) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
        assert client.get("/api/v1/health").status_code == 200
