import pytest
from fastapi.testclient import TestClient

from fee_server.core.config import Settings
from fee_server.main import create_app


def test_health_contract(client):
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {
        "status": "ok",
        "service": "fee-server",
        "version": "0.2.0",
    }


@pytest.mark.parametrize("method", ["get", "post"])
def test_unimplemented_cases_route_returns_404(client, method):
    response = getattr(client, method)("/api/v1/cases")

    assert response.status_code == 404


def test_health_is_read_only(client):
    assert client.post("/api/v1/health").status_code == 405


def test_openapi_describes_health_and_auth(client):
    response = client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["version"] == "0.2.0"

    paths = set(schema["paths"])
    assert "/api/v1/health" in paths
    assert "/api/v1/auth/passkey/registration/options" in paths
    assert "/api/v1/auth/passkey/authentication/verify" in paths
    assert "/api/v1/auth/me" in paths


def test_security_headers_are_present(client):
    response = client.get("/api/v1/health")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_production_hides_docs_and_preserves_health(monkeypatch, tmp_path):
    monkeypatch.setenv("FEE_ENVIRONMENT", "production")
    monkeypatch.setenv("FEE_JWT_SECRET", "a-proper-production-secret-value-32chars")
    monkeypatch.setenv("FEE_DATABASE_URL", f"sqlite:///{tmp_path / 'prod.db'}")

    from fee_server.db.base import Base
    from fee_server.db.session import get_engine

    app = create_app(Settings())
    Base.metadata.create_all(get_engine())
    with TestClient(app) as production_client:
        assert production_client.get("/docs").status_code == 404
        assert production_client.get("/openapi.json").status_code == 404
        assert production_client.get("/api/v1/health").status_code == 200
