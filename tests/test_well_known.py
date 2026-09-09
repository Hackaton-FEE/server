"""Archivos de asociación de dominio para passkeys nativas."""

from fastapi.testclient import TestClient

from fee_server.core.config import Settings
from fee_server.db.base import Base
from fee_server.db.session import get_engine
from fee_server.main import create_app

ANDROID = "/.well-known/assetlinks.json"
APPLE = "/.well-known/apple-app-site-association"


def test_endpoints_exist_and_return_json_without_redirect(client):
    for path in (ANDROID, APPLE):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert response.history == []


def test_apple_file_lists_configured_app_ids(tmp_path):
    settings = Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'wk.db'}",
        jwt_secret="test-secret-test-secret-test-secret-0123",
        ios_app_ids=("ABCDE12345.io.fee.app",),
        android_package_name="io.fee.app",
        android_sha256_fingerprints=("AA:BB:CC",),
    )
    app = create_app(settings)
    Base.metadata.create_all(get_engine())

    with TestClient(app) as configured_client:
        apple = configured_client.get(APPLE).json()
        android = configured_client.get(ANDROID).json()

    assert apple == {"webcredentials": {"apps": ["ABCDE12345.io.fee.app"]}}
    assert android[0]["target"]["package_name"] == "io.fee.app"
