from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from fee_server.core.config import Settings
from fee_server.core.database import Base, Database
from fee_server.main import create_app


def test_sqlite_migration_roundtrip_supports_auth_without_create_all(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    monkeypatch.setenv("FEE_ENVIRONMENT", "test")
    monkeypatch.setenv("FEE_DATABASE_URL", url)
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(config, "head")
    command.check(config)
    app = create_app(Settings(environment="test", database_url=url))
    with TestClient(app) as client:
        credentials = {"email": "migrations@example.com", "password": "migration test password"}
        assert client.post("/api/v1/auth/register", json=credentials).status_code == 201
        tokens = client.post("/api/v1/auth/login", json=credentials)
        assert tokens.status_code == 200
        assert (
            client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {tokens.json()['access_token']}"},
            ).status_code
            == 200
        )
    command.downgrade(config, "base")
    database = Database(url)
    try:
        assert set(inspect(database.engine).get_table_names()) <= {"alembic_version"}
    finally:
        database.dispose()
    command.upgrade(config, "head")
    command.check(config)


@pytest.mark.parametrize(
    "url", ["sqlite://", "sqlite:///:memory:", "sqlite+pysqlite://", "sqlite+pysqlite:///:memory:"]
)
def test_memory_database_aliases_share_schema_across_request_threads(url):
    app = create_app(Settings(environment="test", database_url=url))
    Base.metadata.create_all(app.state.database.engine)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/register",
            json={"email": "memory@example.com", "password": "memory test password"},
        )
        assert response.status_code == 201
