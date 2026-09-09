import pytest
from fastapi.testclient import TestClient

from fee_server.core.config import Settings
from fee_server.core.database import Base
from fee_server.main import create_app


@pytest.fixture
def settings(tmp_path):
    return Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        auth_secret_key="fixture-only-signing-key-0123456789-abcdefghijklmnopqrstuvwxyz",
    )


@pytest.fixture
def app(settings):
    application = create_app(settings)
    Base.metadata.create_all(application.state.database.engine)
    yield application
    application.state.database.dispose()


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client
