import pytest
from fastapi.testclient import TestClient

from fee_server.core.config import Settings
from fee_server.core.rate_limit import limiter
from fee_server.db.base import Base
from fee_server.db.session import get_engine
from fee_server.main import create_app
from tests.passkey_helpers import TEST_ORIGIN

TEST_JWT_SECRET = "test-secret-test-secret-test-secret-0123"


@pytest.fixture(autouse=True)
def _disable_rate_limiting():
    """El limitador guarda estado en memoria entre pruebas; se desactiva aquí.

    Su comportamiento se verifica a nivel de configuración y manualmente.
    """
    limiter.enabled = False
    yield
    limiter.enabled = True


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        jwt_secret=TEST_JWT_SECRET,
        webauthn_rp_id="localhost",
        webauthn_rp_name="FEE Test",
        webauthn_origins=(TEST_ORIGIN,),
    )


@pytest.fixture
def client(settings) -> TestClient:
    app = create_app(settings)
    Base.metadata.create_all(get_engine())
    with TestClient(app) as test_client:
        yield test_client
    Base.metadata.drop_all(get_engine())
