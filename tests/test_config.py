import pytest
from pydantic import ValidationError

from fee_server.core.config import Settings


def test_unknown_environment_fails_at_startup(monkeypatch):
    monkeypatch.setenv("FEE_ENVIRONMENT", "prodution")

    with pytest.raises(ValidationError, match="environment"):
        Settings()
