import pytest

from tests import passkey_helpers as pk


@pytest.fixture
def other_headers(client) -> dict[str, str]:
    session = pk.register(client, pk.new_device(), label="Otra").json()
    return {"Authorization": f"Bearer {session['access_token']}"}


VALID_USERNAME_SCAN = {
    "target_type": "username",
    "identifier": "alias_de_prueba",
    "consent_self_audit": True,
}
