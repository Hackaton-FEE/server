import pytest

from tests import passkey_helpers as pk


@pytest.fixture
def headers(client) -> dict[str, str]:
    session = pk.register(client, pk.new_device()).json()
    return {"Authorization": f"Bearer {session['access_token']}"}
