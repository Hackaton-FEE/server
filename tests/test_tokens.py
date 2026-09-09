import pytest

from fee_server.core.security.tokens import (
    InvalidAccessToken,
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
    read_access_token,
)

SECRET = "unit-test-secret-unit-test-secret-000000"
ISSUER = "fee-server"
AUDIENCE = "fee-app"


def _token(**overrides):
    params = {
        "secret": SECRET,
        "subject": "user-123",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "ttl_seconds": 60,
    }
    params.update(overrides)
    return create_access_token(**params)


def test_valid_token_round_trips_to_the_subject():
    assert (
        read_access_token(secret=SECRET, token=_token(), issuer=ISSUER, audience=AUDIENCE)
        == "user-123"
    )


def test_expired_token_is_rejected():
    token = _token(ttl_seconds=-60)  # más allá del margen de reloj (leeway)

    with pytest.raises(InvalidAccessToken):
        read_access_token(secret=SECRET, token=token, issuer=ISSUER, audience=AUDIENCE)


def test_wrong_audience_is_rejected():
    with pytest.raises(InvalidAccessToken):
        read_access_token(secret=SECRET, token=_token(), issuer=ISSUER, audience="someone-else")


def test_tampered_signature_is_rejected():
    token = _token()[:-4] + "aaaa"

    with pytest.raises(InvalidAccessToken):
        read_access_token(secret=SECRET, token=token, issuer=ISSUER, audience=AUDIENCE)


def test_refresh_token_only_exposes_its_hash():
    raw, stored = generate_refresh_token()

    assert raw != stored
    assert stored == hash_refresh_token(raw)
    assert len(stored) == 64
