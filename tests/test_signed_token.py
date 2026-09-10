import pytest

from fee_server.core.security.signed_token import InvalidSignedToken, read, sign

SECRET = "unit-test-secret-unit-test-secret-000000"


def test_round_trip_returns_the_original_data():
    token = sign(SECRET, "verify_email", 120, {"email_sha256": "abc"})

    data = read(SECRET, token, "verify_email")

    assert data == {"email_sha256": "abc"}


def test_tampered_token_is_rejected():
    token = sign(SECRET, "verify_email", 120, {"x": 1})
    body, signature = token.split(".")
    tampered = body[:-2] + ("00" if body[-2:] != "00" else "11") + "." + signature

    with pytest.raises(InvalidSignedToken):
        read(SECRET, tampered, "verify_email")


def test_wrong_secret_is_rejected():
    token = sign(SECRET, "verify_email", 120, {"x": 1})

    with pytest.raises(InvalidSignedToken):
        read("another-secret-another-secret-0000000000", token, "verify_email")


def test_purpose_mismatch_is_rejected():
    token = sign(SECRET, "verify_email", 120, {"x": 1})

    with pytest.raises(InvalidSignedToken):
        read(SECRET, token, "osint_third_party_consent")


def test_expired_token_is_rejected():
    token = sign(SECRET, "verify_email", -1, {"x": 1})

    with pytest.raises(InvalidSignedToken):
        read(SECRET, token, "verify_email")


def test_malformed_token_is_rejected():
    with pytest.raises(InvalidSignedToken):
        read(SECRET, "not-a-token", "verify_email")
