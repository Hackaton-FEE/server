import time

import pytest

from fee_server.core.security.challenge import (
    InvalidChallenge,
    issue_challenge,
    read_challenge,
)

SECRET = "unit-test-secret-unit-test-secret-000000"


def test_round_trip_returns_the_same_challenge_and_data():
    challenge, token = issue_challenge(SECRET, "register", 120, data={"handle": "ab"})

    read_challenge_bytes, data = read_challenge(SECRET, token, "register")

    assert read_challenge_bytes == challenge
    assert data == {"handle": "ab"}


def test_tampered_token_is_rejected():
    _, token = issue_challenge(SECRET, "register", 120)
    body, signature = token.split(".")
    tampered = body[:-2] + ("00" if body[-2:] != "00" else "11") + "." + signature

    with pytest.raises(InvalidChallenge):
        read_challenge(SECRET, tampered, "register")


def test_wrong_secret_is_rejected():
    _, token = issue_challenge(SECRET, "register", 120)

    with pytest.raises(InvalidChallenge):
        read_challenge("another-secret-another-secret-0000000000", token, "register")


def test_purpose_mismatch_is_rejected():
    _, token = issue_challenge(SECRET, "register", 120)

    with pytest.raises(InvalidChallenge):
        read_challenge(SECRET, token, "authenticate")


def test_expired_challenge_is_rejected():
    _, token = issue_challenge(SECRET, "authenticate", -1)
    time.sleep(0.01)

    with pytest.raises(InvalidChallenge):
        read_challenge(SECRET, token, "authenticate")


def test_unknown_purpose_cannot_be_issued():
    with pytest.raises(ValueError, match="purpose"):
        issue_challenge(SECRET, "delete-everything", 120)
