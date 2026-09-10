"""VerificationService: unidad, sin HTTP."""

import pytest

from fee_server.core.config import Settings
from fee_server.core.problem import (
    InvalidVerificationCodeError,
    InvalidVerificationTokenError,
)
from fee_server.domain.verification.consent import InvalidConsentError, verify_consent_token
from fee_server.domain.verification.service import VerificationService

SECRET = "unit-test-secret-unit-test-secret-000000"
EMAIL = "titular@example.com"


@pytest.fixture
def service() -> VerificationService:
    return VerificationService(Settings(environment="test", jwt_secret=SECRET))


def test_happy_path_yields_a_consent_token_bound_to_requester(service):
    requested = service.request_email(EMAIL, requester_id="user-a")

    confirmed = service.confirm_email(requested.verification_token, "1234", requester_id="user-a")

    verify_consent_token(SECRET, confirmed.consent_token, EMAIL, requester_id="user-a")
    with pytest.raises(InvalidConsentError):
        verify_consent_token(SECRET, confirmed.consent_token, EMAIL, requester_id="user-b")


def test_confirm_rejects_a_token_issued_for_another_account(service):
    requested = service.request_email(EMAIL, requester_id="user-a")

    with pytest.raises(InvalidVerificationTokenError):
        service.confirm_email(requested.verification_token, "1234", requester_id="user-b")


def test_confirm_rejects_a_wrong_code(service):
    requested = service.request_email(EMAIL, requester_id="user-a")

    with pytest.raises(InvalidVerificationCodeError):
        service.confirm_email(requested.verification_token, "9999", requester_id="user-a")


def test_empty_static_code_fails_closed():
    service = VerificationService(
        Settings(environment="test", jwt_secret=SECRET, verification_static_code="")
    )
    requested = service.request_email(EMAIL, requester_id="user-a")

    with pytest.raises(InvalidVerificationCodeError):
        service.confirm_email(requested.verification_token, "1234", requester_id="user-a")
