"""Casos del servicio OSINT que no pasan por HTTP."""

from datetime import timedelta

import pytest

from fee_server.core.problem import ScanNotReadyError
from fee_server.db.models import User
from fee_server.db.session import session_scope
from fee_server.domain.osint.schemas import ScanRequest
from fee_server.domain.osint.service import ScanService
from fee_server.util.time import utcnow


def _user(session) -> User:
    user = User(handle=b"handle-for-osint-tests", label="OSINT")
    session.add(user)
    session.flush()
    return user


def _request(**overrides) -> ScanRequest:
    base = {"target_type": "username", "identifier": "alias_de_prueba", "consent_self_audit": True}
    return ScanRequest(**{**base, **overrides})


def test_results_are_not_ready_before_the_scan_runs(client, settings):
    with session_scope() as session:
        service = ScanService(session, settings)
        scan, _ = service.create_scan(_request(), _user(session))

        with pytest.raises(ScanNotReadyError):
            service.build_results(scan)


def test_scan_never_stores_the_raw_identifier(client, settings):
    secret = "identificador_muy_privado"
    with session_scope() as session:
        service = ScanService(session, settings)
        scan, _ = service.create_scan(_request(identifier=secret), _user(session))

        assert secret not in scan.identifier_hint
        assert scan.identifier_sha256 != secret
        assert len(scan.identifier_sha256) == 64


def test_engine_request_puts_the_username_first(client, settings):
    with session_scope() as session:
        service = ScanService(session, settings)
        _, engine_request = service.create_scan(
            _request(associated_usernames=["otro_alias"]), _user(session)
        )

        assert engine_request.usernames == ("alias_de_prueba", "otro_alias")
        assert engine_request.email is None


def test_purge_expired_marks_scan_and_removes_findings(client, settings):
    with session_scope() as session:
        service = ScanService(session, settings)
        scan, _ = service.create_scan(_request(), _user(session))
        scan.expires_at = utcnow() - timedelta(days=1)
        session.flush()

        assert service.purge_expired() == 1
        session.refresh(scan)
        assert scan.status == "EXPIRED"
