import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import SQLAlchemyError

from fee_server import maintenance
from fee_server.core.database import Base, Database
from fee_server.core.rate_limit import RequestLimit
from fee_server.modules.auth.models import AuthSession, RefreshToken, User

NOW = datetime(2026, 9, 9, 12, 0, tzinfo=UTC)


def seed_auth(database):
    with database.session_factory.begin() as session:
        user = User(email="sample@example.test", password_hash="test-only-unused-hash")
        session.add(user)
        session.flush()
        sessions = {}
        for name, expiry, revoked in (
            ("expired", NOW - timedelta(microseconds=1), False),
            ("boundary", NOW, False),
            ("expired_revoked", NOW - timedelta(days=1), True),
            ("active", NOW + timedelta(microseconds=1), False),
            ("revoked", NOW + timedelta(days=1), True),
        ):
            record = AuthSession(
                user_id=user.id,
                expires_at=expiry,
                revoked_at=NOW - timedelta(days=2) if revoked else None,
            )
            session.add(record)
            session.flush()
            sessions[name] = record.id
            # Keep both current and consumed history until the parent session expires.
            for consumed in (False, True):
                session.add(
                    RefreshToken(
                        session_id=record.id,
                        token_hash=uuid4().hex + uuid4().hex,
                        expires_at=NOW - timedelta(seconds=1) if consumed else expiry,
                        consumed_at=NOW - timedelta(days=2) if consumed else None,
                    )
                )
        for name, expiry in (
            ("expired", int(NOW.timestamp()) - 1),
            ("boundary", int(NOW.timestamp())),
            ("active", int(NOW.timestamp()) + 1),
        ):
            session.add(RequestLimit(key=name, count=2, expires_at=expiry))
        return user.id, sessions


def test_cleanup_preserves_users_and_all_unexpired_session_history(app):
    database = app.state.database
    user_id, sessions = seed_auth(database)

    counts = maintenance.cleanup_auth(database, now=NOW)

    assert counts == maintenance.CleanupCounts(3, 2)
    with database.session_factory() as session:
        assert session.scalars(select(User.id)).all() == [user_id]
        remaining_sessions = set(session.scalars(select(AuthSession.id)))
        assert remaining_sessions == {sessions["active"], sessions["revoked"]}
        remaining_tokens = session.scalars(select(RefreshToken)).all()
        assert len(remaining_tokens) == 4
        assert {token.session_id for token in remaining_tokens} == remaining_sessions
        assert sum(token.consumed_at is not None for token in remaining_tokens) == 2
        assert session.scalars(select(RequestLimit.key)).all() == ["active"]
    assert maintenance.cleanup_auth(database, now=NOW) == maintenance.CleanupCounts(0, 0)


def test_failed_cleanup_rolls_back_session_deletion_and_token_cascade(app):
    database = app.state.database
    _, sessions = seed_auth(database)

    def fail_bucket_delete(_connection, _cursor, statement, _parameters, _context, _executemany):
        if statement.startswith("DELETE FROM auth_request_limits"):
            raise SQLAlchemyError("test-only-private-driver-detail")

    event.listen(database.engine, "before_cursor_execute", fail_bucket_delete)
    try:
        with pytest.raises(SQLAlchemyError):
            maintenance.cleanup_auth(database, now=NOW)
    finally:
        event.remove(database.engine, "before_cursor_execute", fail_bucket_delete)

    with database.session_factory() as session:
        assert set(session.scalars(select(AuthSession.id))) == set(sessions.values())
        assert len(session.scalars(select(RefreshToken)).all()) == 10
        assert len(session.scalars(select(RequestLimit)).all()) == 3


def test_cli_uses_configured_database_and_prints_only_committed_aggregate_counts(
    settings, monkeypatch, capsys
):
    database = Database(settings.database_url)
    Base.metadata.create_all(database.engine)
    seed_auth(database)
    database.dispose()
    monkeypatch.setenv("FEE_ENVIRONMENT", "test")
    monkeypatch.setenv("FEE_DATABASE_URL", settings.database_url)
    monkeypatch.setattr(maintenance, "utcnow", lambda: NOW)

    assert maintenance.main(["cleanup-auth"]) == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {
        "expired_sessions_deleted": 3,
        "expired_rate_limit_buckets_deleted": 2,
    }
    assert "sample@example.test" not in captured.out
    assert settings.database_url not in captured.out


def test_cli_storage_failure_is_generic_and_does_not_create_tables(settings, monkeypatch, capsys):
    monkeypatch.setenv("FEE_ENVIRONMENT", "test")
    monkeypatch.setenv("FEE_DATABASE_URL", settings.database_url)

    assert maintenance.main(["cleanup-auth"]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Authentication cleanup failed\n"
    database = Database(settings.database_url)
    try:
        with database.engine.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).all()
                == []
            )
    finally:
        database.dispose()


def test_cli_configuration_failure_does_not_print_secrets(monkeypatch, capsys):
    monkeypatch.setenv("FEE_DATABASE_URL", "invalid-private-password-url")

    assert maintenance.main(["cleanup-auth"]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Authentication cleanup failed\n"
