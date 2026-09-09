"""Explicit maintenance commands; never run from application startup."""

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime

from sqlalchemy import delete

from fee_server.core.config import Settings
from fee_server.core.database import Database
from fee_server.core.rate_limit import RequestLimit
from fee_server.modules.auth.models import AuthSession, as_utc, utcnow


@dataclass(frozen=True)
class CleanupCounts:
    expired_sessions_deleted: int
    expired_rate_limit_buckets_deleted: int


def cleanup_auth(database: Database, *, now: datetime | None = None) -> CleanupCounts:
    cutoff = as_utc(now) if now is not None else utcnow()
    with database.session_factory.begin() as session:
        sessions = session.execute(delete(AuthSession).where(AuthSession.expires_at <= cutoff))
        buckets = session.execute(
            delete(RequestLimit).where(RequestLimit.expires_at <= int(cutoff.timestamp()))
        )
        counts = CleanupCounts(sessions.rowcount, buckets.rowcount)
    return counts


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FEE authentication maintenance")
    parser.add_argument("command", choices=["cleanup-auth"])
    parser.parse_args(argv)
    try:
        database = Database(Settings().database_url)
        try:
            counts = cleanup_auth(database)
        finally:
            database.dispose()
    except Exception:
        # Driver/configuration errors can include secrets; emit only a fixed category.
        print("Authentication cleanup failed", file=sys.stderr)
        return 1
    print(json.dumps(asdict(counts), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
