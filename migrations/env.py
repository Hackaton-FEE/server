"""Schema changes use the same configured database as the API."""

from alembic import context

from fee_server.core.config import Settings
from fee_server.core.database import Base, Database
from fee_server.core.rate_limit import RequestLimit  # noqa: F401
from fee_server.modules.auth import models  # noqa: F401

settings = Settings()
target_metadata = Base.metadata

if context.is_offline_mode():
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    database = Database(settings.database_url)
    try:
        with database.engine.connect() as connection:
            context.configure(
                connection=connection, target_metadata=target_metadata, compare_type=True
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        database.dispose()
