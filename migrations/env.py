"""Entorno de migraciones Alembic.

La URL de la base de datos sale de la configuración de la app (`Settings`), que
la lee de `FEE_DATABASE_URL`. Los modelos se importan para permitir `autogenerate`.
"""

from alembic import context
from sqlalchemy import engine_from_config, pool

from fee_server.core.config import Settings
from fee_server.db import models  # noqa: F401 - registra las tablas en Base.metadata
from fee_server.db.base import Base

config = context.config
config.set_main_option("sqlalchemy.url", Settings().database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
