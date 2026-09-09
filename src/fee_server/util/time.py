"""Utilidades de fecha/hora en UTC.

SQLite devuelve datetimes sin zona horaria. Normalizamos siempre a UTC con zona
para que las comparaciones (`token expirado?`) sean correctas en cualquier motor.
"""

from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime) -> datetime:
    """Devuelve el mismo instante con `tzinfo=UTC` si venía sin zona."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
