"""Configuración validada desde variables de entorno."""

from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FEE_", frozen=True, hide_input_in_errors=True)

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = Field(default="sqlite:///./fee.db", repr=False)
    auth_secret_key: SecretStr | None = None
    auth_issuer: str = Field(default="fee-server", min_length=1, max_length=128)
    auth_audience: str = Field(default="fee-app", min_length=1, max_length=128)
    access_token_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    refresh_token_ttl_seconds: int = Field(default=2_592_000, ge=3600, le=7_776_000)
    auth_login_max_attempts: int = Field(default=5, ge=1, le=100)
    auth_login_lock_seconds: int = Field(default=300, ge=1, le=3600)
    auth_request_limit: int = Field(default=30, ge=1, le=1000)
    auth_request_window_seconds: int = Field(default=60, ge=1, le=3600)
    max_request_body_bytes: int = Field(default=16_384, ge=1024, le=1_048_576)
    cors_origins: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_security_configuration(self) -> "Settings":
        try:
            url = make_url(self.database_url)
        except ArgumentError:
            raise ValueError("database_url must be a valid SQLAlchemy URL") from None
        if url.drivername not in {"sqlite", "sqlite+pysqlite", "postgresql+psycopg"}:
            raise ValueError("database_url must use sqlite or postgresql+psycopg")
        secret = self.auth_secret_key.get_secret_value() if self.auth_secret_key else None
        if secret is not None and (len(secret.encode()) < 32 or len(set(secret)) < 12):
            raise ValueError("auth_secret_key must contain at least 32 bytes of random material")
        if self.environment == "production":
            if secret is None:
                raise ValueError("production requires auth_secret_key")
            if url.drivername != "postgresql+psycopg":
                raise ValueError("production requires PostgreSQL via postgresql+psycopg")
        for origin in self.cors_origins:
            try:
                parsed = urlsplit(origin)
                _ = parsed.port
            except ValueError:
                raise ValueError("cors_origins contains an invalid origin") from None
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or "*" in origin
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path
                or parsed.query
                or parsed.fragment
                or (self.environment == "production" and parsed.scheme != "https")
            ):
                raise ValueError("cors_origins must contain exact origins (HTTPS in production)")
        return self

    @property
    def docs_enabled(self) -> bool:
        return self.environment != "production"
