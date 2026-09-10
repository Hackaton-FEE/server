"""Configuración validada desde variables de entorno."""

from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Valor obvio e inseguro: sirve para desarrollo local sin configurar nada.
# Un validador impide arrancar con este valor en producción.
DEV_INSECURE_JWT_SECRET = "dev-insecure-secret-change-me-000000000000"

MIN_JWT_SECRET_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FEE_", frozen=True)

    environment: Literal["development", "test", "production"] = "development"

    # --- Base de datos ---
    # SQLAlchemy URL. Por defecto SQLite local; en producción, Postgres/Supabase.
    database_url: str = "sqlite:///./dev.db"

    # --- Sesión: JWT de acceso + refresh token opaco ---
    jwt_secret: str = DEV_INSECURE_JWT_SECRET
    jwt_issuer: str = "fee-server"
    jwt_audience: str = "fee-app"
    access_token_ttl_seconds: int = 3600  # 1 hora
    refresh_token_ttl_seconds: int = 2_592_000  # 30 días

    # --- WebAuthn / passkeys ---
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "FEE"
    # Allowlist EXACTA de orígenes aceptados. iOS: "https://<rp_id>".
    # Android: "android:apk-key-hash:<base64url-sha256-del-certificado>".
    webauthn_origins: tuple[str, ...] = ("http://localhost",)
    challenge_ttl_seconds: int = 120

    # --- Archivos de asociación de dominio (valores del equipo Flutter) ---
    android_package_name: str = ""
    android_sha256_fingerprints: tuple[str, ...] = ()
    ios_app_ids: tuple[str, ...] = ()  # "<TeamID>.<BundleID>"

    # --- Transporte ---
    cors_origins: tuple[str, ...] = ()
    max_request_body_bytes: int = 16_384

    # --- Motor OSINT (huella digital) ---
    # `fake`: motores simulados con salidas deterministas; no tocan la red.
    # `real`: subprocesos a las herramientas vendorizadas (fase posterior).
    osint_engine_mode: Literal["fake", "real"] = "fake"
    osint_retention_days: int = 7
    osint_max_concurrent_scans: int = 2
    osint_engine_timeout_seconds: int = 120
    osint_max_output_bytes: int = 5_000_000
    osint_proxy_url: str = ""
    # Raíz de las herramientas vendorizadas, cada una con su `.venv`.
    # La prepara `vendor/osint/setup.sh`.
    osint_vendor_dir: str = "vendor/osint"

    @property
    def docs_enabled(self) -> bool:
        return self.environment != "production"

    @property
    def osint_uses_real_engines(self) -> bool:
        # El entorno de pruebas nunca ejecuta herramientas reales.
        return self.osint_engine_mode == "real" and self.environment != "test"

    @field_validator("jwt_secret")
    @classmethod
    def _secret_long_enough(cls, value: str) -> str:
        if len(value) < MIN_JWT_SECRET_LENGTH:
            raise ValueError(
                f"FEE_JWT_SECRET debe tener al menos {MIN_JWT_SECRET_LENGTH} caracteres"
            )
        return value

    @model_validator(mode="after")
    def _production_needs_real_secret(self) -> "Settings":
        if self.environment == "production" and self.jwt_secret == DEV_INSECURE_JWT_SECRET:
            raise ValueError("Define FEE_JWT_SECRET con un valor propio en producción")
        return self
