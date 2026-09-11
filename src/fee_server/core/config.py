"""Configuración validada desde variables de entorno."""

from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Valor obvio e inseguro: sirve para desarrollo local sin configurar nada.
# Un validador impide arrancar con este valor en producción.
DEV_INSECURE_JWT_SECRET = "dev-insecure-secret-change-me-000000000000"

MIN_JWT_SECRET_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FEE_", frozen=True, hide_input_in_errors=True)

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
    # Debe coincidir con `FEE_RATE_LIMIT_ENABLED` (mismo nombre de variable),
    # que además construye el `Limiter` de verdad en `core/rate_limit.py`. Este
    # campo solo existe para que un arranque en producción sin límites por IP
    # falle rápido en vez de exponer todos los endpoints sin cuota.
    rate_limit_enabled: bool = False

    # --- Motor OSINT (huella digital) ---
    # `fake`: motores simulados con salidas deterministas; no tocan la red.
    # `real`: subprocesos a las herramientas vendorizadas (fase posterior).
    osint_engine_mode: Literal["fake", "real"] = "fake"
    osint_retention_days: int = 7
    osint_max_concurrent_scans: int = Field(default=2, ge=1)
    osint_engine_timeout_seconds: int = Field(default=120, ge=1)
    osint_max_output_bytes: int = Field(default=5_000_000, ge=1)
    osint_proxy_url: SecretStr = SecretStr("")
    osint_residential_proxy_url: SecretStr = SecretStr("")
    osint_normal_proxy_url: SecretStr = SecretStr("")
    # Raíz de las herramientas vendorizadas, cada una con su `.venv`.
    # La prepara `vendor/osint/setup.sh`.
    osint_vendor_dir: str = "vendor/osint"
    # Tope de alias nuevos por escaneo en la segunda pasada de pivoteo (§8).
    # Profundidad fija en 1: los hallazgos de esa segunda pasada nunca vuelven
    # a extraer candidatos.
    osint_max_pivot_candidates: int = Field(default=3, ge=0, le=10)
    # Forense EXIF sobre avatar_url (§D2.6). Apagarlo hace que el enriquecimiento
    # se salte por completo, como si ningún hallazgo trajera avatar_url.
    osint_image_metadata_enabled: bool = True
    osint_image_max_bytes: int = Field(default=8_000_000, ge=1)
    osint_image_fetch_timeout_seconds: int = Field(default=15, ge=1)

    # --- Verificación de correo (consentimiento para escanear a terceros) ---
    # Código estático para el hackathon: mientras no esté vacío, `confirm` acepta
    # exactamente este valor. Vaciarlo (y añadir envío real) es el interruptor a
    # modo funcional. Ver `domain/verification/`.
    verification_static_code: str = "1234"
    verification_code_ttl_seconds: int = 600
    osint_consent_ttl_seconds: int = 3600

    # --- Asistente de higiene de privacidad (LLM) ---
    # `fake`: respuesta determinista sin red; `real`: proveedor compatible con
    # la API de OpenAI (NVIDIA por defecto). Ver `domain/assistant/`.
    assistant_mode: Literal["disabled", "fake", "real"] = "fake"
    assistant_api_key: SecretStr = SecretStr("")
    assistant_base_url: str = "https://integrate.api.nvidia.com/v1"
    assistant_model: str = "meta/muse-glimmer-30b"
    assistant_max_messages: int = 20
    assistant_max_message_chars: int = 4000
    assistant_max_output_tokens: int = 1024
    assistant_timeout_seconds: int = 30

    @property
    def docs_enabled(self) -> bool:
        return self.environment != "production"

    @property
    def osint_uses_real_engines(self) -> bool:
        # El entorno de pruebas nunca ejecuta herramientas reales.
        return self.osint_engine_mode == "real" and self.environment != "test"

    @property
    def assistant_uses_real_gateway(self) -> bool:
        # El entorno de pruebas nunca llama al proveedor real.
        return self.assistant_mode == "real" and self.environment != "test"

    @property
    def effective_osint_residential_proxy(self) -> str:
        residential = self.osint_residential_proxy_url.get_secret_value()
        if residential:
            return residential
        return self.osint_proxy_url.get_secret_value()

    @property
    def effective_osint_normal_proxy(self) -> str:
        return self.osint_normal_proxy_url.get_secret_value()

    @field_validator("osint_proxy_url", "osint_residential_proxy_url", "osint_normal_proxy_url")
    @classmethod
    def _valid_osint_proxy(cls, value: SecretStr, info: ValidationInfo) -> SecretStr:
        raw = value.get_secret_value()
        if not raw:
            return value
        field_label = f"FEE_{info.field_name.upper()}" if info.field_name else "FEE_OSINT_PROXY_URL"
        message = f"{field_label} debe ser http://[usuario:password@]host:puerto"
        try:
            parsed = urlsplit(raw)
            valid = (
                parsed.scheme == "http"
                and bool(parsed.hostname)
                and parsed.port is not None
                and 1 <= parsed.port <= 65535
                and parsed.path in ("", "/")
                and not parsed.query
                and not parsed.fragment
                and not any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in raw)
                and (parsed.username is None or bool(parsed.username and parsed.password))
            )
        except ValueError:
            raise ValueError(message) from None
        if not valid:
            # aiohttp trust_env ignora HTTPS/SOCKS; aceptarlos permitiría salida
            # directa en Maigret. HTTP es el transporte común de los 4 motores.
            raise ValueError(message)
        return value

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

    @model_validator(mode="after")
    def _production_assistant_needs_api_key(self) -> "Settings":
        if (
            self.environment == "production"
            and self.assistant_mode == "real"
            and not self.assistant_api_key.get_secret_value()
        ):
            raise ValueError(
                "Define FEE_ASSISTANT_API_KEY para usar FEE_ASSISTANT_MODE=real en producción"
            )
        return self

    @model_validator(mode="after")
    def _production_requires_rate_limiting(self) -> "Settings":
        if self.environment == "production" and not self.rate_limit_enabled:
            raise ValueError(
                "Define FEE_RATE_LIMIT_ENABLED=1 en producción: sin límite por IP, "
                "endpoints como /verification/email/confirm o /assistant/chat quedan "
                "sin cuota."
            )
        return self

    @model_validator(mode="after")
    def _production_forbids_the_default_verification_code(self) -> "Settings":
        if self.environment == "production" and self.verification_static_code:
            raise ValueError(
                "FEE_VERIFICATION_STATIC_CODE debe quedar vacío en producción: el "
                "código estático es un atajo de hackathon (ver ADR-OSINT-05) y, si "
                "sigue activo, cualquiera puede fingir el consentimiento del correo "
                "de un tercero. Vacíalo (falla cerrado) hasta implementar envío real."
            )
        return self
