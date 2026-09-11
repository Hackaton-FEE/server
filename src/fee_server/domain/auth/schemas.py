"""Modelos de petición y respuesta del módulo de autenticación."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

# `credential` es el JSON que produce el navegador/SO (PublicKeyCredential).
# Lo aceptamos como dict y lo valida la librería WebAuthn.
CredentialJSON = dict


class _StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegistrationOptionsRequest(_StrictRequest):
    label: str = Field(default="", max_length=64)


class RegistrationVerifyRequest(_StrictRequest):
    challenge_token: str
    credential: CredentialJSON


class AuthenticationOptionsRequest(_StrictRequest):
    pass


class TestingSessionRequest(_StrictRequest):
    """No acepta datos para elegir, vincular ni recuperar cuentas existentes."""


class AuthenticationVerifyRequest(_StrictRequest):
    challenge_token: str
    credential: CredentialJSON


class RefreshRequest(_StrictRequest):
    refresh_token: str


class LogoutRequest(_StrictRequest):
    refresh_token: str


class ChallengeOptionsResponse(BaseModel):
    challenge_token: str
    public_key: dict


class UserSummary(BaseModel):
    id: str
    label: str


class SessionResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserSummary


class MeResponse(BaseModel):
    id: str
    label: str
    created_at: datetime
    credentials_count: int
