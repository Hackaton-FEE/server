"""Modelos de petición y respuesta de la verificación de correo."""

from pydantic import BaseModel, ConfigDict, Field


class _StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EmailVerificationRequest(_StrictRequest):
    email: str = Field(min_length=3, max_length=254)


class EmailVerificationRequested(BaseModel):
    verification_token: str
    expires_in: int


class EmailVerificationConfirm(_StrictRequest):
    verification_token: str
    code: str = Field(min_length=1, max_length=16)


class EmailVerificationConfirmed(BaseModel):
    consent_token: str
    expires_in: int
