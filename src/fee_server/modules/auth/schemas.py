from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator

from fee_server.modules.auth.models import as_utc

Password = Annotated[SecretStr, Field(min_length=12, max_length=128)]
ExistingPassword = Annotated[SecretStr, Field(min_length=1, max_length=128)]


class AuthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class EmailRequest(AuthRequest):
    email: Annotated[EmailStr, Field(max_length=254)]

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: object) -> object:
        if isinstance(value, str):
            if len(value) > 254:
                raise ValueError("Email must contain at most 254 characters")
            return value.strip().lower()
        return value


class RegisterRequest(EmailRequest):
    password: Password


class LoginRequest(EmailRequest):
    password: ExistingPassword


class RefreshRequest(AuthRequest):
    refresh_token: Annotated[SecretStr, Field(min_length=40, max_length=256)]


class ChangePasswordRequest(AuthRequest):
    current_password: ExistingPassword
    new_password: Password


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    is_active: bool
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def utc_created_at(cls, value: datetime) -> datetime:
        return as_utc(value)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    refresh_expires_in: int
    session_id: UUID


class SessionResponse(BaseModel):
    id: UUID
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime
    is_current: bool

    @field_validator("created_at", "expires_at", "last_used_at")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        return as_utc(value)
