"""Configuración validada desde variables de entorno."""

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FEE_", frozen=True)

    environment: Literal["development", "test", "production"] = "development"

    @property
    def docs_enabled(self) -> bool:
        return self.environment != "production"
