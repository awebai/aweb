from __future__ import annotations

from typing import Self

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for library."""

    model_config = SettingsConfigDict(env_prefix="LIBRARY_", env_file=".env", extra="ignore")

    database_url: str = Field(default="postgresql://localhost/library")
    awid_registry_url: str = Field(default="https://api.awid.ai")
    awid_service_token: str | None = Field(default=None)
    public_origin: str = Field(default="https://library.aweb.ai")
    auth_cache_ttl_seconds: int = Field(default=600, ge=1)
    timestamp_skew_seconds: int = Field(default=300, ge=1)
    db_pool_min_connections: int = Field(default=1, ge=1)
    db_pool_max_connections: int = Field(default=5, ge=1)
    db_statement_cache_size: int = Field(default=0, ge=0)
    app_id: str = Field(default="library")
    app_events_origin: str | None = None
    app_emit_kid: str | None = None
    app_emit_key_seed_hex: str | None = None
    app_emit_timeout_seconds: float = Field(default=3.0, gt=0)

    @field_validator("awid_service_token")
    @classmethod
    def normalize_awid_service_token(cls, value: str | None) -> str | None:
        token = (value or "").strip()
        if not token:
            return None
        if len(token.encode("utf-8")) < 32:
            raise ValueError("LIBRARY_AWID_SERVICE_TOKEN must contain at least 32 bytes")
        return token

    @model_validator(mode="after")
    def validate_db_pool(self) -> Self:
        if self.db_pool_max_connections < self.db_pool_min_connections:
            raise ValueError("db_pool_max_connections must be >= db_pool_min_connections")
        return self


def get_settings() -> Settings:
    return Settings()
