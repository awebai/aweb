from __future__ import annotations

from typing import Self

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The verifier's own limits. A revoked certificate is accepted for as long as
# its team's facts stay cached, and a captured request for as long as the
# clock skew allows.
MAX_TIMESTAMP_SKEW_SECONDS = 300
MAX_TEAM_FACTS_TTL_SECONDS = 60


class Settings(BaseSettings):
    """Runtime configuration for library."""

    model_config = SettingsConfigDict(env_prefix="LIBRARY_", env_file=".env", extra="ignore")

    database_url: str = Field(default="postgresql://localhost/library")
    awid_registry_url: str = Field(default="https://api.awid.ai")
    awid_service_token: str | None = Field(default=None, repr=False)
    public_origin: str = Field(default="https://library.aweb.ai")
    # The verifier's own limits: a deployment cannot configure past them.
    auth_cache_ttl_seconds: int = Field(
        default=MAX_TEAM_FACTS_TTL_SECONDS, ge=1, le=MAX_TEAM_FACTS_TTL_SECONDS
    )
    timestamp_skew_seconds: int = Field(
        default=MAX_TIMESTAMP_SKEW_SECONDS, ge=1, le=MAX_TIMESTAMP_SKEW_SECONDS
    )
    # Staged team-key pin enforcement, the one name the aweb server and every
    # naapp read: OFF logs team_key_pin_mismatch and serves the registry's key.
    enforce_team_key_pins: bool = Field(default=False, validation_alias="AWEB_ENFORCE_TEAM_KEY_PINS")
    db_pool_min_connections: int = Field(default=1, ge=1)
    db_pool_max_connections: int = Field(default=5, ge=1)
    db_statement_cache_size: int = Field(default=0, ge=0)

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
