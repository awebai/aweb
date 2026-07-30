from __future__ import annotations

from typing import Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for folio."""

    model_config = SettingsConfigDict(env_prefix="FOLIO_", env_file=".env", extra="ignore")

    database_url: str = Field(default="postgresql://localhost/folio")
    awid_registry_url: str = Field(default="https://api.awid.ai")
    public_origin: str = Field(default="http://127.0.0.1:8765")
    free_max_documents: int = Field(default=3, ge=1)
    free_max_versions_per_doc: int = Field(default=50, ge=1)
    auth_cache_ttl_seconds: int = Field(default=600, ge=1)
    timestamp_skew_seconds: int = Field(default=300, ge=1)
    default_present_ttl_seconds: int = Field(default=86_400, ge=1)
    max_present_ttl_seconds: int = Field(default=604_800, ge=1)
    db_pool_min_connections: int = Field(default=1, ge=1)
    db_pool_max_connections: int = Field(default=5, ge=1)
    db_statement_cache_size: int = Field(default=0, ge=0)
    cloudflare_api_base: str = Field(default="https://api.cloudflare.com/client/v4")
    cloudflare_account_id: str | None = None
    cloudflare_stream_api_token: str | None = None
    cloudflare_stream_playback_host: str = Field(default="customer-example.cloudflarestream.com")
    cloudflare_stream_signing_key_id: str | None = None
    cloudflare_stream_signing_key_pem: str | None = None
    cloudflare_stream_direct_upload_ttl_seconds: int = Field(default=3_600, ge=60)
    cloudflare_stream_signed_playback_ttl_seconds: int = Field(default=3_600, ge=60)
    cloudflare_stream_max_duration_seconds: int = Field(default=600, ge=1)
    app_id: str = Field(default="folio")
    app_events_origin: str | None = None
    app_emit_kid: str | None = None
    app_emit_key_seed_hex: str | None = None
    app_emit_timeout_seconds: float = Field(default=3.0, gt=0)

    @model_validator(mode="after")
    def validate_db_pool(self) -> Self:
        if self.db_pool_max_connections < self.db_pool_min_connections:
            raise ValueError("db_pool_max_connections must be >= db_pool_min_connections")
        return self


def get_settings() -> Settings:
    return Settings()
