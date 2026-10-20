"""Runtime configuration every naapp shares.

An app subclasses :class:`NaappSettings` with its own ``env_prefix`` and gives
the app-specific values (``database_url``, ``public_origin``, ``app_id``) their
defaults; everything else here is common to every naapp.
"""

from __future__ import annotations

from pathlib import Path
from typing import Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from aweb_naapp.outbox import MAX_CALL_TIMEOUT_SECONDS
from aweb_naapp.runtime.team_auth import MAX_TEAM_FACTS_TTL_SECONDS, MAX_TIMESTAMP_SKEW_SECONDS


class NaappSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    public_origin: str
    app_id: str
    awid_registry_url: str = Field(default="https://api.awid.ai")
    awid_service_token: str | None = Field(default=None, repr=False)
    # The verifier's own limits: a deployment cannot configure past them.
    auth_cache_ttl_seconds: int = Field(
        default=MAX_TEAM_FACTS_TTL_SECONDS, ge=1, le=MAX_TEAM_FACTS_TTL_SECONDS
    )
    timestamp_skew_seconds: int = Field(
        default=MAX_TIMESTAMP_SKEW_SECONDS, ge=1, le=MAX_TIMESTAMP_SKEW_SECONDS
    )
    db_pool_min_connections: int = Field(default=1, ge=1)
    db_pool_max_connections: int = Field(default=5, ge=1)
    db_statement_cache_size: int = Field(default=0, ge=0)
    app_events_origin: str | None = None
    # Key files by kid; which purposes a kid signs is the manifest's to declare.
    app_key_files: dict[str, Path] = Field(default_factory=dict)
    app_emit_kid: str | None = None
    # The released form of the app-event key: its seed as a value, for that key only.
    app_emit_key_seed_hex: SecretStr | None = None
    # Bounded by the outbox drain's own limit on one delivery.
    app_emit_timeout_seconds: float = Field(default=3.0, gt=0, le=MAX_CALL_TIMEOUT_SECONDS)
    app_events_stalled_after_seconds: int = Field(default=3600, ge=1)

    @field_validator("awid_service_token")
    @classmethod
    def normalize_awid_service_token(cls, value: str | None) -> str | None:
        token = (value or "").strip()
        if not token:
            return None
        if len(token.encode("utf-8")) < 32:
            prefix = cls.model_config.get("env_prefix", "")
            raise ValueError(f"{prefix}AWID_SERVICE_TOKEN must contain at least 32 bytes")
        return token

    @model_validator(mode="after")
    def validate_db_pool(self) -> Self:
        if self.db_pool_max_connections < self.db_pool_min_connections:
            raise ValueError("db_pool_max_connections must be >= db_pool_min_connections")
        return self
