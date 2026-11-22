"""Runtime configuration every naapp shares.

An app subclasses :class:`NaappSettings` with its own ``env_prefix`` and gives
the app-specific values (``database_url``, ``public_origin``, ``app_id``) their
defaults; everything else here is common to every naapp.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from aweb_naapp.outbox import MAX_CALL_TIMEOUT_SECONDS
from aweb_naapp.runtime.team_auth import (
    MAX_TEAM_FACTS_TTL_SECONDS,
    MAX_TIMESTAMP_SKEW_SECONDS,
    DidAwProfile,
)
from aweb_naapp.settings import mounted_value


class _MountedEnvSource(EnvSettingsSource):
    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        for key, name, complex_value in self._extract_field_info(field, field_name):
            path = self.env_vars.get(self._apply_case_sensitive(name + "_FILE"))
            if path is not None:
                return (
                    mounted_value(name.upper(), self.env_vars.get(name), path),
                    key,
                    complex_value,
                )
        return super().get_field_value(field, field_name)


class AWIDMemberCredentialFiles(BaseModel):
    """An ordinary member certificate of one team and its signing key, in the
    files ``aw`` writes: the signing key as its ``ED25519 PRIVATE KEY`` PEM
    block, and the team certificate as JSON."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signing_key_file: Path
    certificate_file: Path


class NaappSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", hide_input_in_errors=True)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        assert isinstance(env_settings, EnvSettingsSource)
        return (
            init_settings,
            _MountedEnvSource(
                settings_cls,
                case_sensitive=env_settings.case_sensitive,
                env_prefix=env_settings.env_prefix,
                env_nested_delimiter=env_settings.env_nested_delimiter,
                env_nested_max_split=env_settings.env_nested_max_split,
                env_ignore_empty=env_settings.env_ignore_empty,
                env_parse_none_str=env_settings.env_parse_none_str,
                env_parse_enums=env_settings.env_parse_enums,
            ),
            dotenv_settings,
            file_secret_settings,
        )

    database_url: str
    # The schema the app's tables live in, pinned on every connection so the
    # app never depends on its database role's default search_path.
    db_schema: str = Field(default="public", pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    public_origin: str
    app_id: str
    awid_registry_url: str = Field(default="https://api.awid.ai")
    awid_service_token: str | None = Field(default=None, repr=False)
    # A customer-hosted app's own member certificate per team, with which it
    # path-signs that team's gated AWID reads; the service token, when set,
    # takes precedence (a hosted deployment).
    awid_member_credentials: dict[str, AWIDMemberCredentialFiles] = Field(default_factory=dict)
    # The verifier's own limits: a deployment cannot configure past them.
    auth_cache_ttl_seconds: int = Field(
        default=MAX_TEAM_FACTS_TTL_SECONDS, ge=1, le=MAX_TEAM_FACTS_TTL_SECONDS
    )
    timestamp_skew_seconds: int = Field(
        default=MAX_TIMESTAMP_SKEW_SECONDS, ge=1, le=MAX_TIMESTAMP_SKEW_SECONDS
    )
    # An app already serving released callers observes before it requires.
    did_aw_profile: DidAwProfile = DidAwProfile.REQUIRE
    # Staged team-key pin enforcement, one name for every naapp and the aweb
    # server: OFF logs team_key_pin_mismatch and serves the registry's key.
    enforce_team_key_pins: bool = Field(default=False, validation_alias="AWEB_ENFORCE_TEAM_KEY_PINS")
    db_pool_min_connections: int = Field(default=1, ge=1)
    db_pool_max_connections: int = Field(default=5, ge=1)
    db_statement_cache_size: int = Field(default=0, ge=0)
    # Shared page lifecycle policy is deliberately absent until the operator
    # publishes one. The fixed alias is stable across app-specific env prefixes.
    page_retention_policy: dict | None = Field(
        default=None, validation_alias="AWEB_PAGE_RETENTION_POLICY"
    )
    page_deletion_database_url: str | None = Field(
        default=None, repr=False, validation_alias="AWEB_PAGE_DELETION_DATABASE_URL"
    )
    app_events_origin: str | None = None
    # Key files by kid; which purposes a kid signs is the manifest's to declare.
    app_key_files: dict[str, Path] = Field(default_factory=dict)
    app_emit_kid: str | None = None
    # The released form of the app-event key: its seed as a value, for that key only.
    app_emit_key_seed_hex: SecretStr | None = None
    # Bounded by the outbox drain's own limit on one delivery.
    app_emit_timeout_seconds: float = Field(default=3.0, gt=0, le=MAX_CALL_TIMEOUT_SECONDS)
    app_events_stalled_after_seconds: int = Field(default=3600, ge=1)
    hook_events_stalled_after_seconds: int = Field(default=3600, ge=1)
    hook_delivery_timeout_seconds: float = Field(default=30.0, gt=0, le=MAX_CALL_TIMEOUT_SECONDS)
    # Independent random single-purpose HMAC key, not a manifest/signing key.
    manifest_request_key_file: Path | None = None
    manifest_hook_max_request_bytes: int = Field(default=1 << 20, ge=1, le=16 << 20)
    # Tools whose effects belong to a specific hook never emit the generic one.
    hook_tool_effects: dict[str, str] = Field(default_factory=dict)

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
