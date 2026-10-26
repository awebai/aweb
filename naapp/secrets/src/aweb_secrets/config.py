"""secrets' configuration: the shared naapp settings under the ``SECRETS_`` prefix,
plus the console's own origin."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Self

from aweb_naapp.egress import InternalDestinations
from aweb_naapp.runtime.settings import NaappSettings
from pydantic import Field, field_validator, model_validator
from pydantic_settings import SettingsConfigDict


class SecretsSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="SECRETS_", env_file=".env", extra="ignore")

    database_url: str = Field(default="postgresql://localhost/secrets")
    # The agent API origin: team-auth only, no cookies.
    public_origin: str = Field(default="http://127.0.0.1:8770")
    # The human console origin: passkey sessions only, never team-auth. The
    # WebAuthn relying party is this exact host.
    console_origin: str = Field(default="http://127.0.0.1:8771")
    app_id: str = Field(default="secrets")

    # Applied both when recording a child and at every later authority fence.
    derived_max_ttl_s: int = Field(default=3600, gt=0)
    internal_destinations: InternalDestinations = InternalDestinations.DISABLED

    @field_validator("derived_max_ttl_s", mode="before")
    @classmethod
    def positive_integer_cap(cls, value):
        if isinstance(value, str) and value.isascii() and value.isdecimal():
            value = int(value)
        if type(value) is not int:
            raise ValueError("derived_max_ttl_s must be a positive integer")
        return value


class ServiceSettings(SecretsSettings):
    """Inputs to the production root; private material is supplied only by file."""

    custody_key_file: Path | None = None
    kms_key_id: str | None = None
    kms_region: str | None = None
    secret_request_key_file: Path
    secret_params_key_file: Path
    response_key_file: Path
    runner_service_key_file: Path
    email_smtp_host: str
    email_smtp_port: int = Field(default=587, gt=0, le=65535)
    email_tls: Literal["starttls", "implicit"] = "starttls"
    email_username: str
    email_password_file: Path
    email_from: str
    email_ca_file: Path | None = None
    egress_ca_file: Path | None = None
    broker_max_dispatch_seconds: int = Field(default=30, gt=0)
    sweep_margin_seconds: int = Field(default=5, gt=0)
    sweep_interval_seconds: int = Field(default=15, gt=0)
    runner_assignment_ttl_seconds: int = Field(default=60, ge=1, le=300)
    runner_claim_wait_seconds: int = Field(default=1, ge=0, le=30)

    @model_validator(mode="after")
    def one_custody_provider(self) -> Self:
        if (self.custody_key_file is None) == (self.kms_key_id is None):
            raise ValueError("configure exactly one of custody_key_file and kms_key_id")
        return self
