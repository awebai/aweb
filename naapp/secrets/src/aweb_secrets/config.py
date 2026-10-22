"""secrets' configuration: the shared naapp settings under the ``SECRETS_`` prefix,
plus the console's own origin."""

from __future__ import annotations

from aweb_naapp.egress import InternalDestinations
from aweb_naapp.runtime.settings import NaappSettings
from pydantic import Field, field_validator
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
