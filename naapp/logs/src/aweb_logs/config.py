"""logs' configuration: the shared naapp settings under the ``LOGS_`` prefix."""

from __future__ import annotations

from typing import Self
from urllib.parse import urlsplit

from aweb_naapp.runtime.settings import NaappSettings
from pydantic import Field, model_validator
from pydantic_settings import SettingsConfigDict

from aweb_logs.ingest import ClientQuota


class LogsSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="LOGS_", env_file=".env", extra="ignore")

    app_id: str = Field(default="logs")
    # The origin a designated reader's browser uses (design §B5): passkeys are
    # bound to its hostname and its session cookie never reaches the agent origin.
    console_origin: str
    # How often each team whose chain moved gets a checkpoint (design §B3).
    checkpoint_interval_seconds: float = Field(default=300, gt=0)

    # One member's client events per one-minute window (design §B2).
    client_events_per_minute: int = Field(default=30, ge=1)
    client_bytes_per_minute: int = Field(default=131072, ge=1)

    @property
    def client_quota(self) -> ClientQuota:
        return ClientQuota(
            events_per_minute=self.client_events_per_minute,
            bytes_per_minute=self.client_bytes_per_minute,
        )

    @model_validator(mode="after")
    def console_on_its_own_host(self) -> Self:
        console = urlsplit(self.console_origin.rstrip("/"))
        if (
            console.scheme != "https"
            or not console.hostname
            or console.path
            or console.query
            or console.fragment
            or console.username
            or console.password
        ):
            raise ValueError("LOGS_CONSOLE_ORIGIN must be a plain https origin")
        public = urlsplit(self.public_origin).hostname or ""
        # A passkey's relying party, the console host, is usable from its subdomains.
        if public == console.hostname or public.endswith("." + console.hostname):
            raise ValueError("LOGS_CONSOLE_ORIGIN must be on a host of its own")
        return self
