"""logs' configuration: the shared naapp settings under the ``LOGS_`` prefix."""

from __future__ import annotations

from aweb_naapp.runtime.settings import NaappSettings
from pydantic import Field
from pydantic_settings import SettingsConfigDict

from aweb_logs.ingest import ClientQuota


class LogsSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="LOGS_", env_file=".env", extra="ignore")

    app_id: str = Field(default="logs")
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
