"""logs' configuration: the shared naapp settings under the ``LOGS_`` prefix."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import SettingsConfigDict

from aweb_naapp.runtime.settings import NaappSettings


class LogsSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="LOGS_", env_file=".env", extra="ignore")

    app_id: str = Field(default="logs")
