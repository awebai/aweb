from __future__ import annotations

from aweb_naapp.runtime.settings import NaappSettings
from aweb_naapp.runtime.team_auth import DidAwProfile
from pydantic import Field
from pydantic_settings import SettingsConfigDict


class Settings(NaappSettings):
    """Runtime configuration for library: the shared naapp settings under LIBRARY_."""

    model_config = SettingsConfigDict(env_prefix="LIBRARY_", env_file=".env", extra="ignore")

    database_url: str = Field(default="postgresql://localhost/library")
    public_origin: str = Field(default="https://library.aweb.ai")
    app_id: str = Field(default="library")
    # Library already serves released aw callers, so it observes the did:aw
    # current-key check rather than requiring it, as Folio does until its
    # observe measurement shows no refused live callers.
    did_aw_profile: DidAwProfile = DidAwProfile.OBSERVE


def get_settings() -> Settings:
    return Settings()
