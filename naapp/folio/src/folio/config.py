from __future__ import annotations

from aweb_naapp.runtime.settings import NaappSettings
from aweb_naapp.runtime.team_auth import DidAwProfile
from pydantic import Field
from pydantic_settings import SettingsConfigDict


class Settings(NaappSettings):
    """Runtime configuration for folio: the shared naapp settings under FOLIO_."""

    model_config = SettingsConfigDict(env_prefix="FOLIO_", env_file=".env", extra="ignore")

    database_url: str = Field(default="postgresql://localhost/folio")
    public_origin: str = Field(default="http://127.0.0.1:8765")
    app_id: str = Field(default="folio")
    # Folio already serves released aw callers, so it observes the did:aw
    # current-key check rather than requiring it. It moves to REQUIRE in its own
    # change, once observe measurement shows no refused live callers and Juan
    # approves (the aweb-acgh.11 rollout).
    did_aw_profile: DidAwProfile = DidAwProfile.OBSERVE
    default_present_ttl_seconds: int = Field(default=86_400, ge=1)
    max_present_ttl_seconds: int = Field(default=604_800, ge=1)
    cloudflare_api_base: str = Field(default="https://api.cloudflare.com/client/v4")
    cloudflare_account_id: str | None = None
    cloudflare_stream_api_token: str | None = None
    cloudflare_stream_playback_host: str = Field(default="customer-example.cloudflarestream.com")
    cloudflare_stream_signing_key_id: str | None = None
    cloudflare_stream_signing_key_pem: str | None = None
    cloudflare_stream_direct_upload_ttl_seconds: int = Field(default=3_600, ge=60)
    cloudflare_stream_signed_playback_ttl_seconds: int = Field(default=3_600, ge=60)
    cloudflare_stream_max_duration_seconds: int = Field(default=600, ge=1)


def get_settings() -> Settings:
    return Settings()
