from __future__ import annotations

import secrets

import pytest
from pydantic import Field, ValidationError
from pydantic_settings import SettingsConfigDict

from aweb_naapp.runtime.settings import NaappSettings
from aweb_naapp.runtime.team_auth import MAX_TEAM_FACTS_TTL_SECONDS, MAX_TIMESTAMP_SKEW_SECONDS


class ExampleSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_")

    database_url: str = Field(default="postgresql://localhost/example")
    public_origin: str = Field(default="https://example.test")
    app_id: str = Field(default="example")


def _settings(**values: object) -> ExampleSettings:
    return ExampleSettings(_env_file=None, **values)


def test_app_subclass_supplies_its_own_defaults() -> None:
    settings = _settings()
    assert settings.app_id == "example"
    assert settings.database_url == "postgresql://localhost/example"
    assert settings.public_origin == "https://example.test"
    assert settings.awid_registry_url == "https://api.awid.ai"


def test_app_subclass_reads_its_own_env_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EXAMPLE_PUBLIC_ORIGIN", "https://example.example.test")
    monkeypatch.setenv("EXAMPLE_APP_EMIT_KID", "example:emit-1")
    monkeypatch.setenv("EXAMPLE_DB_POOL_MIN_CONNECTIONS", "2")
    monkeypatch.setenv("EXAMPLE_DB_POOL_MAX_CONNECTIONS", "4")
    monkeypatch.setenv("PUBLIC_ORIGIN", "https://unprefixed.test")
    settings = _settings()
    assert settings.public_origin == "https://example.example.test"
    assert settings.app_emit_kid == "example:emit-1"
    assert (settings.db_pool_min_connections, settings.db_pool_max_connections) == (2, 4)


def test_shared_settings_need_the_app_specific_values(monkeypatch: pytest.MonkeyPatch) -> None:
    # The base has no env_prefix, so it would read these bare names.
    for name in ("DATABASE_URL", "PUBLIC_ORIGIN", "APP_ID"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValidationError) as caught:
        NaappSettings(_env_file=None)
    missing = {error["loc"][0] for error in caught.value.errors()}
    assert missing == {"database_url", "public_origin", "app_id"}


def test_db_pool_is_modest_by_default() -> None:
    settings = _settings()
    assert settings.db_pool_min_connections == 1
    assert settings.db_pool_max_connections == 5
    assert settings.db_statement_cache_size == 0


def test_db_pool_rejects_max_below_min() -> None:
    with pytest.raises(ValidationError):
        _settings(db_pool_min_connections=5, db_pool_max_connections=4)


def test_emit_is_disabled_by_default() -> None:
    settings = _settings()
    assert settings.app_events_origin is None
    assert settings.app_emit_kid is None
    assert settings.app_emit_key_seed_hex is None


def test_service_token_is_trimmed_and_blank_means_none(monkeypatch: pytest.MonkeyPatch) -> None:
    token = secrets.token_urlsafe(24)
    monkeypatch.setenv("EXAMPLE_AWID_SERVICE_TOKEN", "  " + token + "  ")
    assert _settings().awid_service_token == token
    monkeypatch.setenv("EXAMPLE_AWID_SERVICE_TOKEN", "  ")
    assert _settings().awid_service_token is None


def test_service_token_shorter_than_32_bytes_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _settings(awid_service_token=secrets.token_hex(15) + "a")
    assert _settings(awid_service_token="x" * 32).awid_service_token == "x" * 32


def test_credentials_are_kept_out_of_repr() -> None:
    token = secrets.token_urlsafe(24)
    seed_hex = secrets.token_hex(32)
    text = repr(_settings(awid_service_token=token, app_emit_key_seed_hex=seed_hex))
    assert token not in text
    assert seed_hex not in text


def test_auth_cache_ttl_defaults_to_the_verifier_limit_and_cannot_exceed_it() -> None:
    assert _settings().auth_cache_ttl_seconds == MAX_TEAM_FACTS_TTL_SECONDS
    assert _settings(auth_cache_ttl_seconds=1).auth_cache_ttl_seconds == 1
    with pytest.raises(ValidationError):
        _settings(auth_cache_ttl_seconds=MAX_TEAM_FACTS_TTL_SECONDS + 1)


def test_timestamp_skew_cannot_exceed_the_verifier_limit() -> None:
    assert (
        _settings(timestamp_skew_seconds=MAX_TIMESTAMP_SKEW_SECONDS).timestamp_skew_seconds == 300
    )
    with pytest.raises(ValidationError):
        _settings(timestamp_skew_seconds=MAX_TIMESTAMP_SKEW_SECONDS + 1)
