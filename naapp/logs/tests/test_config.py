from __future__ import annotations

import pytest

from aweb_logs.config import LogsSettings
from aweb_logs.ingest import ClientQuota


def test_logs_reads_its_own_env_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOGS_DATABASE_URL", "postgresql://localhost/logs")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", "https://logs.example.test")
    monkeypatch.setenv("PUBLIC_ORIGIN", "https://unprefixed.test")
    settings = LogsSettings(_env_file=None)
    assert settings.public_origin == "https://logs.example.test"
    assert settings.database_url == "postgresql://localhost/logs"
    assert settings.app_id == "logs"


def test_logs_needs_its_database_and_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LOGS_DATABASE_URL", "LOGS_PUBLIC_ORIGIN"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError) as caught:
        LogsSettings(_env_file=None)
    missing = {error["loc"][0] for error in caught.value.errors()}  # type: ignore[attr-defined]
    assert missing == {"database_url", "public_origin"}


def test_checkpoints_are_issued_every_five_minutes_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOGS_DATABASE_URL", "postgresql://localhost/logs")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", "https://logs.example.test")
    assert LogsSettings(_env_file=None).checkpoint_interval_seconds == 300
    monkeypatch.setenv("LOGS_CHECKPOINT_INTERVAL_SECONDS", "0")
    with pytest.raises(ValueError):
        LogsSettings(_env_file=None)


def test_client_quotas_default_and_read_their_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOGS_DATABASE_URL", "postgresql://localhost/logs")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", "https://logs.example.test")
    assert LogsSettings(_env_file=None).client_quota == ClientQuota(
        events_per_minute=30, bytes_per_minute=131072
    )
    monkeypatch.setenv("LOGS_CLIENT_EVENTS_PER_MINUTE", "5")
    monkeypatch.setenv("LOGS_CLIENT_BYTES_PER_MINUTE", "2048")
    assert LogsSettings(_env_file=None).client_quota == ClientQuota(
        events_per_minute=5, bytes_per_minute=2048
    )


@pytest.mark.parametrize("name", ["LOGS_CLIENT_EVENTS_PER_MINUTE", "LOGS_CLIENT_BYTES_PER_MINUTE"])
def test_a_client_quota_admits_at_least_one_event(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setenv("LOGS_DATABASE_URL", "postgresql://localhost/logs")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", "https://logs.example.test")
    monkeypatch.setenv(name, "0")
    with pytest.raises(ValueError):
        LogsSettings(_env_file=None)
