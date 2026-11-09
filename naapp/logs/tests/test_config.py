from __future__ import annotations

import pytest

from aweb_logs.config import LogsSettings
from aweb_logs.ingest import ClientQuota


def test_logs_reads_its_own_env_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOGS_DATABASE_URL", "postgresql://localhost/logs")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", "https://logs.example.test")
    monkeypatch.setenv("LOGS_CONSOLE_ORIGIN", "https://console.logs.example.test")
    monkeypatch.setenv("PUBLIC_ORIGIN", "https://unprefixed.test")
    settings = LogsSettings(_env_file=None)
    assert settings.public_origin == "https://logs.example.test"
    assert settings.database_url == "postgresql://localhost/logs"
    assert settings.app_id == "logs"


def test_logs_needs_its_database_and_both_origins(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LOGS_DATABASE_URL", "LOGS_PUBLIC_ORIGIN", "LOGS_CONSOLE_ORIGIN"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError) as caught:
        LogsSettings(_env_file=None)
    missing = {error["loc"][0] for error in caught.value.errors()}  # type: ignore[attr-defined]
    assert missing == {"database_url", "public_origin", "console_origin"}


def test_the_console_origin_is_read_from_its_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOGS_DATABASE_URL", "postgresql://localhost/logs")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", "https://logs.example.test")
    monkeypatch.setenv("LOGS_CONSOLE_ORIGIN", "https://console.logs.example.test")
    assert LogsSettings(_env_file=None).console_origin == "https://console.logs.example.test"


@pytest.mark.parametrize(
    "console_origin",
    [
        "https://logs.example.test",
        "https://LOGS.example.test/",
        "https://logs.example.test:8443",
        "http://console.logs.example.test",
        "https://console.logs.example.test/console",
        "console.logs.example.test",
    ],
    ids=["same", "same-normalized", "same-host-other-port", "plain-http", "with-path", "no-scheme"],
)
def test_the_console_is_a_plain_https_origin_on_its_own_host(
    monkeypatch: pytest.MonkeyPatch, console_origin: str
) -> None:
    monkeypatch.setenv("LOGS_DATABASE_URL", "postgresql://localhost/logs")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", "https://logs.example.test")
    monkeypatch.setenv("LOGS_CONSOLE_ORIGIN", console_origin)
    with pytest.raises(ValueError) as caught:
        LogsSettings(_env_file=None)
    assert {error["loc"] for error in caught.value.errors()} == {()}  # type: ignore[attr-defined]


def test_checkpoints_are_issued_every_five_minutes_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOGS_DATABASE_URL", "postgresql://localhost/logs")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", "https://logs.example.test")
    monkeypatch.setenv("LOGS_CONSOLE_ORIGIN", "https://console.logs.example.test")
    assert LogsSettings(_env_file=None).checkpoint_interval_seconds == 300
    monkeypatch.setenv("LOGS_CHECKPOINT_INTERVAL_SECONDS", "0")
    with pytest.raises(ValueError):
        LogsSettings(_env_file=None)


def test_client_quotas_default_and_read_their_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOGS_DATABASE_URL", "postgresql://localhost/logs")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", "https://logs.example.test")
    monkeypatch.setenv("LOGS_CONSOLE_ORIGIN", "https://console.logs.example.test")
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
    monkeypatch.setenv("LOGS_CONSOLE_ORIGIN", "https://console.logs.example.test")
    monkeypatch.setenv(name, "0")
    with pytest.raises(ValueError):
        LogsSettings(_env_file=None)


@pytest.mark.parametrize(
    "public_origin",
    ["https://api.console.logs.example.test", "https://a.b.CONSOLE.logs.example.test"],
    ids=["subdomain", "deeper-subdomain"],
)
def test_the_public_origin_is_never_under_the_console_host(
    monkeypatch: pytest.MonkeyPatch, public_origin: str
) -> None:
    # A passkey's relying party, the console host, is usable from its subdomains.
    monkeypatch.setenv("LOGS_DATABASE_URL", "postgresql://localhost/logs")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", public_origin)
    monkeypatch.setenv("LOGS_CONSOLE_ORIGIN", "https://console.logs.example.test")
    with pytest.raises(ValueError) as caught:
        LogsSettings(_env_file=None)
    assert {error["loc"] for error in caught.value.errors()} == {()}  # type: ignore[attr-defined]


def test_the_console_may_be_under_the_public_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOGS_DATABASE_URL", "postgresql://localhost/logs")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", "https://logs.example.test")
    monkeypatch.setenv("LOGS_CONSOLE_ORIGIN", "https://console.logs.example.test")
    assert LogsSettings(_env_file=None).console_origin == "https://console.logs.example.test"
