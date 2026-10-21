from __future__ import annotations

import pytest

from aweb_logs.config import LogsSettings


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
