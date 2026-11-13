from __future__ import annotations

import pytest
from pydantic import ValidationError

from library.config import Settings


def test_defaults_use_library_naming() -> None:
    settings = Settings()
    assert "library" in settings.database_url
    assert settings.public_origin == "https://library.aweb.ai"


def test_env_prefix_is_library(monkeypatch) -> None:
    monkeypatch.setenv("LIBRARY_PUBLIC_ORIGIN", "https://library.example.test")
    settings = Settings()
    assert settings.public_origin == "https://library.example.test"


def test_db_pool_validation_rejects_max_below_min() -> None:
    with pytest.raises(ValidationError):
        Settings(db_pool_min_connections=5, db_pool_max_connections=2)
