from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, *, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    log_level: str
    reload: bool
    database_url: str
    redis_url: str
    db_schema: str
    rate_limit_backend: str


def get_settings() -> Settings:
    database_url = os.getenv("AWID_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not database_url:
        raise ValueError(
            "DATABASE_URL or AWID_DATABASE_URL environment variable is required. "
            "Example: postgresql://user:pass@localhost:5432/awid"
        )

    redis_url = os.getenv("AWID_REDIS_URL") or os.getenv("REDIS_URL") or "redis://localhost:6379/0"
    schema = (os.getenv("AWID_DB_SCHEMA") or "awid").strip() or "awid"
    rate_limit_backend = (os.getenv("AWID_RATE_LIMIT_BACKEND") or "redis").strip().lower() or "redis"

    port_raw = os.getenv("AWID_PORT", "8010")
    port = int(port_raw)
    if not 1 <= port <= 65535:
        raise ValueError(f"AWID_PORT must be between 1 and 65535, got {port}")

    return Settings(
        host=os.getenv("AWID_HOST", "0.0.0.0"),
        port=port,
        log_level=os.getenv("AWID_LOG_LEVEL", "info"),
        reload=_env_bool("AWID_RELOAD"),
        database_url=database_url,
        redis_url=redis_url,
        db_schema=schema,
        rate_limit_backend=rate_limit_backend,
    )
