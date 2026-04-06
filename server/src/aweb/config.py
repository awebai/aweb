import os
from dataclasses import dataclass
from typing import Optional

DEFAULT_AWID_REGISTRY_URL = "https://api.awid.ai"


def _env_bool(*names: str, default: bool = False) -> bool:
    for name in names:
        value = os.getenv(name)
        if value is None:
            continue
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return default


def _env_optional_int(*names: str) -> Optional[int]:
    for name in names:
        value = os.getenv(name)
        if value is None or not value.strip():
            continue
        return int(value)
    return None


@dataclass
class Settings:
    host: str
    port: int
    log_level: str
    reload: bool
    redis_url: str
    database_url: str
    database_uses_transaction_pooler: bool
    database_statement_cache_size: Optional[int]
    presence_ttl_seconds: int
    awid_registry_url: str
    dashboard_jwt_secret: str


def get_awid_registry_url() -> str:
    value = (os.getenv("AWID_REGISTRY_URL") or "").strip()
    if not value:
        return DEFAULT_AWID_REGISTRY_URL
    if value.lower() == "local":
        raise ValueError(
            "AWID_REGISTRY_URL=local is no longer supported. Run the awid service separately and point AWEB at its HTTP origin."
        )
    return value


def get_settings() -> Settings:
    """
    Load settings from environment at call time.

    Uses `AWEB_*` settings, falling back to unprefixed infrastructure vars where
    that keeps deployment wiring simple.
    """
    database_url = os.getenv("AWEB_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not database_url:
        raise ValueError(
            "DATABASE_URL or AWEB_DATABASE_URL environment variable is required. "
            "Example: postgresql://user:pass@localhost:5432/aweb"
        )

    redis_url = os.getenv("AWEB_REDIS_URL") or os.getenv("REDIS_URL") or "redis://localhost:6379/0"

    port_str = os.getenv("AWEB_PORT", "8000")
    try:
        port = int(port_str)
        if not 1 <= port <= 65535:
            raise ValueError(f"AWEB_PORT must be between 1 and 65535, got {port}")
    except ValueError as e:
        if "invalid literal" in str(e):
            raise ValueError(f"AWEB_PORT must be a valid integer, got '{port_str}'")
        raise

    presence_ttl_str = os.getenv("AWEB_PRESENCE_TTL_SECONDS", "1800")
    try:
        presence_ttl = int(presence_ttl_str)
        if presence_ttl < 10:
            raise ValueError("AWEB_PRESENCE_TTL_SECONDS must be at least 10")
    except ValueError as e:
        if "invalid literal" in str(e):
            raise ValueError(
                f"AWEB_PRESENCE_TTL_SECONDS must be a valid integer, got '{presence_ttl_str}'"
            )
        raise

    return Settings(
        host=os.getenv("AWEB_HOST", "0.0.0.0"),
        port=port,
        log_level=os.getenv("AWEB_LOG_LEVEL", "info"),
        reload=os.getenv("AWEB_RELOAD", "false").lower() == "true",
        redis_url=redis_url,
        database_url=database_url,
        database_uses_transaction_pooler=_env_bool(
            "AWEB_DATABASE_USES_TRANSACTION_POOLER",
            "DATABASE_USES_TRANSACTION_POOLER",
        ),
        database_statement_cache_size=_env_optional_int(
            "AWEB_DATABASE_STATEMENT_CACHE_SIZE",
            "DATABASE_STATEMENT_CACHE_SIZE",
        ),
        presence_ttl_seconds=presence_ttl,
        awid_registry_url=get_awid_registry_url(),
        dashboard_jwt_secret=os.getenv("AWEB_DASHBOARD_JWT_SECRET", ""),
    )
