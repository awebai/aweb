from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Settings:
    host: str
    port: int
    log_level: str
    reload: bool


def get_settings() -> Settings:
    port_str = os.getenv("AWEB_PORT", "8001")
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"AWEB_PORT must be a valid integer, got '{port_str}'")

    return Settings(
        host=os.getenv("AWEB_HOST", "0.0.0.0"),
        port=port,
        log_level=os.getenv("AWEB_LOG_LEVEL", "info"),
        reload=os.getenv("AWEB_RELOAD", "false").lower() == "true",
    )

