from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse

from awid.log import canonical_server_origin


def _is_development_environment() -> bool:
    for name in ("APP_ENV", "ENVIRONMENT"):
        value = (os.getenv(name) or "").strip().lower()
        if value:
            return value in {"dev", "development", "local", "test", "testing"}
    return False


def _is_localhost_origin(origin: str) -> bool:
    host = (urlparse(origin).hostname or "").lower()
    return host == "localhost" or host.endswith(".localhost")


def _allow_insecure_delivery_origin() -> bool:
    return (os.getenv("AWID_ALLOW_INSECURE_DELIVERY_ORIGIN") or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def validate_delivery_origin(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        canonical = canonical_server_origin(value)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    parsed = urlparse(canonical)
    is_development = _is_development_environment()
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "http" and is_development and _allow_insecure_delivery_origin():
        return canonical
    if _is_localhost_origin(canonical):
        if is_development and parsed.scheme == "http":
            return canonical
        raise ValueError("delivery_origin must not target localhost outside development")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("delivery_origin must not use a literal IP address")

    if parsed.scheme != "https":
        raise ValueError("delivery_origin must use https")
    return canonical
