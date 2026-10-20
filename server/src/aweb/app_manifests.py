"""Exact app manifest bytes from an app origin."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

import httpx

from aweb.app_registry import normalize_origin
from aweb.service_errors import ValidationError

MANIFEST_PATH = "/.well-known/aweb-app.json"
MAX_MANIFEST_BYTES = 10 << 20


def fetch_app_manifest(origin: str, *, timeout: float = 30.0, max_bytes: int = MAX_MANIFEST_BYTES) -> bytes:
    """Return the exact bytes an app origin serves at its well-known manifest path.

    Only a direct 200 is accepted: redirects are not followed, so the bytes come
    from the named origin. Plain http is fetched only from loopback hosts.
    Bodies over ``max_bytes`` are refused.
    """

    origin = normalize_origin(origin)
    parsed = urlparse(origin)
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname or ""):
        raise ValidationError("manifest fetch requires https outside loopback hosts")
    url = origin + MANIFEST_PATH
    try:
        with httpx.Client(follow_redirects=False, timeout=timeout) as client:
            with client.stream("GET", url) as response:
                if response.status_code != 200:
                    raise ValidationError(f"manifest fetch returned status {response.status_code}")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        raise ValidationError("manifest exceeds the size bound")
    except httpx.HTTPError as exc:
        raise ValidationError(f"manifest fetch failed: {exc}") from exc
    return bytes(body)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
