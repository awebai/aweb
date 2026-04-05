"""Stable-identity audit-log helpers."""

from __future__ import annotations

import hashlib
from urllib.parse import urlparse

from aweb.awid.signing import canonical_json_bytes


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_server_origin(server_url: str) -> str:
    server_url = server_url.strip()
    if not server_url:
        raise ValueError("server URL must be non-empty")
    parsed = urlparse(server_url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise ValueError("server URL scheme must be http or https")
    if parsed.username or parsed.password:
        raise ValueError("server URL must not include userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("server URL must not include query or fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("server URL must not include a path (origin only)")
    if not parsed.hostname:
        raise ValueError("server URL must include a host")

    host = parsed.hostname.lower()
    host_out = f"[{host}]" if ":" in host and not host.startswith("[") else host

    port = parsed.port
    default_port = 80 if scheme == "http" else 443
    port_out = None if port in (None, default_port) else port
    return f"{scheme}://{host_out}{f':{port_out}' if port_out is not None else ''}"


def require_canonical_server_origin(server_url: str) -> str:
    canonical = canonical_server_origin(server_url)
    if server_url != canonical:
        raise ValueError(
            f"server URL must be canonical origin form: {canonical} "
            "(no trailing slash, no path, lowercase host)"
        )
    return canonical


def log_entry_payload(
    *,
    did_aw: str,
    seq: int,
    operation: str,
    previous_did_key: str | None,
    new_did_key: str,
    prev_entry_hash: str | None,
    state_hash: str,
    authorized_by: str,
    timestamp: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "authorized_by": authorized_by,
            "did_aw": did_aw,
            "new_did_key": new_did_key,
            "operation": operation,
            "prev_entry_hash": prev_entry_hash,
            "previous_did_key": previous_did_key,
            "seq": seq,
            "state_hash": state_hash,
            "timestamp": timestamp,
        }
    )


def state_hash(
    *,
    did_aw: str,
    current_did_key: str,
    server: str | None,
    address: str | None,
    handle: str | None,
) -> str:
    normalized_server = "" if server is None else server
    normalized_address = "" if address is None else address
    payload = canonical_json_bytes(
        {
            "address": normalized_address,
            "current_did_key": current_did_key,
            "did_aw": did_aw,
            "handle": handle,
            "server": normalized_server,
        }
    )
    return sha256_hex(payload)
