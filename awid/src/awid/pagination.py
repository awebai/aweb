"""Cursor-based pagination helpers for coordination API endpoints.

This module provides consistent pagination across all list endpoints:
- Cursor encoding/decoding for stateless pagination
- Parameter validation with sensible defaults and limits
"""

from __future__ import annotations

import base64
import json
from typing import Any, Optional

# Pagination constants per spec
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_CURSOR_SIZE_BYTES = 8192  # 8KB max cursor size to prevent DoS


def encode_cursor(data: dict[str, Any]) -> str:
    """Encode pagination state as a URL-safe cursor string.

    Args:
        data: Dictionary containing pagination state (e.g., last id, timestamp)

    Returns:
        URL-safe base64 encoded string representing the pagination state
    """
    json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(json_bytes).decode("ascii").rstrip("=")


def decode_cursor(cursor: Optional[str]) -> Optional[dict[str, Any]]:
    """Decode a cursor string back to pagination state.

    Args:
        cursor: URL-safe base64 encoded cursor string, or None/empty

    Returns:
        Dictionary containing pagination state, or None if cursor was None/empty

    Raises:
        ValueError: If cursor is malformed (invalid base64 or JSON) or too large
    """
    if cursor is None or cursor == "":
        return None

    # Validate size before decoding
    if len(cursor) > MAX_CURSOR_SIZE_BYTES:
        raise ValueError(f"Invalid cursor: exceeds maximum size of {MAX_CURSOR_SIZE_BYTES} bytes")

    try:
        # Over-pad to let base64 library handle any valid padding
        json_bytes = base64.urlsafe_b64decode(cursor + "===")
    except ValueError as e:
        raise ValueError(f"Invalid cursor: malformed encoding ({e})") from e

    # Validate decoded size
    if len(json_bytes) > MAX_CURSOR_SIZE_BYTES:
        raise ValueError("Invalid cursor: decoded data exceeds maximum size")

    try:
        data = json.loads(json_bytes.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid cursor: malformed data at position {e.pos}") from e
    except UnicodeDecodeError:
        raise ValueError("Invalid cursor: contains invalid UTF-8 data")

    if not isinstance(data, dict):
        raise ValueError("Invalid cursor: must decode to a dictionary")

    return data


def validate_pagination_params(
    limit: Optional[int],
    cursor: Optional[str],
) -> tuple[int, Optional[dict[str, Any]]]:
    """Validate and normalize pagination parameters.

    Args:
        limit: Requested page size (will be clamped to valid range)
        cursor: Opaque cursor string from previous response

    Returns:
        Tuple of (validated_limit, decoded_cursor_dict)
        - limit is clamped to [1, MAX_LIMIT], defaults to DEFAULT_LIMIT
        - cursor is decoded to dict, or None if not provided

    Raises:
        ValueError: If cursor is malformed
    """
    # Validate and clamp limit
    if limit is None:
        validated_limit = DEFAULT_LIMIT
    elif limit < 1:
        validated_limit = 1
    elif limit > MAX_LIMIT:
        validated_limit = MAX_LIMIT
    else:
        validated_limit = limit

    # Decode cursor (will raise ValueError if malformed)
    decoded_cursor = decode_cursor(cursor)

    return validated_limit, decoded_cursor
