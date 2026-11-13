"""Role validation and normalization helpers."""

from __future__ import annotations

import re

ROLE_MAX_LENGTH = 50
ROLE_MAX_WORDS = 2
ROLE_WORD_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")
ROLE_ERROR_MESSAGE = (
    "Invalid role: use 1-2 words (letters/numbers) with hyphens/underscores allowed; max 50 chars"
)


def normalize_role(role: str) -> str:
    """Normalize role string by trimming, collapsing spaces, and lowercasing."""
    return " ".join(role.strip().split()).lower()


def is_valid_role(role: str) -> bool:
    """Check if role is 1-2 words with allowed characters."""
    if not role or not isinstance(role, str):
        return False
    normalized = normalize_role(role)
    if not normalized or len(normalized) > ROLE_MAX_LENGTH:
        return False
    words = normalized.split(" ")
    if len(words) > ROLE_MAX_WORDS:
        return False
    return all(ROLE_WORD_PATTERN.match(word) for word in words)
