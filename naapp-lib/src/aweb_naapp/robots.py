"""The naapp ``/robots.txt``."""

from __future__ import annotations

from collections.abc import Sequence


def robots_txt(disallow: Sequence[str] = ()) -> str:
    """Rules for every crawler: the given paths are disallowed, and with none
    everything is allowed."""
    rules = [f"Disallow: {path}" for path in disallow] or ["Allow: /"]
    return "\n".join(["User-agent: *", *rules, ""])
