"""Errors and limits shared by the page validation layers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

PAGE_LIMITS: Mapping[str, int] = MappingProxyType(
    {
        "max_bytes": 10 * 1024 * 1024,
        "max_json_depth": 64,
        "max_depth": 8,
        "max_widgets": 2000,
        "max_bundle_items": 64,
        "max_inline_schema_depth": 16,
        "max_inline_schema_pattern": 256,
    }
)


@dataclass(frozen=True, order=True)
class PageError:
    layer: str
    code: str
    pointer: str


def pointer(parts: Iterable[str | int]) -> str:
    """The RFC 6901 JSON pointer for a path of keys and indexes."""
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in parts)
