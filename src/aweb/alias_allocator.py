from __future__ import annotations

from collections.abc import Iterable, Iterator

from aweb.names import CLASSIC_NAMES


class AliasExhaustedError(RuntimeError):
    pass


def extract_name_prefix(alias: str) -> str:
    alias = (alias or "").strip()
    if not alias:
        return ""
    parts = alias.split("-")
    if len(parts) >= 2 and parts[1].isdigit():
        return f"{parts[0]}-{parts[1]}".lower()
    return parts[0].lower()


def candidate_name_prefixes() -> Iterator[str]:
    yield from CLASSIC_NAMES
    for num in range(1, 100):
        for name in CLASSIC_NAMES:
            yield f"{name}-{num:02d}"


def used_name_prefixes(existing_aliases: Iterable[str]) -> set[str]:
    used: set[str] = set()
    for alias in existing_aliases:
        prefix = extract_name_prefix(alias)
        if prefix:
            used.add(prefix)
    return used


def suggest_next_name_prefix(existing_aliases: Iterable[str]) -> str | None:
    used = used_name_prefixes(existing_aliases)
    for candidate in candidate_name_prefixes():
        if candidate not in used:
            return candidate
    return None

