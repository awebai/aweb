"""Host limits and JSON Schema validation of aweb.page/1 pages."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from aweb_naapp.pages.errors import PAGE_LIMITS, PageError, pointer
from aweb_naapp.pages.lint import lint_errors

PAGE_SCHEMA: Mapping[str, Any] = json.loads(
    files("aweb_naapp.pages").joinpath("page-format-v1.schema.json").read_text(encoding="utf-8")
)

# RFC 3339 date-time with a mandatory offset. jsonschema skips "date-time"
# unless an optional package is installed, so the check is registered here.
_DATE_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})"
)


@dataclass(frozen=True)
class Validation:
    errors: tuple[PageError, ...]

    @property
    def valid(self) -> bool:
        return not self.errors


def _format_checker() -> FormatChecker:
    checker = FormatChecker(formats=())

    @checker.checks("date-time")
    def _date_time(value: object) -> bool:
        if not isinstance(value, str):
            return True
        if _DATE_TIME.fullmatch(value) is None:
            return False
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
        return True

    return checker


_VALIDATOR = Draft202012Validator(PAGE_SCHEMA, format_checker=_format_checker())


def _refused(code: str, at: str = "") -> Validation:
    return Validation((PageError("limits", code, at),))


class _Refused(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _Refused("duplicate_key")
        result[key] = value
    return result


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise _Refused("non_finite_number")
    return value


def _non_finite(_: str) -> float:
    raise _Refused("non_finite_number")


def validate_page_bytes(raw: bytes) -> Validation:
    """Validate a page as received: bounded, strict JSON, then validate_page."""
    if len(raw) > PAGE_LIMITS["max_bytes"]:
        return _refused("too_large")
    try:
        page = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_float=_finite_float,
            parse_constant=_non_finite,
        )
    except _Refused as refused:
        return _refused(refused.code)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return _refused("not_json")
    return validate_page(page)


_SAFE_INTEGER = 2**53 - 1


def _walk_error(page: dict[str, Any]) -> PageError | None:
    """The first value, in document order, past the value-count, depth or number rules.

    Every number in a page is a safe integer: fractional values are decimal
    strings, so a float or an integer beyond 2^53-1 is refused wherever it
    appears, record values and inline schemas included. The walk keeps one
    mutable path, so its cost is linear in the page and a pointer is built only
    for the error it reports.
    """
    limit = PAGE_LIMITS["max_json_depth"]
    remaining = PAGE_LIMITS["max_values"] - 1  # the page itself is one value
    path: list[str | int] = []
    stack: list[Iterator[tuple[str | int, object]]] = [iter(page.items())]
    while stack:
        try:
            key, child = next(stack[-1])
        except StopIteration:
            stack.pop()
            if path:
                path.pop()
            continue
        remaining -= 1
        if remaining < 0:
            return PageError("limits", "too_many_values", "")
        if isinstance(child, bool):
            continue
        if isinstance(child, int):
            if not -_SAFE_INTEGER <= child <= _SAFE_INTEGER:
                return PageError("limits", "unsafe_number", pointer((*path, key)))
        elif isinstance(child, float):
            return PageError("limits", "unsafe_number", pointer((*path, key)))
        elif isinstance(child, (dict, list)):
            # the page is depth 1, so a child of the innermost open value is at len(stack) + 1
            if len(stack) + 1 > limit:
                return PageError("limits", "too_deep_json", pointer((*path, key)))
            path.append(key)
            if isinstance(child, dict):
                stack.append(iter(child.items()))
            else:
                stack.append(enumerate(child))
    return None


def _widget_errors(layout: object) -> PageError | None:
    if not isinstance(layout, list):
        return None
    count = 0
    stack: list[tuple[object, int, tuple[str | int, ...]]] = [
        (widget, 1, ("layout", index)) for index, widget in reversed(list(enumerate(layout)))
    ]
    first_too_deep: str | None = None
    while stack:
        widget, depth, path = stack.pop()
        count += 1
        if depth > PAGE_LIMITS["max_depth"]:
            if first_too_deep is None:
                first_too_deep = pointer(path)
            continue
        children = widget.get("children") if isinstance(widget, dict) else None
        if isinstance(children, list):
            stack.extend(
                (child, depth + 1, (*path, "children", index))
                for index, child in reversed(list(enumerate(children)))
            )
    if first_too_deep is not None:
        return PageError("limits", "too_deep", first_too_deep)
    if count > PAGE_LIMITS["max_widgets"]:
        return PageError("limits", "too_many_widgets", "/layout")
    return None


def _limit_errors(page: object) -> Validation | None:
    if not isinstance(page, dict):
        return _refused("not_object")
    widget_error = _widget_errors(page.get("layout"))
    if widget_error is not None:
        return Validation((widget_error,))
    walk_error = _walk_error(page)
    if walk_error is not None:
        return Validation((walk_error,))
    try:
        size = len(
            json.dumps(page, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(
                "utf-8"
            )
        )
    except ValueError:
        return _refused("non_finite_number")
    except TypeError:
        return _refused("not_json")
    if size > PAGE_LIMITS["max_bytes"]:
        return _refused("too_large")
    return None


def validate_page(page: object) -> Validation:
    """Validate a parsed page: limits, then schema, then lint."""
    limited = _limit_errors(page)
    if limited is not None:
        return limited
    schema_errors = sorted(
        {
            PageError("schema", "schema", pointer(error.absolute_path))
            for error in _VALIDATOR.iter_errors(page)
        }
    )
    if schema_errors:
        return Validation(tuple(schema_errors))
    assert isinstance(page, dict)
    return Validation(tuple(sorted(set(lint_errors(page)))))
