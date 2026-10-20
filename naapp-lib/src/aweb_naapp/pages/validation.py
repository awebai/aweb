"""Host limits and JSON Schema validation of aweb.page/1 pages."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
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


def _json_depth_error(page: object) -> str | None:
    stack: list[tuple[object, tuple[str | int, ...]]] = [(page, ())]
    limit = PAGE_LIMITS["max_json_depth"]
    while stack:
        node, path = stack.pop()
        if isinstance(node, dict):
            children: list[tuple[str | int, object]] = list(node.items())
        elif isinstance(node, list):
            children = list(enumerate(node))
        else:
            continue
        if len(path) + 1 > limit:
            return pointer(path)
        stack.extend((child, (*path, key)) for key, child in reversed(children))
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
    too_deep_json = _json_depth_error(page)
    if too_deep_json is not None:
        return _refused("too_deep_json", too_deep_json)
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
