"""Data-only table embeds and byte-preserving prose edits.

This parser establishes structure, never collection access. The host resolves
the collection and checks its schema and the saving member's ACL separately.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from aweb_naapp.pages import PAGE_LIMITS, PAGE_SCHEMA
from jsonschema import Draft202012Validator

_OPEN = re.compile(r" {0,3}:::widget[ \t]*$")
_CLOSE = re.compile(r" {0,3}:::[ \t]*$")
_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)$")
_TABLE = Draft202012Validator({"$ref": "#/$defs/widget_table", "$defs": PAGE_SCHEMA["$defs"]})


class WidgetDocumentError(ValueError):
    """A safe error: never includes the submitted definition or collection data."""

    def __init__(self, code: str = "invalid_widget") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class WidgetBlock:
    start: int
    end: int
    raw: str
    definition: dict[str, Any]


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WidgetDocumentError("duplicate_widget_key")
        result[key] = value
    return result


def _integer(value: str) -> int:
    number = int(value)
    if abs(number) > 2**53 - 1:
        raise WidgetDocumentError()
    return number


def _not_integer(_: str) -> Any:
    raise WidgetDocumentError()


def _definition(raw: str) -> dict[str, Any]:
    if len(raw.encode("utf-8")) > PAGE_LIMITS["max_bytes"]:
        raise WidgetDocumentError()
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_object,
            parse_int=_integer,
            parse_float=_not_integer,
            parse_constant=_not_integer,
        )
        if not _TABLE.is_valid(value):
            raise WidgetDocumentError()
    except (ValueError, RecursionError) as error:
        if isinstance(error, WidgetDocumentError):
            raise
        raise WidgetDocumentError() from None
    return value


def parse_widget_blocks(body: str) -> list[WidgetBlock]:
    """Parse top-level blocks, ignoring examples inside fenced/indented code.

    Closing-line endings remain in prose, so a widget at EOF can gain following
    prose without changing its raw definition. All other block bytes, including
    indentation and internal CRLFs, are retained verbatim.
    """
    if not isinstance(body, str):
        raise WidgetDocumentError()
    lines = body.splitlines(keepends=True)
    blocks: list[WidgetBlock] = []
    ids: set[str] = set()
    offset = index = 0
    fence: str | None = None
    while index < len(lines):
        line = lines[index]
        text = line.rstrip("\r\n")
        if fence is not None:
            if re.fullmatch(
                r" {0,3}" + re.escape(fence[0]) + r"{" + str(len(fence)) + r",}[ \t]*", text
            ):
                fence = None
        elif match := _FENCE.fullmatch(text):
            marker, info = match.groups()
            if marker[0] != "`" or "`" not in info:
                fence = marker
        elif _OPEN.fullmatch(text):
            start = offset
            offset += len(line)
            index += 1
            content: list[str] = []
            while index < len(lines):
                closing = lines[index].rstrip("\r\n")
                if _CLOSE.fullmatch(closing):
                    break
                content.append(lines[index])
                offset += len(lines[index])
                index += 1
            else:
                raise WidgetDocumentError("unclosed_widget")
            definition = _definition("".join(content))
            if definition["id"] in ids:
                raise WidgetDocumentError("duplicate_widget_id")
            ids.add(definition["id"])
            if len(ids) > PAGE_LIMITS["max_widgets"]:
                raise WidgetDocumentError()
            end = offset + len(closing)
            blocks.append(WidgetBlock(start, end, body[start:end], definition))
            line = lines[index]
        offset += len(line)
        index += 1
    return blocks


def table_widgets(body: str) -> dict[str, dict[str, Any]]:
    return {block.definition["id"]: block.definition for block in parse_widget_blocks(body)}


def document_segments(body: str) -> list[dict[str, Any]]:
    """Ordered prose and atomic widgets, suitable for a trusted editor model."""
    segments: list[dict[str, Any]] = []
    start = 0
    for block in parse_widget_blocks(body):
        segments.append({"kind": "prose", "text": body[start : block.start]})
        segments.append(
            {
                "kind": "widget",
                "id": block.definition["id"],
                "raw": block.raw,
                "definition": copy.deepcopy(block.definition),
            }
        )
        start = block.end
    segments.append({"kind": "prose", "text": body[start:]})
    return segments


def require_same_widgets(before: str, after: str) -> None:
    """Human prose saves cannot create, remove, reorder or hide widget blocks."""
    original = [(block.definition["id"], block.raw) for block in parse_widget_blocks(before)]
    proposed = [(block.definition["id"], block.raw) for block in parse_widget_blocks(after)]
    if original != proposed:
        raise WidgetDocumentError("widget_changed")


def merge_document_prose(original: str, prose: Sequence[str]) -> str:
    """Compose prose around immutable widgets, preserving their exact bytes."""
    blocks = parse_widget_blocks(original)
    if (
        isinstance(prose, (str, bytes))
        or len(prose) != len(blocks) + 1
        or any(not isinstance(text, str) for text in prose)
    ):
        raise WidgetDocumentError()
    if not blocks:
        require_same_widgets(original, prose[0])
        return prose[0]
    output: list[str] = []
    at_line_start = True

    def append(value: str) -> None:
        nonlocal at_line_start
        if value:
            output.append(value)
            at_line_start = value.endswith(("\n", "\r"))

    for index, block in enumerate(blocks):
        newline = "\r\n" if "\r\n" in block.raw else "\n"
        text = prose[index]
        if index and text and not text.startswith(("\n", "\r")):
            append(newline)
        append(text)
        if not at_line_start:
            append(newline)
        append(block.raw)
    if prose[-1] and not prose[-1].startswith(("\n", "\r")):
        append("\r\n" if "\r\n" in blocks[-1].raw else "\n")
    append(prose[-1])
    result = "".join(output)
    require_same_widgets(original, result)
    return result
