from __future__ import annotations

import re
from typing import Any

from fastapi import HTTPException

_TEMPLATE_SLOTS = {
    "memo": frozenset({"cover", "sections"}),
    "metrics": frozenset({"cover", "metrics"}),
    "pitch": frozenset({"cover", "sections", "metrics", "ask"}),
}


def _validation_error(message: str) -> HTTPException:
    return HTTPException(status_code=422, detail=message)


def _slots(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    name = payload.get("name")
    if not isinstance(name, str) or not name.strip():
        raise _validation_error("Template name is required")
    name = name.strip().lower()
    allowed_slots = _TEMPLATE_SLOTS.get(name)
    if allowed_slots is None:
        raise _validation_error(f"Unknown template: {name}")

    raw_slots = payload.get("slots", {})
    if not isinstance(raw_slots, dict):
        raise _validation_error("Template slots must be an object")
    unsupported = sorted(str(key) for key in raw_slots if key not in allowed_slots)
    if unsupported:
        raise _validation_error(f"Unsupported slot for {name}: {unsupported[0]}")
    return name, raw_slots


def _text(value: Any, *, field: str, required: bool = False, max_length: int = 8_000) -> str:
    if value is None:
        if required:
            raise _validation_error(f"Template field {field} is required")
        return ""
    if not isinstance(value, str):
        raise _validation_error(f"Template field {field} must be a string")
    text = value.strip()
    if required and not text:
        raise _validation_error(f"Template field {field} is required")
    if len(text) > max_length:
        raise _validation_error(f"Template field {field} is too long")
    return text


def _list(value: Any, *, field: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise _validation_error(f"Template slot {field} must be a list")
    if len(value) > 40:
        raise _validation_error(f"Template slot {field} has too many entries")
    return value


def _dict(value: Any, *, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _validation_error(f"Template slot {field} must be an object")
    return value


def _reject_extra_fields(mapping: dict[str, Any], *, field: str, allowed: set[str]) -> None:
    extra = sorted(str(key) for key in mapping if key not in allowed)
    if extra:
        raise _validation_error(f"Unsupported field for {field}: {extra[0]}")


_LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _escape_table_cell(value: str) -> str:
    normalized = _LINE_BREAK_RE.sub("<br>", value)
    normalized = _CONTROL_CHAR_RE.sub(" ", normalized)
    return normalized.replace("\\", "\\\\").replace("|", r"\|")


def _render_cover(raw: Any) -> list[str]:
    cover = _dict(raw, field="cover")
    _reject_extra_fields(cover, field="cover", allowed={"title", "subtitle", "eyebrow"})
    title = _text(cover.get("title"), field="cover.title", required=True, max_length=240)
    subtitle = _text(cover.get("subtitle"), field="cover.subtitle", max_length=2_000)
    eyebrow = _text(cover.get("eyebrow"), field="cover.eyebrow", max_length=240)
    lines = []
    if eyebrow:
        lines.extend([f"_{eyebrow}_", ""])
    lines.append(f"# {title}")
    if subtitle:
        lines.extend(["", subtitle])
    return lines


def _render_sections(raw: Any) -> list[str]:
    lines: list[str] = []
    for index, item in enumerate(_list(raw, field="sections"), start=1):
        section = _dict(item, field=f"sections[{index}]")
        _reject_extra_fields(section, field=f"sections[{index}]", allowed={"heading", "body"})
        heading = _text(section.get("heading"), field=f"sections[{index}].heading", required=True, max_length=240)
        body = _text(section.get("body"), field=f"sections[{index}].body", max_length=16_000)
        lines.extend([f"## {heading}"])
        if body:
            lines.extend(["", body])
        lines.append("")
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def _render_metrics(raw: Any) -> list[str]:
    rows: list[str] = []
    for index, item in enumerate(_list(raw, field="metrics"), start=1):
        metric = _dict(item, field=f"metrics[{index}]")
        _reject_extra_fields(metric, field=f"metrics[{index}]", allowed={"label", "value", "caption"})
        label = _text(metric.get("label"), field=f"metrics[{index}].label", required=True, max_length=120)
        value = _text(metric.get("value"), field=f"metrics[{index}].value", required=True, max_length=120)
        caption = _text(metric.get("caption"), field=f"metrics[{index}].caption", max_length=240)
        rows.append(f"| {_escape_table_cell(label)} | {_escape_table_cell(value)} | {_escape_table_cell(caption)} |")
    if not rows:
        return []
    return ["## Metrics", "", "| Metric | Value | Notes |", "| --- | --- | --- |", *rows]


def _render_ask(raw: Any) -> list[str]:
    ask = _dict(raw, field="ask")
    if not ask:
        return []
    _reject_extra_fields(ask, field="ask", allowed={"headline", "body", "items"})
    headline = _text(ask.get("headline"), field="ask.headline", max_length=240) or "Ask"
    body = _text(ask.get("body"), field="ask.body", max_length=8_000)
    items = _list(ask.get("items"), field="ask.items")
    lines = [f"## {headline}"]
    if body:
        lines.extend(["", body])
    if items:
        if body:
            lines.append("")
        for index, item in enumerate(items, start=1):
            lines.append(f"- {_text(item, field=f'ask.items[{index}]', required=True, max_length=240)}")
    return lines


def render_declarative_template(payload: dict[str, Any]) -> str:
    """Validate a built-in declarative template and render it to Markdown.

    The stored document remains ordinary Markdown so present pages continue to
    use the M3 layout/theme renderer and sanitizer as the fallback path.
    """

    name, slots = _slots(payload)
    if "cover" not in slots:
        raise _validation_error("Template slot cover is required")

    parts: list[list[str]] = [_render_cover(slots.get("cover"))]
    if name in {"pitch", "metrics"}:
        parts.append(_render_metrics(slots.get("metrics")))
    if name in {"pitch", "memo"}:
        parts.append(_render_sections(slots.get("sections")))
    if name == "pitch":
        parts.append(_render_ask(slots.get("ask")))

    rendered_parts = ["\n".join(part).strip() for part in parts if part]
    return "\n\n".join(part for part in rendered_parts if part) + "\n"
