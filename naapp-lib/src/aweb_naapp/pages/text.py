"""Accessible, non-executing text for an author's validated page or projections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aweb_naapp.pages.errors import PageError
from aweb_naapp.pages.validation import PAGE_SCHEMA, validate_page

_KNOWN = frozenset(
    name.removeprefix("widget_")
    for name in PAGE_SCHEMA["$defs"]
    if name.startswith("widget_") and name != "widget_unknown"
)


@dataclass(frozen=True)
class PageLint:
    errors: tuple[PageError, ...]
    text: str

    @property
    def valid(self):
        return not self.errors


def _plain(value: Any) -> str:
    # A text terminal has no host bidi isolation. Expose controls visibly so
    # record values cannot reorder labels or the disabled-action annotation.
    text = str(value)
    return "".join(
        f"\\u{ord(c):04x}" if ord(c) in {*range(0x202A, 0x202F), *range(0x2066, 0x206A)} else c
        for c in text
    )


def lint_page(
    page: dict,
    *,
    allowed_actions: set[str] | None = None,
    projections: dict[str, list[dict]] | None = None,
) -> PageLint:
    """Validate then render text, with policy verdicts supplied by the host.

    Projections are already authorized by PageStore.read_widget. This function
    never fetches data, interprets Markdown, follows links or reads unknown props.
    An omitted permission set reports that permission has not been evaluated.
    """
    result = validate_page(page)
    if not result.valid:
        return PageLint(result.errors, "")
    lines = [_plain(page["title"])]
    collections = {c["id"]: c for c in page["collections"]}
    actions = {a["id"]: a for a in page["actions"]}

    def action(ref):
        item = actions[ref]
        suffix = (
            " [permission not evaluated]"
            if allowed_actions is None
            else " [disabled by policy]"
            if ref not in allowed_actions
            else ""
        )
        return _plain(item["label"]) + suffix

    def walk(layout, depth=0):
        for widget in layout:
            kind = widget["type"]
            prefix = "  " * depth
            if kind not in _KNOWN:
                lines.append(prefix + "Unavailable: " + _plain(widget["fallback"]))
                continue
            props = widget["props"]
            descriptions = [
                props[field]
                for field in ("markdown", "text", "label", "alt", "caption", "alternative", "value")
                if field in props
            ]
            lines.append(prefix + ("; ".join(_plain(value) for value in descriptions) or kind))
            if kind == "form":
                for field in props["fields"]:
                    lines.append(
                        prefix
                        + "  "
                        + _plain(field["label"])
                        + (" [required]" if field.get("required") else "")
                    )
                    if field.get("description"):
                        lines.append(prefix + "  " + _plain(field["description"]))
            if "bind" in widget:
                records = (projections or {}).get(
                    widget["id"], collections[widget["bind"]["collection"]]["records"]
                )
                if kind == "table":
                    fields = [(column["field"], column["label"]) for column in props["columns"]]
                elif kind in {"cards", "list", "activity_timeline"}:
                    fields = [(field, label) for label, field in props["fields"].items()]
                elif kind == "chart":
                    fields = [(field, field) for field in [props["x"], *props["series"]]]
                else:
                    fields = (
                        [(props["field"], props.get("label", "Value"))] if "field" in props else []
                    )
                for record in records:
                    lines.append(
                        prefix
                        + "  "
                        + "; ".join(
                            f"{_plain(label)}: {_plain(record['value'].get(field, ''))}"
                            for field, label in fields
                        )
                    )
            refs = props.get("row_actions", []) + props.get("actions", [])
            refs += [
                props[name]
                for name in ("action", "submit_action", "answer_action")
                if name in props
            ]
            lines.extend(prefix + "  " + action(ref) for ref in refs)
            state = page["widget_state"].get(widget["id"], {})
            if state:
                lines.append(
                    prefix
                    + "  "
                    + "; ".join(f"{key}: {_plain(value)}" for key, value in state.items())
                )
            walk(widget.get("children", []), depth + 1)

    walk(page["layout"])
    return PageLint((), "\n".join(lines))
