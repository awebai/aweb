"""Semantic lint of schema-valid aweb.page/1 pages.

Lint checks what a JSON Schema cannot: references resolve, identifiers are
unique, records match their collection schemas, inline schemas stay inside the
permitted subset, agent-authored text (layout, widget state and action labels)
carries no bidi controls, and a
bundle decision card binds exactly the item revisions it renders.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from jsonschema import Draft202012Validator

from aweb_naapp.pages.errors import PAGE_LIMITS, PageError, pointer

Path = tuple[str | int, ...]

BUNDLE_PREFIX = b"aweb.page-bundle/1\n"
BUNDLE_ITEM_KEYS = frozenset({"record_id", "record_rev", "proposal_sha256"})
_IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SAFE_INTEGER = 2**53 - 1
_META_SCHEMA = Draft202012Validator(Draft202012Validator.META_SCHEMA)

# Embedding, override and isolate controls (Trojan Source). Marks such as LRM
# are left alone; values bound from records are isolated by the renderer.
_BIDI_CONTROLS = frozenset(chr(code) for code in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))

# Inline schemas (collection schemas and action input schemas) may use only
# these 2020-12 keywords. Every sub-schema a keyword can hold is walked below,
# so a reference can never reach a sub-schema lint has not checked.
_ALLOWED_KEYWORDS = frozenset(
    {
        "type",
        "enum",
        "const",
        "properties",
        "required",
        "additionalProperties",
        "minProperties",
        "maxProperties",
        "dependentRequired",
        "propertyNames",
        "items",
        "prefixItems",
        "minItems",
        "maxItems",
        "uniqueItems",
        "contains",
        "minContains",
        "maxContains",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "allOf",
        "anyOf",
        "oneOf",
        "not",
        "if",
        "then",
        "else",
        "$defs",
        "$ref",
        "title",
        "description",
        "default",
        "examples",
        "format",
        "$comment",
        "deprecated",
        "readOnly",
        "writeOnly",
    }
)
_PATTERN_KEYWORDS = frozenset({"pattern", "patternProperties"})
_SCHEMA_MAPS = ("properties", "$defs")
_SCHEMA_LISTS = ("allOf", "anyOf", "oneOf", "prefixItems")
_SCHEMA_SINGLES = (
    "items",
    "additionalProperties",
    "propertyNames",
    "contains",
    "not",
    "if",
    "then",
    "else",
)
_LOCAL_REF = re.compile(r"#/\$defs/([A-Za-z0-9_.-]+)")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def bundle_sha256(items: Sequence[Mapping[str, Any]]) -> str:
    """The digest a bundle decision card binds: its ordered item list, canonically."""
    return "sha256:" + hashlib.sha256(BUNDLE_PREFIX + _canonical(list(items))).hexdigest()


def _widgets(page: Mapping[str, Any]) -> Iterator[tuple[Mapping[str, Any], Path]]:
    stack: list[tuple[Mapping[str, Any], Path]] = [
        (widget, ("layout", index)) for index, widget in reversed(list(enumerate(page["layout"])))
    ]
    while stack:
        widget, path = stack.pop()
        yield widget, path
        children = widget.get("children", [])
        stack.extend(
            (child, (*path, "children", index))
            for index, child in reversed(list(enumerate(children)))
        )


def _strings(node: object, path: Path) -> Iterator[tuple[str, Path]]:
    stack: list[tuple[object, Path]] = [(node, path)]
    while stack:
        value, at = stack.pop()
        if isinstance(value, str):
            yield value, at
        elif isinstance(value, dict):
            stack.extend((child, (*at, key)) for key, child in value.items())
        elif isinstance(value, list):
            stack.extend((child, (*at, index)) for index, child in enumerate(value))


def _inline_schema_errors(schema: object, path: Path) -> Iterator[PageError]:
    root_defs = schema.get("$defs") if isinstance(schema, dict) else None
    defs = root_defs if isinstance(root_defs, dict) else {}
    # Sub-schemas as written, overall and per $defs entry, and the root's
    # references into $defs: together they give the size once references are
    # expanded. A $defs entry holds no $ref, so expansion is one level deep.
    written = 0
    def_sizes: dict[str, int] = {}
    root_refs: list[str] = []
    stack: list[tuple[object, Path, int, str | None]] = [(schema, path, 1, None)]
    max_depth = PAGE_LIMITS["max_inline_schema_depth"]
    while stack:
        node, at, depth, within = stack.pop()
        if not isinstance(node, dict):
            continue
        written += 1
        if within is not None:
            def_sizes[within] = def_sizes.get(within, 0) + 1
        if depth > max_depth:
            yield PageError("lint", "inline_schema_depth", pointer(at))
            continue
        for key, value in node.items():
            if key in _PATTERN_KEYWORDS:
                yield PageError("lint", "inline_schema_pattern", pointer((*at, key)))
            elif key not in _ALLOWED_KEYWORDS or (key == "$defs" and depth > 1):
                yield PageError("lint", "inline_schema_keyword", pointer((*at, key)))
            elif key == "$ref" and within is not None:
                yield PageError("lint", "inline_schema_def_ref", pointer((*at, key)))
            elif key == "$ref":
                match = _LOCAL_REF.fullmatch(value) if isinstance(value, str) else None
                if match is None or match.group(1) not in defs:
                    yield PageError("lint", "inline_schema_ref", pointer((*at, key)))
                else:
                    root_refs.append(match.group(1))
            elif key == "type" and (
                "number" == value or (isinstance(value, list) and "number" in value)
            ):
                yield PageError("lint", "inline_schema_number", pointer((*at, key)))
        for key in _SCHEMA_MAPS:
            children = node.get(key)
            if isinstance(children, dict) and not (key == "$defs" and depth > 1):
                for name, child in children.items():
                    owner = name if key == "$defs" else within
                    stack.append((child, (*at, key, name), depth + 1, owner))
        for key in _SCHEMA_LISTS:
            children = node.get(key)
            if isinstance(children, list):
                stack.extend(
                    (child, (*at, key, index), depth + 1, within)
                    for index, child in enumerate(children)
                )
        for key in _SCHEMA_SINGLES:
            child = node.get(key)
            if isinstance(child, dict):
                stack.append((child, (*at, key), depth + 1, within))
    expanded = written + sum(def_sizes.get(name, 0) for name in root_refs)
    if expanded > PAGE_LIMITS["max_inline_schema_expansion"]:
        yield PageError("lint", "inline_schema_expansion", pointer(path))


def _checked_schema_errors(schema: object, path: Path) -> list[PageError]:
    """The inline-schema subset first, then the 2020-12 meta-schema."""
    errors = list(_inline_schema_errors(schema, path))
    if not errors:
        errors = sorted(
            {
                PageError("lint", "inline_schema_invalid", pointer((*path, *error.absolute_path)))
                for error in _META_SCHEMA.iter_errors(schema)
            }
        )
    return errors


class _Page:
    def __init__(self, page: Mapping[str, Any]) -> None:
        self.page = page
        self.actions: dict[str, Mapping[str, Any]] = {}
        for action in page["actions"]:
            self.actions.setdefault(action["id"], action)
        self.collections: dict[str, tuple[int, Mapping[str, Any]]] = {}
        for index, collection in enumerate(page["collections"]):
            self.collections.setdefault(collection["id"], (index, collection))

    def fields(self, collection_id: str) -> set[str] | None:
        found = self.collections.get(collection_id)
        if found is None:
            return None
        properties = found[1]["schema"].get("properties")
        return set(properties) if isinstance(properties, dict) else set()

    def record(self, collection_id: str, record_id: str) -> tuple[int, Mapping[str, Any]] | None:
        found = self.collections.get(collection_id)
        if found is None:
            return None
        for index, record in enumerate(found[1]["records"]):
            if record["id"] == record_id:
                return index, record
        return None


def _field_errors(
    page: _Page, collection_id: str | None, refs: list[tuple[str, Path]]
) -> Iterator[PageError]:
    if collection_id is None:
        return
    known = page.fields(collection_id)
    if known is None:
        return
    for field, at in refs:
        if field not in known:
            yield PageError("lint", "unknown_field", pointer(at))


def _action_errors(page: _Page, refs: list[tuple[str, Path]]) -> Iterator[PageError]:
    for action_id, at in refs:
        if action_id not in page.actions:
            yield PageError("lint", "unknown_action", pointer(at))


def _binding_errors(page: _Page, widget: Mapping[str, Any], path: Path) -> Iterator[PageError]:
    bind = widget.get("bind")
    if bind is None:
        return
    if bind["collection"] not in page.collections:
        yield PageError("lint", "unknown_collection", pointer((*path, "bind", "collection")))
        return
    refs = [
        (clause["field"], (*path, "bind", "all", index, "field"))
        for index, clause in enumerate(bind.get("all", []))
    ]
    refs += [
        (order["field"], (*path, "bind", "sort", index, "field"))
        for index, order in enumerate(bind.get("sort", []))
    ]
    props = widget["props"]
    kind = widget["type"]
    if kind == "table":
        refs += [
            (column["field"], (*path, "props", "columns", index, "field"))
            for index, column in enumerate(props["columns"])
        ]
    elif kind in ("cards", "list", "activity_timeline"):
        refs += [
            (field, (*path, "props", "fields", name)) for name, field in props["fields"].items()
        ]
    elif kind == "chart":
        refs += [(props["x"], (*path, "props", "x"))]
        refs += [
            (field, (*path, "props", "series", index))
            for index, field in enumerate(props["series"])
        ]
    elif kind in ("stat", "status_badge") and "field" in props:
        refs += [(props["field"], (*path, "props", "field"))]
    yield from _field_errors(page, bind["collection"], refs)


def _form_errors(page: _Page, widget: Mapping[str, Any], path: Path) -> Iterator[PageError]:
    props = widget["props"]
    action = page.actions.get(props["submit_action"])
    if action is None:
        yield from _action_errors(
            page, [(props["submit_action"], (*path, "props", "submit_action"))]
        )
        return
    required = action["input_schema"].get("required", [])
    provided = {field["id"] for field in props["fields"]}
    if isinstance(required, list) and not set(required) <= provided:
        yield PageError("lint", "form_missing_required_input", pointer((*path, "props", "fields")))


def _is_bundle_item(item: object) -> bool:
    return (
        isinstance(item, dict)
        and set(item) == BUNDLE_ITEM_KEYS
        and isinstance(item["record_id"], str)
        and _IDENTIFIER.fullmatch(item["record_id"]) is not None
        and isinstance(item["record_rev"], int)
        and not isinstance(item["record_rev"], bool)
        and 0 <= item["record_rev"] <= _SAFE_INTEGER
        and isinstance(item["proposal_sha256"], str)
        and _DIGEST.fullmatch(item["proposal_sha256"]) is not None
    )


def _bundle_errors(page: _Page, props: Mapping[str, Any], path: Path) -> Iterator[PageError]:
    items_collection = props["items_collection"]
    if items_collection not in page.collections:
        yield PageError("lint", "unknown_collection", pointer((*path, "props", "items_collection")))
        return
    found = page.record(props["collection"], props["record_id"])
    if found is None:
        yield PageError("lint", "bundle_record_unknown", pointer((*path, "props", "record_id")))
        return
    record_index, record = found
    collection_index = page.collections[props["collection"]][0]
    value_path: Path = ("collections", collection_index, "records", record_index, "value")
    if record["rev"] != props["record_rev"]:
        yield PageError("lint", "bundle_record_mismatch", pointer((*path, "props", "record_rev")))
    value = record["value"]
    items = value.get("items") if set(value) == {"items"} else None
    if not isinstance(items, list) or not all(_is_bundle_item(item) for item in items):
        yield PageError("lint", "bundle_record_shape", pointer(value_path))
        return
    if not items:
        yield PageError("lint", "bundle_empty", pointer((*value_path, "items")))
        return
    if len(items) > PAGE_LIMITS["max_bundle_items"]:
        yield PageError("lint", "bundle_too_many_items", pointer((*value_path, "items")))
        return
    listed: set[str] = set()
    for index, item in enumerate(items):
        if item["record_id"] in listed:
            yield PageError("lint", "bundle_duplicate_item", pointer((*value_path, "items", index)))
        listed.add(item["record_id"])
    for index, item in enumerate(items):
        item_record = page.record(items_collection, item["record_id"])
        if item_record is None:
            yield PageError("lint", "bundle_item_unknown", pointer((*value_path, "items", index)))
        elif item_record[1]["rev"] != item["record_rev"]:
            yield PageError("lint", "bundle_item_mismatch", pointer((*value_path, "items", index)))
    if bundle_sha256(items) != props["proposal_sha256"]:
        yield PageError(
            "lint", "bundle_hash_mismatch", pointer((*path, "props", "proposal_sha256"))
        )


def _decision_card_errors(
    page: _Page, widget: Mapping[str, Any], path: Path
) -> Iterator[PageError]:
    props = widget["props"]
    if props["collection"] not in page.collections:
        yield PageError("lint", "unknown_collection", pointer((*path, "props", "collection")))
    action = page.actions.get(props["answer_action"])
    if action is None:
        yield PageError("lint", "unknown_action", pointer((*path, "props", "answer_action")))
    elif action["kind"] != "answer":
        yield PageError(
            "lint", "answer_action_not_answer", pointer((*path, "props", "answer_action"))
        )
    if props["recommendation"] not in {option["value"] for option in props["options"]}:
        yield PageError(
            "lint", "recommendation_not_option", pointer((*path, "props", "recommendation"))
        )
    if props.get("bundle") is True and props["collection"] in page.collections:
        yield from _bundle_errors(page, props, path)


def _widget_errors(page: _Page) -> Iterator[PageError]:
    seen: set[str] = set()
    for widget, path in _widgets(page.page):
        if widget["id"] in seen:
            yield PageError("lint", "duplicate_widget_id", pointer((*path, "id")))
        seen.add(widget["id"])
        yield from _binding_errors(page, widget, path)
        kind = widget["type"]
        props = widget.get("props", {})
        if kind in ("table",):
            yield from _action_errors(
                page,
                [
                    (a, (*path, "props", "row_actions", i))
                    for i, a in enumerate(props.get("row_actions", []))
                ],
            )
        elif kind in ("cards", "list"):
            yield from _action_errors(
                page,
                [
                    (a, (*path, "props", "actions", i))
                    for i, a in enumerate(props.get("actions", []))
                ],
            )
        elif kind in ("button", "file_drop"):
            yield from _action_errors(page, [(props["action"], (*path, "props", "action"))])
        elif kind == "form":
            yield from _form_errors(page, widget, path)
        elif kind == "decision_card":
            yield from _decision_card_errors(page, widget, path)
    for key in page.page["widget_state"]:
        if key not in seen:
            yield PageError("lint", "state_unknown_widget", pointer(("widget_state", key)))


def _collection_errors(page: _Page) -> Iterator[PageError]:
    seen: set[str] = set()
    for index, collection in enumerate(page.page["collections"]):
        at: Path = ("collections", index)
        if collection["id"] in seen:
            yield PageError("lint", "duplicate_collection_id", pointer((*at, "id")))
        seen.add(collection["id"])
        schema_errors = _checked_schema_errors(collection["schema"], (*at, "schema"))
        yield from schema_errors
        record_ids: set[str] = set()
        validator = None if schema_errors else Draft202012Validator(collection["schema"])
        for record_index, record in enumerate(collection["records"]):
            record_at: Path = (*at, "records", record_index)
            if record["id"] in record_ids:
                yield PageError("lint", "duplicate_record_id", pointer((*record_at, "id")))
            record_ids.add(record["id"])
            if validator is not None and not validator.is_valid(record["value"]):
                yield PageError("lint", "record_invalid", pointer((*record_at, "value")))


def _action_definition_errors(page: _Page) -> Iterator[PageError]:
    seen: set[str] = set()
    for index, action in enumerate(page.page["actions"]):
        at: Path = ("actions", index)
        if action["id"] in seen:
            yield PageError("lint", "duplicate_action_id", pointer((*at, "id")))
        seen.add(action["id"])
        yield from _checked_schema_errors(action["input_schema"], (*at, "input_schema"))


def _bidi_errors(page: Mapping[str, Any]) -> Iterator[PageError]:
    sources: list[tuple[object, Path]] = [
        (page["title"], ("title",)),
        (page["layout"], ("layout",)),
        (page["widget_state"], ("widget_state",)),
    ]
    sources += [
        (action["label"], ("actions", index, "label"))
        for index, action in enumerate(page["actions"])
    ]
    for source, at in sources:
        for text, text_at in _strings(source, at):
            if any(character in _BIDI_CONTROLS for character in text):
                yield PageError("lint", "bidi_control", pointer(text_at))


def lint_errors(page: Mapping[str, Any]) -> Iterator[PageError]:
    """Semantic errors of a page that already satisfies the JSON Schema."""
    model = _Page(page)
    yield from _widget_errors(model)
    yield from _collection_errors(model)
    yield from _action_definition_errors(model)
    yield from _bidi_errors(page)
