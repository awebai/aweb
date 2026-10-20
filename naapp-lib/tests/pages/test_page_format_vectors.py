"""The frozen aweb.page/1 conformance vectors.

Each case names a base page and a small patch to it, raw page bytes, or a
generated tree. The validator must reach the expected verdict and report every
expected error at its layer, code and JSON pointer. Render-layer expectations in
the vectors belong to the renderer and are not checked here.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from aweb_naapp.pages import PAGE_LIMITS, bundle_sha256, validate_page, validate_page_bytes

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads((AWEB_ROOT / "docs" / "vectors" / "page-format-v1.json").read_text())


def _resolve(document: Any, pointer: str) -> tuple[Any, str]:
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:]]
    parent = document
    for part in parts[:-1]:
        parent = parent[int(part)] if isinstance(parent, list) else parent[part]
    return parent, parts[-1]


def _patched(base: Any, patch: list[dict]) -> Any:
    document = copy.deepcopy(base)
    for operation in patch:
        parent, key = _resolve(document, operation["path"])
        if operation["op"] == "remove":
            if isinstance(parent, list):
                del parent[int(key)]
            else:
                del parent[key]
        elif isinstance(parent, list):
            index = len(parent) if key == "-" else int(key)
            if operation["op"] == "add":
                parent.insert(index, copy.deepcopy(operation["value"]))
            else:
                parent[index] = copy.deepcopy(operation["value"])
        else:
            parent[key] = copy.deepcopy(operation["value"])
    return document


def _generated(spec: dict) -> dict:
    page = copy.deepcopy(VECTORS["bases"][spec["base"]])
    if spec["shape"] == "nested":
        widget: dict = {"id": "leaf", "type": "heading", "props": {"text": "Leaf", "level": 2}}
        for depth in range(spec["depth"] - 1):
            widget = {"id": f"stack-{depth}", "type": "stack", "props": {}, "children": [widget]}
        page["layout"] = [widget]
    elif spec["shape"] == "flat":
        per_stack = 100
        stacks = []
        for start in range(0, spec["widgets"], per_stack + 1):
            count = min(per_stack, spec["widgets"] - start - 1)
            children = [
                {"id": f"w-{start}-{n}", "type": "heading", "props": {"text": "W", "level": 3}}
                for n in range(count)
            ]
            stacks.append({"id": f"s-{start}", "type": "stack", "props": {}, "children": children})
        page["layout"] = stacks
    elif spec["shape"] == "deep_record":
        # the record value sits at JSON depth 6, "deep" at 7; each "n" adds one level
        value: dict = {}
        for _ in range(spec["depth"] - 7):
            value = {"n": value}
        collection = page["collections"][0]
        collection["schema"]["properties"]["deep"] = {"type": "object"}
        collection["records"][0]["value"]["deep"] = value
    elif spec["shape"] == "padded":
        page["layout"].append(
            {
                "id": "padding",
                "type": "text",
                "props": {"markdown": "x" * min(spec["bytes"], 1048576)},
            }
        )
        while len(json.dumps(page, ensure_ascii=False).encode()) <= spec["bytes"]:
            page["layout"].append(
                {
                    "id": f"padding-{len(page['layout'])}",
                    "type": "text",
                    "props": {"markdown": "x" * 1048576},
                }
            )
    else:
        raise AssertionError(f"unknown generated shape {spec['shape']!r}")
    return page


def _input(case: dict) -> object:
    source = case["input"]
    if "raw" in source:
        return source["raw"].encode("utf-8")
    if "generate" in source:
        return _generated(source["generate"])
    return _patched(VECTORS["bases"][source["base"]], source.get("patch", []))


def _validate(value: object):
    if isinstance(value, bytes):
        return validate_page_bytes(value)
    return validate_page(value)


def test_limits_are_the_frozen_limits():
    assert dict(PAGE_LIMITS) == VECTORS["limits"]


@pytest.mark.parametrize("name", sorted(VECTORS["bases"]))
def test_every_base_page_is_valid(name):
    result = validate_page(VECTORS["bases"][name])
    assert result.errors == ()
    assert result.valid


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_case(case):
    value = _input(case)
    result = _validate(value)
    reported = {(error.layer, error.code, error.pointer) for error in result.errors}
    expected = {
        (error["layer"], error["code"], error["pointer"]) for error in case["expect"]["errors"]
    }
    assert result.valid is case["expect"]["valid"]
    assert expected <= reported, f"missing {expected - reported}; reported {reported}"
    if case["expect"]["valid"]:
        assert result.errors == ()


def test_validation_does_not_modify_the_page():
    page = copy.deepcopy(VECTORS["bases"]["bundle"])
    before = json.dumps(page, sort_keys=True)
    validate_page(page)
    assert json.dumps(page, sort_keys=True) == before


@pytest.mark.parametrize("vector", VECTORS["bundle_hash"], ids=lambda vector: vector["name"])
def test_bundle_hash(vector):
    assert bundle_sha256(vector["items"]) == vector["sha256"]
