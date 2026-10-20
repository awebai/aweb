"""The shared manifest v2 and discovery vectors, which the Go CLI also passes."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from aweb_naapp.manifest import (
    Attestation,
    ManifestError,
    check_v1_variant,
    load_manifest,
    select_variant,
)

VECTORS = Path(__file__).resolve().parents[2] / "test-vectors" / "app-manifests"
V2 = json.loads((VECTORS / "app-manifest-v2-v1.json").read_text(encoding="utf-8"))
DISCOVERY = json.loads((VECTORS / "app-manifest-discovery-v1.json").read_text(encoding="utf-8"))
RESERVED = frozenset(V2["reserved_names"])


def _apply(node: Any, tokens: list[str], op: str, value: Any) -> Any:
    token = tokens[0].replace("~1", "/").replace("~0", "~")
    last = len(tokens) == 1
    if isinstance(node, dict):
        if last:
            if op == "remove":
                del node[token]
            else:
                node[token] = value
        else:
            node[token] = _apply(node[token], tokens[1:], op, value)
        return node
    if isinstance(node, list):
        if token == "-":
            assert last and op == "set"
            node.append(value)
            return node
        index = int(token)
        if last:
            if op == "remove":
                del node[index]
            else:
                node[index] = value
        else:
            node[index] = _apply(node[index], tokens[1:], op, value)
        return node
    raise AssertionError(f"pointer token {token!r} into a non-container")


def _manifest_bytes(case: dict[str, Any]) -> bytes:
    doc = copy.deepcopy(V2["base_manifests"][case["base"]])
    for mutation in case.get("mutations", []):
        doc = _apply(doc, mutation["path"].split("/")[1:], mutation["op"], mutation.get("value"))
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _assert_outcome(data: bytes, expected: dict[str, Any]) -> None:
    if not expected["accepted"]:
        with pytest.raises(ManifestError) as refused:
            load_manifest(data, reserved_names=RESERVED)
        assert refused.value.code == expected["error"], refused.value
        return
    assert load_manifest(data, reserved_names=RESERVED).view() == expected["resolved"]


def test_vector_schemas() -> None:
    assert V2["schema"] == "aweb.app-manifest.v2.v1"
    assert DISCOVERY["schema"] == "aweb.app-manifest.discovery.v1"


@pytest.mark.parametrize("case", V2["cases"], ids=lambda c: c["name"])
def test_load(case: dict[str, Any]) -> None:
    _assert_outcome(_manifest_bytes(case), case["expected"])


@pytest.mark.parametrize("case", V2["raw_cases"], ids=lambda c: c["name"])
def test_load_raw_bytes(case: dict[str, Any]) -> None:
    _assert_outcome(case["bytes"].encode("utf-8"), case["expected"])


@pytest.mark.parametrize("case", V2["call_cases"], ids=lambda c: c["name"])
def test_invocation_context(case: dict[str, Any]) -> None:
    manifest = load_manifest(_manifest_bytes(case), reserved_names=RESERVED)
    raw = case["attestation"]
    attestation = None if raw is None else Attestation(verified=raw["verified"], payload=raw.get("payload"))
    try:
        manifest.check_invocation_context(case["tool"], attestation)
        got = "context_allowed"
    except ManifestError as refused:
        got = refused.code
    assert got == case["expected"]


@pytest.mark.parametrize("case", V2["answer_payload_cases"], ids=lambda c: c["name"])
def test_answer_payload(case: dict[str, Any]) -> None:
    manifest = load_manifest(_manifest_bytes(case), reserved_names=RESERVED)
    try:
        manifest.check_answer_payload(case["tool"], case["body"])
        got = "not_refused"
    except ManifestError as refused:
        got = refused.code
    assert got == case["expected"]


@pytest.mark.parametrize("case", DISCOVERY["cases"], ids=lambda c: c["name"])
def test_select_variant(case: dict[str, Any]) -> None:
    fetched: list[str] = []

    def fetch(path: str, max_bytes: int) -> tuple[int, bytes]:
        fetched.append(path)
        response = case["responses"].get(path)
        if response is None:
            return 404, b""
        return response["status"], response["body"].encode("utf-8")

    expected = case["expected"]
    if "error" in expected:
        with pytest.raises(ManifestError) as refused:
            select_variant(case["origin"], case["supported_versions"], fetch)
        assert refused.value.code == expected["error"], refused.value
        return
    variant = select_variant(case["origin"], case["supported_versions"], fetch)
    assert (variant.source, variant.manifest_version, variant.url, variant.digest) == (
        expected["source"], expected["manifest_version"], expected["url"], expected["digest"]
    )
    selected_path = variant.url.removeprefix(case["origin"])
    assert variant.data == case["responses"][selected_path]["body"].encode("utf-8")
    assert set(fetched) <= {"/.well-known/aweb-app-versions.json", "/.well-known/aweb-app.json", selected_path}


@pytest.mark.parametrize("case", DISCOVERY["lint_cases"], ids=lambda c: c["name"])
def test_v1_variant_lint(case: dict[str, Any]) -> None:
    v1 = json.dumps(case["v1"], separators=(",", ":")).encode("utf-8")
    v2 = json.dumps(case["v2"], separators=(",", ":")).encode("utf-8")
    if case["expected"] == "compatible":
        check_v1_variant(v1, v2)
        return
    with pytest.raises(ManifestError) as refused:
        check_v1_variant(v1, v2)
    assert refused.value.code == case["expected"]


def test_app_keys_for_reads_v1_emitters_as_app_event_only() -> None:
    manifest = load_manifest(_manifest_bytes({"base": "v1"}))
    assert manifest.app_keys_for("app-event") == {
        "app-2026-10": V2["base_manifests"]["v1"]["event_emitters"][0]["did_key"]
    }
    assert manifest.app_keys_for("app-request") == {}


def test_app_keys_for_v2_by_declared_purpose() -> None:
    manifest = load_manifest(_manifest_bytes({"base": "v2"}))
    key = V2["base_manifests"]["v2"]["app_keys"][0]
    for purpose in ("app-event", "app-request", "app-usage"):
        assert manifest.app_keys_for(purpose) == {key["kid"]: key["did_key"]}
    assert manifest.app_keys_for("hook-delivery") == {}
