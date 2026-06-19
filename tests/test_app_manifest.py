from __future__ import annotations

import copy
import hashlib
import json
import re
from urllib.parse import quote

from fastapi.testclient import TestClient

import library.api as library_api
from library.aweb_manifest import MANIFEST, MANIFEST_PATH, canonical_bytes, read_manifest_bytes
from library.config import Settings

_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}

_EXPECTED_TOOLS = {
    "publish-pack",
    "register",
    "set-profile-tags",
    "set-pack-tags",
    "bind",
    "get-binding",
    "materialize",
    "propose",
    "proposals",
    "approve",
    "reject",
}

# Mutation flag per SoT §9: true iff a successful call is a hosted state change.
_MUTATIONS = {
    "publish-pack": True,
    "register": True,
    "set-profile-tags": True,
    "set-pack-tags": True,
    "bind": True,
    "get-binding": False,
    "materialize": True,
    "propose": True,
    "proposals": False,
    "approve": True,
    "reject": True,
}


def _client() -> TestClient:
    return TestClient(library_api.create_app(Settings(public_origin="https://library.aweb.ai")))


def _manifest_errors(m: dict) -> list[str]:
    """Encode the frozen m1.1 schema rules as checks."""
    errors: list[str] = []

    if m.get("manifest_version") != 1:
        errors.append("manifest_version must be 1")

    app = m.get("app")
    if not isinstance(app, dict):
        errors.append("app must be an object")
    else:
        for key in ("id", "version", "origin", "llms_txt", "skills"):
            value = app.get(key)
            if not isinstance(value, str) or not value:
                errors.append(f"app.{key} must be a non-empty string")
        if not str(app.get("origin", "")).startswith("https://"):
            errors.append("app.origin must be an https URL")

    tools = m.get("tools")
    if not isinstance(tools, list) or not tools:
        errors.append("tools must be a non-empty list")
        return errors

    for tool in tools:
        name = tool.get("name", "<unnamed>")
        for key in ("name", "description"):
            value = tool.get(key)
            if not isinstance(value, str) or not value:
                errors.append(f"{name}: {key} must be a non-empty string")
        if tool.get("method") not in _METHODS:
            errors.append(f"{name}: method {tool.get('method')!r} not in {_METHODS}")

        path = tool.get("path", "")
        if not isinstance(path, str) or not path.startswith("/"):
            errors.append(f"{name}: path must be relative (leading /)")
        elif path.startswith("//") or "://" in path or ".." in path:
            errors.append(f"{name}: path must not carry scheme/host or traversal")

        schema = tool.get("input_schema")
        if not isinstance(schema, dict):
            errors.append(f"{name}: input_schema must be an object")
            schema = {}
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}

        params = tool.get("params")
        if not isinstance(params, list):
            errors.append(f"{name}: params must be a list")
            params = []
        placement: dict[str, str] = {}
        for param in params:
            pin = param.get("in")
            if pin not in ("path", "query", "body"):
                errors.append(f"{name}: param {param.get('name')!r} has invalid in={pin!r}")
            placement[param.get("name")] = pin

        for field in props:
            if field not in placement:
                errors.append(f"{name}: input field {field!r} has no explicit params placement")
        for pname in placement:
            if pname not in props:
                errors.append(f"{name}: param {pname!r} is not an input_schema field")

        placeholders = set(re.findall(r"{([^}]+)}", path if isinstance(path, str) else ""))
        for placeholder in placeholders:
            if placement.get(placeholder) != "path":
                errors.append(f"{name}: placeholder {{{placeholder}}} needs an in:path param")
        for pname, pin in placement.items():
            if pin == "path" and pname not in placeholders:
                errors.append(f"{name}: in:path param {pname!r} has no matching placeholder")

        body = tool.get("body", {})
        if not isinstance(body, dict):
            errors.append(f"{name}: body must be an object")
            body = {}
        mode = body.get("mode", "json")
        if mode not in ("json", "raw"):
            errors.append(f"{name}: body.mode must be json|raw")
        if mode == "raw":
            if body.get("raw_param") not in props:
                errors.append(f"{name}: body.raw_param must name an input field")
            if not body.get("content_type"):
                errors.append(f"{name}: raw body requires an explicit content_type")

        scopes = tool.get("scopes")
        if not isinstance(scopes, list) or not scopes or not all(isinstance(s, str) for s in scopes):
            errors.append(f"{name}: scopes must be a non-empty list of strings")

        if not isinstance(tool.get("mutation"), bool):
            errors.append(f"{name}: mutation must be a boolean")

    return errors


def _coerce(value: object, prop: dict) -> object:
    kind = prop.get("type")
    if kind == "integer":
        return int(value)  # type: ignore[arg-type]
    if kind == "number":
        return float(value)  # type: ignore[arg-type]
    if kind == "boolean":
        return value if isinstance(value, bool) else {"true": True, "false": False}[str(value).lower()]
    return str(value)


def _interpret(manifest: dict, verb: str, args: dict) -> dict:
    tool = next(t for t in manifest["tools"] if t["name"] == verb)
    props = tool["input_schema"].get("properties", {})
    placement = {p["name"]: p["in"] for p in tool["params"]}
    path = tool["path"]
    for pname, pin in placement.items():
        if pin == "path":
            path = path.replace("{" + pname + "}", quote(str(args[pname]), safe=""))
    body = tool.get("body", {})
    if body.get("mode", "json") == "json":
        fields = [p["name"] for p in tool["params"] if p["in"] == "body"]
        coerced = {name: _coerce(args[name], props[name]) for name in fields if name in args}
        body_bytes = (
            json.dumps(coerced, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if coerced
            else b""
        )
    else:
        body_bytes = b""
    return {"method": tool["method"], "path": path, "body": body_bytes, "mutation": tool["mutation"]}


def test_committed_manifest_is_canonical_and_matches_source() -> None:
    committed = MANIFEST_PATH.read_bytes()
    assert committed == canonical_bytes(MANIFEST)
    assert committed == canonical_bytes(json.loads(committed))
    assert read_manifest_bytes() == committed


def test_manifest_conforms_to_m1_1_schema() -> None:
    assert _manifest_errors(MANIFEST) == []
    assert _manifest_errors(json.loads(MANIFEST_PATH.read_bytes())) == []

    assert MANIFEST["manifest_version"] == 1
    assert MANIFEST["app"]["id"] == "library"
    assert MANIFEST["app"]["origin"] == "https://library.aweb.ai"

    names = {tool["name"] for tool in MANIFEST["tools"]}
    assert names == _EXPECTED_TOOLS
    assert {tool["name"]: tool["mutation"] for tool in MANIFEST["tools"]} == _MUTATIONS

    for tool in MANIFEST["tools"]:
        expected_scope = "library:write" if tool["mutation"] else "library:read"
        assert expected_scope in tool["scopes"], tool["name"]

    # library emits no events at v0.
    assert "events" not in MANIFEST
    assert "event_emitters" not in MANIFEST


def test_conformance_validator_rejects_host_injecting_paths() -> None:
    protocol_relative = copy.deepcopy(MANIFEST)
    protocol_relative["tools"][0]["path"] = "//evil.example.com/v1/profile-packs/import"
    assert any("scheme/host" in err for err in _manifest_errors(protocol_relative))


def test_interpreted_spec_bind() -> None:
    spec = _interpret(
        MANIFEST,
        "bind",
        {
            "agent_id": "agent-1",
            "profile_ref": "pack/dev@1",
            "profile_version": "1",
            "profile_digest": "sha256:abc",
        },
    )
    assert spec["method"] == "POST"
    assert spec["path"] == "/v1/agents/agent-1/profile-binding"
    assert spec["body"] == b'{"profile_digest":"sha256:abc","profile_ref":"pack/dev@1","profile_version":"1"}'
    assert spec["mutation"] is True


def test_interpreted_spec_propose() -> None:
    # The propose body must match the implemented ProposalCreateRequest (target
    # required; profile_ref/profile_version/content optional) so a manifest-driven
    # caller is accepted, not 422'd.
    spec = _interpret(MANIFEST, "propose", {"target": "profile", "profile_ref": "coordinator"})
    assert spec["method"] == "POST"
    assert spec["path"] == "/v1/proposals"
    assert spec["body"] == b'{"profile_ref":"coordinator","target":"profile"}'
    assert spec["mutation"] is True


def test_manifest_served_at_both_paths_as_raw_committed_bytes() -> None:
    committed = MANIFEST_PATH.read_bytes()
    client = _client()
    for route in ("/.well-known/aweb-app.json", "/aweb-app.json"):
        response = client.get(route)
        assert response.status_code == 200, (route, response.text)
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.content == committed
        assert hashlib.sha256(response.content).hexdigest() == hashlib.sha256(committed).hexdigest()
