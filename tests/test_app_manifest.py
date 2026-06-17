from __future__ import annotations

import copy
import hashlib
import json
import re
from urllib.parse import quote

from fastapi.testclient import TestClient

import folio.api as folio_api
from folio.aweb_manifest import (
    MANIFEST,
    MANIFEST_PATH,
    canonical_bytes,
    read_manifest_bytes,
)
from folio.config import Settings

_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}

_EXPECTED_TOOLS = {
    "create",
    "list",
    "show",
    "versions",
    "append",
    "append-template",
    "present",
    "revoke",
    "theme-get",
    "theme-set",
    "asset-image",
    "asset-video",
    "asset-get",
    "billing",
}

# Mutation flag per SoT §9: true iff a successful call is a hosted state change.
_MUTATIONS = {
    "create": True,
    "list": False,
    "show": False,
    "versions": False,
    "append": True,
    "append-template": True,
    "present": True,
    "revoke": True,
    "theme-get": False,
    "theme-set": True,
    "asset-image": True,
    "asset-video": True,
    "asset-get": False,
    "billing": False,
}


def _client() -> TestClient:
    return TestClient(folio_api.create_app(Settings(public_origin="https://folio.aweb.ai")))


def _manifest_errors(m: dict) -> list[str]:
    """Encode the frozen m1.1 schema rules (app-manifest-schema.md) as checks."""
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

        # Explicit placement for EVERY input field; no stray params.
        for field in props:
            if field not in placement:
                errors.append(f"{name}: input field {field!r} has no explicit params placement")
        for pname in placement:
            if pname not in props:
                errors.append(f"{name}: param {pname!r} is not an input_schema field")

        # Path placeholders <-> in:path params, both directions.
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
            raw_param = body.get("raw_param")
            if raw_param not in props:
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
    """Coerce a CLI argv string to its input_schema type (mapping §3)."""
    kind = prop.get("type")
    if kind == "integer":
        return int(value)  # type: ignore[arg-type]
    if kind == "number":
        return float(value)  # type: ignore[arg-type]
    if kind == "boolean":
        if isinstance(value, bool):
            return value
        return {"true": True, "false": False}[str(value).lower()]
    return str(value)


def _interpret(manifest: dict, verb: str, args: dict) -> dict:
    """Reference verb→HTTP mapping from the frozen schema (interpreted request, pre-signing)."""
    tool = next(t for t in manifest["tools"] if t["name"] == verb)
    props = tool["input_schema"].get("properties", {})
    placement = {p["name"]: p["in"] for p in tool["params"]}

    path = tool["path"]
    for pname, pin in placement.items():
        if pin == "path":
            path = path.replace("{" + pname + "}", quote(str(args[pname]), safe=""))

    query = [
        (p["name"], _coerce(args[p["name"]], props[p["name"]]))
        for p in tool["params"]
        if p["in"] == "query" and p["name"] in args
    ]

    body = tool.get("body", {})
    mode = body.get("mode", "json")
    if mode == "raw":
        raw = args[body["raw_param"]]
        body_bytes = raw if isinstance(raw, bytes) else str(raw).encode("utf-8")
        content_type = body["content_type"]
    else:
        body_fields = [p["name"] for p in tool["params"] if p["in"] == "body"]
        coerced = {name: _coerce(args[name], props[name]) for name in body_fields if name in args}
        if coerced:
            body_bytes = json.dumps(
                coerced, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            content_type = "application/json"
        else:
            body_bytes = b""
            content_type = None

    return {
        "method": tool["method"],
        "path": path,
        "query": query,
        "content_type": content_type,
        "body": body_bytes,
        "mutation": tool["mutation"],
    }


def test_committed_manifest_is_canonical_and_matches_source() -> None:
    committed = MANIFEST_PATH.read_bytes()

    # The committed file is the byte-stable source of truth the cli team digest-pins.
    assert committed == canonical_bytes(MANIFEST)
    # Canonical form is idempotent: re-canonicalizing the committed bytes is a no-op.
    assert committed == canonical_bytes(json.loads(committed))
    # The reader the route uses returns those exact bytes.
    assert read_manifest_bytes() == committed


def test_manifest_conforms_to_m1_1_schema() -> None:
    assert _manifest_errors(MANIFEST) == []
    assert _manifest_errors(json.loads(MANIFEST_PATH.read_bytes())) == []

    assert MANIFEST["manifest_version"] == 1
    assert MANIFEST["app"]["id"] == "folio"
    assert MANIFEST["app"]["origin"] == "https://folio.aweb.ai"

    names = {tool["name"] for tool in MANIFEST["tools"]}
    assert names == _EXPECTED_TOOLS
    assert len(MANIFEST["tools"]) == len(_EXPECTED_TOOLS)

    mutations = {tool["name"]: tool["mutation"] for tool in MANIFEST["tools"]}
    assert mutations == _MUTATIONS

    # Read tools carry folio:read, mutating tools folio:write.
    for tool in MANIFEST["tools"]:
        expected_scope = "folio:write" if tool["mutation"] else "folio:read"
        assert expected_scope in tool["scopes"], tool["name"]


def test_conformance_validator_rejects_host_injecting_paths() -> None:
    # Guards against a vacuous conformance test: host-injecting paths must fail.
    absolute = copy.deepcopy(MANIFEST)
    absolute["tools"][0]["path"] = "https://evil.example.com/v1/documents"
    assert _manifest_errors(absolute), "an absolute-URL path must be rejected"

    # Protocol-relative path keeps a leading / but still injects a host.
    protocol_relative = copy.deepcopy(MANIFEST)
    protocol_relative["tools"][0]["path"] = "//evil.example.com/v1/documents"
    assert any("scheme/host" in err for err in _manifest_errors(protocol_relative))


def test_interpreted_spec_append_present_asset_image() -> None:
    append = _interpret(MANIFEST, "append", {"slug": "pitch", "body": "# Hello\n\nWorld"})
    assert append["method"] == "POST"
    assert append["path"] == "/v1/documents/pitch/versions"
    assert append["content_type"] == "text/markdown; charset=utf-8"
    assert append["body"] == b"# Hello\n\nWorld"
    assert append["mutation"] is True

    # ttl_seconds and editable arrive as argv strings; both must coerce before serializing.
    present = _interpret(
        MANIFEST, "present", {"slug": "pitch", "ttl_seconds": "3600", "editable": "true"}
    )
    assert present["method"] == "POST"
    assert present["path"] == "/v1/present"
    assert present["content_type"] == "application/json"
    assert present["body"] == b'{"editable":true,"slug":"pitch","ttl_seconds":3600}'
    assert present["mutation"] is True

    asset = _interpret(
        MANIFEST, "asset-image", {"content_type": "image/png", "data_base64": "iVBORw0KGgo="}
    )
    assert asset["method"] == "POST"
    assert asset["path"] == "/v1/assets"
    assert asset["content_type"] == "application/json"
    assert asset["body"] == b'{"content_type":"image/png","data_base64":"iVBORw0KGgo="}'
    assert asset["mutation"] is True

    # `aw folio theme-set --preset aweb` must dispatch as PUT /v1/theme {"preset":"aweb"}.
    theme_set = _interpret(MANIFEST, "theme-set", {"preset": "aweb"})
    assert theme_set["method"] == "PUT"
    assert theme_set["path"] == "/v1/theme"
    assert theme_set["content_type"] == "application/json"
    assert theme_set["body"] == b'{"preset":"aweb"}'
    assert theme_set["mutation"] is True


def test_well_known_route_serves_raw_committed_bytes() -> None:
    committed = MANIFEST_PATH.read_bytes()

    # Public discovery doc: no certificate presented, still 200.
    response = _client().get("/.well-known/aweb-app.json")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.content == committed
    assert hashlib.sha256(response.content).hexdigest() == hashlib.sha256(committed).hexdigest()
