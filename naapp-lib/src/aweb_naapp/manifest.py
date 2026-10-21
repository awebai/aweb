"""Conventions and helpers for the canonical aweb-app.json manifest.

A naapp declares its cert-authed operations as manifest tools (name, method,
path, params, input_schema). Public discovery reads carry ``auth: none``. These
helpers read that shape; the docs generators render from them so the surface and
the manifest never drift.

:func:`load_manifest` is the one reader of manifest bytes of either supported
version. It validates them exactly as the aw CLI does and resolves what a
consumer acts on: tool invocation contexts, surfaces, usage, lifecycle, the
hooks slot and purpose-split app keys. Both implementations pass the shared
vectors in ``test-vectors/app-manifests/``; their error codes are the contract.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit


def canonical_bytes(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no insignificant whitespace, UTF-8.

    Matches the awid signing CanonicalJSON convention so a committed manifest and
    any consumer's serialization are byte-identical.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def write_manifest_file(path: Path, manifest: dict[str, Any]) -> None:
    """Write an app's committed manifest file: the canonical bytes of its authoring
    manifest, whose ``app.origin`` is the hosted origin."""
    path.write_bytes(canonical_bytes(manifest))


def manifest_for_origin(manifest: dict[str, Any], public_origin: str) -> dict[str, Any]:
    """A copy of the manifest with ``app.origin`` set to this deployment's origin."""
    retargeted = copy.deepcopy(manifest)
    retargeted["app"]["origin"] = public_origin.rstrip("/")
    return retargeted


def read_manifest_bytes(path: Path, public_origin: str | None = None) -> bytes:
    """The manifest bytes to serve for a deployment origin.

    The committed file's own origin (the hosted one) gets the committed bytes
    verbatim, never re-serialized. Any other origin, such as a self-hosted
    deployment, gets the same manifest in canonical form with only ``app.origin``
    changed.
    """
    committed = path.read_bytes()
    if public_origin is None:
        return committed
    manifest = json.loads(committed)
    if public_origin.rstrip("/") == manifest["app"]["origin"]:
        return committed
    return canonical_bytes(manifest_for_origin(manifest, public_origin))


def public_tools(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [t for t in manifest["tools"] if t.get("auth") == "none"]


def cert_tools(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [t for t in manifest["tools"] if t.get("auth") != "none"]


def params_by_loc(tool: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p.get("in", "body") for p in tool.get("params", []) if "name" in p}


def tool_params(tool: dict[str, Any]) -> tuple[list[str], list[str]]:
    """A tool's (required, optional) parameter names, in manifest order.

    Path params are required by construction — the route cannot match without
    them — even when the manifest input_schema does not list them in ``required``.
    Treating them as required here (a rendering concern) keeps the served manifest
    digest unchanged.
    """
    schema = tool.get("input_schema") or {}
    path_params = {p["name"] for p in tool.get("params", []) if p.get("in") == "path"}
    required = set(schema.get("required") or []) | path_params
    order: list[str] = [p["name"] for p in tool.get("params", []) if "name" in p]
    for name in schema.get("properties") or {}:
        if name not in order:
            order.append(name)
    req = [n for n in order if n in required]
    opt = [n for n in order if n not in required]
    return req, opt


def example_path(tool: dict[str, Any], values: dict[str, str]) -> str:
    """The path with placeholders replaced by app-supplied example values. Whatever
    is not supplied stays a ``{brace}`` placeholder, so the caller can tell whether
    the result is a genuinely runnable URL (see :func:`is_fully_substituted`)."""
    path = tool["path"]
    for name, value in values.items():
        path = path.replace("{" + name + "}", value)
    return path


def is_fully_substituted(tool: dict[str, Any], values: dict[str, str]) -> bool:
    """True when every path placeholder has an app-supplied example value, so the
    rendered URL is genuinely runnable (no leftover brace)."""
    return "{" not in example_path(tool, values)


# --- Manifest versions 1 and 2 -------------------------------------------------

SUPPORTED_MANIFEST_VERSIONS = (1, 2)
CATALOG_PATH = "/.well-known/aweb-app-versions.json"
LEGACY_MANIFEST_PATH = "/.well-known/aweb-app.json"
MAX_CATALOG_BYTES = 64 << 10
MAX_MANIFEST_BYTES = 10 << 20
MAX_JSON_DEPTH = 512
_MAX_V2_TOOLS = 256
_MAX_V2_PATH_SEGMENTS = 32
_MAX_ROLES = 64
_MAX_ROLE_NAME_BYTES = 128
_MAX_ROLE_LABEL = 128
_MAX_ROLE_DESCRIPTION = 512
# The designatable role grammar of aweb_naapp.roles: dot-separated lowercase
# segments, at least two, no ':'.
_ROLE_NAME = re.compile(r"[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)+")
_ROLE = frozenset({"name", "label", "description"})

AGENT, SURFACE, HOOK = "agent", "surface", "hook"
_CONTEXTS = (AGENT, SURFACE, HOOK)
_DEFAULT_CONTEXTS = frozenset({AGENT, SURFACE})
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_INT64 = (-(1 << 63), (1 << 63) - 1)

# Go's strings.TrimSpace removes Unicode White_Space; Python's str.strip()
# also removes U+001C..U+001F, which Go keeps.
_GO_SPACE = "\t\n\v\f\r \x85\xa0                　"

_LOCAL_EVENT_TYPE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_SURFACE_ID = re.compile(r"[a-z][a-z0-9-]{0,62}")
_FORMAT = re.compile(r"[a-z][a-z0-9.-]{0,63}/[1-9][0-9]{0,8}")
_FIELD_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
_PURPOSE = re.compile(r"[a-z][a-z0-9-]{0,63}")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_HOOK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SCOPE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class ManifestError(ValueError):
    """A manifest refusal with a stable code; the message is for people."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _go_trim(value: str) -> str:
    return value.strip(_GO_SPACE)


def _invalid(message: str) -> ManifestError:
    return ManifestError("manifest_invalid", message)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def _nesting_depth_exceeds(data: bytes, limit: int) -> bool:
    """Whether JSON nests objects and arrays deeper than ``limit``, counting
    only brackets outside strings."""
    depth, in_string, escaped = 0, False, False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            if depth > limit:
                return True
        elif byte in (0x7D, 0x5D):
            depth -= 1
    return False


def _decode_document(data: bytes, what: str = "manifest") -> Any:
    if _nesting_depth_exceeds(data, MAX_JSON_DEPTH):
        raise _invalid(f"{what} is nested deeper than {MAX_JSON_DEPTH} levels")
    try:
        return json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise _invalid(f"{what} is not one JSON document: {exc}") from None


# Decoding mirrors the Go types: a v1 field that is null reads as its zero
# value, a wrongly typed field is refused, and a v2 member is never null.

def _v1_string(obj: Mapping[str, Any], key: str, where: str) -> str:
    value = obj.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise _invalid(f"{where}.{key} must be a string")
    return value


def _v1_bool(obj: Mapping[str, Any], key: str, where: str) -> bool:
    value = obj.get(key)
    if value is None:
        return False
    if not isinstance(value, bool):
        raise _invalid(f"{where}.{key} must be a boolean")
    return value


def _v1_int(obj: Mapping[str, Any], key: str, where: str) -> int:
    value = obj.get(key)
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or not _INT64[0] <= value <= _INT64[1]:
        raise _invalid(f"{where}.{key} must be an integer")
    return value


def _v1_object(value: Any, where: str, fields: frozenset[str]) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _invalid(f"{where} must be an object")
    unknown = set(value) - fields
    if unknown:
        raise _invalid(f"{where} has unknown field {sorted(unknown)[0]!r}")
    return value


def _v1_list(value: Any, where: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise _invalid(f"{where} must be an array")
    return value


def _v2_object(value: Any, where: str, fields: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _invalid(f"{where} must be an object")
    unknown = set(value) - fields
    if unknown:
        raise _invalid(f"{where} has unknown field {sorted(unknown)[0]!r}")
    for key, member in value.items():
        if member is None:
            raise _invalid(f"{where}.{key} must not be null")
    return value


def _v2_list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise _invalid(f"{where} must be an array")
    return value


def _v2_string(obj: Mapping[str, Any], key: str, where: str) -> str:
    value = obj.get(key, "")
    if not isinstance(value, str):
        raise _invalid(f"{where}.{key} must be a string")
    return value


def _v2_int(obj: Mapping[str, Any], key: str, where: str) -> int:
    value = obj.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or not _INT64[0] <= value <= _INT64[1]:
        raise _invalid(f"{where}.{key} must be an integer")
    return value


def _v2_names(obj: Mapping[str, Any], key: str, where: str) -> list[str] | None:
    if key not in obj:
        return None
    value = _v2_list(obj[key], f"{where}.{key}")
    if not all(isinstance(item, str) for item in value):
        raise _invalid(f"{where}.{key} items must be strings")
    return list(value)


_TOP = frozenset({"manifest_version", "app", "tools", "event_emitters", "events",
                  "app_keys", "surfaces", "usage", "lifecycle", "hooks", "roles"})
_V2_TOP = ("app_keys", "surfaces", "usage", "lifecycle", "hooks", "roles")
_APP = frozenset({"id", "version", "origin", "llms_txt", "skills"})
_TOOL = frozenset({"name", "description", "method", "path", "input_schema", "params", "body",
                   "scopes", "auth", "mutation", "invocation_contexts"})
_PARAM = frozenset({"name", "in"})
_BODY = frozenset({"mode", "raw_param", "content_type"})
_EMITTER = frozenset({"kid", "did_key"})
_EVENT = frozenset({"type", "default_delivery_intent", "description"})
_APP_KEY = frozenset({"kid", "did_key", "purposes"})
_SURFACE = frozenset({"id", "label", "format", "list_tool", "read_tool", "invoke_tool", "answer_tool",
                      "inputs", "events"})
_INPUTS = frozenset({"resource", "invocation"})
_SURFACE_EVENT = frozenset({"type", "resource_field", "revision_field"})
_USAGE = frozenset({"format", "snapshot_tool"})
_LIFECYCLE = frozenset({"export_tool", "delete_tool", "status_tool"})
_HOOKS = frozenset({"registration_version", "registrations", "productions"})
_CATALOG = frozenset({"id", "version"})
_REGISTRATION = frozenset({"catalog", "hook", "tool", "scopes"})
_PRODUCTION = frozenset({"catalog", "hook", "reads"})


@dataclass
class _Tool:
    raw: dict[str, Any]
    name: str
    description: str
    method: str
    path: str
    input_schema: dict[str, Any] | None
    params: list[tuple[str, str]]
    body: tuple[str, str, str]
    scopes: list[str]
    auth: str
    mutation: bool
    contexts: list[str] | None

    @property
    def effective_contexts(self) -> frozenset[str]:
        return _DEFAULT_CONTEXTS if self.contexts is None else frozenset(self.contexts)

    @property
    def public(self) -> bool:
        return self.auth != "" and _go_trim(self.auth) == "none" and not self.mutation


def _decode_tool(raw: Any, where: str) -> _Tool:
    tool = _v1_object(raw, where, _TOOL)
    schema = tool.get("input_schema")
    if schema is not None and not isinstance(schema, dict):
        raise _invalid(f"{where}.input_schema must be an object")
    params = []
    for i, item in enumerate(_v1_list(tool.get("params"), f"{where}.params")):
        param = _v1_object(item, f"{where}.params[{i}]", _PARAM)
        params.append((_v1_string(param, "name", "param"), _v1_string(param, "in", "param")))
    body = _v1_object(tool.get("body"), f"{where}.body", _BODY)
    scopes = []
    for item in _v1_list(tool.get("scopes"), f"{where}.scopes"):
        if item is not None and not isinstance(item, str):
            raise _invalid(f"{where}.scopes items must be strings")
        scopes.append(item or "")
    contexts = None
    if "invocation_contexts" in tool:
        contexts = _v2_names(tool, "invocation_contexts", where)
    return _Tool(
        raw=tool,
        name=_v1_string(tool, "name", where),
        description=_v1_string(tool, "description", where),
        method=_v1_string(tool, "method", where),
        path=_v1_string(tool, "path", where),
        input_schema=schema,
        params=params,
        body=(_v1_string(body, "mode", "body"), _v1_string(body, "raw_param", "body"),
              _v1_string(body, "content_type", "body")),
        scopes=scopes,
        auth=_v1_string(tool, "auth", where),
        mutation=_v1_bool(tool, "mutation", where),
        contexts=contexts,
    )


def _decode_events(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise _invalid("events must be an array")
    if len(value) > 64:
        raise _invalid("events exceeds 64 declarations")
    events = []
    for i, item in enumerate(value):
        event = _v2_object(item, f"events[{i}]", _EVENT)
        for key in event:
            if not isinstance(event[key], str):
                raise _invalid(f"events[{i}].{key} must be a string")
        events.append(event)
    return events


def _decode(doc: Any) -> dict[str, Any]:
    """Type-check the whole document before any value rule, as Go's decoder does."""
    if not isinstance(doc, dict):
        raise _invalid("manifest must be a JSON object")
    unknown = set(doc) - _TOP
    if unknown:
        raise _invalid(f"manifest has unknown field {sorted(unknown)[0]!r}")
    for key in _V2_TOP:
        if key in doc and doc[key] is None:
            raise _invalid(f"{key} must not be null")
    out: dict[str, Any] = {"present": set(doc)}
    out["version"] = _v1_int(doc, "manifest_version", "manifest")
    app = _v1_object(doc.get("app"), "app", _APP)
    out["app"] = {key: _v1_string(app, key, "app") for key in _APP}
    out["tools"] = [_decode_tool(item, f"tools[{i}]") for i, item in enumerate(_v1_list(doc.get("tools"), "tools"))]
    emitters = []
    for i, item in enumerate(_v1_list(doc.get("event_emitters"), "event_emitters")):
        emitter = _v1_object(item, f"event_emitters[{i}]", _EMITTER)
        emitters.append((_v1_string(emitter, "kid", "event_emitter"), _v1_string(emitter, "did_key", "event_emitter")))
    out["emitters"] = emitters
    out["events"] = _decode_events(doc["events"]) if "events" in doc else []

    keys = []
    for i, item in enumerate(_v2_list(doc.get("app_keys", []), "app_keys")):
        entry = _v2_object(item, f"app_keys[{i}]", _APP_KEY)
        keys.append((_v2_string(entry, "kid", "app_key"), _v2_string(entry, "did_key", "app_key"),
                     _v2_names(entry, "purposes", "app_key") or []))
    out["app_keys"] = keys

    surfaces = []
    for i, item in enumerate(_v2_list(doc.get("surfaces", []), "surfaces")):
        where = f"surfaces[{i}]"
        surface = _v2_object(item, where, _SURFACE)
        decoded: dict[str, Any] = {key: _v2_string(surface, key, where) for key in _SURFACE - {"inputs", "events"}}
        inputs = _v2_object(surface.get("inputs", {}), f"{where}.inputs", _INPUTS)
        decoded["resource"] = _v2_string(inputs, "resource", f"{where}.inputs")
        decoded["invocation"] = _v2_string(inputs, "invocation", f"{where}.inputs")
        events = []
        for j, raw in enumerate(_v2_list(surface.get("events", []), f"{where}.events")):
            event = _v2_object(raw, f"{where}.events[{j}]", _SURFACE_EVENT)
            events.append({key: _v2_string(event, key, f"{where}.events[{j}]") for key in _SURFACE_EVENT})
        decoded["events"] = events
        surfaces.append(decoded)
    out["surfaces"] = surfaces

    out["usage"] = None
    if "usage" in doc:
        usage = _v2_object(doc["usage"], "usage", _USAGE)
        out["usage"] = {key: _v2_string(usage, key, "usage") for key in _USAGE}
    out["lifecycle"] = None
    if "lifecycle" in doc:
        lifecycle = _v2_object(doc["lifecycle"], "lifecycle", _LIFECYCLE)
        out["lifecycle"] = {key: _v2_string(lifecycle, key, "lifecycle") for key in _LIFECYCLE}
    out["hooks"] = None
    if "hooks" in doc:
        hooks = _v2_object(doc["hooks"], "hooks", _HOOKS)

        def catalog(entry: Mapping[str, Any], where: str) -> tuple[str, int]:
            cat = _v2_object(entry.get("catalog", {}), f"{where}.catalog", _CATALOG)
            return _v2_string(cat, "id", f"{where}.catalog"), _v2_int(cat, "version", f"{where}.catalog")

        registrations = []
        for i, item in enumerate(_v2_list(hooks.get("registrations", []), "hooks.registrations")):
            where = f"hooks.registrations[{i}]"
            reg = _v2_object(item, where, _REGISTRATION)
            registrations.append({"catalog": catalog(reg, where), "hook": _v2_string(reg, "hook", where),
                                  "tool": _v2_string(reg, "tool", where),
                                  "scopes": _v2_names(reg, "scopes", where) or []})
        productions = []
        for i, item in enumerate(_v2_list(hooks.get("productions", []), "hooks.productions")):
            where = f"hooks.productions[{i}]"
            prod = _v2_object(item, where, _PRODUCTION)
            productions.append({"catalog": catalog(prod, where), "hook": _v2_string(prod, "hook", where),
                                "reads": _v2_names(prod, "reads", where) or []})
        out["hooks"] = {"registration_version": _v2_int(hooks, "registration_version", "hooks"),
                        "registrations": registrations, "productions": productions}
    # Roles stay raw until validation, so every fault in them is role_invalid.
    out["roles"] = doc.get("roles")
    return out


def _b58decode(text: str) -> bytes:
    number = 0
    for char in text:
        digit = _B58.find(char)
        if digit < 0:
            raise ValueError("invalid base58 character")
        number = number * 58 + digit
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body


def _is_ed25519_did_key(value: str) -> bool:
    if not value.startswith("did:key:z"):
        return False
    try:
        decoded = _b58decode(value[len("did:key:z"):])
    except ValueError:
        return False
    return len(decoded) == 34 and decoded[:2] == b"\xed\x01"


def _valid_origin(raw: str) -> bool:
    raw = _go_trim(raw)
    if not raw:
        return False
    try:
        parts = urlsplit(raw)
        parts.port  # noqa: B018 - raises on an invalid port, as Go's parser does
    except ValueError:
        return False
    return bool(parts.scheme) and bool(parts.netloc)


def _relative_path(raw: str, name: str) -> str:
    path = _go_trim(raw)
    if not path:
        raise _invalid("tool.path is required")
    if "://" in path or path.startswith("//"):
        raise _invalid(f"tool {name!r} path must be relative")
    try:
        parts = urlsplit(path)
    except ValueError as exc:
        raise _invalid(f"tool {name!r} path is invalid: {exc}") from None
    if parts.scheme or parts.netloc:
        raise _invalid(f"tool {name!r} path must be relative")
    if parts.query:
        raise _invalid(f"tool {name!r} path must not include query")
    if parts.fragment:
        raise _invalid(f"tool {name!r} path must not include fragment")
    if ".." in unquote(parts.path).split("/"):
        raise _invalid(f"tool {name!r} path must not contain path traversal")
    return path if path.startswith("/") else "/" + path


def _placeholders(path: str) -> set[str]:
    out: set[str] = set()
    position = 0
    while True:
        start = path.find("{", position)
        if start < 0:
            return out
        end = path.find("}", start + 1)
        if end < 0:
            return out
        name = _go_trim(path[start + 1:end])
        if name:
            out.add(name)
        position = end + 1


def _schema_properties(schema: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    props = (schema or {}).get("properties")
    if not isinstance(props, dict):
        return {}
    return {name: value for name, value in props.items() if isinstance(value, dict)}


def _schema_type(prop: Mapping[str, Any] | None) -> str:
    value = (prop or {}).get("type")
    return _go_trim(value) if isinstance(value, str) else ""


def _validate_tool(tool: _Tool, reserved: frozenset[str]) -> None:
    name = _go_trim(tool.name)
    if not name:
        raise _invalid("tool.name is required")
    if name in reserved:
        raise _invalid(f"tool name {name!r} is reserved")
    if _go_trim(tool.method).upper() not in _METHODS:
        raise _invalid(f"tool {name!r} has an unsupported method")
    if tool.auth != "":
        if _go_trim(tool.auth) != "none":
            raise _invalid(f"tool {name!r} has unsupported auth")
        if tool.mutation:
            raise _invalid(f"tool {name!r} cannot use auth:none for a mutation")
    path = _relative_path(tool.path, name)
    properties = _schema_properties(tool.input_schema)
    params: dict[str, str] = {}
    for raw_name, raw_in in tool.params:
        param, placement = _go_trim(raw_name), _go_trim(raw_in)
        if not param:
            raise _invalid(f"tool {name!r} has a param with empty name")
        if placement not in ("path", "query", "body"):
            raise _invalid(f"param {param!r} has invalid placement")
        if param in params:
            raise _invalid(f"duplicate param {param!r}")
        params[param] = placement
        if param not in properties:
            raise _invalid(f"param {param!r} is not declared in input_schema")
    for prop in properties:
        if prop not in params:
            raise _invalid(f"input_schema field {prop!r} is missing params placement")
    placeholders = _placeholders(path)
    for placeholder in placeholders:
        if params.get(placeholder) != "path":
            raise _invalid(f"path placeholder {placeholder!r} has no matching in:path param")
    for param, placement in params.items():
        if placement == "path" and param not in placeholders:
            raise _invalid(f"path param {param!r} has no matching placeholder")
    mode, raw_param, content_type = (_go_trim(v) for v in tool.body)
    mode = mode or "json"
    if mode not in ("json", "raw"):
        raise _invalid(f"unsupported body mode {mode!r}")
    if mode == "raw":
        if not raw_param:
            raise _invalid("raw body mode requires body.raw_param")
        if not content_type:
            raise _invalid("raw body mode requires body.content_type")
        if params.get(raw_param) != "body":
            raise _invalid(f"raw body param {raw_param!r} must be declared as in:body")
        if any(placement == "body" and param != raw_param for param, placement in params.items()):
            raise _invalid(f"raw body mode allows only raw_param {raw_param!r} in body")
    elif raw_param:
        raise _invalid("body.raw_param is only valid for raw body mode")
    for param, placement in params.items():
        if placement == "body" and _schema_type(properties.get(param)) == "number":
            raise _invalid(f"body param {param!r} uses unsupported type number")


def _validate_common(d: dict[str, Any], reserved: frozenset[str]) -> str:
    app_id = _go_trim(d["app"]["id"])
    if not app_id:
        raise _invalid("app.id is required")
    if app_id in reserved:
        raise _invalid(f"app id {app_id!r} is reserved")
    if not _valid_origin(d["app"]["origin"]):
        raise _invalid("invalid app.origin")
    for tool in d["tools"]:
        _validate_tool(tool, reserved)
    for event in d["events"]:
        local = _go_trim(event.get("type", "")).removeprefix(app_id + "/")
        if not _LOCAL_EVENT_TYPE.fullmatch(local):
            raise _invalid("events[].type must be an app-local event type")
        if event.get("default_delivery_intent", "ambient") not in ("ambient", "wake", "steer"):
            raise _invalid("events[].default_delivery_intent is invalid")
        if len(_go_trim(event.get("description", ""))) > 4096:
            raise _invalid("events[].description exceeds 4096 characters")
    seen = set()
    for kid, did_key in d["emitters"]:
        kid, did_key = _go_trim(kid), _go_trim(did_key)
        if not kid:
            raise _invalid("event_emitters[].kid is required")
        if kid in seen:
            raise _invalid(f"duplicate event emitter kid {kid!r}")
        seen.add(kid)
        if not did_key:
            raise _invalid("event_emitters[].did_key is required")
        if not _is_ed25519_did_key(did_key):
            raise _invalid(f"event emitter kid {kid!r} did_key is not an Ed25519 did:key")
    return app_id


def _refuse(code: str, message: str) -> ManifestError:
    return ManifestError(code, message)


def _validate_v2(d: dict[str, Any], app_id: str, tools: dict[str, _Tool]) -> None:
    if "event_emitters" in d["present"]:
        raise _invalid("event_emitters is replaced by app_keys in manifest_version 2")
    if len(d["tools"]) > _MAX_V2_TOOLS:
        raise _invalid(f"a manifest_version 2 manifest declares at most {_MAX_V2_TOOLS} tools")
    names = [_go_trim(tool.name) for tool in d["tools"]]
    if len(set(names)) != len(names):
        raise _invalid("tool names must be unique")
    for tool in d["tools"]:
        if "%" in tool.path:
            raise _invalid(f"tool {tool.name!r} path must not carry percent-encoding")
        if len([segment for segment in tool.path.split("/") if segment]) > _MAX_V2_PATH_SEGMENTS:
            raise _invalid(f"tool {tool.name!r} path has more than {_MAX_V2_PATH_SEGMENTS} segments")
    for tool in d["tools"]:
        if tool.contexts is None:
            continue
        if not tool.contexts:
            raise _refuse("tool_contexts_invalid", f"tool {tool.name!r} invocation_contexts must not be empty")
        if any(c not in _CONTEXTS for c in tool.contexts) or len(set(tool.contexts)) != len(tool.contexts):
            raise _refuse("tool_contexts_invalid", f"tool {tool.name!r} invocation_contexts are invalid")
    _validate_app_keys(d["app_keys"])
    _validate_surfaces(d, app_id, tools)
    _validate_answer_routes(d, tools)
    _validate_answer_inputs(d)
    _validate_usage(d["usage"], tools)
    _validate_lifecycle(d["lifecycle"], tools)
    _validate_hooks(d["hooks"], tools)
    _parse_roles(d["roles"])


def _validate_app_keys(keys: list[tuple[str, str, list[str]]]) -> None:
    if len(keys) > 16:
        raise _refuse("app_keys_invalid", "app_keys exceeds 16 keys")
    kids = set()
    for kid, did_key, purposes in keys:
        if not _KEY_ID.fullmatch(kid):
            raise _refuse("app_keys_invalid", f"app key kid {kid!r} is invalid")
        if kid in kids:
            raise _refuse("app_keys_invalid", f"duplicate app key kid {kid!r}")
        kids.add(kid)
        if not _is_ed25519_did_key(did_key):
            raise _refuse("app_keys_invalid", f"app key {kid!r} did_key is not an Ed25519 did:key")
        if not 1 <= len(purposes) <= 8:
            raise _refuse("app_keys_invalid", f"app key {kid!r} must declare 1 to 8 purposes")
        if not all(_PURPOSE.fullmatch(p) for p in purposes) or len(set(purposes)) != len(purposes):
            raise _refuse("app_keys_invalid", f"app key {kid!r} purposes are invalid")


def _resolve_event_type(event_type: str, app_id: str, declared: set[str]) -> str:
    local = event_type
    if "/" in event_type:
        local = event_type.removeprefix(app_id + "/")
        if local == event_type or "/" in local:
            raise _refuse("surface_invalid", f"surface event {event_type!r} is not an event of app {app_id!r}")
    if local not in declared:
        raise _refuse("surface_invalid", f"surface event {event_type!r} is not declared in events")
    return f"{app_id}/{local}"


def _declared_events(d: dict[str, Any], app_id: str) -> set[str]:
    return {_go_trim(event.get("type", "")).removeprefix(app_id + "/") for event in d["events"]}


def _tool_param(tool: _Tool, name: str) -> tuple[str, str] | None:
    for raw_name, raw_in in tool.params:
        if _go_trim(raw_name) == name:
            return name, _go_trim(raw_in)
    return None


def _validate_surfaces(d: dict[str, Any], app_id: str, tools: dict[str, _Tool]) -> None:
    surfaces = d["surfaces"]
    if len(surfaces) > 16:
        raise _refuse("surface_invalid", "surfaces exceeds 16")
    ids = set()
    for s in surfaces:
        sid = s["id"]
        if not _SURFACE_ID.fullmatch(sid):
            raise _refuse("surface_invalid", f"surface id {sid!r} is invalid")
        label = _go_trim(s["label"])
        if not label or len(label) > 128:
            raise _refuse("surface_invalid", f"surface {sid!r} label must be 1 to 128 characters")
        if not _FORMAT.fullmatch(s["format"]):
            raise _refuse("surface_invalid", f"surface {sid!r} format is invalid")
        if not s["list_tool"] or not s["read_tool"]:
            raise _refuse("surface_invalid", f"surface {sid!r} requires list_tool and read_tool")
        if not s["resource"]:
            raise _refuse("surface_invalid", f"surface {sid!r} requires inputs.resource")
        if (s["invoke_tool"] or s["answer_tool"]) and not s["invocation"]:
            raise _refuse("surface_invalid", f"surface {sid!r} requires inputs.invocation")
        if len(s["events"]) > 16:
            raise _refuse("surface_invalid", f"surface {sid!r} events exceeds 16")
        for event in s["events"]:
            if (not event["type"] or not _FIELD_NAME.fullmatch(event["resource_field"])
                    or not _FIELD_NAME.fullmatch(event["revision_field"])):
                raise _refuse("surface_invalid", f"surface {sid!r} event binding is invalid")
        if sid in ids:
            raise _refuse("surface_invalid", f"duplicate surface id {sid!r}")
        ids.add(sid)
    declared = _declared_events(d, app_id)
    for s in surfaces:
        _validate_surface_tools(s, tools)
        _validate_surface_inputs(s, tools)
        for event in s["events"]:
            _resolve_event_type(event["type"], app_id, declared)


def _validate_surface_tools(s: dict[str, Any], tools: dict[str, _Tool]) -> None:
    sid = s["id"]
    if s["answer_tool"]:
        answer = tools.get(s["answer_tool"])
        if answer is None:
            raise _refuse("surface_tool_invalid", f"surface {sid!r} answer_tool is not a declared tool")
        if answer.effective_contexts != {SURFACE}:
            raise _refuse("answer_tool_contexts_invalid",
                          f"surface {sid!r} answer_tool must declare invocation_contexts exactly [\"surface\"]")
    for role, name, get in (("list_tool", s["list_tool"], True), ("read_tool", s["read_tool"], True),
                            ("invoke_tool", s["invoke_tool"], False), ("answer_tool", s["answer_tool"], False)):
        if not name:
            continue
        tool = tools.get(name)
        if tool is None:
            raise _refuse("surface_tool_invalid", f"surface {sid!r} {role} {name!r} is not a declared tool")
        if SURFACE not in tool.effective_contexts:
            raise _refuse("surface_tool_invalid", f"surface {sid!r} {role} {name!r} lacks the surface context")
        if tool.public:
            raise _refuse("surface_tool_invalid", f"surface {sid!r} {role} {name!r} must be member-authenticated")
        if get and (_go_trim(tool.method).upper() != "GET" or tool.mutation):
            raise _refuse("surface_tool_invalid", f"surface {sid!r} {role} {name!r} must be a non-mutating GET")
        if not get and not tool.mutation:
            raise _refuse("surface_tool_invalid", f"surface {sid!r} {role} {name!r} must be a mutation")
    if not s["invoke_tool"]:
        return
    if s["invoke_tool"] == s["answer_tool"]:
        raise _refuse("answer_input_forbidden", f"surface {sid!r} invoke_tool cannot be its answer_tool")


def _answer_tools(surfaces: list[dict[str, Any]] | tuple[Mapping[str, Any], ...]) -> set[str]:
    return {s["answer_tool"] for s in surfaces if s["answer_tool"]}


def _route(tool: _Tool) -> tuple[str, list[str]]:
    segments = [segment for segment in _relative_path(tool.path, tool.name).split("/") if segment]
    return _go_trim(tool.method).upper(), segments


def _segments_reach(caller: list[str], target: list[str]) -> bool:
    """A caller segment holding a placeholder covers one or more target
    segments, because its value may carry an encoded '/' that the server decodes
    before routing. A target segment holding a placeholder matches any one
    caller segment. Fills "caller[i:] can match target[j:]" from the end, in
    O(len(caller) * len(target))."""
    following = [False] * len(target) + [True]
    for segment in reversed(caller):
        current = [False] * (len(target) + 1)
        later_match = False
        for j in range(len(target), -1, -1):
            if "{" in segment:
                current[j] = later_match
            elif j < len(target):
                current[j] = (segment == target[j] or "{" in target[j]) and following[j + 1]
            later_match = later_match or following[j]
        following = current
    return following[0]


def _can_reach_route(caller: _Tool, target: _Tool) -> bool:
    (method_caller, segments_caller), (method_target, segments_target) = _route(caller), _route(target)
    return method_caller == method_target and _segments_reach(segments_caller, segments_target)


def _validate_answer_routes(d: dict[str, Any], tools: dict[str, _Tool]) -> None:
    """No agent-visible tool may reach a surface answer_tool's route as a server
    routes it, on the decoded path. Deliberately conservative, and defence in
    depth: the guarantee is the naapp refusing answer-kind actions."""
    for name in _answer_tools(d["surfaces"]):
        for tool in d["tools"]:
            if _go_trim(tool.name) != name and AGENT in tool.effective_contexts and _can_reach_route(tool, tools[name]):
                raise _refuse("answer_route_agent_visible",
                              f"agent-visible tool {tool.name!r} can reach answer_tool {name!r}'s route")


def _validate_answer_inputs(d: dict[str, Any]) -> None:
    """Only a surface answer_tool may declare an answer input, top-level or
    inside an object body parameter."""
    answers = _answer_tools(d["surfaces"])
    for tool in d["tools"]:
        name = _go_trim(tool.name)
        if name in answers:
            continue
        properties = _schema_properties(tool.input_schema)
        if "answer" in properties:
            raise _refuse("answer_input_forbidden", f"tool {name!r} declares an answer input")
        for param, placement in tool.params:
            if _go_trim(placement) == "body" and "answer" in _schema_properties(properties.get(_go_trim(param))):
                raise _refuse("answer_input_forbidden", f"tool {name!r} declares an answer inside {param!r}")


def _validate_surface_inputs(s: dict[str, Any], tools: dict[str, _Tool]) -> None:
    sid = s["id"]
    for name in (s["read_tool"], s["invoke_tool"], s["answer_tool"]):
        if name and _tool_param(tools[name], s["resource"]) is None:
            raise _refuse("surface_invalid", f"surface {sid!r} resource input is not a param of {name!r}")
    for name in (s["invoke_tool"], s["answer_tool"]):
        if not name:
            continue
        param = _tool_param(tools[name], s["invocation"])
        properties = _schema_properties(tools[name].input_schema)
        if param is None or param[1] != "body" or _schema_type(properties.get(param[0])) != "object":
            raise _refuse("surface_invalid", f"surface {sid!r} invocation input is not an object body param of {name!r}")


def _validate_usage(usage: dict[str, str] | None, tools: dict[str, _Tool]) -> None:
    if usage is None:
        return
    if not _FORMAT.fullmatch(usage["format"]):
        raise _refuse("usage_invalid", "usage format is invalid")
    tool = tools.get(usage["snapshot_tool"]) if usage["snapshot_tool"] else None
    if tool is None:
        raise _refuse("usage_invalid", "usage snapshot_tool is not a declared tool")
    if tool.mutation or tool.public:
        raise _refuse("usage_invalid", "usage snapshot_tool must be a member-authenticated read")


def _validate_lifecycle(lifecycle: dict[str, str] | None, tools: dict[str, _Tool]) -> None:
    if lifecycle is None:
        return
    named = 0
    for role, mutation in (("export_tool", True), ("delete_tool", True), ("status_tool", False)):
        name = lifecycle[role]
        if not name:
            continue
        named += 1
        tool = tools.get(name)
        if tool is None:
            raise _refuse("lifecycle_invalid", f"lifecycle {role} {name!r} is not a declared tool")
        if tool.public:
            raise _refuse("lifecycle_invalid", f"lifecycle {role} {name!r} must be member-authenticated")
        if tool.mutation != mutation:
            raise _refuse("lifecycle_invalid", f"lifecycle {role} {name!r} has the wrong mutation flag")
    if named == 0:
        raise _refuse("lifecycle_invalid", "lifecycle must name at least one tool")


def _validate_hook_catalog(catalog: tuple[str, int], hook: str) -> None:
    if not _HOOK_NAME.fullmatch(catalog[0]):
        raise _refuse("hooks_invalid", "hook catalog id is invalid")
    if catalog[1] < 1:
        raise _refuse("hooks_invalid", "hook catalog version must be positive")
    if not _HOOK_NAME.fullmatch(hook):
        raise _refuse("hooks_invalid", "hook name is invalid")


def _validate_distinct(names: list[str], limit: int, pattern: re.Pattern[str] | None, what: str) -> None:
    if len(names) > limit:
        raise _refuse("hooks_invalid", f"{what} exceeds {limit}")
    if (pattern is not None and not all(pattern.fullmatch(n) for n in names)) or len(set(names)) != len(names):
        raise _refuse("hooks_invalid", f"{what} are invalid or repeated")


def _parse_roles(raw: Any) -> list[dict[str, str | None]]:
    """The roles a team admin may designate; absent declares none. A name is
    compared exactly, and its label and description are shown in the host's
    own chrome, so they carry no control or bidi character."""
    if raw is None:
        return []
    if not isinstance(raw, list) or not 1 <= len(raw) <= _MAX_ROLES:
        raise _refuse("role_invalid", f"roles must be an array of 1 to {_MAX_ROLES} roles")
    roles: list[dict[str, str | None]] = []
    for item in raw:
        if not isinstance(item, dict) or set(item) - _ROLE or any(value is None for value in item.values()):
            raise _refuse("role_invalid", "a role is an object of name, label and description")
        name, label, description = item.get("name", ""), item.get("label", ""), item.get("description")
        if not isinstance(name, str) or not isinstance(label, str) or not isinstance(description, (str, type(None))):
            raise _refuse("role_invalid", "role members are strings")
        if len(name.encode("utf-8")) > _MAX_ROLE_NAME_BYTES or not _ROLE_NAME.fullmatch(name):
            raise _refuse("role_invalid", f"role name {name!r} is not a designatable role name")
        if any(role["name"] == name for role in roles):
            raise _refuse("role_invalid", f"duplicate role name {name!r}")
        if not _valid_role_text(label, _MAX_ROLE_LABEL):
            raise _refuse("role_invalid", f"role {name!r} label must be 1 to {_MAX_ROLE_LABEL} characters "
                          "with no control or bidi character")
        if description is not None and not _valid_role_text(description, _MAX_ROLE_DESCRIPTION):
            raise _refuse("role_invalid", f"role {name!r} description must be 1 to {_MAX_ROLE_DESCRIPTION} "
                          "characters with no control or bidi character")
        roles.append({"name": name, "label": label, "description": description})
    return roles


def _valid_role_text(text: str, max_runes: int) -> bool:
    if not text or len(text) > max_runes:
        return False
    return not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F or _is_bidi_control(ord(c)) for c in text)


def _is_bidi_control(code: int) -> bool:
    return code in (0x061C, 0x200E, 0x200F) or 0x202A <= code <= 0x202E or 0x2066 <= code <= 0x2069


def _validate_hooks(hooks: dict[str, Any] | None, tools: dict[str, _Tool]) -> None:
    if hooks is None:
        return
    if hooks["registration_version"] != 1:
        raise _refuse("hooks_invalid", "unsupported hooks registration_version")
    if len(hooks["registrations"]) > 64:
        raise _refuse("hooks_invalid", "hooks.registrations exceeds 64")
    if len(hooks["productions"]) > 64:
        raise _refuse("hooks_invalid", "hooks.productions exceeds 64")
    registrations: set[tuple[tuple[str, int], str, str]] = set()
    for reg in hooks["registrations"]:
        _validate_hook_catalog(reg["catalog"], reg["hook"])
        _validate_distinct(reg["scopes"], 32, _SCOPE_NAME, "hook registration scopes")
        registration = (reg["catalog"], reg["hook"], reg["tool"])
        if registration in registrations:
            raise _refuse("hooks_invalid", "duplicate hook registration")
        registrations.add(registration)
    productions: set[tuple[tuple[str, int], str]] = set()
    for prod in hooks["productions"]:
        _validate_hook_catalog(prod["catalog"], prod["hook"])
        _validate_distinct(prod["reads"], 64, None, "hook production reads")
        production = (prod["catalog"], prod["hook"])
        if production in productions:
            raise _refuse("hooks_invalid", "duplicate hook production")
        productions.add(production)
    for reg in hooks["registrations"]:
        tool = tools.get(reg["tool"]) if reg["tool"] else None
        if tool is None or tool.effective_contexts != {HOOK}:
            raise _refuse("hook_tool_invalid",
                          f"hook registration tool {reg['tool']!r} must be a local tool declaring exactly [\"hook\"]")
    for prod in hooks["productions"]:
        for read in prod["reads"]:
            tool = tools.get(read)
            if tool is None or tool.mutation:
                raise _refuse("hook_tool_invalid", f"hook production read {read!r} must be a local non-mutating tool")


@dataclass(frozen=True)
class Attestation:
    """A request's aweb.principal-attestation/1 as its verifier left it: whether
    it verified, and its payload. Verification is not part of this module."""

    verified: bool
    payload: Mapping[str, Any] | None


def caller_context(attestation: Attestation | None) -> str:
    """The invocation context a request may use. No attestation means an agent
    caller; a dashboard is never inferred."""
    if attestation is None:
        return AGENT
    if not attestation.verified:
        raise _refuse("attestation_invalid", "principal attestation did not verify")
    channel = (attestation.payload or {}).get("channel")
    if channel == "dashboard":
        return SURFACE
    if channel in ("mcp_l2", "api"):
        return AGENT
    raise _refuse("channel_invalid", "principal attestation channel is missing or not recognised")


@dataclass(frozen=True)
class Manifest:
    """Validated manifest bytes of either version, resolved."""

    document: Mapping[str, Any]
    manifest_version: int
    app_id: str
    agent_tools: tuple[str, ...]
    surface_tools: tuple[str, ...]
    hook_tools: tuple[str, ...]
    install_scopes: tuple[str, ...]
    app_keys: tuple[tuple[str, str, tuple[str, ...]], ...]
    surfaces: tuple[Mapping[str, Any], ...]
    usage: Mapping[str, str] | None
    lifecycle: Mapping[str, str | None] | None
    hooks: Mapping[str, Any] | None
    roles: tuple[Mapping[str, str | None], ...]
    _tools: Mapping[str, _Tool]

    def view(self) -> dict[str, Any]:
        """The resolved view the shared vectors assert."""
        return {
            "manifest_version": self.manifest_version,
            "app_id": self.app_id,
            "agent_tools": list(self.agent_tools),
            "surface_tools": list(self.surface_tools),
            "hook_tools": list(self.hook_tools),
            "install_scopes": list(self.install_scopes),
            "app_keys": [{"kid": k, "did_key": d, "purposes": list(p)} for k, d, p in self.app_keys],
            "surfaces": [copy.deepcopy(dict(s)) for s in self.surfaces],
            "usage": None if self.usage is None else dict(self.usage),
            "lifecycle": None if self.lifecycle is None else dict(self.lifecycle),
            "hooks": copy.deepcopy(self.hooks),
            "roles": [dict(role) for role in self.roles],
        }

    def tools_by_name(self) -> dict[str, Mapping[str, Any]]:
        """Each declared tool as the manifest declares it, keyed by the name a
        consumer resolves it by, in manifest order."""
        return {name: tool.raw for name, tool in self._tools.items()}

    def tool_contexts(self, name: str) -> frozenset[str] | None:
        """A declared tool's effective invocation contexts, ``None`` when undeclared."""
        tool = self._tools.get(_go_trim(name))
        return None if tool is None else tool.effective_contexts

    def app_keys_for(self, purpose: str) -> dict[str, str]:
        """The declared keys usable for one purpose, as ``{kid: did_key}`` in
        manifest order. A version 1 event emitter serves only ``app-event``."""
        return {kid: did_key for kid, did_key, purposes in self.app_keys if purpose in purposes}

    def check_invocation_context(self, tool: str, attestation: Attestation | None) -> None:
        """Refuse a call whose caller context is outside the tool's contexts.

        It only refuses: passing grants nothing, and the call still faces the
        app's grants, roles and policy.
        """
        caller = caller_context(attestation)
        contexts = self.tool_contexts(tool)
        if contexts is None:
            raise _refuse("tool_not_found", f"tool {tool!r} not found")
        if caller not in contexts:
            raise _refuse("tool_context_denied", f"tool {tool!r} is not available to {caller} callers")

    def check_answer_payload(self, tool: str, body: Any) -> None:
        """Refuse a version 2 body that carries an ``answer`` member, top-level
        or in a top-level object member, for any tool except a surface
        answer_tool. Answers reach an app only through that tool."""
        if self.manifest_version != 2 or _go_trim(tool) in _answer_tools(self.surfaces):
            return
        if not isinstance(body, dict):
            return
        if "answer" in body or any(isinstance(v, dict) and "answer" in v for v in body.values()):
            raise _refuse("answer_payload_refused", f"tool {tool!r} cannot carry an answer")


def load_manifest(data: bytes, *, reserved_names: frozenset[str] = frozenset()) -> Manifest:
    """Decode exact manifest bytes of either supported version, validate them
    and resolve them. Refusals raise :class:`ManifestError` with a stable code."""
    document = _decode_document(data)
    d = _decode(document)
    if d["version"] not in SUPPORTED_MANIFEST_VERSIONS:
        raise ManifestError("manifest_version_unsupported", f"unsupported manifest_version {d['version']}")
    app_id = _validate_common(d, reserved_names)
    tools = {_go_trim(tool.name): tool for tool in d["tools"]}
    if d["version"] == 1:
        if any(tool.contexts is not None for tool in d["tools"]) or any(k in d["present"] for k in _V2_TOP):
            raise _invalid("a version 2 field requires manifest_version 2")
    else:
        _validate_v2(d, app_id, tools)

    declared = _declared_events(d, app_id)
    app_keys = [(_go_trim(kid), _go_trim(did), ("app-event",)) for kid, did in d["emitters"]]
    app_keys += [(kid, did, tuple(purposes)) for kid, did, purposes in d["app_keys"]]
    surfaces = [{
        "id": s["id"], "label": s["label"], "format": s["format"],
        "list_tool": s["list_tool"], "read_tool": s["read_tool"],
        "invoke_tool": s["invoke_tool"] or None, "answer_tool": s["answer_tool"] or None,
        "resource_param": s["resource"], "invocation_param": s["invocation"] or None,
        "events": [{"type": _resolve_event_type(e["type"], app_id, declared),
                    "resource_field": e["resource_field"], "revision_field": e["revision_field"]}
                   for e in s["events"]],
    } for s in d["surfaces"]]
    hooks = None
    if d["hooks"] is not None:
        hooks = {
            "registration_version": d["hooks"]["registration_version"],
            "registrations": [{"catalog_id": r["catalog"][0], "catalog_version": r["catalog"][1], "hook": r["hook"],
                               "tool": r["tool"], "scopes": list(r["scopes"])} for r in d["hooks"]["registrations"]],
            "productions": [{"catalog_id": p["catalog"][0], "catalog_version": p["catalog"][1], "hook": p["hook"],
                             "reads": list(p["reads"])} for p in d["hooks"]["productions"]],
        }
    lifecycle = None
    if d["lifecycle"] is not None:
        lifecycle = {role: d["lifecycle"][role] or None for role in ("export_tool", "delete_tool", "status_tool")}
    names = [(_go_trim(tool.name), tool.effective_contexts) for tool in d["tools"]]
    install_scopes = sorted({scope for tool in d["tools"] if tool.effective_contexts & _DEFAULT_CONTEXTS
                             for scope in tool.scopes})
    return Manifest(
        document=document,
        manifest_version=d["version"],
        app_id=app_id,
        agent_tools=tuple(n for n, c in names if AGENT in c),
        surface_tools=tuple(n for n, c in names if SURFACE in c),
        hook_tools=tuple(n for n, c in names if HOOK in c),
        install_scopes=tuple(install_scopes),
        app_keys=tuple(app_keys),
        surfaces=tuple(surfaces),
        usage=d["usage"],
        lifecycle=lifecycle,
        hooks=hooks,
        roles=tuple(_parse_roles(d["roles"])),
        _tools=tools,
    )


# --- Variant discovery ---------------------------------------------------------

Fetch = Callable[[str, int], tuple[int, bytes]]
"""GETs one origin-relative path without following redirects; returns the
status and at most ``max_bytes`` of body, raising when it cannot."""


@dataclass(frozen=True)
class Variant:
    """The manifest a consumer selected, with its exact bytes."""

    source: str
    manifest_version: int
    url: str
    digest: str
    data: bytes


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _identity(data: bytes) -> tuple[int, str]:
    """manifest_version and app.id only, read the way Go's lenient decode does."""
    if _nesting_depth_exceeds(data, MAX_JSON_DEPTH):
        return 0, ""
    try:
        doc = json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError):
        return 0, ""
    if not isinstance(doc, dict):
        return 0, ""
    version, app = doc.get("manifest_version"), doc.get("app")
    if version is None:
        version = 0
    if isinstance(version, bool) or not isinstance(version, int) or not _INT64[0] <= version <= _INT64[1]:
        return 0, ""
    if app is None:
        return version, ""
    if not isinstance(app, dict):
        return 0, ""
    app_id = app.get("id")
    if app_id is None:
        return version, ""
    if not isinstance(app_id, str):
        return 0, ""
    return version, _go_trim(app_id)


def _valid_variant_path(path: str) -> bool:
    """An absolute path that resolves under the install base: no scheme, host,
    query, fragment, backslash, percent-encoding or dot segment."""
    if not path or len(path) > 512 or not path.startswith("/") or path.startswith("//"):
        return False
    if any(c in path for c in "?#\\") or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in path):
        return False
    if "%" in path:
        return False
    return not any(segment in (".", "..") for segment in path[1:].split("/"))


def _parse_catalog(data: bytes) -> tuple[str, list[tuple[int, str, str]]]:
    def invalid(message: str) -> ManifestError:
        return ManifestError("catalog_invalid", message)

    if len(data) > MAX_CATALOG_BYTES:
        raise invalid("manifest catalog exceeds its size bound")
    try:
        doc = _decode_document(data, "manifest catalog")
    except ManifestError as exc:
        raise invalid(str(exc)) from None
    if not isinstance(doc, dict) or set(doc) - {"catalog_version", "app_id", "variants"}:
        raise invalid("manifest catalog is not a catalog object")
    version, app_id, variants = doc.get("catalog_version"), doc.get("app_id"), doc.get("variants")
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise invalid("unsupported catalog_version")
    if not isinstance(app_id, str) or not _go_trim(app_id):
        raise invalid("manifest catalog requires app_id")
    if not isinstance(variants, list) or not 1 <= len(variants) <= 8:
        raise invalid("manifest catalog must list 1 to 8 variants")
    out: list[tuple[int, str, str]] = []
    for item in variants:
        if not isinstance(item, dict) or set(item) - {"manifest_version", "url", "digest"}:
            raise invalid("manifest catalog variant is malformed")
        mv, url, digest = item.get("manifest_version"), item.get("url"), item.get("digest")
        if isinstance(mv, bool) or not isinstance(mv, int) or mv < 1 or any(mv == v for v, _, _ in out):
            raise invalid("manifest catalog variant versions must be distinct and positive")
        if not isinstance(url, str) or not _valid_variant_path(url):
            raise invalid("manifest catalog variant url must be an absolute path under the install base")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise invalid("manifest catalog variant digest is invalid")
        out.append((mv, url, digest))
    return app_id, out


def select_variant(origin: str, supported: tuple[int, ...] | list[int], fetch: Fetch) -> Variant:
    """Discover the manifest an origin offers: the highest supported variant in
    its catalog, digest, version and app id verified. Only a missing catalog
    (404) permits the legacy manifest; no failure falls back."""
    origin = _go_trim(origin).rstrip("/")
    try:
        status, data = fetch(CATALOG_PATH, MAX_CATALOG_BYTES)
    except Exception as exc:
        raise ManifestError("catalog_unavailable", f"fetch manifest catalog: {exc}") from exc
    if status == 404:
        try:
            status, data = fetch(LEGACY_MANIFEST_PATH, MAX_MANIFEST_BYTES)
        except Exception as exc:
            raise ManifestError("legacy_unavailable", f"fetch legacy manifest: {exc}") from exc
        if status != 200:
            raise ManifestError("legacy_unavailable", f"legacy manifest answered HTTP {status}")
        return Variant("legacy", _identity(data)[0], origin + LEGACY_MANIFEST_PATH, _digest(data), data)
    if status != 200:
        raise ManifestError("catalog_unavailable", f"manifest catalog answered HTTP {status}")
    app_id, variants = _parse_catalog(data)
    candidates = [v for v in variants if v[0] in supported]
    if not candidates:
        raise ManifestError("no_supported_variant", "no manifest variant this consumer supports")
    version, path, digest = max(candidates)
    try:
        status, data = fetch(path, MAX_MANIFEST_BYTES)
    except Exception as exc:
        raise ManifestError("variant_unavailable", f"fetch manifest variant {path}: {exc}") from exc
    if status != 200:
        raise ManifestError("variant_unavailable", f"manifest variant {path} answered HTTP {status}")
    if _digest(data) != digest:
        raise ManifestError("variant_digest_mismatch", f"manifest variant {path} does not match its catalog digest")
    if _identity(data) != (version, app_id):
        raise ManifestError("variant_mismatch", f"manifest variant {path} is not version {version} of app {app_id!r}")
    return Variant("catalog", version, origin + path, digest, data)


_MISSING = object()


def _same(a: Any, b: Any) -> bool:
    """Type-exact JSON equality: false is not 0, and 1.0 is not 1."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b, strict=True))
    return bool(a == b)


_MAPPED_TOOL_FIELDS = ("method", "path", "params", "input_schema", "body", "scopes", "auth", "mutation")


def check_v1_variant(v1: bytes, v2: bytes) -> None:
    """Refuse a v1 variant that is not an agent-safe, identically mapped subset
    of the v2 variant it is served beside. Apps run this before publishing."""

    def incompatible(message: str) -> ManifestError:
        return ManifestError("v1_variant_incompatible", message)

    old, new = load_manifest(v1), load_manifest(v2)
    if old.manifest_version != 1 or new.manifest_version != 2:
        raise incompatible("variants must be manifest versions 1 and 2")
    if not _same(old.document.get("app"), new.document.get("app")):
        raise incompatible("the variants declare different apps")
    if not _same(old.document.get("events"), new.document.get("events")):
        raise incompatible("the variants declare different events")
    v2_tools = {_go_trim(t.get("name", "")): t for t in new.document.get("tools") or []}
    for tool in old.document.get("tools") or []:
        name = _go_trim(tool.get("name", ""))
        twin = v2_tools.get(name)
        if twin is None:
            raise incompatible(f"v1 tool {name!r} is not a v2 tool")
        if any(not _same(tool.get(f, _MISSING), twin.get(f, _MISSING)) for f in _MAPPED_TOOL_FIELDS):
            raise incompatible(f"v1 tool {name!r} maps differently in v2")
        if AGENT not in (new.tool_contexts(name) or frozenset()):
            raise incompatible(f"v1 tool {name!r} is not an agent tool in v2")
    v2_event_keys = new.app_keys_for("app-event")
    for kid, did_key in old.app_keys_for("app-event").items():
        if v2_event_keys.get(kid) != did_key:
            raise incompatible(f"v1 event emitter {kid!r} is not a v2 app-event key")
